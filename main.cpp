/**
 * AEGIS Engine - Motor de sandbox en C++ para Linux
 * 
 * Uso: ./aegis-engine < solicitud.json > respuesta.json
 * 
 * Operaciones soportadas:
 * - "execute_python": ejecuta código Python en jaula
 * - "analyze_file_static": análisis forense de archivo sin ejecución
 */

#include <iostream>
#include <string>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include "json.hpp"
#include "sandbox.hpp"
#include "forensic.hpp"
#include "utils.hpp"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <pwd.h>
    #include <grp.h>
#endif

using json = nlohmann::json;

#ifndef _WIN32
// --- Drop de privilegios, fail-closed (solo Linux/POSIX) ---
// El namespace de usuario en sandbox_linux.cpp mapea "UID 0 dentro de la
// jaula" al UID REAL con el que corre aegis-engine. Si ese UID real ya es
// 0 (el servicio arrancó como root, algo común en despliegues systemd que
// necesitan bindear puertos privilegiados o similar), el mapeo apunta a
// root real y no protege nada -- esto ya estaba documentado como hueco
// conocido en el informe de estado.
//
// Esta función baja privilegios a un usuario dedicado sin privilegios
// ANTES de leer o procesar cualquier entrada no confiable. Es fail-closed
// a propósito: si el usuario dedicado no existe, el proceso se niega a
// seguir corriendo como root en vez de continuar "igual, pero inseguro".
static void drop_privileges_if_root() {
    if (geteuid() != 0) return; // ya no somos root real, nada que hacer

    const char* dedicated_user = "aegis-sandbox";
    struct passwd* pw = getpwnam(dedicated_user);
    if (!pw) {
        std::cerr
            << "aegis-engine arrancó como root pero el usuario dedicado '"
            << dedicated_user << "' no existe en este sistema. Por "
            << "seguridad NO continuamos corriendo como root real -- ver "
            << "INFORME_ESTADO.md, sección de namespace de usuario: el "
            << "mapeo de UID no protege nada si el proceso base ya es "
            << "root. Crear el usuario con:\n"
            << "  useradd --system --no-create-home --shell /usr/sbin/nologin "
            << dedicated_user << std::endl;
        std::exit(1);
    }

    // Limpiar grupos suplementarios ANTES de bajar uid/gid: hacerlo
    // después requeriría CAP_SETGID, que ya no tendríamos.
    if (setgroups(0, nullptr) != 0) {
        std::cerr << "No se pudieron limpiar los grupos suplementarios" << std::endl;
        std::exit(1);
    }
    // gid antes que uid: una vez que se baja el uid real, ya no hay
    // privilegio para cambiar el gid.
    if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
        std::cerr << "No se pudo bajar privilegios a '" << dedicated_user << "'" << std::endl;
        std::exit(1);
    }

    // Verificación explícita de que el drop fue efectivo e irreversible:
    // si por algún motivo setuid() de arriba "tuvo éxito" pero dejó abierta
    // la posibilidad de recuperar root (ej. sistema con semántica rara de
    // UIDs guardados), este intento de volver a 0 tiene que FALLAR. Si no
    // falla, algo está mal y abortamos en vez de seguir con una falsa
    // sensación de seguridad.
    if (setuid(0) == 0) {
        std::cerr
            << "ALERTA: se pudo recuperar UID root después de bajar "
            << "privilegios -- el drop no fue efectivo. Abortando."
            << std::endl;
        std::exit(1);
    }
}
#else
// --- Equivalente conceptual en Windows: negarse a correr elevado ---
// Windows no tiene un análogo directo de bajar de UID 0 a un usuario sin
// privilegios en runtime tan simple como POSIX (requeriría relanzarse con
// un token restringido vía CreateProcessAsUser, más complejo y sin poder
// probarlo en este entorno). Como mínimo fail-closed equivalente: si el
// proceso corre elevado (token de Administrador), rechazar arrancar en vez
// de seguir corriendo con privilegios que un escape podría heredar. Igual
// que en Linux: mejor fallar temprano y explícito que dar una falsa
// sensación de aislamiento.
static bool running_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    bool elevated = false;
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
        elevated = elevation.TokenIsElevated != 0;
    }
    CloseHandle(token);
    return elevated;
}

static void drop_privileges_if_root() {
    if (running_elevated()) {
        std::cerr
            << "aegis-engine está corriendo como Administrador. Por "
            << "seguridad NO continuamos: un proceso elevado le da a un "
            << "eventual escape de sandbox privilegios que no debería "
            << "tener. Correr este binario con un usuario estándar, sin "
            << "elevar." << std::endl;
        std::exit(1);
    }
}
#endif

// --- Registro de auditoría persistente ---
// Hasta ahora, si algo salía mal en producción, la única fuente de verdad
// era el logging de quien LLAMA al motor (LITA, en este caso). Si ese
// logging fallaba, estaba desactivado, o el propio proceso llamador se
// vio comprometido, no quedaba ningún rastro independiente de qué corrió
// el sandbox y qué pasó. Este log es intencionalmente austero: NO guarda
// el código ejecutado completo (eso sería un vector de fuga de datos en sí
// mismo si el log se filtra), solo un hash de qué se ejecutó, el
// resultado, y métricas -- suficiente para reconstruir un incidente sin
// convertir el log en un segundo lugar donde buscar datos sensibles.
static void registrar_auditoria(const std::string& codigo, const SandboxResult& result) {
    const char* ruta = std::getenv("AEGIS_AUDIT_LOG");
    std::string ruta_log = ruta ? ruta : "/var/log/aegis-engine/audit.log";

    std::ofstream log_file(ruta_log, std::ios::app);
    if (!log_file.is_open()) {
        // No abortamos la ejecución por esto -- el resultado del sandbox
        // ya es válido y se le va a devolver a quien llamó. Pero si el
        // log de auditoría no se puede escribir (ej. permisos, disco
        // lleno, directorio no existe), eso mismo es información que
        // alguien tiene que ver -- va a stderr, no se pierde en silencio.
        std::cerr << "ADVERTENCIA: no se pudo abrir el log de auditoría en '"
                  << ruta_log << "' -- la ejecución continuó, pero sin "
                  << "registro persistente." << std::endl;
        return;
    }

    auto ahora = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        ahora.time_since_epoch()).count();

    json entrada = {
        {"timestamp_unix", timestamp},
        {"codigo_sha256", sha256_hex(codigo)}, // no se guarda el código en sí
        {"codigo_tamano_bytes", codigo.size()},
        {"status", result.status},
        {"exit_code", result.exit_code},
        {"wall_time", result.wall_time},
        {"peak_memory_mb", result.peak_memory_mb},
        {"security_violation", result.status == "security_violation"}
    };
    log_file << entrada.dump() << "\n";
}

int main() {
    drop_privileges_if_root();
    try {
        // Leer todo stdin
        std::string input_data;
        std::string line;
        while (std::getline(std::cin, line)) {
            input_data += line + "\n";
        }

        json solicitud;
        try {
            solicitud = json::parse(input_data);
        } catch (const std::exception &e) {
            json error_resp = {
                {"status", "error"},
                {"error_message", "JSON inválido: " + std::string(e.what())}
            };
            std::cout << error_resp.dump() << std::endl;
            return 1;
        }

        // Validar campos obligatorios
        if (!solicitud.contains("operation")) {
            throw std::runtime_error("Falta el campo 'operation'");
        }

        std::string operacion = solicitud["operation"];
        json respuesta;

        if (operacion == "execute_python") {
            if (!solicitud.contains("target") || !solicitud["target"].contains("content")) {
                throw std::runtime_error("Falta el código a ejecutar");
            }
            std::string codigo = solicitud["target"]["content"];

            // Límites por defecto
            int max_mem_mb = solicitud.value("limits", json::object()).value("max_memory_mb", 256);
            int max_cpu_sec = solicitud.value("limits", json::object()).value("max_cpu_seconds", 5);
            int max_wall_sec = solicitud.value("limits", json::object()).value("max_wall_seconds", 10);
            bool network = solicitud.value("limits", json::object()).value("network", false);

            // Validación de rango: sin esto, un valor negativo o en 0
            // produce comportamiento indefinido en setrlimit()/alarm()
            // (ej. max_wall_sec<=0 con alarm() dispara la señal casi
            // inmediato o nunca, según la implementación; max_mem_mb
            // negativo se interpreta como enorme al castear a rlim_t sin
            // signo). Los topes superiores son arbitrarios pero generosos;
            // ajustar según el caso de uso real.
            auto clamp = [](int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); };
            max_mem_mb  = clamp(max_mem_mb, 16, 4096);
            max_cpu_sec = clamp(max_cpu_sec, 1, 300);
            max_wall_sec = clamp(max_wall_sec, 1, 600);

            // network=true está deshabilitado a propósito hasta que exista
            // una implementación real de aislamiento de salida (namespace +
            // veth + NAT + reglas que bloqueen rangos privados/metadata),
            // probada de verdad -- no a medias. Con la implementación
            // actual, permitir network=true significaba compartir la red
            // real del host sin ningún aislamiento (ver sandbox_linux.cpp).
            // Rechazarlo explícito acá es mejor que dar una falsa sensación
            // de "acceso a internet controlado" que en los hechos era
            // "sin control en absoluto".
            if (network) {
                throw std::runtime_error(
                    "network=true está deshabilitado temporalmente: la implementación "
                    "de aislamiento de red de salida (firewall de namespace) todavía no "
                    "existe de forma probada. Usar network=false."
                );
            }

            // Ejecutar en sandbox
            SandboxResult result = run_in_sandbox(codigo, max_mem_mb, max_cpu_sec, max_wall_sec, network);
            registrar_auditoria(codigo, result);

            respuesta["status"] = result.status;
            respuesta["result"] = {
                {"stdout", result.stdout_output},
                {"stderr", result.stderr_output},
                {"exit_code", result.exit_code},
                {"wall_time", result.wall_time},
                {"peak_memory_mb", result.peak_memory_mb}
            };
            if (!result.error_msg.empty())
                respuesta["error_message"] = result.error_msg;
        }
        else if (operacion == "analyze_file_static") {
            if (!solicitud.contains("target") || !solicitud["target"].contains("content")) {
                throw std::runtime_error("Falta la ruta del archivo a analizar");
            }
            std::string filepath = solicitud["target"]["content"];
            ForensicReport report = analyze_file_static(filepath);

            respuesta["status"] = "success";
            respuesta["forensic_report"] = {
                {"file_type", report.file_type},
                {"mime_type", report.mime_type},
                {"size_bytes", report.size_bytes},
                {"md5", report.md5},
                {"sha256", report.sha256},
                {"strings_of_interest", report.iocs},
                {"pe_sections", report.pe_sections},
                {"elf_segments", report.elf_segments}
            };
        }
        else {
            throw std::runtime_error("Operación no soportada: " + operacion);
        }

        std::cout << respuesta.dump(4) << std::endl;
    }
    catch (const std::exception &e) {
        json error_resp = {
            {"status", "error"},
            {"error_message", e.what()}
        };
        std::cout << error_resp.dump() << std::endl;
        return 1;
    }

    return 0;
}
