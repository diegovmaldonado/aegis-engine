#include "sandbox.hpp"
#include "utils.hpp"
#include "json.hpp"
#include <windows.h>
#include <string>
#include <chrono>
#include <sstream>

using json = nlohmann::json;

std::string sandbox_platform_name() { return "windows (via WSL2)"; }

// --- Por qué esta versión reemplaza a la de Job Objects nativos ---
//
// La primera versión de este archivo usaba Job Objects + token restringido.
// Eso limita bien memoria/CPU/nº de procesos, pero NO aísla filesystem ni
// red como un namespace de Linux -- Windows no tiene un equivalente nativo
// y simple a eso. Hacerlo bien nativamente (WFP a nivel de kernel, o un
// contenedor Windows con Hyper-V isolation) es un proyecto en sí mismo, y
// -sin una máquina Windows para probarlo- entregarlo sin verificar hubiera
// sido la parte más débil de todo este trabajo.
//
// La alternativa (la que en la práctica usan Docker Desktop y WSL2 mismo):
// correr el binario de LINUX -- el que SÍ probé y verifiqué en este mismo
// entorno (namespaces + pivot_root + seccomp real + cgroups/RLIMIT) -- 
// dentro de la VM ligera de Hyper-V que WSL2 ya trae instalada en Windows
// 10/11. Este .exe es un envoltorio delgado: recibe el JSON por stdin igual
// que siempre, se lo pasa a `wsl.exe` para que lo ejecute con el binario
// Linux ya construido, y devuelve la respuesta tal cual. La superficie de
// aislamiento real es exactamente la misma que ya quedó probada en Linux,
// en vez de una reimplementación nativa de Windows sin testear.
//
// Requisito de despliegue: WSL2 instalado (`wsl --install`), con una
// distro (ej. Ubuntu) que tenga el binario `aegis-engine` de Linux ya
// compilado dentro, en una ruta conocida (ej. /opt/aegis/aegis-engine).

static const wchar_t* WSL_DISTRO = L"Ubuntu";
static const wchar_t* LINUX_BINARY_PATH = L"/opt/aegis/aegis-engine";

SandboxResult run_in_sandbox(const std::string& codigo,
                             int max_mem_mb,
                             int max_cpu_sec,
                             int max_wall_sec,
                             bool network) {
    SandboxResult result;

    // Construimos el mismo JSON de solicitud que main.cpp ya recibió, y se
    // lo re-enviamos por stdin al proceso Linux dentro de WSL2 -- el mismo
    // protocolo de un extremo al otro.
    // ANTES esto se armaba escapando el string a mano, y solo cubría
    // comillas, backslash y \n -- cualquier \r, tab, u otro carácter de
    // control dentro del código del usuario generaba JSON inválido que el
    // binario Linux del otro lado rechazaba. nlohmann::json ya hace el
    // escapado completo y correcto del spec, así que lo usamos acá también
    // (ya lo estamos incluyendo para parsear la respuesta, ver abajo).
    json solicitud = {
        {"operation", "execute_python"},
        {"target", {{"content", codigo}}},
        {"limits", {
            {"max_memory_mb", max_mem_mb},
            {"max_cpu_seconds", max_cpu_sec},
            {"max_wall_seconds", max_wall_sec},
            {"network", network}
        }}
    };
    std::string request = solicitud.dump();

    // Pipes para hablar con el proceso wsl.exe igual que hablaríamos con
    // cualquier proceso hijo por stdin/stdout.
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE child_stdin_rd, child_stdin_wr, child_stdout_rd, child_stdout_wr;
    CreatePipe(&child_stdin_rd, &child_stdin_wr, &sa, 0);
    CreatePipe(&child_stdout_rd, &child_stdout_wr, &sa, 0);
    SetHandleInformation(child_stdin_wr, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(child_stdout_rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = child_stdin_rd;
    si.hStdOutput = child_stdout_wr;
    si.hStdError = child_stdout_wr;
    PROCESS_INFORMATION pi{};

    std::wstring cmdline = L"wsl.exe -d " + std::wstring(WSL_DISTRO) +
        L" " + std::wstring(LINUX_BINARY_PATH);

    BOOL created = CreateProcessW(nullptr, &cmdline[0], nullptr, nullptr,
        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    CloseHandle(child_stdin_rd);
    CloseHandle(child_stdout_wr);

    if (!created) {
        result.status = "error";
        result.error_msg = "No se pudo lanzar wsl.exe (¿WSL2 instalado? ¿distro '" +
            std::string(WSL_DISTRO, WSL_DISTRO + wcslen(WSL_DISTRO)) + "' presente?), "
            "código " + std::to_string(GetLastError());
        CloseHandle(child_stdin_wr);
        CloseHandle(child_stdout_rd);
        return result;
    }

    DWORD written;
    WriteFile(child_stdin_wr, request.data(), (DWORD)request.size(), &written, nullptr);
    CloseHandle(child_stdin_wr); // EOF para que el binario Linux sepa que terminó el input

    auto t_start = std::chrono::steady_clock::now();

    // El límite de pared real lo sigue aplicando el binario de LINUX
    // adentro de WSL2 (ya probado); acá solo ponemos un límite de
    // seguridad adicional por si wsl.exe mismo se cuelga.
    DWORD wait_result = WaitForSingleObject(pi.hProcess,
        static_cast<DWORD>(max_wall_sec + 5) * 1000);

    // BUG CORREGIDO: antes se leía el pipe de salida ANTES de revisar si
    // hubo timeout. Si el proceso se cuelga, ReadFile queda bloqueado
    // esperando datos que nunca llegan porque el proceso nunca cerró su
    // extremo del pipe -- el timeout de más arriba nunca llegaba a
    // aplicarse de verdad, era un deadlock silencioso. Ahora: si hubo
    // timeout, primero se mata el proceso (lo que sí cierra sus handles),
    // y recién después se drena lo que haya quedado en el pipe.
    std::string output;
    const size_t MAX_CAPTURED_OUTPUT = 8 * 1024 * 1024; // mismo tope que el lado Linux

    if (wait_result == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000); // esperar a que termine de verdad
    } else {
        char buf[4096]; DWORD n;
        while (output.size() < MAX_CAPTURED_OUTPUT &&
               ReadFile(child_stdout_rd, buf, sizeof(buf), &n, nullptr) && n > 0) {
            output.append(buf, n);
        }
    }

    if (wait_result == WAIT_TIMEOUT) {
        result.status = "timeout";
        result.error_msg = "wsl.exe no respondió a tiempo";
    } else {
        // El binario Linux ya devuelve un JSON con status/result -- lo
        // parseamos de verdad acá, en vez de reportar "success" siempre
        // sin importar qué haya pasado adentro (bug anterior: eso hacía
        // que security_violation, timeout, cpu_limit_exceeded, etc. se
        // perdieran del todo en la ruta Windows y todo se viera como
        // ejecución exitosa).
        try {
            json respuesta_linux = json::parse(output);
            result.status = respuesta_linux.value("status", "error");
            auto res = respuesta_linux.value("result", json::object());
            result.stdout_output = res.value("stdout", "");
            result.stderr_output = res.value("stderr", "");
            result.exit_code = res.value("exit_code", -1);
            result.peak_memory_mb = res.value("peak_memory_mb", 0.0);
            result.error_msg = respuesta_linux.value("error_message", "");
        } catch (const json::parse_error& e) {
            result.status = "error";
            result.error_msg = "No se pudo parsear la respuesta del binario "
                "Linux dentro de WSL2 (¿wsl.exe imprimió algo fuera del "
                "protocolo, como un warning de arranque de la distro?): " +
                std::string(e.what());
        }
    }

    result.wall_time = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(child_stdout_rd);

    return result;
}
