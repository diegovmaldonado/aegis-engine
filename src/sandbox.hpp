#ifndef SANDBOX_HPP
#define SANDBOX_HPP

#include <string>

struct SandboxResult {
    std::string status;        // "success", "timeout", "security_violation", "error"
    std::string stdout_output;
    std::string stderr_output;
    int exit_code = -1;
    double wall_time = 0.0;
    double peak_memory_mb = 0.0;
    std::string error_msg;
};

/**
 * Ejecuta código Python en un entorno aislado.
 * Implementación seleccionada en tiempo de COMPILACIÓN (no de ejecución):
 * sandbox_linux.cpp en Linux, sandbox_windows.cpp en Windows.
 * El binario resultante ya sabe para qué SO fue compilado; no hay
 * detección de SO en runtime porque las APIs de aislamiento
 * (namespaces/seccomp/cgroups vs. Job Objects) son de sistema y no
 * intercambiables en un mismo binario.
 *
 * @param codigo        Código Python fuente.
 * @param max_mem_mb    Memoria máxima en MB.
 * @param max_cpu_sec   Tiempo máximo de CPU en segundos.
 * @param max_wall_sec  Tiempo máximo de pared en segundos.
 * @param network       Si es true, se permite acceso de red (desaconsejado).
 * @return SandboxResult con los resultados.
 */
SandboxResult run_in_sandbox(const std::string& codigo,
                             int max_mem_mb,
                             int max_cpu_sec,
                             int max_wall_sec,
                             bool network);

/** Nombre de la plataforma para la que este binario fue compilado. */
std::string sandbox_platform_name();

#endif // SANDBOX_HPP
