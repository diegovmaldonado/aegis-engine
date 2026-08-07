#include "sandbox.hpp"
#include "utils.hpp"
#include <windows.h>
#include <string>
#include <chrono>
#include <fstream>

std::string sandbox_platform_name() { return "windows"; }

// Equivalente Windows de namespaces+cgroups+seccomp de Linux:
//  - Job Object              -> límites de memoria/CPU/nº de procesos,
//                                y mata todo el árbol de procesos al cerrarse
//                                (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE).
//  - Token restringido        -> quita privilegios (equivalente a no ser root),
//                                similar en espíritu a lo que CLONE_NEWUSER
//                                lograría en Linux.
//  - CREATE_SUSPENDED + job   -> el proceso se crea pausado, se asigna al job
//    ANTES de arrancar, para que no pueda escapar de los límites corriendo
//    aunque sea una fracción de segundo sin restricciones.
//
// LIMITACIÓN HONESTA: un Job Object no aísla el filesystem ni la red como
// namespaces de Linux. Para eso, la vía nativa de Windows es un contenedor
// (Windows Sandbox / Hyper-V isolation) o AppContainer. Este código deja el
// proceso restringido en CPU/memoria/privilegios, pero NO aislado de la red
// ni del filesystem del host de forma tan fuerte como en Linux -- ver nota
// al final del informe.

SandboxResult run_in_sandbox(const std::string& codigo,
                             int max_mem_mb,
                             int max_cpu_sec,
                             int max_wall_sec,
                             bool network) {
    SandboxResult result;

    // 1. Escribir el código a un archivo temporal en una carpeta acotada.
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);
    std::string script_path = std::string(temp_dir) + "aegis_script.py";
    {
        std::ofstream f(script_path);
        if (!f) {
            result.status = "error";
            result.error_msg = "No se pudo escribir el script temporal";
            return result;
        }
        f << codigo;
    }

    // 2. Crear el Job Object con límites de memoria y nº de procesos
    //    (equivalente a memory.max y pids.max de cgroups v2 en Linux).
    HANDLE job = CreateJobObjectA(nullptr, nullptr);
    if (!job) {
        result.status = "error";
        result.error_msg = "CreateJobObject falló";
        return result;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext_limits{};
    ext_limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |     // mata todo si el handle se cierra
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS |        // limita nº de procesos (anti fork-bomb)
        JOB_OBJECT_LIMIT_PROCESS_MEMORY |        // memoria por proceso
        JOB_OBJECT_LIMIT_JOB_MEMORY |            // memoria total del job
        JOB_OBJECT_LIMIT_PROCESS_TIME;           // tiempo de CPU acumulado (el que
                                                  // faltaba en la versión Linux original)
    ext_limits.BasicLimitInformation.ActiveProcessLimit = 8;
    ext_limits.ProcessMemoryLimit = static_cast<SIZE_T>(max_mem_mb) * 1024 * 1024;
    ext_limits.JobMemoryLimit = static_cast<SIZE_T>(max_mem_mb) * 1024 * 1024;
    // PROCESS_TIME está en unidades de 100ns.
    ULONGLONG cpu_100ns = static_cast<ULONGLONG>(max_cpu_sec) * 10'000'000ULL;
    ext_limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = cpu_100ns;

    SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                             &ext_limits, sizeof(ext_limits));

    // Restringe qué puede hacer el proceso a nivel de escritorio/UI
    // (portapapeles, otras ventanas, etc. -- equivalente parcial a IPC namespace).
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui_limits{};
    ui_limits.UIRestrictionsClass = JOB_OBJECT_UILIMIT_HANDLES |
                                     JOB_OBJECT_UILIMIT_READCLIPBOARD |
                                     JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
                                     JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
                                     JOB_OBJECT_UILIMIT_DESKTOP |
                                     JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                                     JOB_OBJECT_UILIMIT_GLOBALATOMS |
                                     JOB_OBJECT_UILIMIT_EXITWINDOWS;
    SetInformationJobObject(job, JobObjectBasicUIRestrictions,
                             &ui_limits, sizeof(ui_limits));

    // 3. Token restringido: quita el grupo Administradores y privilegios
    //    peligrosos del proceso hijo (equivalente en espíritu a no correr
    //    como root dentro del namespace en Linux).
    HANDLE proc_token;
    HANDLE restricted_token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &proc_token)) {
        CreateRestrictedToken(proc_token, DISABLE_MAX_PRIVILEGE,
                               0, nullptr, 0, nullptr, 0, nullptr, &restricted_token);
        CloseHandle(proc_token);
    }

    // 4. Lanzar python.exe SUSPENDIDO, asignarlo al Job ANTES de reanudarlo.
    std::string cmdline = "python.exe \"" + script_path + "\"";
    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    BOOL created;
    if (restricted_token) {
        created = CreateProcessAsUserA(restricted_token, nullptr,
            &cmdline[0], nullptr, nullptr, FALSE,
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP,
            nullptr, nullptr, &si, &pi);
    } else {
        created = CreateProcessA(nullptr, &cmdline[0], nullptr, nullptr, FALSE,
            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP,
            nullptr, nullptr, &si, &pi);
    }

    if (!created) {
        result.status = "error";
        result.error_msg = "CreateProcess falló, código " + std::to_string(GetLastError());
        CloseHandle(job);
        if (restricted_token) CloseHandle(restricted_token);
        return result;
    }

    AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);

    auto t_start = std::chrono::steady_clock::now();
    DWORD wait_ms = static_cast<DWORD>(max_wall_sec) * 1000;
    DWORD wait_result = WaitForSingleObject(pi.hProcess, wait_ms);

    if (wait_result == WAIT_TIMEOUT) {
        result.status = "timeout";
        result.error_msg = "Tiempo límite de pared excedido";
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 2000);
    } else {
        DWORD exit_code = 0;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        result.exit_code = static_cast<int>(exit_code);
        // STATUS_ACCESS_VIOLATION u otros códigos de excepción indican que
        // el proceso murió por violar un límite o intentar algo prohibido.
        result.status = (exit_code >= 0xC0000000) ? "security_violation" : "success";
    }

    result.wall_time = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();

    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(pi.hProcess, &pmc, sizeof(pmc))) {
        result.peak_memory_mb = pmc.PeakWorkingSetSize / (1024.0 * 1024.0);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(job); // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE mata cualquier
                       // proceso remanente del árbol al cerrar este handle.
    if (restricted_token) CloseHandle(restricted_token);
    DeleteFileA(script_path.c_str());

    return result;
}
