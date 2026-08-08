#include "cgroups_linux.hpp"
#include "utils.hpp"
#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <cerrno>

bool setup_cgroups(pid_t pid, int memory_mb, int cpu_seconds) {
    const std::string cgroup_base = "/sys/fs/cgroup";

    // Verificación real de que esto es un cgroup2 unificado de verdad, y no
    // un tmpfs cualquiera (bug encontrado en pruebas: en layouts híbridos,
    // /sys/fs/cgroup existe pero es tmpfs plano; escribir "memory.max" ahí
    // crea un archivo común que no limita NADA, sin dar ningún error).
    // cgroup.controllers solo existe en una raíz de cgroup2 real.
    std::ifstream controllers(cgroup_base + "/cgroup.controllers");
    if (!controllers) {
        log_error("cgroups v2 no disponible en /sys/fs/cgroup (no es una "
                  "raíz de cgroup2 real -- posible layout híbrido con v1). "
                  "Los límites de RLIMIT_AS/RLIMIT_CPU en el hijo siguen "
                  "activos como respaldo, pero sin la telemetría de "
                  "memory.peak ni el límite de tasa de CPU de cgroups.");
        return false;
    }
    std::string controllers_str((std::istreambuf_iterator<char>(controllers)),
                                  std::istreambuf_iterator<char>());
    if (controllers_str.find("memory") == std::string::npos) {
        log_error("El controlador 'memory' no está delegado en cgroup2 "
                   "(cgroup.controllers no lo lista). Revisar "
                   "cgroup.subtree_control del padre. RLIMIT_AS sigue "
                   "activo como respaldo.");
        return false;
    }

    const std::string subgroup = cgroup_base + "/aegis_" + std::to_string(pid);
    if (mkdir(subgroup.c_str(), 0755) != 0 && errno != EEXIST) {
        log_error("mkdir cgroup falló: " + subgroup);
        return false;
    }

    // Memoria
    {
        std::ofstream f(subgroup + "/memory.max");
        if (!f) { log_error("no se pudo escribir memory.max"); return false; }
        f << (static_cast<long long>(memory_mb) * 1024 * 1024);
    }

    // Memoria de swap: la ponemos en 0 para que un proceso que se queda sin
    // RAM no escape el límite usando swap (omitido en la versión original).
    {
        std::ofstream f(subgroup + "/memory.swap.max");
        if (f) f << 0;
    }

    // CPU: cgroups v2 expresa esto como "cuota período" en microsegundos.
    // cpu.max = "<cuota> <período>" -- ej. "100000 100000" = 1 core completo.
    // Aquí lo usamos como límite de *tasa* (evita que un proceso acapare
    // todos los cores), NO como límite de tiempo total acumulado -- para eso
    // se usa RLIMIT_CPU en el hijo (ver sandbox_linux.cpp), que sí corta por
    // tiempo de CPU total consumido, independientemente de cuántos cores use.
    {
        std::ofstream f(subgroup + "/cpu.max");
        if (f) {
            long period_us = 100000; // 100ms, valor estándar del kernel
            f << period_us << " " << period_us; // 1 core equivalente
        }
    }

    // PIDs: evita fork-bombs limitando cuántos procesos puede crear el hijo.
    {
        std::ofstream f(subgroup + "/pids.max");
        if (f) f << 64;
    }

    {
        std::ofstream f(subgroup + "/cgroup.procs");
        if (!f) { log_error("no se pudo escribir cgroup.procs"); return false; }
        f << pid;
    }

    return true;
}

void cleanup_cgroup(pid_t pid) {
    const std::string subgroup = "/sys/fs/cgroup/aegis_" + std::to_string(pid);
    rmdir(subgroup.c_str()); // falla en silencio si ya no existe o no está vacío
}

double read_peak_memory(pid_t pid) {
    std::ifstream f("/sys/fs/cgroup/aegis_" + std::to_string(pid) + "/memory.peak");
    if (!f) return 0.0;
    unsigned long long peak_bytes = 0;
    f >> peak_bytes;
    return peak_bytes / (1024.0 * 1024.0);
}
