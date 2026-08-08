#ifndef CGROUPS_LINUX_HPP
#define CGROUPS_LINUX_HPP

#include <sys/types.h>

/**
 * Configura cgroups v2 para limitar memoria Y CPU (la versión original
 * solo limitaba memoria; cpu_seconds quedaba comentado como pendiente).
 * @return true si éxito, false en caso de error (con log_error invocado).
 */
bool setup_cgroups(pid_t pid, int memory_mb, int cpu_seconds);

/** Limpia (rmdir) el cgroup creado para este pid. Llamar siempre al terminar. */
void cleanup_cgroup(pid_t pid);

double read_peak_memory(pid_t pid);

#endif
