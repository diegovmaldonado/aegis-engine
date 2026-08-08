#ifndef SECCOMP_LINUX_HPP
#define SECCOMP_LINUX_HPP

/**
 * Instala un filtro seccomp REAL usando libseccomp (no un BPF a mano).
 * Política: lista blanca mínima para ejecutar un intérprete Python
 * standard (sin sockets si network=false). Cualquier syscall fuera
 * de la lista termina el proceso inmediatamente (SECCOMP_RET_KILL_PROCESS).
 *
 * @param allow_network si false, excluye socket/connect/bind/listen/accept.
 * @return 0 en éxito, -1 en error (con log_error ya invocado).
 */
int install_seccomp_filter(bool allow_network);

#endif
