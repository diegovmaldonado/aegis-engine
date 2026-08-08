#include "seccomp_linux.hpp"
#include "utils.hpp"
#include <seccomp.h>
#include <sys/syscall.h>
#include <errno.h>

// Filtro REAL: a diferencia de la versión educativa original (que armaba
// una lista y nunca la instalaba), esto construye un contexto seccomp con
// libseccomp -- la biblioteca que usan Docker, Firefox y systemd para esto
// mismo -- en vez de escribir BPF a mano, que es frágil y fácil de hacer mal.
//
// Política: SCMP_ACT_KILL_PROCESS por defecto (mata todo el proceso, no solo
// el hilo, para que no sobreviva nada del hijo si intenta algo fuera de lista).
// Se permite explícitamente solo lo que un intérprete Python normal necesita.

static const int SYSCALLS_BASE[] = {
    SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(open), SCMP_SYS(openat),
    SCMP_SYS(close), SCMP_SYS(fstat), SCMP_SYS(stat), SCMP_SYS(lstat),
    SCMP_SYS(newfstatat), SCMP_SYS(lseek), SCMP_SYS(mmap), SCMP_SYS(mprotect),
    SCMP_SYS(munmap), SCMP_SYS(brk), SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask),
    SCMP_SYS(rt_sigreturn), SCMP_SYS(ioctl), SCMP_SYS(access), SCMP_SYS(pipe),
    SCMP_SYS(pipe2), SCMP_SYS(dup), SCMP_SYS(dup2), SCMP_SYS(dup3),
    SCMP_SYS(getpid), SCMP_SYS(gettid), SCMP_SYS(exit), SCMP_SYS(exit_group),
    SCMP_SYS(futex), SCMP_SYS(clock_gettime), SCMP_SYS(clock_nanosleep),
    SCMP_SYS(nanosleep), SCMP_SYS(getrandom), SCMP_SYS(sched_yield),
    SCMP_SYS(getcwd), SCMP_SYS(readlink), SCMP_SYS(uname), SCMP_SYS(getdents64),
    SCMP_SYS(prlimit64), SCMP_SYS(rseq), SCMP_SYS(set_tid_address),
    SCMP_SYS(set_robust_list), SCMP_SYS(arch_prctl), SCMP_SYS(sigaltstack),
    SCMP_SYS(getrlimit), SCMP_SYS(madvise), SCMP_SYS(statx), SCMP_SYS(wait4),
    SCMP_SYS(execve), SCMP_SYS(fcntl), SCMP_SYS(pread64), SCMP_SYS(getuid),
    SCMP_SYS(getgid), SCMP_SYS(geteuid), SCMP_SYS(getegid),
    // NOTA: NO se incluyen: ptrace, mount, umount2, chroot, pivot_root,
    // reboot, init_module, delete_module, kexec_load, setns, unshare,
    // bpf, keyctl, personality, iopl, ioperm -- ninguno de estos es
    // necesario para correr Python, y son justo los que un exploit de
    // escape de sandbox intentaría usar.
};

static const int SYSCALLS_NETWORK[] = {
    SCMP_SYS(socket), SCMP_SYS(connect), SCMP_SYS(bind), SCMP_SYS(listen),
    SCMP_SYS(accept), SCMP_SYS(accept4), SCMP_SYS(sendto), SCMP_SYS(recvfrom),
    SCMP_SYS(sendmsg), SCMP_SYS(recvmsg), SCMP_SYS(getsockname),
    SCMP_SYS(getsockopt), SCMP_SYS(setsockopt), SCMP_SYS(shutdown),
};

int install_seccomp_filter(bool allow_network) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (!ctx) {
        log_error("seccomp_init falló");
        return -1;
    }

    for (int sys : SYSCALLS_BASE) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, sys, 0) != 0) {
            log_error("seccomp_rule_add falló para una syscall base");
            seccomp_release(ctx);
            return -1;
        }
    }

    if (allow_network) {
        for (int sys : SYSCALLS_NETWORK) {
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, sys, 0);
        }
    }

    // mmap/mprotect con PROT_EXEC son necesarios para el JIT/loader de CPython,
    // pero se podrían restringir más con seccomp_rule_add_exact + argumentos
    // si se quiere ir más allá (queda fuera de este alcance).

    if (seccomp_load(ctx) != 0) {
        log_error("seccomp_load falló");
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx); // el filtro ya cargado en el kernel sobrevive esto
    return 0;
}
