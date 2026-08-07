#include "sandbox.hpp"
#include "utils.hpp"
#include "seccomp_linux.hpp"
#include "cgroups_linux.hpp"
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <chrono>

std::string sandbox_platform_name() { return "linux"; }

namespace {

// NOTA DE CONCURRENCIA: hasta esta versión, pipe_stdout/pipe_stderr eran
// variables globales y el timeout se manejaba con alarm()+SIGALRM. Ambas
// cosas son *por proceso*, no por ejecución: si aegis-engine llega a
// invocar run_in_sandbox() desde dos hilos al mismo tiempo (ej. un
// servidor que atiende varias solicitudes concurrentes), un hilo pisaba
// los file descriptors del otro antes de que clone() los usara, y una
// llamada a alarm() cancelaba el timer que había puesto la otra
// ejecución. Ahora todo el estado por ejecución vive en ChildArgs (pasado
// por puntero, sin globals) y el timeout se mide comparando tiempo
// transcurrido en el propio loop de espera, sin depender de señales.
// Esto hace que run_in_sandbox() sea segura de llamar concurrentemente
// desde varios hilos del mismo proceso.

// Estructura pasada al hijo vía puntero (clone() no permite capturar lambdas
// con estado por closure fácilmente, así que usamos un struct explícito).
struct ChildArgs {
    bool network;
    int cpu_seconds;
    int max_mem_mb;
    int code_fd;    // fd real del extremo de lectura del pipe de código
    int sync_fd;    // fd de lectura: el hijo bloquea acá hasta que el padre
                     // termine de escribir uid_map/gid_map (ver más abajo)
    int stdout_write_fd; // extremo de escritura del pipe de stdout (antes global)
    int stderr_write_fd; // extremo de escritura del pipe de stderr (antes global)
    int stdout_read_fd;  // extremo de lectura -- el hijo lo cierra, es del padre
    int stderr_read_fd;
};

int child_main(void* raw_arg) {
    ChildArgs* args = static_cast<ChildArgs*>(raw_arg);

    // --- Namespace de usuario: esperar a que el padre escriba uid_map/gid_map ---
    // CLONE_NEWUSER crea el namespace, pero mapear uid 0 (root DENTRO de la
    // jaula) a un UID sin privilegios del host lo hace el PADRE escribiendo
    // /proc/<hijo>/uid_map DESPUÉS del clone(). Si el hijo sigue de largo
    // antes de que eso pase, hay una ventana donde el mapeo aún no existe.
    // No es estrictamente necesaria para que mount()/pivot_root funcionen
    // (esas capacidades ya están disponibles dentro del namespace nuevo
    // desde el momento de clone()), pero es la forma correcta y estándar
    // de hacerlo (mismo patrón que usan unshare/runc). Bloqueamos leyendo
    // 1 byte de un pipe que el padre escribe recién cuando terminó.
    char sync_byte;
    read(args->sync_fd, &sync_byte, 1);
    close(args->sync_fd);

    sethostname("sandbox", 7);

    // --- Aislamiento de filesystem: pivot_root en vez de solo chdir ---
    // El original solo hacía chdir("/sandbox") dentro del namespace de
    // montaje, lo cual NO impide que el proceso acceda al resto del
    // filesystem del host vía rutas absolutas (ej. "/etc/passwd" seguía
    // siendo visible). pivot_root con un tmpfs nuevo como raíz sí lo impide.
    mkdir("/tmp/aegis_root", 0755);
    if (mount("tmpfs", "/tmp/aegis_root", "tmpfs", 0, "size=256m") != 0) {
        perror("mount tmpfs raiz");
        return 1;
    }
    chdir("/tmp/aegis_root");
    mkdir("proc", 0555);
    mkdir("dev", 0555);
    mkdir("tmp", 01777);
    mkdir("old_root", 0700);

    // Bind-mount de solo lectura del runtime de Python del HOST hacia la
    // jaula. Necesario porque pivot_root aísla completamente el filesystem:
    // sin esto, python3 y sus bibliotecas compartidas quedan fuera de la
    // nueva raíz y no se puede ejecutar nada (verificado con prueba real:
    // "execlp python3: No such file or directory" antes de este fix).
    // MS_RDONLY + MS_BIND: el código dentro de la jaula puede LEER estos
    // directorios pero no escribirlos ni modificarlos.
    // OJO: /etc NO se monta completo -- expondría /etc/shadow, claves SSH
    // del host, etc. (bug real encontrado en pruebas: la primera versión de
    // este fix bindeaba /etc entero). Solo se necesitan /usr, /lib, /lib64
    // y /bin para que el intérprete de Python y sus bibliotecas compartidas
    // existan dentro de la jaula.
    const char* runtime_dirs[] = {"usr", "lib", "lib64", "bin"};
    for (const char* d : runtime_dirs) {
        std::string src = std::string("/") + d;
        std::string dst = std::string("/tmp/aegis_root/") + d;
        struct stat st;
        if (stat(src.c_str(), &st) != 0) continue; // no existe en el host, se salta
        mkdir(dst.c_str(), 0555);
        if (mount(src.c_str(), dst.c_str(), nullptr, MS_BIND | MS_REC, nullptr) == 0) {
            mount(nullptr, dst.c_str(), nullptr,
                  MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, nullptr);
        }
    }
    // Si en el futuro hace falta algo puntual de /etc (ej. nsswitch.conf
    // para resolución DNS con red habilitada), copiar SOLO ese archivo
    // específico -- nunca bind-montar el directorio completo.

    if (syscall(SYS_pivot_root, ".", "old_root") != 0) {
        perror("pivot_root");
        return 1;
    }
    chdir("/");
    // Desmontar y descartar la raíz vieja: sin esto, el proceso hijo
    // seguiría teniendo acceso al filesystem real del host bajo /old_root.
    umount2("/old_root", MNT_DETACH);
    rmdir("/old_root");

    mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr);

    mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
    mknod("/dev/zero", S_IFCHR | 0666, makedev(1, 5));
    mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9));

    // --- Límite de tiempo de CPU total (faltaba en la versión original;
    // cgroups.cpu.max solo limita la TASA, no el acumulado) ---
    struct rlimit rl_cpu{ (rlim_t)args->cpu_seconds, (rlim_t)args->cpu_seconds + 1 };
    setrlimit(RLIMIT_CPU, &rl_cpu);

    // --- Límite de memoria a nivel de proceso, independiente de cgroups ---
    // Encontrado en pruebas reales: en entornos donde cgroups v2 no delega
    // el controlador "memory" (layout híbrido con v1, común en algunos
    // contenedores), memory.max se escribe sin error pero NO limita nada
    // -- fallo silencioso. RLIMIT_AS actúa directamente en el kernel a
    // nivel de proceso (mm->task_size), sin depender de que cgroups esté
    // bien delegado, y es la razón por la que se agrega acá como respaldo,
    // no como reemplazo de cgroups (cgroups sigue siendo mejor cuando SÍ
    // está disponible, porque además reporta memory.peak para telemetría).
    struct rlimit rl_mem{ (rlim_t)args->max_mem_mb * 1024 * 1024,
                          (rlim_t)args->max_mem_mb * 1024 * 1024 };
    setrlimit(RLIMIT_AS, &rl_mem);

    // --- Respaldo de fork-bomb, análogo al de memoria/CPU ---
    // pids.max en cgroups ya cubre esto, pero solo si cgroups está
    // disponible (ver setup_cgroups). Si cgroups falla, hasta ahora no
    // había NADA que impidiera un fork-bomb dentro de la jaula -- a
    // diferencia de memoria (RLIMIT_AS) y CPU (RLIMIT_CPU), que sí tenían
    // doble capa. RLIMIT_NPROC cierra ese hueco a nivel de kernel,
    // independiente de cgroups.
    struct rlimit rl_nproc{ 64, 64 };
    setrlimit(RLIMIT_NPROC, &rl_nproc);

    // --- Sin core dumps ---
    // Un crash dentro de la jaula (ej. un segfault provocado a propósito
    // para probar algo, o simplemente un bug del código ejecutado) podía
    // generar un core dump. Sin límite, eso es tiempo de I/O y espacio de
    // disco que no aporta nada acá (nadie va a depurar el core de código
    // no confiable), y en el peor caso es una forma más de agotar
    // recursos del sistema.
    struct rlimit rl_core{ 0, 0 };
    setrlimit(RLIMIT_CORE, &rl_core);

    // --- Tope de descriptores de archivo abiertos ---
    // Sin esto, un script puede abrir archivos/sockets en loop hasta
    // agotar la tabla de descriptores del proceso (y presionar los límites
    // del sistema si son muchas ejecuciones). 64 es de sobra para
    // ejecutar un script Python normal (stdin/stdout/stderr + unos pocos
    // archivos), y deja margen sin ser tan alto como para no servir de
    // límite real.
    struct rlimit rl_nofile{ 64, 64 };
    setrlimit(RLIMIT_NOFILE, &rl_nofile);

    // No-new-privs: bloquea setuid/setgid binaries dentro de la jaula,
    // requisito además para poder instalar el filtro seccomp sin ser root real.
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // Leer el código desde un fd heredado en vez de una variable de entorno:
    // pasar código arbitrario por env var (como hacía el original) es
    // observable por cualquier proceso con /proc/<pid>/environ y puede
    // truncarse con bytes NUL; un fd es más robusto y no queda en el entorno.
    char buffer[65536];
    std::string codigo;
    ssize_t n;
    while ((n = read(args->code_fd, buffer, sizeof(buffer))) > 0) {
        codigo.append(buffer, n);
    }
    close(args->code_fd);

    {
        std::ofstream code_file("/tmp/script.py");
        code_file << codigo;
    }

    if (install_seccomp_filter(args->network) != 0) {
        return 1; // log_error ya se llamó dentro
    }

    close(args->stdout_read_fd);
    close(args->stderr_read_fd);
    dup2(args->stdout_write_fd, STDOUT_FILENO);
    dup2(args->stderr_write_fd, STDERR_FILENO);
    close(args->stdout_write_fd);
    close(args->stderr_write_fd);

    // Ejecutar como usuario sin privilegios sigue pendiente de mapeo de
    // usuario/UID namespace completo (CLONE_NEWUSER) -- ver notas al final.
    execl("/usr/bin/python3", "python3", "/tmp/script.py", nullptr);
    perror("execl python3");
    return 1;
}

} // namespace

SandboxResult run_in_sandbox(const std::string& codigo,
                             int max_mem_mb,
                             int max_cpu_sec,
                             int max_wall_sec,
                             bool network) {
    SandboxResult result;

    // Pipes LOCALES a esta ejecución (antes eran globales -- ver nota de
    // concurrencia arriba). Cada llamada a run_in_sandbox(), aunque sea
    // desde hilos distintos al mismo tiempo, tiene ahora sus propios fds
    // sin pisar los de otra ejecución en curso.
    int pipe_stdout[2];
    int pipe_stderr[2];
    if (pipe(pipe_stdout) == -1 || pipe(pipe_stderr) == -1) {
        result.status = "error";
        result.error_msg = "No se pudieron crear pipes";
        return result;
    }

    // --- El código se pasa por un memfd, no por pipe ---
    // BUG REAL ENCONTRADO: la versión anterior escribía el código completo
    // a un pipe (write(code_pipe[1], codigo...)) ANTES de llamar a clone().
    // Un pipe en Linux tiene un buffer limitado (65536 bytes por defecto).
    // Si el código a ejecutar supera ese tamaño, write() se queda
    // BLOQUEADO esperando que alguien lea del otro extremo -- pero el
    // hijo, el único que lee ese pipe, todavía no existe (clone() no se
    // había llamado). Resultado: deadlock total del proceso padre con
    // cualquier código de más de ~64KB, silencioso, sin ningún mensaje de
    // error. Para el caso de uso real de este motor (código generado
    // automáticamente, que fácilmente puede superar ese tamaño en módulos
    // no triviales), este bug era prácticamente garantizado de disparar
    // tarde o temprano en producción.
    // Un memfd (archivo anónimo en memoria) no tiene esa limitación: el
    // tamaño solo está acotado por memoria disponible, no por un buffer
    // fijo, así que escribir el código completo nunca bloquea al padre
    // esperando a un lector que no existe.
    int code_fd = static_cast<int>(syscall(SYS_memfd_create, "aegis_code", 0));
    if (code_fd == -1) {
        result.status = "error";
        result.error_msg = std::string("No se pudo crear memfd para el código: ") + strerror(errno);
        return result;
    }
    {
        const char* data = codigo.data();
        size_t remaining = codigo.size();
        while (remaining > 0) {
            ssize_t written = write(code_fd, data, remaining);
            if (written <= 0) {
                result.status = "error";
                result.error_msg = std::string("Escritura incompleta al memfd de código: ") + strerror(errno);
                close(code_fd);
                return result;
            }
            data += written;
            remaining -= static_cast<size_t>(written);
        }
        lseek(code_fd, 0, SEEK_SET); // rebobinar para que el hijo lea desde el principio
    }

    // Pipe de sincronización para el namespace de usuario (ver child_main).
    int sync_pipe[2];
    if (pipe(sync_pipe) == -1) {
        result.status = "error";
        result.error_msg = "No se pudo crear pipe de sincronización";
        close(code_fd);
        return result;
    }

    // CLONE_NEWUSER agregado: sin esto, el proceso dentro de la jaula corre
    // con el MISMO UID real que lanzó aegis-engine -- si ese proceso corre
    // como root (típico en un servicio), un escape del sandbox heredaría
    // privilegios de root reales del host. Con CLONE_NEWUSER + el mapeo de
    // abajo, el proceso se ve a sí mismo como UID 0 DENTRO de su propio
    // namespace, pero en el host es un UID normal sin privilegios --mismo
    // principio que usan los contenedores "rootless" (podman, runc
    // sin privilegios).
    int flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC |
                CLONE_NEWUTS | CLONE_NEWCGROUP;
    // --- CLONE_NEWNET SIEMPRE, sin excepción ---
    // BUG GRAVE ENCONTRADO: la versión anterior solo aislaba la red cuando
    // network=false ("if (!network) flags |= CLONE_NEWNET;"). Con
    // network=true, el proceso sandboxeado quedaba con acceso DIRECTO a la
    // red real del host -- no "acceso a internet con algo de riesgo", sino
    // sin ningún aislamiento: LAN del host, servicios internos, el
    // endpoint de metadata de la nube (169.254.169.254) si esto corre en
    // AWS/GCP/Azure, todo. Un firewall de salida real (namespace + veth +
    // NAT + reglas que bloqueen rangos privados) es un subproyecto en sí
    // mismo que requiere pruebas de red reales para confiar en él -- no es
    // algo para escribir a ciegas y llamar "listo". Mientras esa
    // implementación no exista y esté probada, la decisión correcta es
    // fail-closed: aislar la red SIEMPRE, y rechazar explícitamente
    // network=true en main.cpp (ver ahí) en vez de dar una falsa sensación
    // de "internet permitido" que en realidad significa "sin aislamiento".
    flags |= CLONE_NEWNET;

    const size_t stack_size = 2 * 1024 * 1024;
    char* stack = new char[stack_size];

    ChildArgs args{ network, max_cpu_sec, max_mem_mb, code_fd, sync_pipe[0],
                     pipe_stdout[1], pipe_stderr[1], pipe_stdout[0], pipe_stderr[0] };

    auto t_start = std::chrono::steady_clock::now();

    // clone() sin CLONE_FILES copia la tabla de descriptores: el hijo hereda
    // code_fd con el MISMO número de fd que tiene en el padre, así que
    // no hace falta (ni conviene) forzarlo a un número fijo.
    pid_t child = clone(child_main, stack + stack_size, flags | SIGCHLD, &args);
    close(code_fd);

    if (child == -1) {
        result.status = "error";
        result.error_msg = std::string("clone() falló: ") + strerror(errno);
        close(sync_pipe[0]); close(sync_pipe[1]);
        delete[] stack;
        return result;
    }

    // --- Mapeo real de uid/gid, hecho por el PADRE (tiene que ser así:
    // solo un proceso FUERA del nuevo namespace de usuario puede escribir
    // su uid_map/gid_map). Mapea uid/gid 0 (root, tal como lo ve el
    // proceso adentro) al UID/GID REAL con el que corre aegis-engine --
    // NO a root real del host. "deny" en setgroups es requisito del
    // kernel para poder escribir gid_map sin privilegios de root reales. ---
    {
        std::string base = "/proc/" + std::to_string(child);
        std::ofstream(base + "/setgroups") << "deny";
        std::ofstream(base + "/uid_map") << "0 " << getuid() << " 1";
        std::ofstream(base + "/gid_map") << "0 " << getgid() << " 1";
    }
    close(sync_pipe[0]);
    write(sync_pipe[1], "x", 1); // desbloquea al hijo, que esperaba esto
    close(sync_pipe[1]);

    // Si cgroups falla (ej. controlador de memoria no delegado, layout
    // híbrido v1/v2), NO abortamos la ejecución: RLIMIT_AS y RLIMIT_CPU,
    // ya aplicados dentro de child_main, siguen dando un límite real.
    // Se pierde la telemetría de memory.peak y el límite de TASA de CPU,
    // pero no la protección de fondo. setup_cgroups ya logueó el detalle.
    bool cgroups_ok = setup_cgroups(child, max_mem_mb, max_cpu_sec);
    if (!cgroups_ok) {
        log_error("Continuando sin cgroups -- protegido solo por RLIMIT_AS/RLIMIT_CPU");
    }

    close(pipe_stdout[1]);
    close(pipe_stderr[1]);
    fcntl(pipe_stdout[0], F_SETFL, O_NONBLOCK);
    fcntl(pipe_stderr[0], F_SETFL, O_NONBLOCK);

    std::string out_data, err_data;
    char buf[4096];
    int status = 0;
    bool finished = false;

    // Tope de salida capturada: sin esto, un script que hace print() en
    // loop infinito puede agotar la memoria del proceso PADRE (que corre
    // fuera de la jaula, sin RLIMIT_AS) antes de que el límite de tiempo
    // de pared llegue a matarlo. 8 MB por stream es de sobra para uso
    // normal y evita ese vector de DoS contra el host.
    const size_t MAX_CAPTURED_OUTPUT = 8 * 1024 * 1024;
    bool output_truncated = false;

    while (!finished) {
        ssize_t n = read(pipe_stdout[0], buf, sizeof(buf));
        if (n > 0 && out_data.size() < MAX_CAPTURED_OUTPUT) out_data.append(buf, n);
        else if (n > 0) output_truncated = true;
        n = read(pipe_stderr[0], buf, sizeof(buf));
        if (n > 0 && err_data.size() < MAX_CAPTURED_OUTPUT) err_data.append(buf, n);
        else if (n > 0) output_truncated = true;

        pid_t w = waitpid(child, &status, WNOHANG);
        if (w == child) { finished = true; }

        // Timeout por tiempo transcurrido en vez de alarm()/SIGALRM: alarm()
        // es una única alarma *por proceso*, así que si dos ejecuciones
        // corrieran en paralelo en hilos distintos, una cancelaría el timer
        // de la otra. Comparar steady_clock acá es local a esta llamada y
        // por lo tanto seguro entre hilos.
        double elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - t_start).count();
        if (!finished && elapsed >= max_wall_sec) {
            result.status = "timeout";
            result.error_msg = "Tiempo límite de pared excedido";
            kill(child, SIGKILL);
            waitpid(child, nullptr, 0);
            finished = true;
        }
        // Si la salida se desbordó y el proceso sigue vivo, no tiene
        // sentido seguir esperando a que termine solo -- lo cortamos.
        if (!finished && output_truncated && out_data.size() >= MAX_CAPTURED_OUTPUT
            && err_data.size() >= MAX_CAPTURED_OUTPUT) {
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            finished = true;
        }
        if (!finished) usleep(5000);
    }
    if (output_truncated) {
        result.error_msg += std::string(result.error_msg.empty() ? "" : "; ")
            + "Salida truncada: excedió " + std::to_string(MAX_CAPTURED_OUTPUT / (1024*1024)) + "MB";
    }

    close(pipe_stdout[0]);
    close(pipe_stderr[0]);

    if (result.status.empty()) {
        if (WIFEXITED(status)) {
            result.exit_code = WEXITSTATUS(status);
            result.status = "success";
        } else if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            result.exit_code = -1;
            // SIGSYS = seccomp mató el proceso por syscall prohibida;
            // SIGXCPU = RLIMIT_CPU excedido. Distinguirlos ayuda a diagnosticar.
            result.status = (sig == SIGSYS) ? "security_violation" :
                             (sig == SIGXCPU) ? "cpu_limit_exceeded" : "killed";
            result.error_msg = "Terminado por señal " + std::to_string(sig);
        }
    }

    result.stdout_output = out_data;
    result.stderr_output = err_data;
    result.peak_memory_mb = read_peak_memory(child);
    result.wall_time = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();

    cleanup_cgroup(child);
    delete[] stack;
    return result;
}
