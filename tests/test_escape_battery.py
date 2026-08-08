#!/usr/bin/env python3
"""
Batería de intentos de escape contra aegis-engine.

Cómo correrla (en una máquina Linux real, con el binario ya compilado):

    python3 tests/test_escape_battery.py /ruta/a/aegis-engine

Cada caso define:
- codigo: el Python que se manda a ejecutar dentro del sandbox.
- expect: qué se espera que devuelva el motor. "security_violation" para
  ataques que seccomp debería matar; "safe_output" para casos donde el
  código corre pero el resultado NO debe contener nada sensible (ej. no
  debe filtrar contenido real del host).

Este arnés no reemplaza una revisión de seguridad externa -- es una red de
regresión: si algo que debería fallar empieza a "funcionar", te enterás acá
antes que en producción. No cubre TODO lo que un revisor humano buscaría
(eso incluye cosas como fuzzing del propio parser JSON, condiciones de
carrera bajo carga, etc.).
"""

import json
import subprocess
import sys
import textwrap


def run(binary_path: str, codigo: str, network: bool = False, wall: int = 10) -> dict:
    solicitud = {
        "operation": "execute_python",
        "target": {"content": codigo},
        "limits": {
            "max_memory_mb": 128,
            "max_cpu_seconds": wall,
            "max_wall_seconds": wall,
            "network": network,
        },
    }
    proceso = subprocess.run(
        [binary_path],
        input=json.dumps(solicitud),
        capture_output=True,
        text=True,
        timeout=wall + 15,
    )
    try:
        return json.loads(proceso.stdout)
    except json.JSONDecodeError:
        return {"status": "NO_JSON", "raw_stdout": proceso.stdout, "raw_stderr": proceso.stderr}


CASOS = [
    {
        "nombre": "mount() vía ctypes",
        "expect_status": "security_violation",
        "codigo": textwrap.dedent("""
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            r = libc.mount(b"none", b"/", b"tmpfs", 0, None)
            print("mount devolvió:", r)
        """),
    },
    {
        "nombre": "ptrace sobre sí mismo (anti-debug / escape clásico)",
        "expect_status": "security_violation",
        "codigo": textwrap.dedent("""
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            PTRACE_TRACEME = 0
            r = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
            print("ptrace devolvió:", r)
        """),
    },
    {
        "nombre": "unshare() para crear namespace propio dentro del sandbox",
        "expect_status": "security_violation",
        "codigo": textwrap.dedent("""
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            CLONE_NEWNS = 0x00020000
            r = libc.unshare(CLONE_NEWNS)
            print("unshare devolvió:", r)
        """),
    },
    {
        "nombre": "setns() para saltar a otro namespace",
        "expect_status": "security_violation",
        "codigo": textwrap.dedent("""
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            fd = open("/proc/1/ns/mnt")
            r = libc.setns(fd.fileno(), 0)
            print("setns devolvió:", r)
        """),
    },
    {
        "nombre": "socket crudo (bypass de bloqueo de red por AF_PACKET)",
        "expect_status": "security_violation",
        "codigo": textwrap.dedent("""
            import socket
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            print("socket AF_PACKET creado")
        """),
    },
    {
        "nombre": "leer /etc/shadow del host vía ruta absoluta",
        "expect_status": "safe_output",
        "codigo": textwrap.dedent("""
            try:
                with open("/etc/shadow") as f:
                    print("LEAK:", f.read()[:100])
            except Exception as e:
                print("bloqueado como se esperaba:", type(e).__name__)
        """),
        # No debe aparecer "LEAK:" en el stdout -- /etc no está bind-montado.
        "forbidden_substrings": ["LEAK:"],
    },
    {
        "nombre": "symlink a /etc/passwd del host creado dentro de /tmp de la jaula",
        "expect_status": "safe_output",
        "codigo": textwrap.dedent("""
            import os
            os.symlink("/etc/passwd", "/tmp/link_a_passwd")
            try:
                with open("/tmp/link_a_passwd") as f:
                    contenido = f.read()
                    print("LEAK:", contenido[:100])
            except Exception as e:
                print("bloqueado como se esperaba:", type(e).__name__)
        """),
        "forbidden_substrings": ["LEAK:"],
    },
    {
        "nombre": "escape vía /proc/self/root (symlink a la raíz real pre-pivot_root)",
        "expect_status": "safe_output",
        "codigo": textwrap.dedent("""
            import os
            try:
                objetivo = os.readlink("/proc/self/root")
                contenido = os.listdir("/proc/self/root")
                print("LEAK:", objetivo, contenido[:10])
            except Exception as e:
                print("bloqueado o inocuo:", type(e).__name__)
        """),
        "forbidden_substrings": ["LEAK:"],
    },
    {
        "nombre": "doble fork para escapar del PID namespace y sobrevivir al padre",
        "expect_status": "security_violation",
        # Corregido tras revisar seccomp_linux.cpp: clone/fork NO están en
        # SYSCALLS_BASE, así que esto debería morir directo con
        # security_violation -- ni siquiera llega a necesitar el respaldo
        # de RLIMIT_NPROC/pids.max. Si esto pasa con otro status, es una
        # señal de que el filtro seccomp no se está aplicando como se
        # documentó.
        "codigo": textwrap.dedent("""
            import os, sys, time
            pid = os.fork()
            if pid == 0:
                pid2 = os.fork()
                if pid2 == 0:
                    time.sleep(30)  # el proceso nieto intenta sobrevivir
                    sys.exit(0)
                sys.exit(0)
            os.waitpid(pid, 0)
            print("fork completado")
        """),
    },
    {
        "nombre": "fork-bomb (debe morir por security_violation, no solo por pids.max)",
        "expect_status": "security_violation",
        "codigo": textwrap.dedent("""
            import os
            while True:
                os.fork()
        """),
        "wall": 8,
    },
    {
        "nombre": "agotar memoria más allá del límite (RLIMIT_AS / cgroups)",
        "expect_status": "killed_or_memoryerror",
        "codigo": textwrap.dedent("""
            data = bytearray(500 * 1024 * 1024)  # 500MB con límite de 128MB
            print("no debería llegar acá")
        """),
    },
    {
        "nombre": "loop de impresión infinita (debe cortar por tope de salida u output cap)",
        "expect_status": "timeout_or_output_capped",
        "codigo": textwrap.dedent("""
            while True:
                print("x" * 1000)
        """),
        "wall": 6,
    },
    {
        "nombre": "acceso a red bloqueado por defecto (network=False)",
        "expect_status": "security_violation",
        "network": False,
        "codigo": textwrap.dedent("""
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("8.8.8.8", 53))
            print("conectado -- ESTO NO DEBERÍA PASAR")
        """),
    },
]


def main():
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} /ruta/a/aegis-engine")
        sys.exit(1)

    binary_path = sys.argv[1]
    fallos = []

    for caso in CASOS:
        nombre = caso["nombre"]
        wall = caso.get("wall", 10)
        network = caso.get("network", False)
        print(f"\n--- {nombre} ---")
        try:
            resultado = run(binary_path, caso["codigo"], network=network, wall=wall)
        except subprocess.TimeoutExpired:
            resultado = {"status": "TIMEOUT_PROCESO_PYTHON_NO_EL_SANDBOX"}

        status = resultado.get("status", "?")
        stdout = resultado.get("result", {}).get("stdout", "")
        print(f"status devuelto: {status}")

        problema = None
        expect = caso.get("expect_status")
        if expect == "security_violation" and status != "security_violation":
            problema = f"ESPERABA security_violation, recibió '{status}' -- posible escape real"
        for prohibido in caso.get("forbidden_substrings", []):
            if prohibido in stdout:
                problema = f"stdout contiene '{prohibido}' -- FILTRACIÓN REAL: {stdout[:200]!r}"

        if problema:
            print(f"  ❌ {problema}")
            fallos.append((nombre, problema))
        else:
            print("  ✅ comportamiento esperado")

    print("\n" + "=" * 60)
    if fallos:
        print(f"{len(fallos)} caso(s) con comportamiento inesperado:")
        for nombre, problema in fallos:
            print(f"  - {nombre}: {problema}")
        sys.exit(1)
    else:
        print("Todos los casos automáticos dieron el resultado esperado.")
        print("\nRECORDATORIO -- esto el script NO lo puede verificar solo:")
        print("  1. Después de correr el caso de doble-fork, revisar a mano")
        print("     con `ps aux | grep python3` que no haya quedado ningún")
        print("     proceso huérfano vivo en el host.")
        print("  2. Correr la batería completa varias veces bajo carga")
        print("     concurrente (varios aegis-engine a la vez) para revisar")
        print("     condiciones de carrera, no solo una vez en secuencial.")
        sys.exit(0)


if __name__ == "__main__":
    main()
