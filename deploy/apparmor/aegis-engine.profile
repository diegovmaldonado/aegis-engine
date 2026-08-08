# Perfil de AppArmor para aegis-engine -- CAPA EXTRA, no reemplaza nada
# de lo ya implementado (namespaces + seccomp + cgroups siguen siendo la
# defensa principal). Esto es lo mismo que hacen Docker/gVisor: un MAC
# (control de acceso obligatorio) además del sandboxing de sistema, para
# que un bypass de una capa todavía tenga que atravesar la otra.
#
# IMPORTANTE -- esto NO está probado en una máquina real. Escribir un
# perfil de AppArmor y no cargarlo nunca contra el binario real es
# exactamente el tipo de "hardening de papel" que hay que evitar. Antes
# de confiar en este perfil:
#   1. sudo apparmor_parser -r /etc/apparmor.d/aegis-engine
#   2. Correr la batería completa de tests/test_escape_battery.py con el
#      perfil cargado en modo "enforce" y confirmar que sigue todo OK --
#      un perfil mal escrito puede romper cosas que SÍ deberían funcionar
#      (ej. bloquear una ruta que python3 necesita para arrancar).
#   3. Revisar /var/log/audit/audit.log o `dmesg` por rechazos DENIED
#      inesperados durante esa corrida.
#
# Instalar en: /etc/apparmor.d/aegis-engine
# Ajustar AEGIS_BINARY_PATH a la ruta real de despliegue.

#include <tunables/global>

profile aegis-engine /opt/aegis/aegis-engine flags=(enforce) {
  #include <abstractions/base>

  # El binario necesita leer sus propias bibliotecas dinámicas y las de
  # Python que va a exponer dentro de la jaula (antes de pivot_root).
  /opt/aegis/aegis-engine mr,
  /usr/lib/x86_64-linux-gnu/** mr,
  /usr/bin/python3* mr,
  /lib/x86_64-linux-gnu/** mr,

  # tmpfs y /proc que el propio binario crea/monta para la jaula.
  /tmp/aegis_root/** rw,
  /proc/** r,

  # Capacidades mínimas necesarias para namespaces + cgroups + drop de
  # privilegios -- CAP_SYS_ADMIN para mount/pivot_root/namespaces,
  # CAP_SETUID/CAP_SETGID solo hasta que se ejecuta drop_privileges_if_root
  # (si el binario ya corre como el usuario dedicado sin privilegios
  # desde el arranque, ni siquiera necesita estas dos).
  capability sys_admin,
  capability setuid,
  capability setgid,
  capability sys_resource,   # setrlimit
  capability dac_override,   # mounts/bind-mounts dentro de la jaula

  # Explícitamente denegado -- redundante con seccomp a propósito
  # (defensa en profundidad real: dos mecanismos independientes tienen
  # que fallar los DOS para que esto sea explotable).
  deny capability sys_module,
  deny capability sys_ptrace,
  deny capability net_admin,
  deny /etc/shadow r,
  deny /etc/gshadow r,
  deny /root/** rw,
  deny /home/** rw,

  # Log de auditoría propio del motor.
  /var/log/aegis-engine/audit.log w,

  # Delegar el resto a los perfiles hijo que corren DENTRO de la jaula
  # (python3 ya está confinado por seccomp+namespaces, no por este mismo
  # perfil -- este perfil cubre al proceso aegis-engine en sí, no a lo
  # que corre adentro de la jaula tras pivot_root).
}
