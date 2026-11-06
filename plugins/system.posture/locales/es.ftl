# system.posture messages (es). Keys are stable; never concatenate.
posture-secure-boot-name = Arranque seguro
posture-secure-boot-title = El arranque seguro está desactivado
posture-secure-boot-summary = Sin él, un programa de arranque manipulado podría iniciarse antes que el sistema y pasar inadvertido.
posture-lockdown-name = Bloqueo del kernel
posture-lockdown-title = El bloqueo del kernel está desactivado
posture-lockdown-summary = Los programas que se ejecutan como administrador pueden cambiar el kernel en ejecución. El bloqueo limita eso.
posture-disk-encryption-name = Cifrado de disco
posture-disk-encryption-title = El disco del sistema no está cifrado
posture-disk-encryption-summary = Cualquiera que consiga el disco puede leer tus archivos si el equipo se pierde o se roba.
posture-swap-encryption-name = Swap cifrado
posture-swap-encryption-title = El espacio de swap no está cifrado
posture-swap-encryption-summary = Las contraseñas y los documentos pueden escribirse en el disco en claro cuando la memoria se llena.
posture-tpm2-name = Chip TPM 2.0
posture-tpm2-title = Chip TPM 2.0
posture-tpm2-summary = Hay un chip TPM presente y puede proteger las claves del disco.
posture-mac-name = Confinamiento de aplicaciones
posture-mac-title = El confinamiento de aplicaciones no se está aplicando
posture-mac-summary =
    { $mode ->
        [selinux-permissive] SELinux solo registra los problemas en lugar de bloquearlos.
       *[other] Ni SELinux ni AppArmor se están aplicando, así que un programa comprometido no está limitado.
    }
posture-firewall-name = Cortafuegos
posture-firewall-title = No hay ningún cortafuegos en marcha
posture-firewall-summary = Se puede acceder a los servicios de este equipo desde la red sin ningún filtrado.
posture-tmp-mount-name = /tmp seguro
posture-tmp-mount-title = Los archivos temporales no están restringidos
posture-tmp-mount-summary =
    { $separate ->
        [no] /tmp no es un montaje independiente, así que no se puede restringir.
       *[yes] /tmp permite archivos de dispositivo o programas con privilegios.
    }
posture-shm-mount-name = Memoria compartida segura
posture-shm-mount-title = La memoria compartida no está restringida
posture-shm-mount-summary =
    { $separate ->
        [no] Falta /dev/shm, lo cual es inusual.
       *[yes] /dev/shm permite archivos de dispositivo o programas con privilegios.
    }
posture-core-dumps-name = Volcados de memoria
posture-core-dumps-title = Los programas con privilegios pueden dejar volcados de memoria
posture-core-dumps-summary = Un fallo puede escribir secretos de la memoria en un archivo que otros podrían leer.
posture-sudo-nopasswd-name = Contraseña de administrador
posture-sudo-nopasswd-title = El acceso de administrador no pide contraseña
posture-sudo-nopasswd-summary = Cualquier programa que se ejecute como tu usuario puede convertirse en administrador en silencio.
posture-updates-pending-name = Actualizaciones de seguridad
posture-updates-pending-title = Actualizaciones de seguridad
posture-updates-pending-summary = Aún sin comprobar: llegará con el plugin de actualizaciones.
posture-updates-automatic-name = Actualizaciones automáticas
posture-updates-automatic-title = Actualizaciones automáticas
posture-updates-automatic-summary = Aún sin comprobar: llegará con el plugin de actualizaciones.
posture-firmware-hsi-name = Seguridad del firmware
posture-firmware-hsi-title = Seguridad del firmware
posture-firmware-hsi-summary = Aún sin comprobar: llegará con el plugin de firmware.
detect-mac-title = Control de acceso obligatorio hoy
detect-mac-selinux-enforcing = SELinux se está aplicando: los programas quedan confinados a lo que permite su política.
detect-mac-apparmor = AppArmor está activado: los programas con un perfil quedan confinados a él.
detect-mac-selinux-permissive = SELinux está activado pero solo registra lo que bloquearía. Para aplicarlo, revisa los registros en busca de denegaciones de programas que uses, luego establece SELINUX=enforcing en /etc/selinux/config y reinicia.
detect-mac-selinux-disabled = SELinux está instalado pero desactivado en /etc/selinux/config. Al activarlo se reetiquetan los archivos en el próximo reinicio, lo que puede tardar un rato; empieza con el modo permisivo.
detect-mac-none = No hay ningún control de acceso obligatorio activo. IbexWall no instala nada; para obtener sus paquetes, ejecuta: { $install }. Después necesita un ajuste de arranque, así que sigue la guía de tu distribución.
