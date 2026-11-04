# system.posture messages (en). Keys are stable; never concatenate.
posture-secure-boot-name = Secure Boot
posture-secure-boot-title = Secure Boot is turned off
posture-secure-boot-summary = Without it, a tampered boot program could start before the system and go unnoticed.
posture-lockdown-name = Kernel lockdown
posture-lockdown-title = Kernel lockdown is off
posture-lockdown-summary = Programs running as administrator can change the running kernel. Lockdown limits that.
posture-disk-encryption-name = Disk encryption
posture-disk-encryption-title = The system disk is not encrypted
posture-disk-encryption-summary = Your files can be read by anyone who gets the disk if the computer is lost or stolen.
posture-swap-encryption-name = Encrypted swap
posture-swap-encryption-title = Swap space is not encrypted
posture-swap-encryption-summary = Passwords and documents can be written to disk in plain form when memory is full.
posture-tpm2-name = TPM 2.0 chip
posture-tpm2-title = TPM 2.0 chip
posture-tpm2-summary = A TPM chip is present and can protect disk keys.
posture-mac-name = Application confinement
posture-mac-title = Application confinement is not enforcing
posture-mac-summary =
    { $mode ->
        [selinux-permissive] SELinux only logs problems instead of blocking them.
       *[other] Neither SELinux nor AppArmor is enforcing, so a compromised program is not limited.
    }
posture-firewall-name = Firewall
posture-firewall-title = No firewall is running
posture-firewall-summary = Services on this computer can be reached from the network without any filtering.
posture-tmp-mount-name = Safe /tmp
posture-tmp-mount-title = Temporary files are not restricted
posture-tmp-mount-summary =
    { $separate ->
        [no] /tmp is not a separate mount, so it cannot be restricted.
       *[yes] /tmp allows device files or privileged programs.
    }
posture-shm-mount-name = Safe shared memory
posture-shm-mount-title = Shared memory is not restricted
posture-shm-mount-summary =
    { $separate ->
        [no] /dev/shm is missing, which is unusual.
       *[yes] /dev/shm allows device files or privileged programs.
    }
posture-core-dumps-name = Core dumps
posture-core-dumps-title = Privileged programs may leave memory dumps
posture-core-dumps-summary = A crash can write secrets from memory to a file that others might read.
posture-sudo-nopasswd-name = Administrator password
posture-sudo-nopasswd-title = Administrator access does not ask for a password
posture-sudo-nopasswd-summary = Any program running as your user can become administrator silently.
posture-updates-pending-name = Security updates
posture-updates-pending-title = Security updates
posture-updates-pending-summary = Not checked yet: this arrives with the updates plugin.
posture-updates-automatic-name = Automatic updates
posture-updates-automatic-title = Automatic updates
posture-updates-automatic-summary = Not checked yet: this arrives with the updates plugin.
posture-firmware-hsi-name = Firmware security
posture-firmware-hsi-title = Firmware security
posture-firmware-hsi-summary = Not checked yet: this arrives with the firmware plugin.
