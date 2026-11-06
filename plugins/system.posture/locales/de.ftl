# system.posture messages (en). Keys are stable; never concatenate.
posture-secure-boot-name = Secure Boot
posture-secure-boot-title = Secure Boot ist ausgeschaltet
posture-secure-boot-summary = Ohne es könnte ein manipuliertes Startprogramm vor dem System starten und unbemerkt bleiben.
posture-lockdown-name = Kernel-Lockdown
posture-lockdown-title = Der Kernel-Lockdown ist aus
posture-lockdown-summary = Programme, die als Administrator laufen, können den laufenden Kernel ändern. Der Lockdown schränkt das ein.
posture-disk-encryption-name = Festplattenverschlüsselung
posture-disk-encryption-title = Die Systemfestplatte ist nicht verschlüsselt
posture-disk-encryption-summary = Ihre Dateien kann jeder lesen, der die Festplatte in die Hände bekommt, wenn der Computer verloren geht oder gestohlen wird.
posture-swap-encryption-name = Verschlüsselter Swap
posture-swap-encryption-title = Der Auslagerungsspeicher ist nicht verschlüsselt
posture-swap-encryption-summary = Passwörter und Dokumente können im Klartext auf die Festplatte geschrieben werden, wenn der Arbeitsspeicher voll ist.
posture-tpm2-name = TPM-2.0-Chip
posture-tpm2-title = TPM-2.0-Chip
posture-tpm2-summary = Ein TPM-Chip ist vorhanden und kann Festplattenschlüssel schützen.
posture-mac-name = Programmeingrenzung
posture-mac-title = Die Programmeingrenzung wird nicht durchgesetzt
posture-mac-summary =
    { $mode ->
        [selinux-permissive] SELinux protokolliert Probleme nur, statt sie zu blockieren.
       *[other] Weder SELinux noch AppArmor wird durchgesetzt, daher ist ein kompromittiertes Programm nicht eingeschränkt.
    }
posture-firewall-name = Firewall
posture-firewall-title = Es läuft keine Firewall
posture-firewall-summary = Dienste auf diesem Computer sind aus dem Netzwerk ohne jede Filterung erreichbar.
posture-tmp-mount-name = Sicheres /tmp
posture-tmp-mount-title = Temporäre Dateien sind nicht eingeschränkt
posture-tmp-mount-summary =
    { $separate ->
        [no] /tmp ist kein eigener Einhängepunkt und kann daher nicht eingeschränkt werden.
       *[yes] /tmp erlaubt Gerätedateien oder privilegierte Programme.
    }
posture-shm-mount-name = Sicherer gemeinsamer Speicher
posture-shm-mount-title = Der gemeinsame Speicher ist nicht eingeschränkt
posture-shm-mount-summary =
    { $separate ->
        [no] /dev/shm fehlt, was ungewöhnlich ist.
       *[yes] /dev/shm erlaubt Gerätedateien oder privilegierte Programme.
    }
posture-core-dumps-name = Core Dumps
posture-core-dumps-title = Privilegierte Programme können Speicherabbilder hinterlassen
posture-core-dumps-summary = Ein Absturz kann Geheimnisse aus dem Speicher in eine Datei schreiben, die andere lesen könnten.
posture-sudo-nopasswd-name = Administratorpasswort
posture-sudo-nopasswd-title = Der Administratorzugriff verlangt kein Passwort
posture-sudo-nopasswd-summary = Jedes Programm, das als Ihr Benutzer läuft, kann unbemerkt zum Administrator werden.
posture-updates-pending-name = Sicherheitsupdates
posture-updates-pending-title = Sicherheitsupdates
posture-updates-pending-summary = Noch nicht geprüft: Das kommt mit dem Updates-Plugin.
posture-updates-automatic-name = Automatische Updates
posture-updates-automatic-title = Automatische Updates
posture-updates-automatic-summary = Noch nicht geprüft: Das kommt mit dem Updates-Plugin.
posture-firmware-hsi-name = Firmware-Sicherheit
posture-firmware-hsi-title = Firmware-Sicherheit
posture-firmware-hsi-summary = Noch nicht geprüft: Das kommt mit dem Firmware-Plugin.
detect-mac-title = Mandatory Access Control heute
detect-mac-selinux-enforcing = SELinux wird durchgesetzt: Programme sind auf das beschränkt, was ihre Richtlinie erlaubt.
detect-mac-apparmor = AppArmor ist an: Programme mit einem Profil sind darauf beschränkt.
detect-mac-selinux-permissive = SELinux ist an, protokolliert aber nur, was es blockieren würde. Um es durchzusetzen, prüfen Sie die Protokolle auf abgelehnte Zugriffe von Programmen, die Sie nutzen, setzen Sie dann SELINUX=enforcing in /etc/selinux/config und starten Sie neu.
detect-mac-selinux-disabled = SELinux ist installiert, aber in /etc/selinux/config ausgeschaltet. Beim Einschalten werden die Dateien beim nächsten Neustart neu beschriftet, was eine Weile dauern kann; beginnen Sie mit dem permissiven Modus.
detect-mac-none = Es ist keine Mandatory Access Control aktiv. IbexWall installiert nichts; um die Pakete dafür zu erhalten, führen Sie aus: { $install }. Danach ist eine Boot-Einstellung nötig, folgen Sie dazu dem Leitfaden Ihrer Distribution.
