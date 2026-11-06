# system.posture messages (fr). Keys are stable; never concatenate.
posture-secure-boot-name = Démarrage sécurisé (Secure Boot)
posture-secure-boot-title = Le démarrage sécurisé est désactivé
posture-secure-boot-summary = Sans lui, un programme de démarrage falsifié pourrait se lancer avant le système sans que personne ne le remarque.
posture-lockdown-name = Verrouillage du noyau
posture-lockdown-title = Le verrouillage du noyau est désactivé
posture-lockdown-summary = Les programmes exécutés en administrateur peuvent modifier le noyau en cours d'exécution. Le verrouillage limite cela.
posture-disk-encryption-name = Chiffrement du disque
posture-disk-encryption-title = Le disque système n'est pas chiffré
posture-disk-encryption-summary = Vos fichiers peuvent être lus par quiconque obtient le disque si l'ordinateur est perdu ou volé.
posture-swap-encryption-name = Swap chiffré
posture-swap-encryption-title = L'espace d'échange (swap) n'est pas chiffré
posture-swap-encryption-summary = Des mots de passe et des documents peuvent être écrits en clair sur le disque quand la mémoire est pleine.
posture-tpm2-name = Puce TPM 2.0
posture-tpm2-title = Puce TPM 2.0
posture-tpm2-summary = Une puce TPM est présente et peut protéger les clés du disque.
posture-mac-name = Confinement des applications
posture-mac-title = Le confinement des applications n'est pas appliqué
posture-mac-summary =
    { $mode ->
        [selinux-permissive] SELinux se contente de journaliser les problèmes au lieu de les bloquer.
       *[other] Ni SELinux ni AppArmor ne sont appliqués, donc un programme compromis n'est pas limité.
    }
posture-firewall-name = Pare-feu
posture-firewall-title = Aucun pare-feu ne fonctionne
posture-firewall-summary = Les services de cet ordinateur peuvent être atteints depuis le réseau sans aucun filtrage.
posture-tmp-mount-name = /tmp sûr
posture-tmp-mount-title = Les fichiers temporaires ne sont pas restreints
posture-tmp-mount-summary =
    { $separate ->
        [no] /tmp n'est pas un montage séparé, donc il ne peut pas être restreint.
       *[yes] /tmp autorise les fichiers de périphérique ou les programmes privilégiés.
    }
posture-shm-mount-name = Mémoire partagée sûre
posture-shm-mount-title = La mémoire partagée n'est pas restreinte
posture-shm-mount-summary =
    { $separate ->
        [no] /dev/shm est absent, ce qui est inhabituel.
       *[yes] /dev/shm autorise les fichiers de périphérique ou les programmes privilégiés.
    }
posture-core-dumps-name = Vidages mémoire (core dumps)
posture-core-dumps-title = Les programmes privilégiés peuvent laisser des vidages mémoire
posture-core-dumps-summary = Un plantage peut écrire des secrets de la mémoire dans un fichier que d'autres pourraient lire.
posture-sudo-nopasswd-name = Mot de passe administrateur
posture-sudo-nopasswd-title = L'accès administrateur ne demande pas de mot de passe
posture-sudo-nopasswd-summary = N'importe quel programme exécuté sous votre utilisateur peut devenir administrateur en silence.
posture-updates-pending-name = Mises à jour de sécurité
posture-updates-pending-title = Mises à jour de sécurité
posture-updates-pending-summary = Pas encore vérifié : cela arrive avec le plugin de mises à jour.
posture-updates-automatic-name = Mises à jour automatiques
posture-updates-automatic-title = Mises à jour automatiques
posture-updates-automatic-summary = Pas encore vérifié : cela arrive avec le plugin de mises à jour.
posture-firmware-hsi-name = Sécurité des micrologiciels
posture-firmware-hsi-title = Sécurité des micrologiciels
posture-firmware-hsi-summary = Pas encore vérifié : cela arrive avec le plugin des micrologiciels.
detect-mac-title = Contrôle d'accès obligatoire aujourd'hui
detect-mac-selinux-enforcing = SELinux est appliqué : les programmes sont confinés à ce que leur politique autorise.
detect-mac-apparmor = AppArmor est activé : les programmes ayant un profil y sont confinés.
detect-mac-selinux-permissive = SELinux est activé mais se contente de journaliser ce qu'il bloquerait. Pour l'appliquer, cherchez dans les journaux les refus concernant des programmes que vous utilisez, puis définissez SELINUX=enforcing dans /etc/selinux/config et redémarrez.
detect-mac-selinux-disabled = SELinux est installé mais désactivé dans /etc/selinux/config. L'activer réétiquette les fichiers au prochain redémarrage, ce qui peut prendre du temps ; commencez par le mode permissif.
detect-mac-none = Aucun contrôle d'accès obligatoire n'est actif. IbexWall n'installe rien ; pour obtenir ses paquets, exécutez : { $install }. Il faut ensuite un réglage de démarrage, suivez le guide de votre distribution.
