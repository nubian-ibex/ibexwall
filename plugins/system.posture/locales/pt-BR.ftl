# system.posture messages (pt-BR). Keys are stable; never concatenate.
plugin-system.posture-summary = O quanto este computador está protegido.
posture-secure-boot-name = Secure Boot
posture-secure-boot-title = Secure Boot está desativado
posture-secure-boot-summary = Sem ele, um programa de boot adulterado poderia iniciar antes do sistema sem ser notado.
posture-lockdown-name = Bloqueio do kernel (lockdown)
posture-lockdown-title = O bloqueio do kernel está desligado
posture-lockdown-summary = Programas executados como administrador podem alterar o kernel em execução. O lockdown limita isso.
posture-disk-encryption-name = Criptografia do disco
posture-disk-encryption-title = O disco do sistema não está criptografado
posture-disk-encryption-summary = Seus arquivos podem ser lidos por quem obtiver o disco se o computador for perdido ou roubado.
posture-swap-encryption-name = Swap criptografada
posture-swap-encryption-title = A área de swap não está criptografada
posture-swap-encryption-summary = Senhas e documentos podem ser gravados no disco sem criptografia quando a memória enche.
posture-tpm2-name = Chip TPM 2.0
posture-tpm2-title = Chip TPM 2.0
posture-tpm2-summary = Há um chip TPM que pode proteger as chaves do disco.
posture-mac-name = Confinamento de aplicativos
posture-mac-title = O confinamento de aplicativos não está ativo
posture-mac-summary =
    { $mode ->
        [selinux-permissive] O SELinux apenas registra problemas em vez de bloqueá-los.
       *[other] Nem o SELinux nem o AppArmor estão ativos, então um programa comprometido não fica limitado.
    }
posture-firewall-name = Firewall
posture-firewall-title = Nenhum firewall está em execução
posture-firewall-summary = Os serviços deste computador podem ser acessados pela rede sem nenhum filtro.
posture-tmp-mount-name = /tmp protegido
posture-tmp-mount-title = Os arquivos temporários não estão restritos
posture-tmp-mount-summary =
    { $separate ->
        [no] /tmp não é uma montagem separada, então não pode ser restrito.
       *[yes] /tmp permite arquivos de dispositivo ou programas privilegiados.
    }
posture-shm-mount-name = Memória compartilhada protegida
posture-shm-mount-title = A memória compartilhada não está restrita
posture-shm-mount-summary =
    { $separate ->
        [no] /dev/shm não existe, o que é incomum.
       *[yes] /dev/shm permite arquivos de dispositivo ou programas privilegiados.
    }
posture-core-dumps-name = Despejos de memória (core dumps)
posture-core-dumps-title = Programas privilegiados podem deixar despejos de memória
posture-core-dumps-summary = Uma falha pode gravar segredos da memória em um arquivo que outros usuários poderiam ler.
posture-sudo-nopasswd-name = Senha de administrador
posture-sudo-nopasswd-title = O acesso de administrador não pede senha
posture-sudo-nopasswd-summary = Qualquer programa executado com o seu usuário pode virar administrador sem avisar.
posture-updates-pending-name = Atualizações de segurança
posture-updates-pending-title = Atualizações de segurança
posture-updates-pending-summary = Ainda não verificado: isso chega com o plugin de atualizações.
posture-updates-automatic-name = Atualizações automáticas
posture-updates-automatic-title = Atualizações automáticas
posture-updates-automatic-summary = Ainda não verificado: isso chega com o plugin de atualizações.
posture-firmware-hsi-name = Segurança do firmware
posture-firmware-hsi-title = Segurança do firmware
posture-firmware-hsi-summary = Ainda não verificado: isso chega com o plugin de firmware.
