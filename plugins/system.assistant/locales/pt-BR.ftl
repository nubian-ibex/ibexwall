assistant-http-title = Acesso para assistentes em outras máquinas
assistant-http-summary = O acesso remoto por HTTPS está { $enabled ->
    [true] ligado
   *[other] desligado
}. Ele escuta em { $listen }.
assistant-token-title = Uma chave de acesso para um assistente
assistant-token-summary = { $name } ({ $client }, { $preset ->
    [read] só pode ler
    [plan] pode ler e preparar planos
    [propose] pode ler e sugerir mudanças
   *[other] tem acesso personalizado
}) alcança esta máquina remotamente. Expira em: { $expires }.
assistant-may-affect-remote = Ligar o acesso remoto abre uma porta que só responde a uma chave válida, com TLS. Assistentes podem ler e, se você permitir, propor; nunca aplicam uma mudança.
assistant-tls-title = O certificado do acesso remoto
assistant-tls-summary = Os clientes devem confiar nesta impressão digital: { $fingerprint }
