assistant-http-title = Acceso para asistentes en otras máquinas
assistant-http-summary = El acceso remoto mediante HTTPS está { $enabled ->
    [true] activado
   *[other] desactivado
}. Escucha en { $listen }.
assistant-token-title = Un token de acceso para un asistente
assistant-token-summary = { $name } ({ $client }, { $preset ->
    [read] solo puede leer
    [plan] puede leer y preparar planes
    [propose] puede leer y sugerir cambios
   *[other] tiene acceso personalizado
}) puede acceder a esta máquina de forma remota. Caduca: { $expires }.
assistant-may-affect-remote = Activar el acceso remoto abre un puerto que solo responde a un token válido, mediante TLS. Los asistentes pueden leer y, si lo permites, proponer; nunca pueden aplicar un cambio.
assistant-tls-title = El certificado del acceso remoto
assistant-tls-summary = Los clientes deberían confiar en esta huella: { $fingerprint }
