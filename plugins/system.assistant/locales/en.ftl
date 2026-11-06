assistant-http-title = Access for assistants on other machines
assistant-http-summary = Remote access over HTTPS is { $enabled ->
    [true] on
   *[other] off
}. It listens on { $listen }.
assistant-token-title = An access token for an assistant
assistant-token-summary = { $name } ({ $client }, { $preset ->
    [read] can only read
    [plan] can read and prepare plans
    [propose] can read and suggest changes
   *[other] has custom access
}) can reach this machine remotely. Expires: { $expires }.
assistant-may-affect-remote = Turning remote access on opens a port that answers only to a valid token, over TLS. Assistants can read and, if you allow it, propose; they can never apply a change.
assistant-tls-title = The certificate for remote access
assistant-tls-summary = Clients should trust this fingerprint: { $fingerprint }
