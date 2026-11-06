assistant-http-title = Accès pour les assistants sur d'autres machines
assistant-http-summary = L'accès à distance via HTTPS est { $enabled ->
    [true] activé
   *[other] désactivé
}. Il écoute sur { $listen }.
assistant-token-title = Un jeton d'accès pour un assistant
assistant-token-summary = { $name } ({ $client }, { $preset ->
    [read] peut seulement lire
    [plan] peut lire et préparer des plans
    [propose] peut lire et suggérer des changements
   *[other] a un accès personnalisé
}) peut joindre cette machine à distance. Expire : { $expires }.
assistant-may-affect-remote = Activer l'accès à distance ouvre un port qui ne répond qu'à un jeton valide, via TLS. Les assistants peuvent lire et, si vous l'autorisez, proposer ; ils ne peuvent jamais appliquer une modification.
assistant-tls-title = Le certificat pour l'accès à distance
assistant-tls-summary = Les clients devraient faire confiance à cette empreinte : { $fingerprint }
