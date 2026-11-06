assistant-http-title = Zugriff für Assistenten auf anderen Rechnern
assistant-http-summary = Der Fernzugriff über HTTPS ist { $enabled ->
    [true] eingeschaltet
   *[other] ausgeschaltet
}. Er lauscht auf { $listen }.
assistant-token-title = Ein Zugriffstoken für einen Assistenten
assistant-token-summary = { $name } ({ $client }, { $preset ->
    [read] darf nur lesen
    [plan] darf lesen und Pläne vorbereiten
    [propose] darf lesen und Änderungen vorschlagen
   *[other] hat einen eigenen Zugriff
}) kann diesen Rechner aus der Ferne erreichen. Läuft ab: { $expires }.
assistant-may-affect-remote = Das Einschalten des Fernzugriffs öffnet einen Port, der nur auf ein gültiges Token über TLS antwortet. Assistenten können lesen und, wenn Sie es erlauben, Vorschläge machen; sie können nie eine Änderung anwenden.
assistant-tls-title = Das Zertifikat für den Fernzugriff
assistant-tls-summary = Clients sollten diesem Fingerabdruck vertrauen: { $fingerprint }
