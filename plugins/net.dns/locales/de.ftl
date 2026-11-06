dns-unprotected-title = DNS-Abfragen werden nicht von IbexWall verschlüsselt
dns-unprotected-summary = Ihr Computer sendet DNS-Abfragen über den eigenen Server des Netzwerks, der sie sehen und verändern kann. Schalten Sie sicheres DNS ein, um sie zu verschlüsseln.
dns-may-affect-captive = Anmeldeseiten von Captive Portals (Hotels, Flughäfen) werden möglicherweise nicht geladen.
dns-may-affect-vpn = VPN-Clients, die ihr eigenes DNS setzen, werden möglicherweise überschrieben.
dns-may-affect-split = Split-DNS in Firmennetzen (interne Namen) wird möglicherweise nicht mehr aufgelöst.
dns-network-servers-title = Ihr Netzwerk stellt eigene DNS-Server bereit
dns-network-servers-summary = Das Netzwerk, in dem Sie sich befinden (oder Ihr VPN), bietet an: { $servers }. Sicheres DNS verwendet sie nicht, es sei denn, Sie fügen sie als Server oder für bestimmte Domains hinzu.
dns-plain-upstream-title = Einiges DNS läuft unverschlüsselt in Ihrem lokalen Netzwerk
dns-plain-upstream-summary = Abfragen für die Namen, die Sie an { $servers } geleitet haben, werden unverschlüsselt an diesen lokalen Server gesendet. Jeder in diesem Netzwerk kann sie lesen.
detect-dns-title = Wie Ihr DNS heute funktioniert
detect-dns-ibexwall = Sicheres DNS läuft bereits: Abfragen verlassen diesen Computer verschlüsselt über den Resolver von IbexWall.
detect-dns-resolved-tls = Ihr System verwendet { $stack } und verschlüsselt Abfragen bereits mit TLS. Verwendete Server: { $servers }.
detect-dns-resolved-plain = Ihr System verwendet { $stack } und sendet Abfragen unverschlüsselt an: { $servers }. Eine vorgeschlagene Einrichtung steht unten zur Prüfung bereit.
detect-dns-other = Ihr System verwendet { $stack } für DNS. IbexWall kann diese Einrichtung noch nicht verwalten, daher wird nichts vorgeschlagen. Verwendete Server: { $servers }.
detect-dns-proxy =
    Ihr DNS verlässt diesen Computer bereits verschlüsselt über { $proxy }, das auf { $listen } lauscht. Resolver: { $resolvers }. Es { $dnssec ->
        [yes] verlangt
       *[other] verlangt kein
    } DNSSEC, { $nolog ->
        [yes] verwendet nur
       *[other] besteht nicht auf
    } Resolver ohne Protokollierung, und { $nofilter ->
        [yes] meidet
       *[other] verwendet möglicherweise
    } filternde Resolver. IbexWall lässt es, wie es ist, und bietet keine Änderung an.
detect-dns-proxy-idle = { $proxy } läuft hier (lauscht auf { $listen }), aber die Abfragen dieses Computers laufen nicht darüber. Richten Sie Ihren System-Resolver darauf aus, um es zu nutzen. IbexWall schlägt nichts vor.
