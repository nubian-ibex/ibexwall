dns-unprotected-title = Les requêtes DNS ne sont pas chiffrées par IbexWall
dns-unprotected-summary = Votre ordinateur envoie ses requêtes DNS par le serveur propre au réseau, qui peut les voir et les modifier. Activez le DNS sécurisé pour les chiffrer.
dns-may-affect-captive = Les pages de connexion des portails captifs (hôtels, aéroports) peuvent ne pas s'afficher.
dns-may-affect-vpn = Les clients VPN qui définissent leur propre DNS peuvent être remplacés.
dns-may-affect-split = Le DNS scindé d'entreprise (noms internes) peut cesser de résoudre.
dns-network-servers-title = Votre réseau fournit ses propres serveurs DNS
dns-network-servers-summary = Le réseau sur lequel vous êtes (ou votre VPN) propose : { $servers }. Le DNS sécurisé ne les utilise pas, sauf si vous les ajoutez comme serveur ou pour des domaines précis.
dns-plain-upstream-title = Une partie du DNS circule sans chiffrement sur votre réseau local
dns-plain-upstream-summary = Les requêtes pour les noms que vous avez dirigés vers { $servers } sont envoyées sans chiffrement à ce serveur local. Toute personne sur ce réseau peut les lire.
detect-dns-title = Comment fonctionne votre DNS aujourd'hui
detect-dns-ibexwall = Le DNS sécurisé fonctionne déjà : les requêtes quittent cet ordinateur chiffrées, via le résolveur d'IbexWall.
detect-dns-resolved-tls = Votre système utilise { $stack } et chiffre déjà les requêtes avec TLS. Serveurs utilisés : { $servers }.
detect-dns-resolved-plain = Votre système utilise { $stack } et envoie les requêtes sans chiffrement à : { $servers }. Une configuration suggérée est prête à être examinée ci-dessous.
detect-dns-other = Votre système utilise { $stack } pour le DNS. IbexWall ne peut pas encore gérer cette configuration, donc rien n'est suggéré. Serveurs utilisés : { $servers }.
detect-dns-proxy =
    Votre DNS quitte déjà cet ordinateur chiffré via { $proxy }, qui écoute sur { $listen }. Résolveurs : { $resolvers }. Il { $dnssec ->
        [yes] exige
       *[other] n'exige pas
    } DNSSEC, { $nolog ->
        [yes] n'utilise que
       *[other] n'insiste pas sur
    } des résolveurs qui ne conservent aucun journal, et { $nofilter ->
        [yes] évite
       *[other] peut utiliser
    } les résolveurs qui filtrent. IbexWall le laisse tel quel et ne propose aucun changement.
detect-dns-proxy-idle = { $proxy } fonctionne ici (à l'écoute sur { $listen }), mais les requêtes de cet ordinateur ne passent pas par lui. Dirigez le résolveur de votre système vers lui pour l'utiliser. IbexWall ne suggère rien.
