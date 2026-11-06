dns-unprotected-title = DNS lookups are not encrypted by IbexWall
dns-unprotected-summary = Your computer sends DNS lookups through the network's own server, which can see and change them. Turn on Secure DNS to encrypt them.
dns-may-affect-captive = Sign-in pages of captive portals (hotels, airports) may not load.
dns-may-affect-vpn = VPN clients that set their own DNS may be overridden.
dns-may-affect-split = Corporate split DNS (internal names) may stop resolving.
dns-network-servers-title = Your network provides its own DNS servers
dns-network-servers-summary = The network you are on (or your VPN) offers: { $servers }. Secure DNS does not use them unless you add them as a server or for specific domains.
dns-plain-upstream-title = Some DNS goes unencrypted on your local network
dns-plain-upstream-summary = Lookups for the names you routed to { $servers } are sent without encryption to that local server. Anyone on that network can read them.
detect-dns-title = How your DNS works today
detect-dns-ibexwall = Secure DNS is already running: lookups leave this computer encrypted, through IbexWall's resolver.
detect-dns-resolved-tls = Your system uses { $stack } and already encrypts lookups with TLS. Servers in use: { $servers }.
detect-dns-resolved-plain = Your system uses { $stack } and sends lookups without encryption to: { $servers }. A suggested setup is ready to review below.
detect-dns-other = Your system uses { $stack } for DNS. IbexWall cannot manage that setup yet, so nothing is suggested. Servers in use: { $servers }.
detect-dns-proxy =
    Your DNS already leaves this computer encrypted through { $proxy }, listening on { $listen }. Resolvers: { $resolvers }. It { $dnssec ->
        [yes] requires
       *[other] does not require
    } DNSSEC, { $nolog ->
        [yes] only uses
       *[other] does not insist on
    } resolvers that keep no logs, and { $nofilter ->
        [yes] avoids
       *[other] may use
    } resolvers that filter. IbexWall leaves it as it is and offers no change.
detect-dns-proxy-idle = { $proxy } is running here (listening on { $listen }), but this computer's lookups do not go through it. Point your system resolver at it to use it. IbexWall suggests nothing.
