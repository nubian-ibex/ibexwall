dns-unprotected-title = IbexWall no cifra las consultas DNS
dns-unprotected-summary = Tu equipo envía las consultas DNS a través del servidor propio de la red, que puede verlas y modificarlas. Activa el DNS seguro para cifrarlas.
dns-may-affect-captive = Las páginas de inicio de sesión de portales cautivos (hoteles, aeropuertos) pueden no cargarse.
dns-may-affect-vpn = Los clientes VPN que establecen su propio DNS pueden ser anulados.
dns-may-affect-split = El DNS dividido corporativo (nombres internos) puede dejar de resolverse.
dns-network-servers-title = Tu red proporciona sus propios servidores DNS
dns-network-servers-summary = La red en la que estás (o tu VPN) ofrece: { $servers }. El DNS seguro no los usa a menos que los añadas como servidor o para dominios concretos.
dns-plain-upstream-title = Parte del DNS va sin cifrar por tu red local
dns-plain-upstream-summary = Las consultas de los nombres que dirigiste a { $servers } se envían sin cifrar a ese servidor local. Cualquiera en esa red puede leerlas.
detect-dns-title = Cómo funciona hoy tu DNS
detect-dns-ibexwall = El DNS seguro ya está en marcha: las consultas salen cifradas de este equipo, a través del resolvedor de IbexWall.
detect-dns-resolved-tls = Tu sistema usa { $stack } y ya cifra las consultas con TLS. Servidores en uso: { $servers }.
detect-dns-resolved-plain = Tu sistema usa { $stack } y envía las consultas sin cifrar a: { $servers }. Más abajo tienes una configuración sugerida lista para revisar.
detect-dns-other = Tu sistema usa { $stack } para el DNS. IbexWall aún no puede gestionar esa configuración, así que no se sugiere nada. Servidores en uso: { $servers }.
detect-dns-proxy =
    Tu DNS ya sale de este equipo cifrado a través de { $proxy }, que escucha en { $listen }. Resolvedores: { $resolvers }. { $dnssec ->
        [yes] Exige
       *[other] No exige
    } DNSSEC, { $nolog ->
        [yes] solo usa
       *[other] no insiste en usar
    } resolvedores que no guardan registros, y { $nofilter ->
        [yes] evita
       *[other] puede usar
    } resolvedores que filtran. IbexWall lo deja como está y no ofrece ningún cambio.
detect-dns-proxy-idle = { $proxy } está en marcha aquí (escucha en { $listen }), pero las consultas de este equipo no pasan por él. Apunta el resolvedor de tu sistema hacia él para usarlo. IbexWall no sugiere nada.
