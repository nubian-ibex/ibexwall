exposure-open-title = Un puerto responde en este equipo
exposure-open-summary = El puerto TCP { $port } ({ $service }) responde en { $addresses }. Comprueba que lo esperas; lo que no uses es mejor tenerlo cerrado.
exposure-may-affect-logs = El análisis abre una conexión con cada puerto de las direcciones de este propio equipo, así que los servicios que registran conexiones las mostrarán.
detect-exposure-title = Puertos abiertos, vistos desde este equipo
detect-exposure-none = nmap no está instalado. IbexWall no instala nada; para obtenerlo, ejecuta: { $install }
detect-exposure-ready = nmap está instalado. Un análisis solo abarca las direcciones de este propio equipo, nunca otra máquina.
detect-exposure-scanned = Se ha hecho un análisis; los puertos que responden aparecen arriba. Visto desde la propia máquina, esto no muestra lo que un cortafuegos bloquea desde fuera.
