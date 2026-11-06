openscap-failed-title = Falla una regla del perfil de seguridad
openscap-failed-summary = La regla { $rule } del perfil { $profile } no se cumple en este equipo. Abre la página de la regla en la SCAP Security Guide para ver qué pide y cómo corregirlo.
openscap-may-affect-load = La comprobación lee muchos archivos y ajustes y puede ralentizar el equipo mientras se ejecuta. No cambia nada.
detect-openscap-title = Comprobación del perfil de seguridad (OpenSCAP)
detect-openscap-none = OpenSCAP no está instalado. IbexWall no instala nada; para obtenerlo, ejecuta: { $install }
detect-openscap-no-content = OpenSCAP está instalado pero el contenido de la SCAP Security Guide para esta distribución no (por ejemplo, el paquete scap-security-guide en Fedora), así que no hay ningún perfil con el que comprobar.
detect-openscap-ready = OpenSCAP y su contenido están instalados. Puedes comprobar con un perfil ahora o de forma programada.
detect-openscap-scanned = La última comprobación del perfil { $profile } superó { $passed } reglas y falló { $failed }. Las reglas fallidas aparecen arriba, las peores primero.
