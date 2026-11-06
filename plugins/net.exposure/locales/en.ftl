exposure-open-title = A port answers on this computer
exposure-open-summary = TCP port { $port } ({ $service }) answers on { $addresses }. Check that you expect it; anything you do not use is better closed.
exposure-may-affect-logs = The scan opens a connection to every port of this computer's own addresses, so services that log connections will list them.
detect-exposure-title = Open ports, seen from this computer
detect-exposure-none = nmap is not installed. IbexWall installs nothing; to get it, run: { $install }
detect-exposure-ready = nmap is installed. A scan covers only this computer's own addresses, never another machine.
detect-exposure-scanned = A scan has run; the ports that answer are listed above. Seen from the machine itself, this does not show what a firewall blocks from outside.
