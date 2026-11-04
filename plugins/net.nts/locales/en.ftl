nts-missing-title = The clock is not kept by a client that can authenticate servers
nts-missing-summary = chrony is not installed. Without it the time comes from plain NTP or nothing, and anyone on the path can change it. Install chrony, then turn this on.
nts-off-title = The clock takes time from servers it cannot authenticate
nts-off-summary = chrony has no NTS source. A forged time answer can break certificate checks and logs.
nts-may-affect-firewall-4460 = NTS asks each server for keys on TCP port 4460 first. A firewall that blocks it keeps the clock on its other sources.
nts-may-affect-clock = Time comes from the chosen servers in addition to the ones already set; IbexWall does not remove the distro's own.
