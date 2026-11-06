openscap-failed-title = A rule of the security profile fails
openscap-failed-summary = The rule { $rule } of the profile { $profile } is not met on this computer. Open the rule's page in the SCAP Security Guide for what it asks and how to fix it.
openscap-may-affect-load = The check reads many files and settings and can slow the computer while it runs. It changes nothing.
detect-openscap-title = Security profile check (OpenSCAP)
detect-openscap-none = OpenSCAP is not installed. IbexWall installs nothing; to get it, run: { $install }
detect-openscap-no-content = OpenSCAP is installed but the SCAP Security Guide content for this distribution is not (for example the scap-security-guide package on Fedora), so there is no profile to check against.
detect-openscap-ready = OpenSCAP and its content are installed. You can check against a profile now or on a schedule.
detect-openscap-scanned = The last check of the profile { $profile } passed { $passed } rules and failed { $failed }. The failed rules are listed above, worst first.
