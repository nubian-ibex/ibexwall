app-name = IbexWall
app-tagline = System protection
nav-label = Main navigation
nav-overview = Overview
nav-plugins = Plugins
nav-posture = System posture
nav-history = History
nav-settings = Settings
sidebar-status-active = Protection active
skip-to-content = Skip to content

overview-title = Overview
overview-last-check = Last full check { $when }
overview-never-checked = No check has run yet
overview-check-now = Check now
overview-checking = Checking…
overview-status-protected = Your computer is protected
overview-status-attention = Your computer can be better protected
overview-status-unknown = Let's check your computer
overview-badge-protected = Protected
overview-badge-attention = Attention
overview-badge-unknown = Not checked
overview-summary =
    { $failed ->
        [0] All { $assessed } checks that can run here are in order.
        [one] { $passed } of { $assessed } checks are in order. There is 1 recommendation that makes the system safer.
       *[other] { $passed } of { $assessed } checks are in order. There are { $failed } recommendations that make the system safer.
    }
overview-summary-unknown = Run a check to see how well this computer is protected. Nothing is changed.
overview-view-recommendation = See recommendation
overview-view-all = See all protections
overview-run-first = Run the first check
overview-protections = Protections
overview-recommendation = Recommendation
overview-not-assessed =
    { $count ->
        [one] 1 check cannot be assessed yet.
       *[other] { $count } checks cannot be assessed yet.
    }

trust-no-change = Nothing changes on your system without your approval
trust-undo = Every change can be undone
trust-open = Open and auditable code
trust-local = Your data stays on this computer

score-label = Score { $score } out of 100
score-none = No score yet
score-of = of 100

card-boot = Secure boot
card-disk = Encrypted disk
card-firewall = Firewall
card-confinement = Program limits
card-accounts = Administrator access
card-ports = Network exposure
card-updates = Updates and firmware
card-state-ok = In order
card-state-attention = Attention
card-state-unknown = Not assessed
card-detail-checks = { $count } checks

outcome-pass = In order
outcome-fail = Attention
outcome-not-applicable = Not applicable here
outcome-not-assessed = Not assessed yet

severity-info = Info
severity-low = Low
severity-medium = Medium
severity-high = High
severity-critical = Critical

state-loading = Loading…
state-empty-title = Nothing to show yet
state-empty-body = Run a check and the results will appear here.
state-error-title = Cannot reach the IbexWall service
state-error-body = The protection service did not answer. Your protections keep working; this window just cannot read their state.
state-denied-title = Permission needed
state-denied-body = Your account is not allowed to read this information. Ask an administrator to allow { $action }.
state-retry = Try again

theme-label = Theme
theme-system = Follow system
theme-light = Light
theme-dark = Dark
language-label = Language

plugins-title = Plugins
plugins-subtitle = Every protection is a plugin you can turn on or off
plugins-kind-check = Read-only
plugins-kind-control = Changes the system
plugins-kind-monitor = Watches
plugins-origin-official = Official
plugins-origin-community = Community
plugins-origin-local = Local
plugins-enabled = On
plugins-disabled = Off
plugins-detail = Detail
plugins-close = Close detail
plugins-permissions = What this plugin can do
plugins-permissions-write = Change files under { $paths }
plugins-permissions-units = Control services: { $units }
plugins-permissions-sysctl = Set kernel parameters: { $keys }
plugins-permissions-exec = Run programs: { $commands }
plugins-permissions-nft = Add firewall rules with its own prefix
plugins-permissions-none = Read the system; it cannot change anything
plugins-findings = Open findings
plugins-no-findings = No open findings
plugins-locked = Set by your organization
plugins-incompatible = Not compatible with this system

simulate = Simulate
apply = Apply changes
applying = Applying…
confirm-title = Keep the changes?
plan-expires = This preview expires { $when }

may-affect-label = What this can affect
may-affect-title = This can affect
restore-point-note = A restore point ({ $point }) is created before anything changes.

keep-changes-title = Keep the changes
keep-changes-prompt = Keep the changes? ({ $seconds } s left, they are undone automatically after that)
keep-changes = Keep changes
undo-changes = Undo changes

applied-committed = Changes applied
applied-rolled-back = Changes undone
simulate-empty = Nothing to change

posture-title = System posture
posture-subtitle = Every check, what it means and what it is worth
posture-how-title = How we calculate
posture-how-intro = Each check has a weight by severity. The score is the sum of the weights of the checks in order, divided by the weights of the checks that apply on this computer.
posture-how-weight = Weight
posture-how-outcome = Status
posture-how-na = Checks that do not apply here and checks that cannot be assessed yet do not count for or against the score.
posture-recommendation = Recommendation
posture-checks = Checks
posture-open-findings = Open findings ({ $count })

history-title = History
history-subtitle = Every change, who approved it and what happened
history-actor-user = { $actor }
history-actor-system = IbexWall itself
history-result-committed = Applied and kept
history-result-rolled_back = Undone
history-result-pending_confirm = Waiting for confirmation
history-result-failed = Failed (undone)
history-empty-title = Nothing has changed yet
history-empty-body = When you apply a protection, it shows up here with a way to undo it.
history-undo = Undo this change
history-view = View

settings-title = Settings
settings-subtitle = Appearance and language
language-en = English
language-pt-BR = Portuguese (Brazil)

nav-dns = Secure DNS
dns-title = Secure DNS
dns-subtitle = Encrypt your DNS lookups and block trackers and malicious domains
dns-unavailable-title = Secure DNS is not available
dns-unavailable-body = The Secure DNS plugin is not installed on this computer.
dns-status-off = Secure DNS is off
dns-status-off-body = Your computer sends DNS lookups through the network's own server.
dns-status-pass = Your DNS lookups are encrypted
dns-status-pass-body = The local resolver is running and answering for this computer.
dns-status-fail = Secure DNS is on but not working
dns-status-fail-body = The local resolver is not answering. Review the settings below or turn it off.
dns-status-not_applicable = Secure DNS does not apply here
dns-status-not_applicable-body = This system does not use the setup Secure DNS works with.
dns-status-not_assessed = This system cannot be checked yet
dns-status-not_assessed-body = Secure DNS supports systemd-resolved for now. Other setups are not supported yet.
dns-status-unknown = Checking
dns-status-unknown-body = The result will appear after the next check.
dns-provider = Provider
dns-provider-quad9 = Quad9
dns-provider-quad9-logs = does not record user IP addresses
dns-provider-cloudflare = Cloudflare
dns-provider-cloudflare-logs = truncates IP addresses and deletes them within 25 hours
dns-jurisdiction = Jurisdiction: { $code }
dns-transport = How lookups are encrypted
dns-transport-tls = DNS over TLS (recommended)
dns-transport-https = DNS over HTTPS
dns-transport-h3 = DNS over HTTPS (HTTP/3)
dns-transport-quic = DNS over QUIC
dns-list = Block list
dns-list-none = None
dns-list-hagezi-light = HaGeZi Light (fewest blocks)
dns-list-hagezi-normal = HaGeZi Normal
dns-list-hagezi-pro = HaGeZi Pro (recommended by its authors)
dns-list-hagezi-pro-plus = HaGeZi Pro++ (more blocks)
dns-list-hagezi-ultimate = HaGeZi Ultimate (may break sites)
dns-list-oisd-small = OISD small
dns-list-oisd-big = OISD big
dns-list-stevenblack = StevenBlack unified hosts
dns-enforcement = Refuse unencrypted DNS
dns-enforcement-body = Programs cannot send plain DNS or DoT queries around Secure DNS.
dns-block-doh = Stop browsers from bypassing it
dns-block-doh-body = Asks Firefox to keep its own DNS off. Browser settings are never changed without your approval.
dns-review-note = Nothing changes until you review the exact changes and apply them.

change-failed-title = IbexWall could not proceed
change-failed-other = The request failed. Nothing was changed.

dns-browser-policy = Turn off each browser's own encrypted DNS
dns-browser-policy-body = With your approval, writes the browser policy that keeps Firefox, Chrome, Chromium, Brave and Edge from using their own DoH servers. Only browsers installed on this computer are touched, and undoing the change removes the policy.

dns-provider-adguard = AdGuard DNS
dns-provider-adguard-logs = processes no personal data; only overall usage statistics
dns-provider-dns4eu = DNS4EU (protective)
dns-provider-dns4eu-logs = see the provider's privacy documentation

dns-counters-title = Since the resolver started
dns-counter-blocked-list = Domains blocked by the list
dns-counter-blocked-doh = Attempts to reach other DoH servers
dns-counter-forwarded = Lookups forwarded encrypted
dns-counter-errors = Upstream failures
dns-counters-updated = Updated { $when }.
dns-counters-not-running = The resolver is not reporting right now.
dns-counters-privacy = Counts only. IbexWall does not record which domains you look up.

nav-apps = Apps and network
apps-title = Apps and network
apps-subtitle = See which programs use the internet and where they connect.
apps-mode-allow = Allow
apps-mode-allow-body = Free access to the internet.
apps-mode-monitor = Monitor
apps-mode-monitor-body = Free access, but everything is recorded.
apps-mode-ask = Ask
apps-mode-ask-body = You decide at every new destination.
apps-mode-block = Block
apps-mode-block-body = No access to the internet.
apps-mode-later = Available with the firewall, in a later version.
apps-mode-group = Network mode for { $app }
apps-monitor-running = The connection monitor is running.
apps-monitor-limited = The connection monitor is running with a limit: { $reason }
apps-monitor-off = The connection monitor is off: { $reason }
apps-monitor-off-body = Apps and destinations appear here once it is running. Nothing is blocked while it is off.
apps-search = Search apps
apps-filters = Filter apps
apps-filter-all = All · { $count }
apps-filter-active = Connected now · { $count }
apps-filter-new = New · { $count }
apps-list-label = Apps
apps-empty-title = No apps seen yet
apps-empty-body = Programs appear here after their first connection.
apps-none-match = No app matches your search.
apps-kind-flatpak = Flatpak
apps-kind-snap = Snap
apps-kind-desktop_app = App
apps-kind-system_service = System service
apps-kind-container = Container
apps-kind-cli = Program
apps-kind-unknown = Unknown
apps-new-badge = New
apps-summary =
    { $destinations ->
        [one] 1 destination
       *[other] { $destinations } destinations
    } · { $connections ->
        [one] 1 connection
       *[other] { $connections } connections
    }
apps-last-activity = Last activity { $when }
apps-select = Show details for { $app }
apps-details-title = Details
apps-details-hint = Choose an app to see where it connects.
apps-package = Package: { $name }
apps-exe = Program file: { $path }
apps-first-seen = First seen { $when }
apps-where = Where it connects
apps-no-destinations = No destinations recorded yet.
apps-no-domain = no domain known
apps-port = port { $port }
apps-times =
    { $count ->
        [one] 1 time
       *[other] { $count } times
    }
apps-block-title = Cut this app's network access
apps-block-body = Flatpak will start this app without network access. You can undo it from History.
apps-block-scope = Works for Flatpak apps installed for the whole system. Apps installed for a single user cannot be changed from here.
apps-block-start = Block network access
apps-block-enable-failed = Could not turn on the Flatpak network plugin.
apps-block-unavailable = Blocking is not available on this system.
apps-block-other = Blocking a single app arrives with the firewall, in a later version.
apps-privacy = Everything shown stays on this computer. Only counts and times are kept, never what was sent.
