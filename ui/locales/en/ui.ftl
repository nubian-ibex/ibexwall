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
