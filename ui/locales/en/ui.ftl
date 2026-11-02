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
