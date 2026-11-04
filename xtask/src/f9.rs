// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F9 VM phase: VPN and endpoint plugins on real machines. Scenario scripts
//! are plain strings (no `format!`), so shell and JSON braces stay as
//! written; they share the helpers in `LIB`.

use std::path::Path;

use anyhow::Result;

use super::f1::{install_plugin, provision, run_script, start_daemon};
use super::vm::{Vm, run_capture};

const PLUGINS: [&str; 1] = ["endpoint.isolate"];

const LIB: &str = r#"
set -e
JSON_ID="python3 -c 'import json,sys;d=json.JSONDecoder().raw_decode(sys.stdin.read())[0];t=d.get(\"plan\") or d.get(\"transaction\");print(t[\"id\"] if isinstance(t,dict) else t)'"
# Plan and apply, leaving the transaction in TX and its output in OUT.
# Network changes wait for a confirmation: the caller decides.
apply_plan() {
  PLUGIN=$1; shift
  P=$(sudo ibexctl plan "$PLUGIN" "$@" --json 2>/tmp/plan.err | eval "$JSON_ID") || { echo "PLAN FAILED: $(cat /tmp/plan.err)"; return 1; }
  OUT=$(sudo ibexctl apply "$P" --confirm-timeout ${CONFIRM:-300} --json 2>&1 || true)
  TX=$(echo "$OUT" | eval "$JSON_ID")
  [ -n "$TX" ] || { echo "APPLY FAILED: $OUT"; sudo journalctl -u ibexwalld -n 20 --no-pager; return 1; }
}
confirm_tx() { sudo ibexctl confirm "$TX" >/dev/null || { echo "CONFIRM FAILED"; return 1; }; }
# Can this machine open a TCP connection to $1:$2 within 4 seconds?
reach() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }
# Every table but ours, as a digest: proof that nothing else was touched.
foreign_digest() { sudo nft list ruleset 2>/dev/null | python3 -c '
import re,sys
text = sys.stdin.read()
blocks = re.split(r"(?m)^(?=table )", text)
print("".join(b for b in blocks if b and not b.startswith("table inet ibexwall")))' | sha256sum; }
pkg() {
  if command -v dnf >/dev/null; then sudo dnf install -y -q "$@"
  elif command -v apt-get >/dev/null; then sudo apt-get update -qq; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif command -v pacman >/dev/null; then sudo pacman -Sy --noconfirm --needed "$@"
  fi
}
"#;

const ISOLATE: &str = r#"
sudo ibexctl plugins enable endpoint.isolate >/dev/null
PEER=${SSH_CLIENT%% *}
[ -n "$PEER" ] || { echo "NO SSH PEER"; exit 1; }
FOREIGN=$(foreign_digest)
if reach 1.1.1.1 443; then OUTSIDE=yes; else OUTSIDE=no; fi
echo "METRIC: peer $PEER, the internet is reachable before: $OUTSIDE"

# An empty allow list would cut the machine off for good: refused.
if sudo ibexctl plan endpoint.isolate --json >/dev/null 2>&1; then echo "AN EMPTY ALLOW LIST WAS PLANNED"; exit 1; fi

# A real local service, to prove loopback survives.
python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 1

apply_plan endpoint.isolate --set allow=$PEER
echo "$OUT" | grep -q pending_confirm || { echo "NO CONFIRMATION WINDOW: $OUT"; exit 1; }

# Isolated: our own session lives, loopback works, the rest is gone.
sudo nft list chain inet ibexwall endpoint_isolate_out >/dev/null
sudo nft list chain inet ibexwall endpoint_isolate_in >/dev/null
reach 127.0.0.1 18080 || { echo "LOOPBACK BROKE"; exit 1; }
if reach 1.1.1.1 443; then echo "THE INTERNET IS STILL REACHABLE"; exit 1; fi
if reach 9.9.9.9 53; then echo "ANOTHER ADDRESS IS STILL REACHABLE"; exit 1; fi
if timeout 5 getent hosts example.com >/dev/null 2>&1; then echo "DNS STILL ANSWERS"; exit 1; fi
confirm_tx
sudo ibexctl check endpoint.isolate --json | python3 -c '
import json,sys
ids = [f["id"] for f in json.load(sys.stdin)["findings"]]
assert "isolate.active" in ids, ids'
echo "METRIC: isolated: session, loopback kept; internet, other hosts and DNS cut"

# Undo: everything back, nothing else touched.
sudo ibexctl rollback "$TX" >/dev/null || { echo "ROLLBACK FAILED"; sudo journalctl -u ibexwalld -n 10 --no-pager; exit 1; }
if sudo nft list chain inet ibexwall endpoint_isolate_out >/dev/null 2>&1; then echo "THE OUTPUT CHAIN SURVIVED"; exit 1; fi
if sudo nft list chain inet ibexwall endpoint_isolate_in >/dev/null 2>&1; then echo "THE INPUT CHAIN SURVIVED"; exit 1; fi
sudo test ! -e /etc/ibexwall/isolate/active.json || { echo "THE MARKER SURVIVED"; exit 1; }
[ "$(foreign_digest)" = "$FOREIGN" ] || { echo "ANOTHER TABLE CHANGED"; exit 1; }
if [ "$OUTSIDE" = yes ]; then reach 1.1.1.1 443 || { echo "THE INTERNET DID NOT COME BACK"; exit 1; }; fi
echo "METRIC: rolled back: chains and marker gone, foreign tables identical, network back"

# Not confirmed: it undoes itself.
CONFIRM=8 apply_plan endpoint.isolate --set allow=$PEER
sleep 20
if sudo nft list chain inet ibexwall endpoint_isolate_out >/dev/null 2>&1; then echo "AN UNCONFIRMED ISOLATION STAYED"; exit 1; fi
sudo test ! -e /etc/ibexwall/isolate/active.json || { echo "THE MARKER STAYED"; exit 1; }
echo "METRIC: an unconfirmed isolation reverted on its own"
"#;

pub fn run(vm: &Vm, workspace: &Path, install: &str) -> Result<()> {
    println!("== f9: build ==");
    let mut args = vec!["build".to_string(), "--release".to_string()];
    for id in PLUGINS {
        args.push("-p".into());
        args.push(format!(
            "ibexwall-plugin-{}",
            id.rsplit('.').next().unwrap()
        ));
    }
    for package in ["ibexwall-exec", "ibexwall-cli", "ibexwall-core"] {
        args.push("-p".into());
        args.push(package.into());
    }
    args.push("--bins".into());
    run_capture("cargo", args, None, "building the F9 plugins")?;
    crate::devkey::run()?;
    provision(vm, workspace, install)?;
    for id in PLUGINS {
        install_plugin(vm, workspace, id)?;
    }
    start_daemon(vm)?;

    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $body:expr) => {
            if !run_script(vm, $name, &[LIB, $body].concat()) {
                failures += 1;
            }
        };
    }

    scenario!(
        "e1 endpoint.isolate: the network is cut except the allow list, then comes back, or reverts unconfirmed",
        ISOLATE
    );

    if failures == 0 {
        println!("PASS: f9 acceptance suite (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f9 scenario(s) failed")
    }
}
