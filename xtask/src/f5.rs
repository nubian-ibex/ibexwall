// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! F5 VM phase: the inbound firewall on real firewalld and ufw machines.

use std::path::Path;

use anyhow::Result;

use super::f1::run_script;
use super::vm::Vm;

pub fn run(vm: &Vm, _workspace: &Path, _install: &str) -> Result<()> {
    let mut failures = 0;
    macro_rules! scenario {
        ($name:expr, $script:expr) => {
            if !run_script(vm, $name, $script) {
                failures += 1;
            }
        };
    }

    scenario!(
        "s5a what firewalld and ufw write for an allowed port",
        r#"
set -e
install() {
  if command -v dnf >/dev/null; then sudo dnf install -y -q "$@"
  elif command -v apt-get >/dev/null; then sudo apt-get update -qq; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif command -v pacman >/dev/null; then sudo pacman -Sy --noconfirm --needed "$@"
  fi
}
flat() { tr '\n' '|' | cut -c1-600; }
install firewalld ufw
sudo systemctl disable --now ufw 2>/dev/null || true

# firewalld
sudo systemctl enable --now firewalld
sleep 2
echo "METRIC: firewalld $(firewall-cmd --version) default=$(sudo firewall-cmd --get-default-zone) conf=$(grep -h '^DefaultZone' /etc/firewalld/firewalld.conf)"
sudo firewall-cmd --permanent --add-port=8080/tcp >/dev/null
sudo firewall-cmd --add-port=8080/tcp >/dev/null
Z=$(sudo firewall-cmd --get-default-zone)
echo "METRIC: zone file /etc/firewalld/zones/$Z.xml: $(sudo cat /etc/firewalld/zones/$Z.xml | flat)"
echo "METRIC: list-all: $(sudo firewall-cmd --list-all | flat)"
sudo firewall-cmd --permanent --add-port=1000-2000/udp >/dev/null
sudo firewall-cmd --permanent --add-service=http >/dev/null
echo "METRIC: zone file after range+service: $(sudo cat /etc/firewalld/zones/$Z.xml | flat)"
sudo systemctl disable --now firewalld
sudo rm -f /etc/firewalld/zones/$Z.xml

# ufw
sudo ufw --force enable >/dev/null
sudo ufw allow 8080/tcp >/dev/null
sudo ufw allow 53 >/dev/null
echo "METRIC: ufw $(ufw version | head -1) conf=$(grep -h '^ENABLED' /etc/ufw/ufw.conf)"
echo "METRIC: ufw user.rules tuples: $(sudo grep -h 'tuple' /etc/ufw/user.rules | flat)"
echo "METRIC: ufw user6.rules tuples: $(sudo grep -h 'tuple' /etc/ufw/user6.rules | flat)"
echo "METRIC: ufw status: $(sudo ufw status | flat)"
sudo ufw delete allow 8080/tcp >/dev/null
echo "METRIC: ufw after delete: $(sudo grep -h 'tuple' /etc/ufw/user.rules | flat)"
sudo ufw --force disable >/dev/null
echo "METRIC: ufw conf after disable: $(grep -h '^ENABLED' /etc/ufw/ufw.conf)"
"#
    );

    if failures == 0 {
        println!("PASS: f5 (all scenarios)");
        Ok(())
    } else {
        anyhow::bail!("{failures} f5 scenario(s) failed")
    }
}
