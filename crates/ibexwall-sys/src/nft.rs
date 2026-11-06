// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! nftables access, limited to what IbexWall may do: own chains in
//! `table inet ibexwall`. A plugin proposes a typed [`Fragment`] (simple
//! rules, no free text), the core validates it and this module compiles it
//! to libnftables JSON and applies it atomically. Prior chain contents are
//! captured so a transaction can be undone exactly.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use ibexwall_proto::names::NFT_TABLE;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A set of owned chains, as a plugin proposes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fragment {
    pub chains: Vec<Chain>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub name: String,
    /// Base chain priority relative to other tables (lower runs first).
    #[serde(default)]
    pub priority: i32,
    /// Which hook the base chain attaches to (output by default).
    #[serde(default)]
    pub hook: Hook,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hook {
    #[default]
    Output,
    Input,
}

impl Hook {
    fn name(self) -> &'static str {
        match self {
            Hook::Output => "output",
            Hook::Input => "input",
        }
    }
}

/// One rule. Every condition that is present must match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Only packets leaving through the loopback interface.
    #[serde(default)]
    pub oif_loopback: bool,
    /// Only packets arriving through the loopback interface.
    #[serde(default)]
    pub iif_loopback: bool,
    /// Only packets arriving on an interface whose name starts with this
    /// (container and VM bridges, VPNs: not "external" traffic).
    #[serde(default)]
    pub iif_prefix: Option<String>,
    /// Only packets leaving through an interface whose name starts with
    /// this (a VPN's `wg`, `tun`).
    #[serde(default)]
    pub oif_prefix: Option<String>,
    /// Only packets from these addresses or networks (`10.0.0.0/8`,
    /// `2001:db8::/32`, a bare address).
    #[serde(default)]
    pub saddr: Vec<String>,
    /// Only packets to these addresses or networks.
    #[serde(default)]
    pub daddr: Vec<String>,
    /// Only packets of connections already established or related.
    #[serde(default)]
    pub ct_established: bool,
    /// Only the first packet of a new connection.
    #[serde(default)]
    pub ct_new: bool,
    /// Only packets whose mark, under `mask`, equals `value`.
    #[serde(default)]
    pub mark: Option<MarkMatch>,
    /// Only ICMP and ICMPv6.
    #[serde(default)]
    pub icmp: bool,
    /// Only packets whose sending user is not this uid.
    #[serde(default)]
    pub uid_not: Option<u32>,
    /// With `dports`: the transport protocols to match.
    #[serde(default)]
    pub protocols: Vec<Proto>,
    #[serde(default)]
    pub dports: Vec<u16>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
}

/// `mark & mask == value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarkMatch {
    pub mask: u32,
    pub value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Accept,
    Drop,
    /// Hands the packet to a userspace queue, with `bypass`: nothing
    /// listening means the packet is accepted (fail open, spec 4.7).
    Queue {
        num: u16,
    },
    /// Refuses at once (ICMP port unreachable or TCP reset): applications
    /// fall back faster than they would after a silent drop.
    Reject,
}

const MAX_CHAINS: usize = 8;
const MAX_RULES: usize = 64;
const MAX_PORTS: usize = 16;
const MAX_ADDRESSES: usize = 32;

/// `1.2.3.4`, `10.0.0.0/8`, `fe80::/10`: the address, its prefix length
/// and whether it is IPv6.
fn parse_network(text: &str) -> Result<(std::net::IpAddr, u8)> {
    let (addr, len) = match text.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (text, None),
    };
    let addr: std::net::IpAddr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!("not an address"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let len = match len {
        Some(l) => l
            .parse::<u8>()
            .ok()
            .filter(|l| *l <= max)
            .ok_or_else(|| anyhow::anyhow!("bad prefix length"))?,
        None => max,
    };
    Ok((addr, len))
}

fn address_set(entries: &[String], v6: bool) -> Vec<Value> {
    entries
        .iter()
        .filter_map(|text| parse_network(text).ok())
        .filter(|(addr, _)| addr.is_ipv6() == v6)
        .map(|(addr, len)| {
            if len == if v6 { 128 } else { 32 } {
                json!(addr.to_string())
            } else {
                json!({ "prefix": { "addr": addr.to_string(), "len": len } })
            }
        })
        .collect()
}

impl Fragment {
    /// Structural limits; the plugin manifest's name prefix is checked by
    /// the core separately.
    pub fn validate(&self) -> Result<()> {
        if self.chains.is_empty() || self.chains.len() > MAX_CHAINS {
            bail!("a fragment needs 1 to {MAX_CHAINS} chains");
        }
        for chain in &self.chains {
            let name = chain.name.as_str();
            let ok = (1..=60).contains(&name.len())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            if !ok {
                bail!("chain name `{name}` must be 1 to 60 characters of a-z, 0-9 or `_`");
            }
            if chain.rules.len() > MAX_RULES {
                bail!("chain `{name}` has more than {MAX_RULES} rules");
            }
            for rule in &chain.rules {
                for prefix in rule.iif_prefix.iter().chain(rule.oif_prefix.iter()) {
                    let ok = (1..=14).contains(&prefix.len())
                        && prefix
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
                    if !ok {
                        bail!("chain `{name}`: `{prefix}` is not an interface name prefix");
                    }
                }
                if rule.saddr.len() > MAX_ADDRESSES || rule.daddr.len() > MAX_ADDRESSES {
                    bail!("chain `{name}`: at most {MAX_ADDRESSES} addresses per rule");
                }
                for text in rule.saddr.iter().chain(rule.daddr.iter()) {
                    parse_network(text)
                        .map_err(|e| anyhow::anyhow!("chain `{name}`: `{text}`: {e}"))?;
                }
                // A rule only yields an expression for a family where
                // every non-empty address list has a matching address. A
                // source in one family with a destination in the other
                // would compile to nothing and a blocking rule would
                // fail open, so refuse it here.
                let has_v4 = |addrs: &[String]| {
                    addrs
                        .iter()
                        .any(|a| parse_network(a).is_ok_and(|(ip, _)| ip.is_ipv4()))
                };
                let has_v6 = |addrs: &[String]| {
                    addrs
                        .iter()
                        .any(|a| parse_network(a).is_ok_and(|(ip, _)| ip.is_ipv6()))
                };
                let v4_ok = (rule.saddr.is_empty() || has_v4(&rule.saddr))
                    && (rule.daddr.is_empty() || has_v4(&rule.daddr));
                let v6_ok = (rule.saddr.is_empty() || has_v6(&rule.saddr))
                    && (rule.daddr.is_empty() || has_v6(&rule.daddr));
                if !v4_ok && !v6_ok {
                    bail!("chain `{name}`: saddr and daddr share no address family");
                }
                if rule.protocols.is_empty() != rule.dports.is_empty() {
                    bail!("chain `{name}`: protocols and dports go together");
                }
                if rule.dports.len() > MAX_PORTS || rule.dports.contains(&0) {
                    bail!("chain `{name}`: dports must be 1 to {MAX_PORTS} ports, none zero");
                }
            }
        }
        Ok(())
    }

    pub fn chain_names(&self) -> Vec<String> {
        self.chains.iter().map(|chain| chain.name.clone()).collect()
    }

    /// The libnftables JSON commands that make these chains exist with
    /// exactly these rules: add, flush, then the rules, in one batch.
    pub fn compile(&self) -> Vec<Value> {
        let mut commands =
            vec![json!({ "add": { "table": { "family": "inet", "name": NFT_TABLE } } })];
        for chain in &self.chains {
            let handle = json!({ "family": "inet", "table": NFT_TABLE, "name": chain.name });
            commands.push(json!({ "add": { "chain": {
                "family": "inet", "table": NFT_TABLE, "name": chain.name,
                "type": "filter", "hook": chain.hook.name(), "prio": chain.priority, "policy": "accept",
            } } }));
            commands.push(json!({ "flush": { "chain": handle } }));
            for rule in &chain.rules {
                for expr in rule.expressions() {
                    commands.push(json!({ "add": { "rule": {
                        "family": "inet", "table": NFT_TABLE, "chain": chain.name, "expr": expr,
                    } } }));
                }
            }
        }
        commands
    }
}

impl Rule {
    /// One expression list per protocol (a rule on tcp and udp is two
    /// nftables rules).
    fn expressions(&self) -> Vec<Vec<Value>> {
        let mut base = vec![];
        if self.ct_established {
            base.push(json!({ "match": { "op": "in",
                "left": { "ct": { "key": "state" } },
                "right": ["established", "related"] } }));
        }
        if self.ct_new {
            base.push(json!({ "match": { "op": "in",
                "left": { "ct": { "key": "state" } },
                "right": "new" } }));
        }
        if let Some(mark) = self.mark {
            base.push(json!({ "match": { "op": "==",
                "left": { "&": [{ "meta": { "key": "mark" } }, mark.mask] },
                "right": mark.value } }));
        }
        if self.iif_loopback {
            base.push(json!({ "match": { "op": "==",
                "left": { "meta": { "key": "iifname" } }, "right": "lo" } }));
        }
        if let Some(prefix) = &self.iif_prefix {
            // A trailing `*` is nftables' own prefix match.
            base.push(json!({ "match": { "op": "==",
                "left": { "meta": { "key": "iifname" } }, "right": format!("{prefix}*") } }));
        }
        if self.icmp {
            base.push(json!({ "match": { "op": "in",
                "left": { "meta": { "key": "l4proto" } },
                "right": { "set": ["icmp", "ipv6-icmp"] } } }));
        }
        if let Some(prefix) = &self.oif_prefix {
            base.push(json!({ "match": { "op": "==",
                "left": { "meta": { "key": "oifname" } }, "right": format!("{prefix}*") } }));
        }
        if self.oif_loopback {
            base.push(json!({ "match": { "op": "==",
                "left": { "meta": { "key": "oifname" } }, "right": "lo" } }));
        }
        if let Some(uid) = self.uid_not {
            base.push(json!({ "match": { "op": "!=",
                "left": { "meta": { "key": "skuid" } }, "right": uid } }));
        }
        let verdict = match self.verdict {
            Verdict::Accept => json!({ "accept": null }),
            Verdict::Drop => json!({ "drop": null }),
            Verdict::Reject => json!({ "reject": null }),
            Verdict::Queue { num } => json!({ "queue": { "num": num, "flags": "bypass" } }),
        };
        // Addresses of one family go in one rule; a list that mixes IPv4
        // and IPv6 becomes two rules.
        let mut variants: Vec<Vec<Value>> = Vec::new();
        if self.saddr.is_empty() && self.daddr.is_empty() {
            variants.push(base);
        } else {
            for v6 in [false, true] {
                let (s, d) = (address_set(&self.saddr, v6), address_set(&self.daddr, v6));
                if (!self.saddr.is_empty() && s.is_empty())
                    || (!self.daddr.is_empty() && d.is_empty())
                {
                    continue;
                }
                let mut expr = base.clone();
                for (field, set) in [("saddr", s), ("daddr", d)] {
                    if !set.is_empty() {
                        expr.push(json!({ "match": { "op": "==",
                            "left": { "payload": { "protocol": if v6 { "ip6" } else { "ip" }, "field": field } },
                            "right": { "set": set } } }));
                    }
                }
                variants.push(expr);
            }
        }
        let mut out = Vec::new();
        for variant in variants {
            if self.protocols.is_empty() {
                let mut expr = variant;
                expr.push(verdict.clone());
                out.push(expr);
                continue;
            }
            for proto in &self.protocols {
                let name = match proto {
                    Proto::Tcp => "tcp",
                    Proto::Udp => "udp",
                };
                let mut expr = variant.clone();
                expr.push(json!({ "match": { "op": "==",
                    "left": { "payload": { "protocol": name, "field": "dport" } },
                    "right": { "set": self.dports } } }));
                expr.push(verdict.clone());
                out.push(expr);
            }
        }
        out
    }
}

/// The nftables operations the engine needs.
pub trait Nft: Send + Sync {
    /// Applies the fragment atomically (checked first).
    fn apply(&self, fragment: &Fragment) -> Result<()>;
    /// The current definition of a chain in our table, `None` if absent.
    fn capture(&self, chain: &str) -> Result<Option<Value>>;
    /// Puts a chain back as captured: removes it when `prior` is `None`.
    fn restore(&self, chain: &str, prior: Option<&Value>) -> Result<()>;
    /// The names of every chain in our table (empty when there is none).
    fn chains(&self) -> Result<Vec<String>>;
}

/// Runs `nft -j` with a command batch on stdin. `check` only validates.
fn run_batch(commands: &[Value], check: bool) -> Result<()> {
    let payload = serde_json::to_vec(&json!({ "nftables": commands }))?;
    let mut command = Command::new("nft");
    command.arg("-j");
    if check {
        command.arg("-c");
    }
    command
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("spawning nft")?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(&payload)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "nft {} failed: {}",
            if check { "check" } else { "apply" },
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Removes every `handle` key: handles belong to the live ruleset and are
/// rejected on input.
pub fn strip_handles(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("handle");
            map.values_mut().for_each(strip_handles);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_handles),
        _ => {}
    }
}

/// The chain and rule items of a `nft -j list chain` reply, wrapped as
/// `add` commands, ready to replay.
fn replay_commands(prior: &Value) -> Vec<Value> {
    let mut items: Vec<Value> = prior
        .get("nftables")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| item.get("chain").is_some() || item.get("rule").is_some())
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    items.iter_mut().for_each(strip_handles);
    items
        .into_iter()
        .map(|item| json!({ "add": item }))
        .collect()
}

fn removal_commands(chain: &str) -> Vec<Value> {
    // `add` of an existing chain is a no-op, so the removal also works
    // when a crash left the chain absent.
    let handle = json!({ "family": "inet", "table": NFT_TABLE, "name": chain });
    vec![
        json!({ "add": { "table": { "family": "inet", "name": NFT_TABLE } } }),
        json!({ "add": { "chain": handle } }),
        json!({ "flush": { "chain": handle } }),
        json!({ "delete": { "chain": handle } }),
    ]
}

/// Real nftables through the `nft` binary (argv only, JSON on stdin).
pub struct RealNft;

/// A failed nft call only means "the object is absent" when nft itself
/// says so. Any other failure (permissions, a broken install, netlink
/// busy) must surface as an error: reading it as "IbexWall has no
/// chains" once deleted the whole persisted firewall.
fn absent_ok(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr).contains("No such file")
}

impl Nft for RealNft {
    fn apply(&self, fragment: &Fragment) -> Result<()> {
        fragment.validate()?;
        let commands = fragment.compile();
        run_batch(&commands, true)?;
        run_batch(&commands, false)
    }

    fn capture(&self, chain: &str) -> Result<Option<Value>> {
        let output = Command::new("nft")
            .args(["-j", "list", "chain", "inet", NFT_TABLE, chain])
            .output()
            .context("spawning nft")?;
        if !output.status.success() {
            if absent_ok(&output.stderr) {
                // The chain (or the whole table) does not exist yet.
                return Ok(None);
            }
            anyhow::bail!(
                "listing chain {chain} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let mut value: Value =
            serde_json::from_slice(&output.stdout).context("parsing nft output")?;
        strip_handles(&mut value);
        Ok(Some(value))
    }

    fn chains(&self) -> Result<Vec<String>> {
        let output = match Command::new("nft")
            .args(["-j", "list", "table", "inet", NFT_TABLE])
            .output()
        {
            Ok(output) => output,
            // No nft installed: there are no chains of ours to list.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => return Err(error).context("spawning nft"),
        };
        if !output.status.success() {
            if absent_ok(&output.stderr) {
                return Ok(vec![]);
            }
            anyhow::bail!(
                "listing the table failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let listing: Value =
            serde_json::from_slice(&output.stdout).context("parsing nft output")?;
        Ok(listing["nftables"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["chain"]["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn restore(&self, chain: &str, prior: Option<&Value>) -> Result<()> {
        let mut commands = removal_commands(chain);
        if let Some(prior) = prior {
            commands.extend(replay_commands(prior));
        }
        run_batch(&commands, true)?;
        run_batch(&commands, false)?;
        // Leave no trace when nothing of ours remains: the table goes too.
        if table_is_empty() {
            let delete =
                [json!({ "delete": { "table": { "family": "inet", "name": NFT_TABLE } } })];
            run_batch(&delete, false)?;
        }
        Ok(())
    }
}

/// True when `table inet ibexwall` exists and holds no chain, set or map.
fn table_is_empty() -> bool {
    let Ok(output) = Command::new("nft")
        .args(["-j", "list", "table", "inet", NFT_TABLE])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let Ok(listing) = serde_json::from_slice::<Value>(&output.stdout) else {
        return false;
    };
    listing["nftables"].as_array().is_some_and(|items| {
        !items.iter().any(|item| {
            [
                "chain",
                "set",
                "map",
                "rule",
                "flowtable",
                "counter",
                "quota",
            ]
            .iter()
            .any(|kind| item.get(kind).is_some())
        })
    })
}

/// Fake keeping chain definitions in memory, for engine tests.
#[derive(Default)]
pub struct FakeNft {
    chains: Mutex<BTreeMap<String, Value>>,
    pub log: crate::log::OpLog,
    /// When set, `chains` and `capture` fail with this message: tests
    /// simulate an nft error (permissions, netlink busy) that must not
    /// read as "there are no chains".
    pub fail_calls: Mutex<Option<String>>,
}

impl FakeNft {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has(&self, chain: &str) -> bool {
        self.chains
            .lock()
            .expect("lock poisoned")
            .contains_key(chain)
    }
}

impl Nft for FakeNft {
    fn apply(&self, fragment: &Fragment) -> Result<()> {
        fragment.validate()?;
        self.log
            .push(format!("apply {}", fragment.chain_names().join(",")));
        let mut chains = self.chains.lock().expect("lock poisoned");
        for chain in &fragment.chains {
            chains.insert(chain.name.clone(), json!({ "rules": chain.rules.len() }));
        }
        Ok(())
    }

    fn capture(&self, chain: &str) -> Result<Option<Value>> {
        if let Some(reason) = self.fail_calls.lock().expect("lock poisoned").clone() {
            anyhow::bail!(reason);
        }
        Ok(self
            .chains
            .lock()
            .expect("lock poisoned")
            .get(chain)
            .cloned())
    }

    fn chains(&self) -> Result<Vec<String>> {
        if let Some(reason) = self.fail_calls.lock().expect("lock poisoned").clone() {
            anyhow::bail!(reason);
        }
        Ok(self
            .chains
            .lock()
            .expect("lock poisoned")
            .keys()
            .cloned()
            .collect())
    }

    fn restore(&self, chain: &str, prior: Option<&Value>) -> Result<()> {
        self.log
            .push(format!("restore {chain} prior={}", prior.is_some()));
        let mut chains = self.chains.lock().expect("lock poisoned");
        match prior {
            Some(prior) => chains.insert(chain.to_string(), prior.clone()),
            None => chains.remove(chain),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> Fragment {
        serde_json::from_value(json!({ "chains": [{
            "name": "net_dns_guard", "priority": -10,
            "rules": [
                { "oif_loopback": true, "verdict": "accept" },
                { "uid_not": 990, "protocols": ["udp", "tcp"], "dports": [53, 853], "verdict": "reject" },
            ],
        }] }))
        .unwrap()
    }

    #[test]
    fn a_rule_whose_address_families_do_not_overlap_is_refused() {
        // An IPv4 source with an IPv6 destination would have compiled to
        // no rule at all, turning a drop into an allow.
        let fragment: Fragment = serde_json::from_value(json!({ "chains": [{
            "name": "dev_x",
            "rules": [
                { "saddr": ["192.0.2.1"], "daddr": ["2001:db8::1"], "verdict": "drop" }
            ],
        }] }))
        .unwrap();
        assert!(
            fragment.validate().is_err(),
            "mismatched families must be refused"
        );
    }

    #[test]
    fn compiles_to_one_batch_with_add_flush_and_one_rule_per_protocol() {
        let commands = guard().compile();
        let kinds: Vec<String> = commands
            .iter()
            .map(|c| {
                let (verb, body) = c.as_object().unwrap().iter().next().unwrap();
                let object = body.as_object().unwrap().keys().next().unwrap();
                format!("{verb} {object}")
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "add table",
                "add chain",
                "flush chain",
                "add rule", // loopback accept
                "add rule",
                "add rule", // reject on udp and on tcp
            ]
        );
        let chain = &commands[1]["add"]["chain"];
        assert_eq!(
            (chain["hook"].as_str(), chain["prio"].as_i64()),
            (Some("output"), Some(-10))
        );
    }

    #[test]
    fn the_dns_rule_exempts_the_resolver_uid_and_matches_both_ports() {
        let commands = guard().compile();
        let rule = &commands[4]["add"]["rule"]["expr"];
        assert_eq!(rule[0]["match"]["left"]["meta"]["key"], "skuid");
        assert_eq!(rule[0]["match"]["op"], "!=");
        assert_eq!(rule[0]["match"]["right"], 990);
        assert_eq!(rule[1]["match"]["left"]["payload"]["protocol"], "udp");
        assert_eq!(rule[1]["match"]["right"]["set"], json!([53, 853]));
        assert_eq!(rule[2], json!({ "reject": null }));
        assert_eq!(
            commands[5]["add"]["rule"]["expr"][1]["match"]["left"]["payload"]["protocol"],
            "tcp"
        );
    }

    #[test]
    fn only_typed_fields_are_accepted() {
        for bad in [
            json!({ "chains": [{ "name": "a", "rules": [], "policy": "drop" }] }),
            json!({ "chains": [{ "name": "a", "rules": [{ "verdict": "accept", "raw": "x" }] }] }),
            json!({ "chains": [{ "name": "a", "rules": [{ "verdict": "jump" }] }] }),
        ] {
            assert!(
                serde_json::from_value::<Fragment>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn structural_limits_are_enforced() {
        let named = |name: &str, rules: Value| -> Fragment {
            serde_json::from_value(json!({ "chains": [{ "name": name, "rules": rules }] })).unwrap()
        };
        assert!(named("ok_1", json!([])).validate().is_ok());
        for name in ["", "Upper", "has space", "semi;colon", &"a".repeat(61)] {
            assert!(named(name, json!([])).validate().is_err(), "{name:?}");
        }
        let dangling = json!([{ "protocols": ["udp"], "verdict": "drop" }]);
        assert!(named("c", dangling).validate().is_err());
        let zero = json!([{ "protocols": ["udp"], "dports": [0], "verdict": "drop" }]);
        assert!(named("c", zero).validate().is_err());
        let many = json!(
            (0..65)
                .map(|_| json!({ "verdict": "accept" }))
                .collect::<Vec<_>>()
        );
        assert!(named("c", many).validate().is_err());
        assert!(Fragment { chains: vec![] }.validate().is_err());
    }

    #[test]
    fn handles_are_stripped_so_a_captured_chain_can_be_replayed() {
        let mut listed = json!({ "nftables": [
            { "metainfo": { "version": "1.1.6" } },
            { "chain": { "family": "inet", "table": "ibexwall", "name": "c", "handle": 3, "hook": "output" } },
            { "rule": { "family": "inet", "table": "ibexwall", "chain": "c", "handle": 4, "expr": [{ "accept": null }] } },
        ] });
        strip_handles(&mut listed);
        let replay = replay_commands(&listed);
        assert_eq!(replay.len(), 2);
        assert!(
            replay
                .iter()
                .all(|c| c.to_string().find("handle").is_none())
        );
        assert!(replay[0]["add"]["chain"].is_object() && replay[1]["add"]["rule"].is_object());
    }

    #[test]
    fn removal_works_even_if_the_chain_is_already_gone() {
        let verbs: Vec<String> = removal_commands("c")
            .iter()
            .map(|c| c.as_object().unwrap().keys().next().unwrap().clone())
            .collect();
        assert_eq!(verbs, ["add", "add", "flush", "delete"]);
    }

    #[test]
    fn the_fake_applies_captures_and_restores() {
        let nft = FakeNft::new();
        nft.apply(&guard()).unwrap();
        assert!(nft.has("net_dns_guard"));
        let prior = nft.capture("net_dns_guard").unwrap();
        assert!(prior.is_some());
        nft.restore("net_dns_guard", None).unwrap();
        assert!(!nft.has("net_dns_guard"));
        nft.restore("net_dns_guard", prior.as_ref()).unwrap();
        assert!(nft.has("net_dns_guard"));
    }

    fn inbound() -> Fragment {
        serde_json::from_value(json!({ "chains": [{
            "name": "net_firewall_input", "priority": 5, "hook": "input",
            "rules": [
                { "ct_established": true, "verdict": "accept" },
                { "iif_loopback": true, "verdict": "accept" },
                { "icmp": true, "verdict": "accept" },
                { "iif_prefix": "docker", "verdict": "accept" },
                { "protocols": ["udp"], "dports": [68, 546], "verdict": "accept" },
                { "verdict": "drop" },
            ],
        }] }))
        .unwrap()
    }

    #[test]
    fn interface_prefixes_and_addresses_compile_one_rule_per_family() {
        let fragment: Fragment = serde_json::from_value(json!({ "chains": [{
            "name": "net_vpn_out",
            "rules": [
                { "oif_prefix": "wg", "verdict": "accept" },
                { "daddr": ["10.0.0.0/8", "192.0.2.7", "fd00::/8"], "protocols": ["udp"], "dports": [51820], "verdict": "accept" },
                { "saddr": ["2001:db8::1"], "verdict": "drop" },
            ],
        }] })).unwrap();
        fragment.validate().unwrap();
        let commands = fragment.compile();
        // table, chain, flush, then: 1 + 2 (v4 and v6) + 1 rules.
        assert_eq!(commands.len(), 3 + 4);
        let expr = |n: usize| commands[3 + n]["add"]["rule"]["expr"].clone();
        assert_eq!(expr(0)[0]["match"]["right"], "wg*");
        assert_eq!(expr(1)[0]["match"]["left"]["payload"]["protocol"], "ip");
        assert_eq!(
            expr(1)[0]["match"]["right"]["set"],
            json!([{ "prefix": { "addr": "10.0.0.0", "len": 8 } }, "192.0.2.7"])
        );
        assert_eq!(expr(2)[0]["match"]["left"]["payload"]["protocol"], "ip6");
        assert_eq!(expr(3)[0]["match"]["left"]["payload"]["field"], "saddr");
    }

    #[test]
    fn bad_addresses_and_prefixes_are_refused_before_nft_sees_them() {
        for rule in [
            json!({ "daddr": ["not-an-address"], "verdict": "drop" }),
            json!({ "daddr": ["10.0.0.0/33"], "verdict": "drop" }),
            json!({ "daddr": ["::1/129"], "verdict": "drop" }),
            json!({ "saddr": ["1.2.3.4; flush ruleset"], "verdict": "drop" }),
            json!({ "oif_prefix": "w g", "verdict": "drop" }),
        ] {
            let fragment: Fragment =
                serde_json::from_value(json!({ "chains": [{ "name": "c", "rules": [rule] }] }))
                    .unwrap();
            assert!(fragment.validate().is_err());
        }
    }

    #[test]
    fn an_input_chain_compiles_with_its_hook_and_conditions() {
        let fragment = inbound();
        fragment.validate().unwrap();
        let commands = fragment.compile();
        let chain = &commands[1]["add"]["chain"];
        assert_eq!(
            (
                chain["hook"].as_str(),
                chain["prio"].as_i64(),
                chain["policy"].as_str()
            ),
            (Some("input"), Some(5), Some("accept"))
        );
        let rule = |n: usize| &commands[3 + n]["add"]["rule"]["expr"];
        assert_eq!(rule(0)[0]["match"]["left"]["ct"]["key"], "state");
        assert_eq!(
            rule(0)[0]["match"]["right"],
            json!(["established", "related"])
        );
        assert_eq!(rule(1)[0]["match"]["left"]["meta"]["key"], "iifname");
        assert_eq!(rule(1)[0]["match"]["right"], "lo");
        assert_eq!(
            rule(2)[0]["match"]["right"]["set"],
            json!(["icmp", "ipv6-icmp"])
        );
        assert_eq!(rule(3)[0]["match"]["right"], "docker*");
        assert_eq!(rule(4)[0]["match"]["left"]["payload"]["field"], "dport");
        assert_eq!(rule(5), &json!([{ "drop": null }]));
    }

    #[test]
    fn interface_prefixes_cannot_smuggle_anything() {
        for prefix in ["", "a b", "docker*", "x\"y", &"a".repeat(20)] {
            let fragment: Fragment = serde_json::from_value(json!({ "chains": [{
                "name": "net_firewall_input", "hook": "input",
                "rules": [{ "iif_prefix": prefix, "verdict": "accept" }],
            }] }))
            .unwrap();
            assert!(fragment.validate().is_err(), "{prefix:?}");
        }
    }

    #[test]
    fn existing_fragments_still_hook_output() {
        let commands = guard().compile();
        assert_eq!(commands[1]["add"]["chain"]["hook"], "output");
    }

    #[test]
    fn the_ask_chain_queues_new_marked_flows_with_bypass_and_rejects_refused_ones() {
        let fragment: Fragment = serde_json::from_value(json!({ "chains": [{
            "name": "net_apps_ask", "priority": 5,
            "rules": [
                { "ct_new": true, "mark": { "mask": 0xff0000, "value": 0x10000 },
                  "verdict": { "queue": { "num": 4242 } } },
                { "mark": { "mask": 0xff0000, "value": 0x20000 }, "verdict": "reject" },
            ],
        }] }))
        .unwrap();
        fragment.validate().unwrap();
        let commands = fragment.compile();
        let queue = &commands[3]["add"]["rule"]["expr"];
        assert_eq!(queue[0]["match"]["right"], "new");
        let mark = &queue[1]["match"];
        assert_eq!(mark["left"]["&"][1], 0xff0000);
        assert_eq!(mark["right"], 0x10000);
        assert_eq!(
            queue[2],
            json!({ "queue": { "num": 4242, "flags": "bypass" } })
        );
        assert_eq!(
            commands[4]["add"]["rule"]["expr"][1],
            json!({ "reject": null })
        );
    }
}
