# Operation RedTail — NH-TR-2026-04-14

## Summary

Advanced Linux ELF botnet variant detected via Nerd Herd proprietary honeypot infrastructure on **14 April 2026**.
The malware implements cryptojacking (Monero/XMR) via private proxy pools with APT-level evasion techniques.

| Vector | Target | Persistence | Detection |
|--------|--------|-------------|-----------|
| RCE / ELF dropper | Cryptojacking XMR | systemd service | Honeypot NH |

---

## Key Findings

- **PRNG Obfuscation**: LCG engine (constant `0x6c078965`) decrypts C2 config in-memory — static analysis alone is insufficient
- **Anti-Debug**: Double forking + cyclic `/proc` scanning for GDB/Wireshark/watch
- **Masquerading**: Process renamed to `nginx` post-execution, evading `top`/`ps` for untrained operators
- **Persistence**: Systemd unit `your-redtail.service` (high-confidence IoC — unusual in production systems)
- **PrivEsc**: PolicyKit/Sudo abuse for root access (kernel module installation / network parameter modification)
- **C2 Infrastructure**: 4 private Stratum proxy pools over TCP/2137 with custom TLS (`libredtail` module)

## C2 Configuration (extracted via memory forensics)

```json
"pools": [
  { "nicehash": true, "url": "proxies.internetshadow.org:2137" },
  { "nicehash": true, "url": "proxies.internetshadow.link:2137" },
  { "nicehash": true, "url": "proxies.identities.network:2137" },
  { "nicehash": true, "url": "proxies.insanitycpp.cx:2137" }
]
```

## MITRE ATT&CK Coverage

| Tactic | ID | Technique |
|--------|----|-----------|
| Execution | T1059.004 | Unix Shell |
| Defense Evasion | T1027 | Obfuscated Files (LCG PRNG) |
| Defense Evasion | T1055 | Process Masquerading (nginx) |
| Defense Evasion | T1622 | Debugger Evasion (double fork) |
| Discovery | T1057 | Process Discovery (/proc scan) |
| Persistence | T1543.002 | Systemd Service |
| Privilege Escalation | T1548.003 | Sudo / PolicyKit |
| Command & Control | T1071 | App Layer Protocol (Stratum TLS) |
| Impact | T1496 | Resource Hijacking (XMRig) |

## Files

- [`iocs.csv`](./iocs.csv) — Machine-readable IoC list (TLP:WHITE subset)
- [`iocs.yaml`](./iocs.yaml) — STIX-compatible YAML with full MITRE mapping, detection rules, mitigation steps

Full technical report: **TLP:AMBER** — request via info@nerdherd.it

## Quick Detection

```bash
# Block C2 traffic immediately
iptables -A OUTPUT -p tcp --dport 2137 -j DROP

# Check for persistence unit
systemctl status your-redtail.service

# Hunt for masqueraded nginx processes
ps aux | grep nginx | awk '{print $11}' | sort -u
# Legitimate nginx: /usr/sbin/nginx or /usr/bin/nginx only

# Hunt for libredtail
find / -name "libredtail*" 2>/dev/null

# Check active C2 connections
ss -tnp | grep ':2137'
```

---

*Nerd Herd Business Technology Solutions — www.nerdherd.it*
*Analyst: OP-01 | info@nerdherd.it*
