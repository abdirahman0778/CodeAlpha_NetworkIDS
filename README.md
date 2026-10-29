# Task 4 — Network Intrusion Detection System (Suricata)

## Goal
Monitor an **authorized private test environment**, load two simple custom detection rules, generate harmless local test traffic, review alerts, and describe a careful response workflow.

## Ubuntu/Debian/Kali lab setup
```bash
sudo apt update
sudo apt install -y suricata jq
suricata --build-info | head
ip -br addr
```

Identify your **test interface** and HOME_NET. Suricata's normal configuration is often `/etc/suricata/suricata.yaml`; confirm the path on your machine:
```bash
sudo grep -n 'HOME_NET\|default-rule-path\|rule-files\|eve-log' /etc/suricata/suricata.yaml
```

Copy `rules/codealpha.rules` to `/etc/suricata/rules/codealpha.rules`, then add `- codealpha.rules` under `rule-files:` in `/etc/suricata/suricata.yaml` (preserve existing rule files). Set `HOME_NET` to the **IP/subnet of your lab environment**; for loopback-only testing a `127.0.0.0/8` value may be useful, but Suricata/OS interface support varies. Configure EVE JSON output to include `alert` events if not already enabled.

```bash
sudo install -m 644 rules/codealpha.rules /etc/suricata/rules/codealpha.rules
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

If the rule test fails, verify the `default-rule-path` points to `/etc/suricata/rules`, the `rule-files` entry and `HOME_NET` variable. **Do not** replace your entire existing configuration with the sample rules.

## Run local tests
Use the actual interface (e.g. `lo` or `eth0`):
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i lo --init-errors-fatal
```
In a second terminal, generate **only local** traffic:
```bash
ping -c 3 127.0.0.1
python3 -m http.server 8080 --bind 127.0.0.1
```
And a third terminal: `curl -I http://127.0.0.1:8080`. For a physical interface, generate traffic between devices you own on a private subnet and ensure HOME_NET includes both addresses. Loopback capture behavior depends on OS and Suricata version; use a second lab VM if local alerts do not appear.

## Review actual alerts
```bash
sudo grep '"event_type":"alert"' /var/log/suricata/eve.json | tail -n 10
sudo python3 scripts/read_alerts.py /var/log/suricata/eve.json
```
Some installations write to a different EVE file or need elevated read permissions. Do not invent alerts: screenshot actual results and note any missing detections.

## Response mechanism
This **IDS is detection-first**, not an IPS: receiving an alert alone does not block traffic. In this project, the response is: log alert -> validate source & rule -> notify operator -> review relevant logs -> document decision -> optionally block **only after human authorization** using existing firewall change procedures. Never auto-block network devices or production traffic based only on this demo alert.

## Evidence checklist
- Suricata installation/version and tested interface
- `suricata -T` configuration pass/fail output
- Dated rule file and YAML `rule-files`/HOME_NET screenshot
- Benign test command and corresponding actual alert(s)
- Screenshot of `read_alerts.py` output and concise incident-response note
- Known limitations: no deep packet inspection validation, no production coverage, no automated blocking
