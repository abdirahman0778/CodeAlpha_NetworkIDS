# Network Intrusion Detection System — Security Response Report

**Project:** CodeAlpha Cybersecurity Internship — Task 4  
**Assessment Date:** October 29, 2026  
**Operating System:** Kali Linux  
**IDS Software:** Suricata 8.0.7 RELEASE  
**Network Interface:** eth0  
**Monitoring Mode:** Network Intrusion Detection System (IDS)  
**Environment:** Controlled VMware Network Laboratory  
**Assessment Status:** Technical Testing Completed Successfully

---

## 1. Executive Summary

This report documents the implementation, configuration, testing, and validation of a Network Intrusion Detection System (NIDS) using Suricata 8.0.7.

The project demonstrates signature-based network traffic monitoring using two custom detection rules designed to identify:

1. ICMP Echo Requests within the monitored laboratory network.
2. TCP SYN connection attempts targeting port 8080.

Suricata was configured to monitor network traffic on the Kali Linux `eth0` interface.

Controlled traffic was generated, and the resulting security alerts were verified through Suricata's `fast.log` and `eve.json` files.

### Key Assessment Results

- Suricata 8.0.7 successfully installed and verified.
- Two custom detection rules configured and validated.
- Live network monitoring successfully started.
- Ten ICMP alerts recorded across two test runs.
- Two TCP alerts recorded from a single connection attempt.
- Twelve total alerts verified through EVE JSON logs.
- Five real ICMP alerts successfully processed using a Python analysis script.
- No production systems or unauthorized targets were tested.

**Overall Technical Result: PASS**

---

## 2. Assessment Objectives

The primary objectives of this project were to:

1. Install and configure Suricata as a Network Intrusion Detection System.
2. Develop custom signature-based detection rules.
3. Monitor network traffic using a designated network interface.
4. Generate controlled network traffic for testing.
5. Identify matching network events and generate security alerts.
6. Collect and analyze Suricata log files.
7. Demonstrate basic incident investigation and response procedures.
8. Document the results and limitations of the implementation.

---

## 3. Network Laboratory Environment

The assessment was conducted using Kali Linux inside a VMware virtualized network environment.

| Component | Configuration |
|---|---|
| Operating System | Kali Linux |
| IDS Engine | Suricata 8.0.7 RELEASE |
| Network Interface | eth0 |
| Kali Linux IP | 192.168.197.128 |
| Lab Subnet | 192.168.197.0/24 |
| Default Gateway | 192.168.197.2 |
| TCP Test Destination | 192.168.197.1 |
| Monitoring Mode | Passive IDS |
| Detection Rules | Custom Suricata Rules |
| Log Formats | fast.log and eve.json |
| Analysis Tools | Python 3, jq, grep |

### 3.1 HOME_NET Configuration

Suricata was configured with the following HOME_NET address groups:

`[192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12]`

The configured address ranges included the laboratory network `192.168.197.0/24`.

No permanent modification of the HOME_NET configuration was required.

---

## 4. Suricata Configuration and Validation

### 4.1 Installation Verification

The Suricata installation was verified using:

```bash
suricata -V
```

**Actual Result:**

```text
This is Suricata version 8.0.7 RELEASE
```

### 4.2 Custom Detection Rules

**Rules File:** `rules/codealpha.rules`

#### Rule 1 — ICMP Echo Request Detection

```suricata
alert icmp $HOME_NET any -> $HOME_NET any (msg:"CODEALPHA LAB ICMP echo request"; itype:8; sid:1000001; rev:1;)
```

**Purpose:** Detect ICMP Echo Requests matching the monitored HOME_NET address range.

**Signature ID:** 1000001  
**Revision:** 1  
**Protocol:** ICMP

#### Rule 2 — TCP Port 8080 Detection

```suricata
alert tcp $HOME_NET any -> $HOME_NET 8080 (msg:"CODEALPHA LAB TCP port 8080 connection"; flow:to_server; flags:S; sid:1000002; rev:2;)
```

**Purpose:** Detect TCP SYN connection attempts directed toward port 8080.

**Signature ID:** 1000002  
**Revision:** 2  
**Protocol:** TCP  
**Direction:** to_server

### 4.3 Rules Validation

The following command was executed:

```bash
sudo suricata -T \
  -c /etc/suricata/suricata.yaml \
  -S ~/CodeAlpha_NetworkIDS/rules/codealpha.rules
```

**Actual Result:**

```text
Configuration provided was successfully loaded. Exiting.
```

Both custom detection rules passed configuration validation.

**Validation Status: PASS**

---

## 5. Live Network Monitoring

Suricata was started in live capture mode on the Kali Linux network interface.

### 5.1 Execution Command

```bash
sudo suricata \
  -c /etc/suricata/suricata.yaml \
  -S ~/CodeAlpha_NetworkIDS/rules/codealpha.rules \
  -i eth0 \
  -l ~/CodeAlpha_NetworkIDS/logs
```

### 5.2 Execution Result

Suricata successfully initialized the detection engine.

```text
Threads created -> W: 4 FM: 1 FR: 1
Engine started.
```

This confirmed that the IDS engine started monitoring network traffic on `eth0`.

**Monitoring Status: PASS**

---

## 6. ICMP Detection Testing

### 6.1 Test Objective

Verify that Suricata detects ICMP Echo Requests generated within the authorized laboratory network.

### 6.2 Test Command

```bash
ping -c 5 192.168.197.2
```

### 6.3 Test Results

| Metric | Result |
|---|---|
| Source IP | 192.168.197.128 |
| Destination IP | 192.168.197.2 |
| Protocol | ICMP |
| Requests Sent Per Test | 5 |
| Replies Received Per Test | 5 |
| Packet Loss | 0% |
| Signature ID | 1000001 |
| Detection Status | PASS |

The ping test was performed twice during the assessment.

Each run generated five matching ICMP alerts.

### 6.4 Verified ICMP Alerts

**First Test Run:** 5 alerts  
**Second Test Run:** 5 alerts

**Total ICMP Alerts: 10**

The events were recorded in Suricata's `fast.log` and `eve.json` files.

**Detection Signature:**

`CODEALPHA LAB ICMP echo request`

### 6.5 Interpretation

The results confirmed that Suricata successfully detected ICMP Echo Requests matching the configured custom rule.

These packets represented legitimate laboratory connectivity tests.

ICMP traffic alone does not indicate malicious activity.

---

## 7. TCP Port 8080 Detection Testing

### 7.1 Test Objective

Verify that Suricata identifies TCP SYN connection attempts targeting port 8080.

### 7.2 Test Command

```bash
nc -vz -w 2 192.168.197.1 8080
```

### 7.3 Test Result

The TCP connection attempt timed out.

However, Suricata successfully detected the matching network traffic and generated two alerts.

| Metric | Result |
|---|---|
| Source IP | 192.168.197.128 |
| Source Port | 44520 |
| Destination IP | 192.168.197.1 |
| Destination Port | 8080 |
| Protocol | TCP |
| Signature ID | 1000002 |
| Rule Revision | 2 |
| Alerts Generated | 2 |
| Connection Result | Timed out |
| Detection Result | PASS |

### 7.4 Detection Evidence

**Signature:**

`CODEALPHA LAB TCP port 8080 connection`

Both alerts were associated with the same Suricata flow identifier.

This indicates that the two alerts corresponded to the same observed network flow rather than two independently confirmed connection attempts.

### 7.5 Interpretation

The test demonstrated that Suricata could detect TCP SYN packets directed toward port 8080.

The connection timeout did not prevent the IDS from generating alerts.

No successful TCP application connection was demonstrated.

---

## 8. EVE JSON Alert Analysis

Suricata generated structured JSON logs containing information about the detected network events.

### 8.1 Log File

`~/CodeAlpha_NetworkIDS/logs/eve.json`

### 8.2 Verification Command

```bash
sudo jq -r '
select(.event_type == "alert") |
.alert.signature
' ~/CodeAlpha_NetworkIDS/logs/eve.json | sort | uniq -c
```

### 8.3 Actual Final Results

```text
10 CODEALPHA LAB ICMP echo request
 2 CODEALPHA LAB TCP port 8080 connection
```

### 8.4 Final Alert Summary

| Detection Signature | Protocol | Alerts |
|---|---|---:|
| CODEALPHA LAB ICMP echo request | ICMP | 10 |
| CODEALPHA LAB TCP port 8080 connection | TCP | 2 |
| **Total** | | **12** |

All twelve recorded alerts were verified through the EVE JSON analysis.

**JSON Verification Status: PASS**

---

## 9. Python Security Alert Analysis

A Python script was used to read and summarize Suricata alert events.

**Script:** `scripts/read_alerts.py`

### 9.1 Test Input

Five real ICMP alert events were extracted from Suricata's EVE JSON logs.

**Input File:** `real_alerts.json`

### 9.2 Execution Command

```bash
python3 ~/CodeAlpha_NetworkIDS/scripts/read_alerts.py \
  ~/CodeAlpha_NetworkIDS/real_alerts.json
```

### 9.3 Actual Execution Results

```text
Total alerts: 5
5x CODEALPHA LAB ICMP echo request
```

The script successfully displayed event timestamps, source addresses, destination addresses, and alert signatures.

### 9.4 Analysis Conclusion

The Python analyzer successfully processed the five extracted real ICMP alerts.

The complete twelve-alert dataset was verified using `jq`, but a separate Python run against all twelve records was not performed.

**Python Analysis Status: PASS for the tested five-alert dataset**

---

## 10. Incident Detection and Response

Suricata operated as a passive Network Intrusion Detection System.

The EVE JSON events contained the following action:

`"action": "allowed"`

This indicates that Suricata detected and logged matching network traffic without blocking it.

### 10.1 Implemented Response Mechanisms

The following response activities were demonstrated:

1. Automatic generation of signature-based security alerts.
2. Logging of detected events in `fast.log`.
3. Structured event collection in `eve.json`.
4. Identification of source and destination addresses.
5. Verification of triggered detection signatures.
6. Alert counting and analysis using Python and jq.
7. Documentation of observed events for security investigation.

### 10.2 Recommended Incident Response Procedure

For suspicious or unexpected network events, the recommended process is:

1. **Detection:** Review Suricata security alerts.
2. **Triage:** Determine whether the activity is expected or suspicious.
3. **Investigation:** Analyze timestamps, IP addresses, ports, and signatures.
4. **Correlation:** Compare network alerts with system and application logs.
5. **Containment:** Apply authorized firewall or network restrictions when an actual threat is confirmed.
6. **Recovery:** Restore affected services if necessary.
7. **Documentation:** Record the findings, response actions, and lessons learned.

### 10.3 Response Limitations

No automatic packet blocking, firewall modification, endpoint isolation, or threat containment was implemented.

The laboratory implementation demonstrated detection, alert generation, analysis, and documented response recommendations.

---

## 11. Verification Evidence

The following screenshots were captured during the assessment.

| Evidence File | Description |
|---|---|
| `screenshots/rules-validation.png` | Successful Suricata rule validation |
| `screenshots/icmp-test.png` | ICMP connectivity test with 0% packet loss |
| `screenshots/icmp-alerts.png` | Suricata ICMP alerts in fast.log |
| `screenshots/tcp-alert.png` | TCP port 8080 detection alerts |
| `screenshots/tcp-json-alerts.png` | Structured TCP alert verification |
| `screenshots/real-alert-analysis.png` | Python processing of five real ICMP alerts |
| `screenshots/alert-summary.png` | Final summary of 10 ICMP and 2 TCP alerts |

All evidence was generated from the controlled laboratory testing environment.

---

## 12. Security Recommendations

The following improvements are recommended for a more advanced IDS implementation:

1. Configure detection rules to match the actual protected network environment.
2. Review and update Suricata signatures regularly.
3. Establish alert severity classifications.
4. Reduce false positives through rule tuning.
5. Forward security events to a centralized logging or SIEM platform.
6. Implement log retention and rotation.
7. Define incident response escalation procedures.
8. Monitor IDS performance and packet loss.
9. Restrict access to IDS configurations and security logs.
10. Introduce additional detection scenarios for authorized laboratory testing.

---

## 13. Assessment Limitations

This project was conducted in a controlled VMware laboratory environment.

The assessment was limited to ICMP Echo Requests and TCP SYN traffic directed toward port 8080.

The following activities were not evaluated:

- Advanced network exploitation
- Malware detection
- Large-scale network monitoring
- Distributed intrusion detection
- Automated threat containment
- Production deployment
- Network-based intrusion prevention
- Comprehensive signature effectiveness
- Full SIEM integration

The custom rules generated alerts for matching network events, but the observed traffic was intentionally generated for testing and was not classified as a real attack.

---

## 14. Final Assessment Summary

| Assessment Component | Result |
|---|---|
| Suricata Installation | PASS |
| Suricata Version Verification | PASS |
| Network Interface Identification | PASS |
| Custom Detection Rules Validation | PASS |
| HOME_NET Verification | PASS |
| Live Network Monitoring | PASS |
| ICMP Detection | PASS |
| TCP Port 8080 Detection | PASS |
| fast.log Verification | PASS |
| EVE JSON Verification | PASS |
| Python Alert Analysis | PASS |
| Security Response Documentation | COMPLETED |

### Final Detection Statistics

**ICMP Alerts:** 10  
**TCP Alerts:** 2  
**Total Alerts:** 12  
**Validated Custom Rules:** 2

---

## 15. Final Conclusion

The CodeAlpha Network Intrusion Detection System project successfully demonstrated the implementation and testing of Suricata 8.0.7 in a controlled Kali Linux laboratory.

Two custom detection rules were validated and successfully triggered by authorized ICMP and TCP test traffic.

A total of twelve alert events were recorded and verified through Suricata's logging system.

The assessment also demonstrated structured JSON event analysis, Python-based alert processing, and documented incident response procedures.

The project confirms successful implementation of fundamental network intrusion detection capabilities, including traffic monitoring, signature matching, alert generation, and security event analysis.

**Final Technical Assessment: PASS**

**Project:** CodeAlpha Cybersecurity Internship — Task 4  
**Assessment Date:** October 29, 2026  
**Status:** Technical Implementation and Testing Completed Successfully