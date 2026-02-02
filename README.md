# snort-ids-elk-lab
Snort-based Intrusion Detection System integrated with ELK Stack for detecting port scans, brute-force attacks, and visualizing security alerts in a SOC-style lab environment.

**📌 Overview**

This repository contains an Intrusion Detection and Threat Monitoring Platform developed during my internship at Evolution Info Secure.
The project implements Snort 2.9 as an Intrusion Detection System (IDS) and integrates it with the ELK Stack (Elasticsearch, Logstash, Kibana) to enable centralized log analysis, real-time alerting, and security visualization.

The environment simulates real-world attack scenarios using virtual machines and demonstrates end-to-end detection, logging, and visualization of network threats.

🏢 Internship Context

Organization: Evolution Info Secure

Role: Cybersecurity Analyst Intern / Project Associate

Duration: May 2024 – July 2025

Objective: Design and validate an IDS + SIEM workflow for detecting reconnaissance and brute-force attacks in a controlled lab environment

This project was assigned as part of practical exposure to network security monitoring, IDS tuning, and log analysis workflows.

**🎯 Project Objectives**

Deploy Snort 2.9 in IDS mode on a Linux server

Detect common attack patterns:

Port scanning

Ping sweeps

UDP reconnaissance

SSH brute-force attempts

Forward Snort alerts to ELK Stack for centralized monitoring

Build Kibana dashboards for threat analysis and visualization

Validate detections through simulated attacks from a dedicated attacker VM

**🧱 Architecture**

The project uses a multi-VM lab architecture:

🖥️ Virtual Machines
VM	Purpose
Ubuntu Server 22.04	Snort IDS (monitors network traffic)
Ubuntu Desktop 22.04	ELK Stack (Elasticsearch, Logstash, Kibana)
Kali Linux	Attack simulation (Nmap, Hydra, scans)
**🔁 Data Flow**

Snort detects suspicious traffic on the server

Alerts are written as Fast Alert logs

Filebeat ships logs to Logstash

Logstash parses logs using Grok filters

Elasticsearch indexes structured events

Kibana visualizes alerts via dashboards

(Architecture diagram and dashboards are documented in the project report)

**⚙️ Detection Capabilities**
Implemented Detections

Port Scanning

TCP SYN scans

Stealth scans

UDP scans

Ping Sweep / Host Discovery

SSH Brute-Force Attempts

Custom Snort rule with threshold-based detection

Example SSH brute-force rule:

alert tcp $EXTERNAL_NET any -> $HOME_NET 22 \
(msg:"Multiple SSH Login Attempts Detected"; flags:S; \
threshold:type both, track by_src, count 5, seconds 60; \
sid:1000001; rev:1;)

**📊 Kibana Dashboards**

The following visualizations were created:

Alert frequency over time

Top source IP addresses

Top destination IPs

Most targeted ports

Most frequent Snort alert messages

These dashboards enable SOC-style threat investigation and pattern analysis.

🛠️ Tools & Technologies

IDS: Snort 2.9

SIEM / Logging: Elasticsearch, Logstash, Kibana

Log Shipper: Filebeat

Operating Systems: Ubuntu Server, Ubuntu Desktop, Kali Linux

Attack Tools: Nmap, Hydra

Protocols Monitored: TCP, UDP, ICMP, SSH

Networking: Host-only adapter with static IPs

**🧪 Testing & Validation**

Attack scenarios were simulated from a Kali Linux VM:

Nmap port scans (TCP/UDP)

Ping sweep discovery

SSH brute-force using Hydra

Snort successfully generated alerts for all simulated attacks, which were parsed and visualized in Kibana, validating end-to-end detection and monitoring .

**📂 Project Status**

✔ Environment fully implemented and validated in lab
✔ All virtual machines are preserved
⚠️ Repository focuses on configuration, architecture, and security workflows rather than a one-click deployment

This repo is intended to demonstrate practical IDS/SIEM experience, not a packaged product.

**🔮 Future Improvements**

Automate deployment using Docker or Ansible

Add JSON-based Snort logging

Integrate alerting with email / Slack

Map detections to MITRE ATT&CK

Add correlation rules in Logstash

Expand to Suricata comparison

👨‍💻 Author

Rohil Gajjar
Cybersecurity Analyst Intern – Evolution Info Secure
LinkedIn: linkedin.com/in/rohil-gajjar02
