splunk-rdp-bruteforce-lab – Windows RDP Brute-Force Detection Lab (Splunk)

Built a home lab using Windows and Kali VMs with Splunk ingesting Security logs to detect RDP brute‑force attacks. Developed SPL rules that aggregate 4625 failures and correlate them with 4624 successes to identify suspicious login behavior and potential account compromise.

Overview
This project demonstrates end‑to‑end detection engineering for Remote Desktop Protocol (RDP) brute‑force attacks using Windows Security Event logs and Splunk. It covers attack simulation, log ingestion, SPL detections, and alerting suitable for a SOC or blue‑team workflow.

Lab Architecture

Windows VM (target): RDP enabled, generating WinEventLog:Security events (Event IDs 4624 and 4625).

Kali Linux VM (attacker): uses xfreerdp to perform repeated RDP login attempts (failed and successful).

Splunk instance: indexes Windows Security logs in index=main, sourcetype=WinEventLog:Security, and runs scheduled detections.

Data Generation
From Kali, generate repeated failed RDP logins:

for i in {1..20}; do
xfreerdp /u:Zikayz /p:'wrongpass' /v:192.168.1.250 /cert:ignore
done

Optionally, follow with one successful login using the correct password to model a successful compromise.

Confirm events in Splunk:

index=main sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625)
| table _time EventCode Logon_Type Account_Name Source_Network_Address Workstation_Name ComputerName
| sort - _time
| head 30

Detections (SPL)

RDP brute-force attempts (failures only)
Detects multiple failed RDP-style logons from a source to a host over a period of time.

index=main sourcetype=WinEventLog:Security EventCode=4625 Logon_Type=3
| stats count as failed_attempts min(_time) as firstTime max(_time) as lastTime values(Account_Name) as accounts by Workstation_Name ComputerName
| where failed_attempts >= 5
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| sort - failed_attempts

Brute-force followed by success (correlation)
Detects a pattern where several failed logons are followed by a successful logon for the same user in a short window (classic “brute force then compromise” scenario). Adjust field names to your environment as needed.

index=main sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
Logon_Type=3
| eval src_ip=coalesce(IpAddress, Source_Network_Address)
| bin _time span=10m
| stats
count(eval(EventCode=4625)) as failed_count
count(eval(EventCode=4624)) as success_count
min(_time) as first_seen
max(_time) as last_seen
values(EventCode) as event_codes
values(src_ip) as src_ips
values(Account_Name) as accounts
by ComputerName, _time
| where failed_count >= 3 AND success_count >= 1

Alert Configuration
Example for the brute‑force attempts detection:

Type: Scheduled search.

Schedule: Every 5 minutes.

Time range: Earliest = -15m@m, Latest = now.

Trigger condition: Number of Results > 0.

Actions: Add to Triggered Alerts (optionally email or webhook).

You can create a similar alert for the “failures then success” correlation search.

How to Run This Lab

Set up Windows and Kali VMs on the same network and enable RDP on Windows.

Configure Splunk to ingest Windows Security logs (WinEventLog://Security) into index=main.

Generate failed and successful RDP attempts from Kali.

Run the SPL searches in Splunk Search & Reporting to validate results.

Save the detections as scheduled alerts and capture screenshots of triggered alerts for your portfolio.

Screenshots
(Placeholders you can replace with real images:)

Splunk search results showing aggregated 4625 failures (brute force attempts).

Triggered alert entry for RDP brute force detection.

License
This project is licensed under the MIT License. See the LICENSE file for details.
