# Ubuntu-Azure-Hybrid-Lab

## Description
This repository contains a step by step walkthrough of how I built a hybrid cloud monitoring and security lab using Ubuntu Server, UFW, NGINX, Fail2Ban, Azure Arc, and Log Analytics. In this project, I deployed an on-premises Ubuntu VM in Oracle VirtualBox, hardened it with system updates, a host-based firewall (UFW), SSH hardening, and Fail2Ban, and hosted a secure HTTPS web server using NGINX with a self-signed TLS certificate.

I then connected the server to Microsoft Azure using Azure Arc, configured a Log Analytics Workspace to ingest syslog and performance metrics, and used KQL queries to build alerts for high CPU usage, NGINX service failures, and SSH brute-force attempts. Alerts were wired to an Action Group that sends notifications via email and SMS. To validate the setup, I used my Windows host command line to SSH into the VM and simulate brute-force attempts, gaining hands-on experience with Linux hardening, firewall configuration (UFW), cloud monitoring, and hybrid infrastructure security using Azure Arc.

<h2>Languages and Utilities Used</h2>

- <b>Bash</b>
- <b>NGINX</b>
- <b>Fail2Ban</b>
- <b>UFW</b>
- <b>Azure Monitor / Arc</b>

<h2>Environments Used </h2>

- <b>Ubuntu Server 22.04.3</b>
- <b>Windows 11 (Host)</b>
- <b>Microsoft Azure</b>

## Diagram
<img width="1251" height="696" alt="Untitled Diagram drawio" src="https://github.com/user-attachments/assets/4832f37a-fee0-4942-ae1b-c048125d5b83" />



# Walkthrough:
## Downloaded Ubuntu Server 22.04.3 ISO file
[Ubuntu Server](https://ubuntu.com/download/server)

## Created and Configured the Ubuntu Server VM (On-Prem)
I started by creating a virtual machine in Oracle VirtualBox and named it Ubuntu. To simulate a real on-prem server, I used a Bridged Network Adapter, allowing the VM to receive an IP address from my home network just like a physical server would.

<img width="599" height="459" alt="Image" src="https://github.com/user-attachments/assets/584d8e9e-36ae-4d42-b17f-4712fa57ac83" />

After mounting the Ubuntu Server ISO and powering on the VM, I installed Ubuntu Server (no GUI) and created a local admin user with OpenSSH enabled.

<img width="1220" height="760" alt="Image" src="https://github.com/user-attachments/assets/d0160eb3-776e-416f-9e47-e2c726fca1a8" /> 
<img width="966" height="340" alt="Image" src="https://github.com/user-attachments/assets/4c4202f1-bd61-4514-846f-a9018c5f9c71" />

## Updated & Patched the System
```sudo apt update && sudo apt upgrade -y```
<img width="1223" height="764" alt="Image" src="https://github.com/user-attachments/assets/54956f7a-69e9-4dbd-9e8e-a5f32d998c6a" />

## Set Accurate Timezone
Timezones ensure log accuracy. If logs don’t match real time, incident response becomes a mess.

```sudo timedatectl set-timezone America/New_York```

<img width="622" height="206" alt="Image" src="https://github.com/user-attachments/assets/5756e785-8524-4e3e-8a73-1be0b3bc5a82" />

## Created an Admin User
I created a separate admin-privileged user so we’re not logging in as the default account, which improves security and follows the baic securitys principle of Least Privilege and Identity and Access Management (IAM).

```bash
sudo adduser admin
sudo usermod -aG sudo admin
```

<img width="641" height="404" alt="Image" src="https://github.com/user-attachments/assets/f8951fcb-c852-4f25-860a-749b735bb802" />

## Verified Networking
```ping google.com```

<img width="743" height="193" alt="Image" src="https://github.com/user-attachments/assets/9f54549d-116c-4787-8fed-5dc5be81935c" />

## Configured UFW Firewall
Before installing services, I enabled a firewall using UFW (Uncomplicated Firewall). I allowed SSH first to avoid locking myself out. This restricts inbound traffic to only approved services.

```bash
sudo apt install ufw -y
sudo ufw allow OpenSSH
sudo ufw enable
sudo ufw status
```

<img width="448" height="228" alt="Image" src="https://github.com/user-attachments/assets/0c601f19-99d6-4c7d-95e3-dd9253295c55" />

## Installed Nginx Web Server
I installed and enabled NGINX so the server can serve web pages and automatically run the web service at every boot. It allows our server to host and deliver web pages to users, acting as the web service that responds to HTTP/HTTPS requests.
```bash
sudo apt install nginx -y
sudo systemctl enable --now nginx
```

<img width="1222" height="763" alt="Image" src="https://github.com/user-attachments/assets/13130826-9b8e-4a17-a56e-1358c7f956df" />

## Allowed Nginx Through Firewall
```bash
sudo ufw allow 'Nginx HTTP'
sudo ufw status
```

<img width="497" height="247" alt="Image" src="https://github.com/user-attachments/assets/3ab17a03-0a8f-4abd-b3f9-c075391f2f0a" />

## Enabled TLS/HTTPS (Self-Signed Certificate)
We installed OpenSSL to generate encryption keys, then created a 2048-bit self-signed TLS certificate that lasts 1 year, producing a private key (```/etc/ssl/private/nginx-selfsigned.key```) and a matching certificate (```/etc/ssl/certs/nginx-selfsigned.crt```) so our server can use HTTPS.

```bash
sudo apt install openssl -y
sudo openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key \
  -out /etc/ssl/certs/nginx-selfsigned.crt
```

<img width="1221" height="485" alt="Image" src="https://github.com/user-attachments/assets/44bade51-698d-4ba9-9999-3876b65dfdba" />

## Configured NGINX 
I configured NGINX to use our self-signed certificate, so the server can serve encrypted HTTPS traffic instead of plain HTTP. Then I validated the configuration, and restarted the service.

- Opens a config file so we can link our certificate to NGINX
```bash
sudo nano /etc/nginx/snippets/self-signed.conf
```

- Tells NGINX where to find the TLS certificate and private key.
```bash
ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
```

- Opens the main site settings so we can enable HTTPS on our web server.
```bash
sudo nano /etc/nginx/sites-available/default
```
- Enables NGINX to serve HTTPS on port 443 using our self-signed certificate. Added below ```listen 80 default_server;```
```bash
listen 443 ssl default_server;
include snippets/self-signed.conf;
```

- Tested configuration then restarted service
```bash
sudo nginx -t
sudo systemctl restart nginx
```

<img width="1220" height="759" alt="Image" src="https://github.com/user-attachments/assets/8025da6e-25a1-4ed2-942f-4cb1e40c6172" />

## Installed and Configured Fail2Ban (SSH + NGINX Protection)

To detect and block brute-force attacks, I installed Fail2Ban and created jail rules for both SSH and NGINX authentication errors.
```bash
sudo apt install fail2ban -y
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```
- Added a jail rule that automatically blocks suspicious IPs trying to brute-force SSH or our NGINX site.
```bash
[sshd]
enabled = true
bantime = 1h

[nginx-http-auth]
enabled = true
```
- Then restarted and verified the jail
```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```
<img width="495" height="153" alt="Image" src="https://github.com/user-attachments/assets/9d8b599f-84c8-4a7c-8ee3-245c703e54f4" />

## Created Azure Resource Group + Log Analytics Workspace
I created a Resource Group and a Log Analytics Workspace so Azure could organize and store our server’s logs, allowing us to monitor the Ubuntu machine, collect security data, and build alerts for the hybrid lab.

<img width="812" height="483" alt="Image" src="https://github.com/user-attachments/assets/4ae86e1d-89a5-478b-86e7-4d4a3c6a2d73" />

## Connected the VM to Microsoft Azure Using Azure Arc
In Azure Arc → Machines, I generated and ran the onboarding script on the VM via SSH. After installation, the VM appeared as a hybrid machine in Azure Arc.
<img width="1570" height="278" alt="Image" src="https://github.com/user-attachments/assets/eb27d7e3-dea7-4e6f-8df9-a29a4ce1bede" />

## Enabled VM Insights
I enabled Insights on the Arc server to collect system metrics (CPU, RAM, disk, and logs) so Azure can monitor our on-prem Ubuntu machine just like a cloud server.
<img width="911" height="445" alt="Image" src="https://github.com/user-attachments/assets/150bd551-423d-43b2-bcb7-7afd3d71ad64" />

## Tested the Data Flow
Installed a Stress tool and spiked the CPU to confirm that Azure can detect performance changes from our on-prem Ubuntu server in real time.
```bash
sudo apt install stress -y
stress --cpu 2 --timeout 60
```

<img width="1534" height="604" alt="Image" src="https://github.com/user-attachments/assets/82993e2c-78cb-49fd-a7d9-0e5207807188" />

## Configured Syslog Monitoring in Azure Monitor
I enabled Syslog collection through a Data Collection rule in Azure Monitor and enabled ```auth```, ```authpriv```, and ```daemon``` so Azure Log Analytics can collect important security logs from our Linux server such as SSH login attempts, Fail2Ban bans, and NGINX service events, allowing us to monitor threats and build cloud alerts for our hybrid environment.

<img width="812" height="753" alt="Image" src="https://github.com/user-attachments/assets/daf6a80f-c4fe-4327-b96f-6b6fc5228d0c" />
<img width="1067" height="367" alt="Image" src="https://github.com/user-attachments/assets/4b1c08ce-cafd-4807-b537-20c7db4b89a2" />

## Genertaed Syslog & SSH Activity 
- Ran these commands on my Ubuntu VM
  ```bash
  sudo systemctl restart ssh
  sudo systemctl restart nginx
  sudo fail2ban-client status
  ```

- Tried a few failed login attempts from my Windows 11 host machine
<img width="619" height="499" alt="image" src="https://github.com/user-attachments/assets/c1edfcce-311e-4b2a-9edc-ac2763106cb6" />

## Used KQL to Test Syslog Query
To confirm log ingestion, I ran queries in Log Analytics:
<img width="1256" height="730" alt="image" src="https://github.com/user-attachments/assets/91867d96-5f2e-4938-88d5-420b5e1ad420" />

## Created An Action Group in Azure Monitor + SMS/Email Notifications 
I created an Action Group with my email/phone so Azure can send me real-time alerts whenever my on-prem server triggers security or performance events, allowingmeus to test and verify notifications just like a real production environment.
<img width="1919" height="422" alt="image" src="https://github.com/user-attachments/assets/d08fba2e-e64d-490e-add2-3993be6be52f" />

## Created Cloud Alerts Rules
<b>High CPU (CPU > 80% for 5 minutes)</b>
- Query
```Kusto
InsightsMetrics
| where Name == "PercentProcessorTime"
| summarize AvgCPU = avg(Val) by bin(TimeGenerated, 5m)
| where AvgCPU > 80
```

<b>Nginx stops</b>
- Query
```Kusto
Syslog
| where TimeGenerated > ago(5m)
| where SyslogMessage contains "nginx"
| where SyslogMessage contains "fail" or SyslogMessage contains "Failed" or SyslogMessage contains "Stopped" or SyslogMessage contains "stop"
| project TimeGenerated, SeverityLevel, ProcessName, SyslogMessage
| order by TimeGenerated desc
```

<b>SSH Brute Force Detected</b>
- Query
```Kusto
Syslog
| where TimeGenerated > ago(10m)
| where SyslogMessage contains "Failed password"
| parse SyslogMessage with * "from " srcIp " port" *
| summarize Attempts = count() by srcIp
| where Attempts >= 3
```

<img width="1919" height="520" alt="image" src="https://github.com/user-attachments/assets/2f45d8c2-a0c2-4840-927a-9adac217cbde" />

## Real-time Alerts
<img width="1639" height="437" alt="image" src="https://github.com/user-attachments/assets/6dedaa61-249b-4ed5-a703-a80592875199" />
<img width="1170" height="1577" alt="image" src="https://github.com/user-attachments/assets/7ba4bbfb-f2de-4a1d-ac34-7dbf5d6febb4" />

