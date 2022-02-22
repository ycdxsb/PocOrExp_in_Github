# Update 2022-02-22
## CVE-2022-25375
 An issue was discovered in drivers/usb/gadget/function/rndis.c in the Linux kernel before 5.16.10. The RNDIS USB gadget lacks validation of the size of the RNDIS_MSG_SET command. Attackers can obtain sensitive information from kernel memory.

- [https://github.com/szymonh/rndis-co](https://github.com/szymonh/rndis-co) :  ![starts](https://img.shields.io/github/stars/szymonh/rndis-co.svg) ![forks](https://img.shields.io/github/forks/szymonh/rndis-co.svg)


## CVE-2022-24086
 Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier) are affected by an improper input validation vulnerability during the checkout process. Exploitation of this issue does not require user interaction and could result in arbitrary code execution.

- [https://github.com/Mr-xn/CVE-2022-24086](https://github.com/Mr-xn/CVE-2022-24086) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-24086.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-24086.svg)


## CVE-2022-23131
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).

- [https://github.com/0tt7/CVE-2022-23131](https://github.com/0tt7/CVE-2022-23131) :  ![starts](https://img.shields.io/github/stars/0tt7/CVE-2022-23131.svg) ![forks](https://img.shields.io/github/forks/0tt7/CVE-2022-23131.svg)
- [https://github.com/zwjjustdoit/cve-2022-23131](https://github.com/zwjjustdoit/cve-2022-23131) :  ![starts](https://img.shields.io/github/stars/zwjjustdoit/cve-2022-23131.svg) ![forks](https://img.shields.io/github/forks/zwjjustdoit/cve-2022-23131.svg)


## CVE-2021-40449
 Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-40450, CVE-2021-41357.

- [https://github.com/BL0odz/CVE-2021-40449-NtGdiResetDC-UAF](https://github.com/BL0odz/CVE-2021-40449-NtGdiResetDC-UAF) :  ![starts](https://img.shields.io/github/stars/BL0odz/CVE-2021-40449-NtGdiResetDC-UAF.svg) ![forks](https://img.shields.io/github/forks/BL0odz/CVE-2021-40449-NtGdiResetDC-UAF.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/ravindubw/CVE-2021-4034](https://github.com/ravindubw/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ravindubw/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ravindubw/CVE-2021-4034.svg)
- [https://github.com/JoaoFukuda/CVE-2021-4034_POC](https://github.com/JoaoFukuda/CVE-2021-4034_POC) :  ![starts](https://img.shields.io/github/stars/JoaoFukuda/CVE-2021-4034_POC.svg) ![forks](https://img.shields.io/github/forks/JoaoFukuda/CVE-2021-4034_POC.svg)


## CVE-2021-3281
 In Django 2.2 before 2.2.18, 3.0 before 3.0.12, and 3.1 before 3.1.6, the django.utils.archive.extract method (used by &quot;startapp --template&quot; and &quot;startproject --template&quot;) allows directory traversal via an archive with absolute paths or relative paths with dot segments.

- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/NFIRBV/krijg-de-hik](https://github.com/NFIRBV/krijg-de-hik) :  ![starts](https://img.shields.io/github/stars/NFIRBV/krijg-de-hik.svg) ![forks](https://img.shields.io/github/forks/NFIRBV/krijg-de-hik.svg)


## CVE-2017-7651
 In Eclipse Mosquitto 1.4.14, a user can shutdown the Mosquitto server simply by filling the RAM memory with a lot of connections with large payload. This can be done without authentications if occur in connection phase of MQTT protocol.

- [https://github.com/St3v3nsS/CVE-2017-7651](https://github.com/St3v3nsS/CVE-2017-7651) :  ![starts](https://img.shields.io/github/stars/St3v3nsS/CVE-2017-7651.svg) ![forks](https://img.shields.io/github/forks/St3v3nsS/CVE-2017-7651.svg)

