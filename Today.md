# Update 2025-06-26
## CVE-2025-49144
 Notepad++ is a free and open-source source code editor. In versions 8.8.1 and prior, a privilege escalation vulnerability exists in the Notepad++ v8.8.1 installer that allows unprivileged users to gain SYSTEM-level privileges through insecure executable search paths. An attacker could use social engineering or clickjacking to trick users into downloading both the legitimate installer and a malicious executable to the same directory (typically Downloads folder - which is known as Vulnerable directory). Upon running the installer, the attack executes automatically with SYSTEM privileges. This issue has been fixed and will be released in version 8.8.2.

- [https://github.com/Vr00mm/CVE-2025-49144](https://github.com/Vr00mm/CVE-2025-49144) :  ![starts](https://img.shields.io/github/stars/Vr00mm/CVE-2025-49144.svg) ![forks](https://img.shields.io/github/forks/Vr00mm/CVE-2025-49144.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/63square/CVE-2025-49132](https://github.com/63square/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/63square/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/63square/CVE-2025-49132.svg)


## CVE-2025-48466
 Successful exploitation of the vulnerability could allow an unauthenticated, remote attacker to send Modbus TCP packets to manipulate Digital Outputs, potentially allowing remote control of relay channel which may lead to operational or safety risks.

- [https://github.com/shipcod3/CVE-2025-48466](https://github.com/shipcod3/CVE-2025-48466) :  ![starts](https://img.shields.io/github/stars/shipcod3/CVE-2025-48466.svg) ![forks](https://img.shields.io/github/forks/shipcod3/CVE-2025-48466.svg)


## CVE-2025-48461
 Successful exploitation of the vulnerability could allow an unauthenticated attacker to conduct brute force guessing and account takeover as the session cookies are predictable, potentially allowing the attackers to gain root, admin or user access and reset passwords.

- [https://github.com/joelczk/CVE-2025-48461](https://github.com/joelczk/CVE-2025-48461) :  ![starts](https://img.shields.io/github/stars/joelczk/CVE-2025-48461.svg) ![forks](https://img.shields.io/github/forks/joelczk/CVE-2025-48461.svg)


## CVE-2025-5309
 The chat feature within Remote Support (RS) and Privileged Remote Access (PRA) is vulnerable to a Server-Side Template Injection vulnerability which can lead to remote code execution.

- [https://github.com/issamjr/CVE-2025-5309-Scanner](https://github.com/issamjr/CVE-2025-5309-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-5309-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-5309-Scanner.svg)


## CVE-2025-4546
 A vulnerability was found in 1Panel-dev MaxKB up to 1.10.7. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the component Knowledge Base Module. The manipulation leads to csv injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 1.10.8 is able to address this issue. It is recommended to upgrade the affected component. The vendor was contacted early about this disclosure.

- [https://github.com/zgsnj123/CVE-2025-45466](https://github.com/zgsnj123/CVE-2025-45466) :  ![starts](https://img.shields.io/github/stars/zgsnj123/CVE-2025-45466.svg) ![forks](https://img.shields.io/github/forks/zgsnj123/CVE-2025-45466.svg)
- [https://github.com/zgsnj123/CVE-2025-45467](https://github.com/zgsnj123/CVE-2025-45467) :  ![starts](https://img.shields.io/github/stars/zgsnj123/CVE-2025-45467.svg) ![forks](https://img.shields.io/github/forks/zgsnj123/CVE-2025-45467.svg)


## CVE-2025-1718
 An authenticated user with file access privilege via FTP access can cause the Relion 670/650 and SAM600-IO series device to reboot due to improper disk space management.

- [https://github.com/issamjr/CVE-2025-1718-Scanner](https://github.com/issamjr/CVE-2025-1718-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-1718-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-1718-Scanner.svg)


## CVE-2025-0133
For GlobalProtect users with Clientless VPN enabled, there is a limited impact on confidentiality due to inherent risks of Clientless VPN that facilitate credential theft. You can read more about this risk in the informational bulletin  PAN-SA-2025-0005 https://security.paloaltonetworks.com/PAN-SA-2025-0005   https://security.paloaltonetworks.com/PAN-SA-2025-0005 . There is no impact to confidentiality for GlobalProtect users if you did not enable (or you disable) Clientless VPN.

- [https://github.com/INTELEON404/CVE-2025-0133](https://github.com/INTELEON404/CVE-2025-0133) :  ![starts](https://img.shields.io/github/stars/INTELEON404/CVE-2025-0133.svg) ![forks](https://img.shields.io/github/forks/INTELEON404/CVE-2025-0133.svg)


## CVE-2023-46818
 An issue was discovered in ISPConfig before 3.2.11p1. PHP code injection can be achieved in the language file editor by an admin if admin_allow_langedit is enabled.

- [https://github.com/SyFi/CVE-2023-46818](https://github.com/SyFi/CVE-2023-46818) :  ![starts](https://img.shields.io/github/stars/SyFi/CVE-2023-46818.svg) ![forks](https://img.shields.io/github/forks/SyFi/CVE-2023-46818.svg)


## CVE-2022-25581
 Classcms v2.5 and below contains an arbitrary file upload via the component \class\classupload. This vulnerability allows attackers to execute code injection via a crafted .txt file.

- [https://github.com/wooluo/CVE-2022-25581](https://github.com/wooluo/CVE-2022-25581) :  ![starts](https://img.shields.io/github/stars/wooluo/CVE-2022-25581.svg) ![forks](https://img.shields.io/github/forks/wooluo/CVE-2022-25581.svg)


## CVE-2022-1257
 Insecure storage of sensitive information vulnerability in MA for Linux, macOS, and Windows prior to 5.7.6 allows a local user to gain access to sensitive information through storage in ma.db. The sensitive information has been moved to encrypted database files.

- [https://github.com/kayes817/CVE-2022-1257](https://github.com/kayes817/CVE-2022-1257) :  ![starts](https://img.shields.io/github/stars/kayes817/CVE-2022-1257.svg) ![forks](https://img.shields.io/github/forks/kayes817/CVE-2022-1257.svg)


## CVE-2019-7304
 Canonical snapd before version 2.37.1 incorrectly performed socket owner validation, allowing an attacker to run arbitrary commands as root. This issue affects: Canonical snapd versions prior to 2.37.1.

- [https://github.com/coby-nguyen/Document-Linux-Privilege-Escalation](https://github.com/coby-nguyen/Document-Linux-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/coby-nguyen/Document-Linux-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/coby-nguyen/Document-Linux-Privilege-Escalation.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/Perimora/cve_2019-5736-PoC](https://github.com/Perimora/cve_2019-5736-PoC) :  ![starts](https://img.shields.io/github/stars/Perimora/cve_2019-5736-PoC.svg) ![forks](https://img.shields.io/github/forks/Perimora/cve_2019-5736-PoC.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/makmour/open-ssh-user-enumeration](https://github.com/makmour/open-ssh-user-enumeration) :  ![starts](https://img.shields.io/github/stars/makmour/open-ssh-user-enumeration.svg) ![forks](https://img.shields.io/github/forks/makmour/open-ssh-user-enumeration.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/hdgokani/CVE-2018-1273](https://github.com/hdgokani/CVE-2018-1273) :  ![starts](https://img.shields.io/github/stars/hdgokani/CVE-2018-1273.svg) ![forks](https://img.shields.io/github/forks/hdgokani/CVE-2018-1273.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144](https://github.com/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144.svg)


## CVE-2016-1000002
 gdm3 3.14.2 and possibly later has an information leak before screen lock

- [https://github.com/hdgokani/CVE2016-10000027](https://github.com/hdgokani/CVE2016-10000027) :  ![starts](https://img.shields.io/github/stars/hdgokani/CVE2016-10000027.svg) ![forks](https://img.shields.io/github/forks/hdgokani/CVE2016-10000027.svg)

