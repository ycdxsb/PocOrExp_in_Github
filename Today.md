# Update 2025-06-27
## CVE-2025-49144
 Notepad++ is a free and open-source source code editor. In versions 8.8.1 and prior, a privilege escalation vulnerability exists in the Notepad++ v8.8.1 installer that allows unprivileged users to gain SYSTEM-level privileges through insecure executable search paths. An attacker could use social engineering or clickjacking to trick users into downloading both the legitimate installer and a malicious executable to the same directory (typically Downloads folder - which is known as Vulnerable directory). Upon running the installer, the attack executes automatically with SYSTEM privileges. This issue has been fixed and will be released in version 8.8.2.

- [https://github.com/TheTorjanCaptain/CVE-2025-49144_PoC](https://github.com/TheTorjanCaptain/CVE-2025-49144_PoC) :  ![starts](https://img.shields.io/github/stars/TheTorjanCaptain/CVE-2025-49144_PoC.svg) ![forks](https://img.shields.io/github/forks/TheTorjanCaptain/CVE-2025-49144_PoC.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/melonlonmeo/CVE-2025-49132](https://github.com/melonlonmeo/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/melonlonmeo/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/melonlonmeo/CVE-2025-49132.svg)


## CVE-2025-48828
 Certain vBulletin versions might allow attackers to execute arbitrary PHP code by abusing Template Conditionals in the template engine. By crafting template code in an alternative PHP function invocation syntax, such as the "var_dump"("test") syntax, attackers can bypass security checks and execute arbitrary PHP code, as exploited in the wild in May 2025.

- [https://github.com/ill-deed/vBulletin-CVE-2025-48828-Multi-target](https://github.com/ill-deed/vBulletin-CVE-2025-48828-Multi-target) :  ![starts](https://img.shields.io/github/stars/ill-deed/vBulletin-CVE-2025-48828-Multi-target.svg) ![forks](https://img.shields.io/github/forks/ill-deed/vBulletin-CVE-2025-48828-Multi-target.svg)


## CVE-2025-47577
 Unrestricted Upload of File with Dangerous Type vulnerability in TemplateInvaders TI WooCommerce Wishlist allows Upload a Web Shell to a Web Server.This issue affects TI WooCommerce Wishlist: from n/a before 2.10.0.

- [https://github.com/sug4r-wr41th/CVE-2025-47577](https://github.com/sug4r-wr41th/CVE-2025-47577) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2025-47577.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2025-47577.svg)


## CVE-2025-30712
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core).   The supported version that is affected is 7.1.6. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox.  While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle VM VirtualBox accessible data as well as  unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle VM VirtualBox. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L).

- [https://github.com/jamesb5959/CVE-2025-30712-_PoC](https://github.com/jamesb5959/CVE-2025-30712-_PoC) :  ![starts](https://img.shields.io/github/stars/jamesb5959/CVE-2025-30712-_PoC.svg) ![forks](https://img.shields.io/github/forks/jamesb5959/CVE-2025-30712-_PoC.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-30208](https://github.com/B1ack4sh/Blackash-CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-30208.svg)


## CVE-2025-27558
 IEEE P802.11-REVme D1.1 through D7.0 allows FragAttacks against mesh networks. In mesh networks using Wi-Fi Protected Access (WPA, WPA2, or WPA3) or Wired Equivalent Privacy (WEP), an adversary can exploit this vulnerability to inject arbitrary frames towards devices that support receiving non-SSP A-MSDU frames. NOTE: this issue exists because of an incorrect fix for CVE-2020-24588. P802.11-REVme, as of early 2025, is a planned release of the 802.11 standard.

- [https://github.com/Atlas-ghostshell/CVE-2025-27558_Patching](https://github.com/Atlas-ghostshell/CVE-2025-27558_Patching) :  ![starts](https://img.shields.io/github/stars/Atlas-ghostshell/CVE-2025-27558_Patching.svg) ![forks](https://img.shields.io/github/forks/Atlas-ghostshell/CVE-2025-27558_Patching.svg)


## CVE-2025-5222
 A stack buffer overflow was found in Internationl components for unicode (ICU ). While running the genrb binary, the 'subtag' struct overflowed at the SRBRoot::addTag function. This issue may lead to memory corruption and local arbitrary code execution.

- [https://github.com/berkley4/icu-74-debian](https://github.com/berkley4/icu-74-debian) :  ![starts](https://img.shields.io/github/stars/berkley4/icu-74-debian.svg) ![forks](https://img.shields.io/github/forks/berkley4/icu-74-debian.svg)


## CVE-2025-4870
 A vulnerability classified as critical was found in itsourcecode Restaurant Management System 1.0. This vulnerability affects unknown code of the file /admin/menu_save.php. The manipulation of the argument menu leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/trh4ckn0n/CVE-2025-48703](https://github.com/trh4ckn0n/CVE-2025-48703) :  ![starts](https://img.shields.io/github/stars/trh4ckn0n/CVE-2025-48703.svg) ![forks](https://img.shields.io/github/forks/trh4ckn0n/CVE-2025-48703.svg)


## CVE-2025-4460
 A vulnerability classified as problematic has been found in TOTOLINK N150RT 3.4.0-B20190525. This affects an unknown part of the component URL Filtering Page. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/mr-xmen786/CVE-2025-44608](https://github.com/mr-xmen786/CVE-2025-44608) :  ![starts](https://img.shields.io/github/stars/mr-xmen786/CVE-2025-44608.svg) ![forks](https://img.shields.io/github/forks/mr-xmen786/CVE-2025-44608.svg)


## CVE-2025-3248
code.

- [https://github.com/ill-deed/Langflow-CVE-2025-3248-Multi-target](https://github.com/ill-deed/Langflow-CVE-2025-3248-Multi-target) :  ![starts](https://img.shields.io/github/stars/ill-deed/Langflow-CVE-2025-3248-Multi-target.svg) ![forks](https://img.shields.io/github/forks/ill-deed/Langflow-CVE-2025-3248-Multi-target.svg)


## CVE-2024-51984
 An authenticated attacker can reconfigure the target device to use an external service (such as LDAP or FTP) controlled by the attacker. If an existing password is present for an external service, the attacker can force the target device to authenticate to an attacker controlled device using the existing credentials for that external service. In the case of an external LDAP or FTP service, this will disclose the plaintext password for that external service to the attacker.

- [https://github.com/sfewer-r7/BrotherVulnerabilities](https://github.com/sfewer-r7/BrotherVulnerabilities) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/BrotherVulnerabilities.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/BrotherVulnerabilities.svg)


## CVE-2024-51983
 An unauthenticated attacker who can connect to the Web Services feature (HTTP TCP port 80) can issue a WS-Scan SOAP request containing an unexpected JobToken value which will crash the target device. The device will reboot, after which the attacker can reissue the command to repeatedly crash the device.

- [https://github.com/sfewer-r7/BrotherVulnerabilities](https://github.com/sfewer-r7/BrotherVulnerabilities) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/BrotherVulnerabilities.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/BrotherVulnerabilities.svg)


## CVE-2024-51982
 An unauthenticated attacker who can connect to TCP port 9100 can issue a Printer Job Language (PJL) command that will crash the target device. The device will reboot, after which the attacker can reissue the command to repeatedly crash the device. A malformed PJL variable FORMLINES is set to a non number value causing the target to crash.

- [https://github.com/sfewer-r7/BrotherVulnerabilities](https://github.com/sfewer-r7/BrotherVulnerabilities) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/BrotherVulnerabilities.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/BrotherVulnerabilities.svg)


## CVE-2024-51981
 An unauthenticated attacker may perform a blind server side request forgery (SSRF), due to a CLRF injection issue that can be leveraged to perform HTTP request smuggling. This SSRF leverages the WS-Addressing feature used during a WS-Eventing subscription SOAP operation. The attacker can control all the HTTP data sent in the SSRF connection, but the attacker can not receive any data back from this connection.

- [https://github.com/sfewer-r7/BrotherVulnerabilities](https://github.com/sfewer-r7/BrotherVulnerabilities) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/BrotherVulnerabilities.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/BrotherVulnerabilities.svg)


## CVE-2024-51980
 An unauthenticated attacker may perform a limited server side request forgery (SSRF), forcing the target device to open a TCP connection to an arbitrary port number on an arbitrary IP address. This SSRF leverages the WS-Addressing ReplyTo element in a Web service (HTTP TCP port 80) SOAP request. The attacker can not control the data sent in the SSRF connection, nor can the attacker receive any data back. This SSRF is suitable for TCP port scanning of an internal network when the Web service (HTTP TCP port 80) is exposed across a network segment.

- [https://github.com/sfewer-r7/BrotherVulnerabilities](https://github.com/sfewer-r7/BrotherVulnerabilities) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/BrotherVulnerabilities.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/BrotherVulnerabilities.svg)


## CVE-2024-51979
 An authenticated attacker may trigger a stack based buffer overflow by performing a malformed request to either the HTTP service (TCP port 80), the HTTPS service (TCP port 443), or the IPP service (TCP port 631). The malformed request will contain an empty Origin header value and a malformed Referer header value. The Referer header value will trigger a stack based buffer overflow when the host value in the Referer header is processed and is greater than 64 bytes in length.

- [https://github.com/sfewer-r7/BrotherVulnerabilities](https://github.com/sfewer-r7/BrotherVulnerabilities) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/BrotherVulnerabilities.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/BrotherVulnerabilities.svg)


## CVE-2024-51978
 An unauthenticated attacker who knows the target device's serial number, can generate the default administrator password for the device. An unauthenticated attacker can first discover the target device's serial number via CVE-2024-51977 over HTTP/HTTPS/IPP, or via a PJL request, or via an SNMP request.

- [https://github.com/sfewer-r7/BrotherVulnerabilities](https://github.com/sfewer-r7/BrotherVulnerabilities) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/BrotherVulnerabilities.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/BrotherVulnerabilities.svg)


## CVE-2024-51977
 An unauthenticated attacker who can access either the HTTP service (TCP port 80), the HTTPS service (TCP port 443), or the IPP service (TCP port 631), can leak several pieces of sensitive information from a vulnerable device. The URI path /etc/mnt_info.csv can be accessed via a GET request and no authentication is required. The returned result is a comma separated value (CSV) table of information. The leaked information includes the device’s model, firmware version, IP address, and serial number.

- [https://github.com/sfewer-r7/BrotherVulnerabilities](https://github.com/sfewer-r7/BrotherVulnerabilities) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/BrotherVulnerabilities.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/BrotherVulnerabilities.svg)


## CVE-2024-43917
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in TemplateInvaders TI WooCommerce Wishlist allows SQL Injection.This issue affects TI WooCommerce Wishlist: from n/a through 2.8.2.

- [https://github.com/sug4r-wr41th/CVE-2024-43917](https://github.com/sug4r-wr41th/CVE-2024-43917) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2024-43917.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2024-43917.svg)


## CVE-2024-38819
 Applications serving static resources through the functional web frameworks WebMvc.fn or WebFlux.fn are vulnerable to path traversal attacks. An attacker can craft malicious HTTP requests and obtain any file on the file system that is also accessible to the process in which the Spring application is running.

- [https://github.com/vishalnoza/CVE-2024-38819-POC2](https://github.com/vishalnoza/CVE-2024-38819-POC2) :  ![starts](https://img.shields.io/github/stars/vishalnoza/CVE-2024-38819-POC2.svg) ![forks](https://img.shields.io/github/forks/vishalnoza/CVE-2024-38819-POC2.svg)


## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/ademto/wordpress-cve-2024-10924-pentest](https://github.com/ademto/wordpress-cve-2024-10924-pentest) :  ![starts](https://img.shields.io/github/stars/ademto/wordpress-cve-2024-10924-pentest.svg) ![forks](https://img.shields.io/github/forks/ademto/wordpress-cve-2024-10924-pentest.svg)


## CVE-2022-2588
 It was discovered that the cls_route filter implementation in the Linux kernel would not remove an old filter from the hashtable before freeing it if its handle had the value 0.

- [https://github.com/Igr1s-red/CVE-2022-2588](https://github.com/Igr1s-red/CVE-2022-2588) :  ![starts](https://img.shields.io/github/stars/Igr1s-red/CVE-2022-2588.svg) ![forks](https://img.shields.io/github/forks/Igr1s-red/CVE-2022-2588.svg)


## CVE-2022-0995
 An out-of-bounds (OOB) memory write flaw was found in the Linux kernel’s watch_queue event notification subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain privileged access or cause a denial of service on the system.

- [https://github.com/A1b2rt/cve-2022-0995](https://github.com/A1b2rt/cve-2022-0995) :  ![starts](https://img.shields.io/github/stars/A1b2rt/cve-2022-0995.svg) ![forks](https://img.shields.io/github/forks/A1b2rt/cve-2022-0995.svg)


## CVE-2021-31630
 Command Injection in Open PLC Webserver v3 allows remote attackers to execute arbitrary code via the "Hardware Layer Code Box" component on the "/hardware" page of the application.

- [https://github.com/adibna/cve-2021-31630](https://github.com/adibna/cve-2021-31630) :  ![starts](https://img.shields.io/github/stars/adibna/cve-2021-31630.svg) ![forks](https://img.shields.io/github/forks/adibna/cve-2021-31630.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/Samuel-G3/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow](https://github.com/Samuel-G3/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow) :  ![starts](https://img.shields.io/github/stars/Samuel-G3/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow.svg) ![forks](https://img.shields.io/github/forks/Samuel-G3/Escalamiento-de-Privilegios-usando-el-Kernel-Exploit-Dirty-Cow.svg)

