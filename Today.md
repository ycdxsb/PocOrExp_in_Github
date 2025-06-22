# Update 2025-06-22
## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/typicalsmc/CVE-2025-49132-PoC](https://github.com/typicalsmc/CVE-2025-49132-PoC) :  ![starts](https://img.shields.io/github/stars/typicalsmc/CVE-2025-49132-PoC.svg) ![forks](https://img.shields.io/github/forks/typicalsmc/CVE-2025-49132-PoC.svg)


## CVE-2025-48988
Users are recommended to upgrade to version 11.0.8, 10.1.42 or 9.0.106, which fix the issue.

- [https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976](https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976) :  ![starts](https://img.shields.io/github/stars/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg) ![forks](https://img.shields.io/github/forks/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg)


## CVE-2025-48976
Users are recommended to upgrade to versions 1.6 or 2.0.0-M4, which fix the issue.

- [https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976](https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976) :  ![starts](https://img.shields.io/github/stars/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg) ![forks](https://img.shields.io/github/forks/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg)


## CVE-2025-44203
 In HotelDruid 3.0.7, an unauthenticated attacker can exploit verbose SQL error messages on creadb.php before the 'create database' button is pressed. By sending malformed POST requests to this endpoint, the attacker may obtain the administrator username, password hash, and salt. In some cases, the attack results in a Denial of Service (DoS), preventing the administrator from logging in even with the correct credentials.

- [https://github.com/IvanT7D3/CVE-2025-44203](https://github.com/IvanT7D3/CVE-2025-44203) :  ![starts](https://img.shields.io/github/stars/IvanT7D3/CVE-2025-44203.svg) ![forks](https://img.shields.io/github/forks/IvanT7D3/CVE-2025-44203.svg)


## CVE-2025-6335
 A vulnerability was found in DedeCMS up to 5.7.2 and classified as critical. This issue affects some unknown processing of the file /include/dedetag.class.php of the component Template Handler. The manipulation of the argument notes leads to command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/jujubooom/CVE-2025-6335](https://github.com/jujubooom/CVE-2025-6335) :  ![starts](https://img.shields.io/github/stars/jujubooom/CVE-2025-6335.svg) ![forks](https://img.shields.io/github/forks/jujubooom/CVE-2025-6335.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/And-oss/CVE-2025-6019-exploit](https://github.com/And-oss/CVE-2025-6019-exploit) :  ![starts](https://img.shields.io/github/stars/And-oss/CVE-2025-6019-exploit.svg) ![forks](https://img.shields.io/github/forks/And-oss/CVE-2025-6019-exploit.svg)


## CVE-2025-4102
 The Beaver Builder Plugin (Starter Version) plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'save_enabled_icons' function in all versions up to, and including, 2.9.1. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible. The vulnerability was partially patched in version 2.9.1.

- [https://github.com/ImTheCopilotNow/CVE-2025-4102025](https://github.com/ImTheCopilotNow/CVE-2025-4102025) :  ![starts](https://img.shields.io/github/stars/ImTheCopilotNow/CVE-2025-4102025.svg) ![forks](https://img.shields.io/github/forks/ImTheCopilotNow/CVE-2025-4102025.svg)


## CVE-2024-50562
 An Insufficient Session Expiration vulnerability [CWE-613] in FortiOS SSL-VPN version 7.6.0, version 7.4.6 and below, version 7.2.10 and below, 7.0 all versions, 6.4 all versions may allow an attacker in possession of a cookie used to log in the SSL-VPN portal to log in again, although the session has expired or was logged out.

- [https://github.com/Shahid-BugB/fortinet-cve-2024-50562](https://github.com/Shahid-BugB/fortinet-cve-2024-50562) :  ![starts](https://img.shields.io/github/stars/Shahid-BugB/fortinet-cve-2024-50562.svg) ![forks](https://img.shields.io/github/forks/Shahid-BugB/fortinet-cve-2024-50562.svg)


## CVE-2024-9796
 The WP-Advanced-Search WordPress plugin before 3.3.9.2 does not sanitize and escape the t parameter before using it in a SQL statement, allowing unauthenticated users to perform SQL injection attacks

- [https://github.com/BwithE/CVE-2024-9796](https://github.com/BwithE/CVE-2024-9796) :  ![starts](https://img.shields.io/github/stars/BwithE/CVE-2024-9796.svg) ![forks](https://img.shields.io/github/forks/BwithE/CVE-2024-9796.svg)


## CVE-2021-30047
 VSFTPD 3.0.3 allows attackers to cause a denial of service due to limited number of connections allowed.

- [https://github.com/Andreyfreis/CVE-2021-30047](https://github.com/Andreyfreis/CVE-2021-30047) :  ![starts](https://img.shields.io/github/stars/Andreyfreis/CVE-2021-30047.svg) ![forks](https://img.shields.io/github/forks/Andreyfreis/CVE-2021-30047.svg)


## CVE-2020-21365
 Directory traversal vulnerability in wkhtmltopdf through 0.12.5 allows remote attackers to read local files and disclose sensitive information via a crafted html file running with the default configurations.

- [https://github.com/samaellovecraft/CVE-2020-21365](https://github.com/samaellovecraft/CVE-2020-21365) :  ![starts](https://img.shields.io/github/stars/samaellovecraft/CVE-2020-21365.svg) ![forks](https://img.shields.io/github/forks/samaellovecraft/CVE-2020-21365.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/edyekomu/CVE-2017-12615-PoC](https://github.com/edyekomu/CVE-2017-12615-PoC) :  ![starts](https://img.shields.io/github/stars/edyekomu/CVE-2017-12615-PoC.svg) ![forks](https://img.shields.io/github/forks/edyekomu/CVE-2017-12615-PoC.svg)


## CVE-2011-0762
 The vsf_filename_passes_filter function in ls.c in vsftpd before 2.3.3 allows remote authenticated users to cause a denial of service (CPU consumption and process slot exhaustion) via crafted glob expressions in STAT commands in multiple FTP sessions, a different vulnerability than CVE-2010-2632.

- [https://github.com/Andreyfreis/CVE-2011-0762](https://github.com/Andreyfreis/CVE-2011-0762) :  ![starts](https://img.shields.io/github/stars/Andreyfreis/CVE-2011-0762.svg) ![forks](https://img.shields.io/github/forks/Andreyfreis/CVE-2011-0762.svg)

