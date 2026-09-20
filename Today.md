# Update 2026-09-20
## CVE-2026-93453
 SOGo before 5.12.11 constructs password-reset links using the client-supplied Origin header as the authority, allowing unauthenticated attackers to redirect recovery tokens to attacker-controlled domains. Attackers can submit password recovery requests with a malicious Origin header to have valid password-reset tokens mailed to victim recovery addresses within links pointing to attacker infrastructure, enabling account takeover.

- [https://github.com/Faceless0x7/CVE-2026-93453](https://github.com/Faceless0x7/CVE-2026-93453) :  ![starts](https://img.shields.io/github/stars/Faceless0x7/CVE-2026-93453.svg) ![forks](https://img.shields.io/github/forks/Faceless0x7/CVE-2026-93453.svg)


## CVE-2026-84753
 Unauthenticated PHP Object Injection in Mail Mint = 1.31.0 versions.

- [https://github.com/abraxas/CVE-2026-84753](https://github.com/abraxas/CVE-2026-84753) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-84753.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-84753.svg)


## CVE-2026-82226
 Unauthenticated PHP Object Injection in Tickera = 3.6.0.2 versions.

- [https://github.com/abraxas/CVE-2026-82226](https://github.com/abraxas/CVE-2026-82226) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-82226.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-82226.svg)


## CVE-2026-81642
 In NLnet Labs Unbound up to and including 1.26.0, a vulnerability was found in the DNSSEC validator that enables denial of service and possible remote code execution as a result of digesting DNSKEYs. A DNSKEY with an owner compression pointer to its own RDATA can overflow the digest buffer. Remote code execution is possible through attacker controlled data. An adversary can exploit the vulnerability by controlling a malicious zone and querying a vulnerable Unbound.

- [https://github.com/suominen/CVE-2026-81642](https://github.com/suominen/CVE-2026-81642) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-81642.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-81642.svg)


## CVE-2026-79294
 Cross Site Scripting vulnerability in Moonshot AI Kimi version as of 2026-07-18 allows a remote attacker to execute arbitrary code via the HTML artifact Preview rendering; public Share view component

- [https://github.com/MGTx2/CVE-2026-79294](https://github.com/MGTx2/CVE-2026-79294) :  ![starts](https://img.shields.io/github/stars/MGTx2/CVE-2026-79294.svg) ![forks](https://img.shields.io/github/forks/MGTx2/CVE-2026-79294.svg)


## CVE-2026-77991
 Joomla Extension - joomlaeventmanager.net - Privileged remote code execution in Joomla Event Manager  5.0.1 - The administrator source model allows to write dangerous file type incl. PHP, leading to remote code execution.

- [https://github.com/abraxas/CVE-2026-77991](https://github.com/abraxas/CVE-2026-77991) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-77991.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-77991.svg)


## CVE-2026-75827
 Grav before 2.0.15 contains an arbitrary file write vulnerability in the Blueprint dynamic-data bare-function validation that uses an incomplete denylist instead of a positive allowlist. Attackers with page-edit or blueprint-config access can invoke the error_log function through a data directive to append PHP payloads to web-accessible files, achieving remote code execution.

- [https://github.com/abraxas/CVE-2026-75827](https://github.com/abraxas/CVE-2026-75827) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-75827.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-75827.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/RMDycz/K80Pro-miro-CVE-2026-64560](https://github.com/RMDycz/K80Pro-miro-CVE-2026-64560) :  ![starts](https://img.shields.io/github/stars/RMDycz/K80Pro-miro-CVE-2026-64560.svg) ![forks](https://img.shields.io/github/forks/RMDycz/K80Pro-miro-CVE-2026-64560.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/arvindear/wp2shell-PoC](https://github.com/arvindear/wp2shell-PoC) :  ![starts](https://img.shields.io/github/stars/arvindear/wp2shell-PoC.svg) ![forks](https://img.shields.io/github/forks/arvindear/wp2shell-PoC.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/arvindear/wp2shell-PoC](https://github.com/arvindear/wp2shell-PoC) :  ![starts](https://img.shields.io/github/stars/arvindear/wp2shell-PoC.svg) ![forks](https://img.shields.io/github/forks/arvindear/wp2shell-PoC.svg)


## CVE-2026-45140
 Chamilo LMS is an open-source learning management system. Prior to 2.0.1, Chamilo LMS allows an unauthenticated remote attacker to execute arbitrary code on the server. The authoritative advisory does not identify the affected endpoint, component, input, or exploitation mechanism. This issue is fixed in version 2.0.1.

- [https://github.com/abraxas/CVE-2026-45140](https://github.com/abraxas/CVE-2026-45140) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-45140.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-45140.svg)


## CVE-2026-18574
 An authentication bypass vulnerability in Check Point Security Management Server and Multi-Domain Security Management Server (MDS) could allow an unauthenticated remote attacker with network access to Management services to execute arbitrary commands on the Security Management Server. Successful exploitation could result in full compromise of the Security Management system. Check Point discovered this issue internally and has no indication of active exploitation.

- [https://github.com/HORKimhab/CVE-2026-18574](https://github.com/HORKimhab/CVE-2026-18574) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-18574.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-18574.svg)


## CVE-2026-18464
 The WP MAPS PRO WordPress plugin before 6.1.3 does not perform a capability check in one of its AJAX actions, which is also available to unauthenticated users, and does not restrict the operation it dispatches, allowing unauthenticated attackers to trigger uncontrolled recursion that exhausts server resources, resulting in a Denial of Service.

- [https://github.com/ghoxtbyte/CVE-2026-18464](https://github.com/ghoxtbyte/CVE-2026-18464) :  ![starts](https://img.shields.io/github/stars/ghoxtbyte/CVE-2026-18464.svg) ![forks](https://img.shields.io/github/forks/ghoxtbyte/CVE-2026-18464.svg)


## CVE-2026-16265
 The WP Maps  WordPress plugin before 4.9.7 does not perform a capability check in one of its AJAX actions and does not restrict the operation it dispatches, allowing users with a Subscriber account to trigger uncontrolled recursion that exhausts server resources, resulting in a Denial of Service.

- [https://github.com/ghoxtbyte/CVE-2026-16265](https://github.com/ghoxtbyte/CVE-2026-16265) :  ![starts](https://img.shields.io/github/stars/ghoxtbyte/CVE-2026-16265.svg) ![forks](https://img.shields.io/github/forks/ghoxtbyte/CVE-2026-16265.svg)


## CVE-2026-8726
 The extension fails to properly sanitize user input before using it in a database query. As a result, an unauthenticated attacker can inject arbitrary SQL through a URL parameter on pages using the "Date Menu of news articles" plugin. Exploitation requires the "Date Menu of news articles" plugin to be in use and the TypoScript/Plugin setting disableOverrideDemand not to be enabled.

- [https://github.com/Shentao83/news-8.6.0-cve-2026-8726-backport](https://github.com/Shentao83/news-8.6.0-cve-2026-8726-backport) :  ![starts](https://img.shields.io/github/stars/Shentao83/news-8.6.0-cve-2026-8726-backport.svg) ![forks](https://img.shields.io/github/forks/Shentao83/news-8.6.0-cve-2026-8726-backport.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/MuhamadRifkii/CVE-2026-43499-POCO-X3-GT](https://github.com/MuhamadRifkii/CVE-2026-43499-POCO-X3-GT) :  ![starts](https://img.shields.io/github/stars/MuhamadRifkii/CVE-2026-43499-POCO-X3-GT.svg) ![forks](https://img.shields.io/github/forks/MuhamadRifkii/CVE-2026-43499-POCO-X3-GT.svg)


## CVE-2026-4282
 A flaw was found in Keycloak. The SingleUseObjectProvider, a global key-value store, lacks proper type and namespace isolation. This vulnerability allows an unauthenticated attacker to forge authorization codes. Successful exploitation can lead to the creation of admin-capable access tokens, resulting in privilege escalation.

- [https://github.com/hex0user/CVE-2026-4282-Scanner](https://github.com/hex0user/CVE-2026-4282-Scanner) :  ![starts](https://img.shields.io/github/stars/hex0user/CVE-2026-4282-Scanner.svg) ![forks](https://img.shields.io/github/forks/hex0user/CVE-2026-4282-Scanner.svg)


## CVE-2026-1731
 BeyondTrust Remote Support (RS) and certain older versions of Privileged Remote Access (PRA) contain a critical pre-authentication remote code execution vulnerability. By sending specially crafted requests, an unauthenticated remote attacker may be able to execute operating system commands in the context of the site user.

- [https://github.com/hex0user/CVE-2026-1731](https://github.com/hex0user/CVE-2026-1731) :  ![starts](https://img.shields.io/github/stars/hex0user/CVE-2026-1731.svg) ![forks](https://img.shields.io/github/forks/hex0user/CVE-2026-1731.svg)


## CVE-2025-69295
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in TeconceTheme Coven Core coven-core allows Blind SQL Injection.This issue affects Coven Core: from n/a through = 1.3.

- [https://github.com/hex0user/CVE-2025-69295](https://github.com/hex0user/CVE-2025-69295) :  ![starts](https://img.shields.io/github/stars/hex0user/CVE-2025-69295.svg) ![forks](https://img.shields.io/github/forks/hex0user/CVE-2025-69295.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/damnkrishna/CVE-2025-32433-LAB](https://github.com/damnkrishna/CVE-2025-32433-LAB) :  ![starts](https://img.shields.io/github/stars/damnkrishna/CVE-2025-32433-LAB.svg) ![forks](https://img.shields.io/github/forks/damnkrishna/CVE-2025-32433-LAB.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2024-49138
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/basitsajidSOC/SOC-Investigation-CVE-2024-49138](https://github.com/basitsajidSOC/SOC-Investigation-CVE-2024-49138) :  ![starts](https://img.shields.io/github/stars/basitsajidSOC/SOC-Investigation-CVE-2024-49138.svg) ![forks](https://img.shields.io/github/forks/basitsajidSOC/SOC-Investigation-CVE-2024-49138.svg)


## CVE-2024-30804
 An issue discovered in the DeviceIoControl component in ASUS Fan_Xpert before v.10013 allows an attacker to execute arbitrary code via crafted IOCTL requests.

- [https://github.com/Geozstevenzz/CVE-2024-30804](https://github.com/Geozstevenzz/CVE-2024-30804) :  ![starts](https://img.shields.io/github/stars/Geozstevenzz/CVE-2024-30804.svg) ![forks](https://img.shields.io/github/forks/Geozstevenzz/CVE-2024-30804.svg)


## CVE-2024-28157
 Jenkins GitBucket Plugin 0.8 and earlier does not sanitize Gitbucket URLs on build views, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to configure jobs.

- [https://github.com/Jayesh-Dev21/PoC_CVE-2024-28157](https://github.com/Jayesh-Dev21/PoC_CVE-2024-28157) :  ![starts](https://img.shields.io/github/stars/Jayesh-Dev21/PoC_CVE-2024-28157.svg) ![forks](https://img.shields.io/github/forks/Jayesh-Dev21/PoC_CVE-2024-28157.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe](https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/JohnRyk/ICMPShock3](https://github.com/JohnRyk/ICMPShock3) :  ![starts](https://img.shields.io/github/stars/JohnRyk/ICMPShock3.svg) ![forks](https://img.shields.io/github/forks/JohnRyk/ICMPShock3.svg)

