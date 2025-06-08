# Update 2025-06-08
## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/hakaioffsec/CVE-2025-49113-exploit](https://github.com/hakaioffsec/CVE-2025-49113-exploit) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2025-49113-exploit.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2025-49113-exploit.svg)
- [https://github.com/SyFi/CVE-2025-49113](https://github.com/SyFi/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/SyFi/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/SyFi/CVE-2025-49113.svg)


## CVE-2025-31710
 In engineermode service, there is a possible command injection due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/Skorpion96/unisoc-su](https://github.com/Skorpion96/unisoc-su) :  ![starts](https://img.shields.io/github/stars/Skorpion96/unisoc-su.svg) ![forks](https://img.shields.io/github/forks/Skorpion96/unisoc-su.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-31161](https://github.com/B1ack4sh/Blackash-CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-31161.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/HaGsec/CVE-2025-30208](https://github.com/HaGsec/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/HaGsec/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/HaGsec/CVE-2025-30208.svg)


## CVE-2025-27580
 NIH BRICS (aka Biomedical Research Informatics Computing System) through 14.0.0-67 generates predictable tokens (that depend on username, time, and the fixed 7Dl9#dj- string) and thus allows unauthenticated users with a Common Access Card (CAC) to escalate privileges and compromise any account, including administrators.

- [https://github.com/TrustStackSecurity/CVE-2025-27580](https://github.com/TrustStackSecurity/CVE-2025-27580) :  ![starts](https://img.shields.io/github/stars/TrustStackSecurity/CVE-2025-27580.svg) ![forks](https://img.shields.io/github/forks/TrustStackSecurity/CVE-2025-27580.svg)


## CVE-2025-27152
 axios is a promise based HTTP client for the browser and node.js. The issue occurs when passing absolute URLs rather than protocol-relative URLs to axios. Even if ⁠baseURL is set, axios sends the request to the specified absolute URL, potentially causing SSRF and credential leakage. This issue impacts both server-side and client-side usage of axios. This issue is fixed in 1.8.2.

- [https://github.com/davidblakecoe/axios-CVE-2025-27152-PoC](https://github.com/davidblakecoe/axios-CVE-2025-27152-PoC) :  ![starts](https://img.shields.io/github/stars/davidblakecoe/axios-CVE-2025-27152-PoC.svg) ![forks](https://img.shields.io/github/forks/davidblakecoe/axios-CVE-2025-27152-PoC.svg)


## CVE-2025-24076
 Improper access control in Windows Cross Device Service allows an authorized attacker to elevate privileges locally.

- [https://github.com/mbanyamer/CVE-2025-24076](https://github.com/mbanyamer/CVE-2025-24076) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2025-24076.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2025-24076.svg)


## CVE-2025-5054
When handling a crash, the function `_check_global_pid_and_forward`, which detects if the crashing process resided in a container, was being called before `consistency_checks`, which attempts to detect if the crashing process had been replaced. Because of this, if a process crashed and was quickly replaced with a containerized one, apport could be made to forward the core dump to the container, potentially leaking sensitive information. `consistency_checks` is now being called before `_check_global_pid_and_forward`. Additionally, given that the PID-reuse race condition cannot be reliably detected from userspace alone, crashes are only forwarded to containers if the kernel provided a pidfd, or if the crashing process was unprivileged (i.e., if dump mode == 1).

- [https://github.com/daryllundy/cve-2025-5054](https://github.com/daryllundy/cve-2025-5054) :  ![starts](https://img.shields.io/github/stars/daryllundy/cve-2025-5054.svg) ![forks](https://img.shields.io/github/forks/daryllundy/cve-2025-5054.svg)


## CVE-2025-4123
The default Content-Security-Policy (CSP) in Grafana will block the XSS though the `connect-src` directive.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-4123](https://github.com/B1ack4sh/Blackash-CVE-2025-4123) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-4123.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-4123.svg)


## CVE-2025-3102
 The SureTriggers: All-in-One Automation Platform plugin for WordPress is vulnerable to an authentication bypass leading to administrative account creation due to a missing empty value check on the 'secret_key' value in the 'autheticate_user' function in all versions up to, and including, 1.0.78. This makes it possible for unauthenticated attackers to create administrator accounts on the target website when the plugin is installed and activated but not configured with an API key.

- [https://github.com/baribut/CVE-2025-3102](https://github.com/baribut/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/baribut/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/baribut/CVE-2025-3102.svg)


## CVE-2024-31982
 XWiki Platform is a generic wiki platform. Starting in version 2.4-milestone-1 and prior to versions 4.10.20, 15.5.4, and 15.10-rc-1, XWiki's database search allows remote code execution through the search text. This allows remote code execution for any visitor of a public wiki or user of a closed wiki as the database search is by default accessible for all users. This impacts the confidentiality, integrity and availability of the whole XWiki installation. This vulnerability has been patched in XWiki 14.10.20, 15.5.4 and 15.10RC1. As a workaround, one may manually apply the patch to the page `Main.DatabaseSearch`. Alternatively, unless database search is explicitly used by users, this page can be deleted as this is not the default search interface of XWiki.

- [https://github.com/NanoWraith/CVE-2024-31982](https://github.com/NanoWraith/CVE-2024-31982) :  ![starts](https://img.shields.io/github/stars/NanoWraith/CVE-2024-31982.svg) ![forks](https://img.shields.io/github/forks/NanoWraith/CVE-2024-31982.svg)


## CVE-2024-29973
The command injection vulnerability in the “setCookie” parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.

- [https://github.com/NanoWraith/CVE-2024-29973](https://github.com/NanoWraith/CVE-2024-29973) :  ![starts](https://img.shields.io/github/stars/NanoWraith/CVE-2024-29973.svg) ![forks](https://img.shields.io/github/forks/NanoWraith/CVE-2024-29973.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/NanoWraith/CVE-2024-25600](https://github.com/NanoWraith/CVE-2024-25600) :  ![starts](https://img.shields.io/github/stars/NanoWraith/CVE-2024-25600.svg) ![forks](https://img.shields.io/github/forks/NanoWraith/CVE-2024-25600.svg)


## CVE-2024-23692
 Rejetto HTTP File Server, up to and including version 2.3m, is vulnerable to a template injection vulnerability. This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the affected system by sending a specially crafted HTTP request. As of the CVE assignment date, Rejetto HFS 2.3m is no longer supported.

- [https://github.com/NanoWraith/CVE-2024-23692](https://github.com/NanoWraith/CVE-2024-23692) :  ![starts](https://img.shields.io/github/stars/NanoWraith/CVE-2024-23692.svg) ![forks](https://img.shields.io/github/forks/NanoWraith/CVE-2024-23692.svg)


## CVE-2024-21006
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/d3fudd/CVE-2024-21006_POC](https://github.com/d3fudd/CVE-2024-21006_POC) :  ![starts](https://img.shields.io/github/stars/d3fudd/CVE-2024-21006_POC.svg) ![forks](https://img.shields.io/github/forks/d3fudd/CVE-2024-21006_POC.svg)


## CVE-2024-20674
 Windows Kerberos Security Feature Bypass Vulnerability

- [https://github.com/gpotter2/CVE-2024-20674](https://github.com/gpotter2/CVE-2024-20674) :  ![starts](https://img.shields.io/github/stars/gpotter2/CVE-2024-20674.svg) ![forks](https://img.shields.io/github/forks/gpotter2/CVE-2024-20674.svg)


## CVE-2024-5084
 The Hash Form – Drag & Drop Form Builder plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'file_upload_action' function in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/NanoWraith/CVE-2024-5084](https://github.com/NanoWraith/CVE-2024-5084) :  ![starts](https://img.shields.io/github/stars/NanoWraith/CVE-2024-5084.svg) ![forks](https://img.shields.io/github/forks/NanoWraith/CVE-2024-5084.svg)


## CVE-2022-24500
 Windows SMB Remote Code Execution Vulnerability

- [https://github.com/0x7n6/CVE-2022-24500](https://github.com/0x7n6/CVE-2022-24500) :  ![starts](https://img.shields.io/github/stars/0x7n6/CVE-2022-24500.svg) ![forks](https://img.shields.io/github/forks/0x7n6/CVE-2022-24500.svg)


## CVE-2021-4191
 An issue has been discovered in GitLab CE/EE affecting versions 13.0 to 14.6.5, 14.7 to 14.7.4, and 14.8 to 14.8.2. Private GitLab instances with restricted sign-ups may be vulnerable to user enumeration to unauthenticated users through the GraphQL API.

- [https://github.com/zkeerthan/GitLab-Enumerator](https://github.com/zkeerthan/GitLab-Enumerator) :  ![starts](https://img.shields.io/github/stars/zkeerthan/GitLab-Enumerator.svg) ![forks](https://img.shields.io/github/forks/zkeerthan/GitLab-Enumerator.svg)


## CVE-2020-14871
 Vulnerability in the Oracle Solaris product of Oracle Systems (component: Pluggable authentication module). Supported versions that are affected are 10 and 11. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Solaris. While the vulnerability is in Oracle Solaris, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle Solaris. Note: This CVE is not exploitable for Solaris 11.1 and later releases, and ZFSSA 8.7 and later releases, thus the CVSS Base Score is 0.0. CVSS 3.1 Base Score 10.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/FromPartsUnknown/CoreTrawler](https://github.com/FromPartsUnknown/CoreTrawler) :  ![starts](https://img.shields.io/github/stars/FromPartsUnknown/CoreTrawler.svg) ![forks](https://img.shields.io/github/forks/FromPartsUnknown/CoreTrawler.svg)

