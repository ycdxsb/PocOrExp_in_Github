# Update 2025-04-11
## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/llussiess/CVE-2025-31161](https://github.com/llussiess/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/llussiess/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/llussiess/CVE-2025-31161.svg)


## CVE-2025-31125
 Vite is a frontend tooling framework for javascript. Vite exposes content of non-allowed files using ?inline&import or ?raw?import. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. This vulnerability is fixed in 6.2.4, 6.1.3, 6.0.13, 5.4.16, and 4.5.11.

- [https://github.com/jackieya/ViteVulScan](https://github.com/jackieya/ViteVulScan) :  ![starts](https://img.shields.io/github/stars/jackieya/ViteVulScan.svg) ![forks](https://img.shields.io/github/forks/jackieya/ViteVulScan.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/jackieya/ViteVulScan](https://github.com/jackieya/ViteVulScan) :  ![starts](https://img.shields.io/github/stars/jackieya/ViteVulScan.svg) ![forks](https://img.shields.io/github/forks/jackieya/ViteVulScan.svg)
- [https://github.com/4xura/CVE-2025-30208](https://github.com/4xura/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/4xura/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/4xura/CVE-2025-30208.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/l1uk/nextjs-middleware-exploit](https://github.com/l1uk/nextjs-middleware-exploit) :  ![starts](https://img.shields.io/github/stars/l1uk/nextjs-middleware-exploit.svg) ![forks](https://img.shields.io/github/forks/l1uk/nextjs-middleware-exploit.svg)


## CVE-2025-29810
 Improper access control in Active Directory Domain Services allows an authorized attacker to elevate privileges over a network.

- [https://github.com/aleongx/CVE-2025-29810-check](https://github.com/aleongx/CVE-2025-29810-check) :  ![starts](https://img.shields.io/github/stars/aleongx/CVE-2025-29810-check.svg) ![forks](https://img.shields.io/github/forks/aleongx/CVE-2025-29810-check.svg)


## CVE-2025-29018
 A Stored Cross-Site Scripting (XSS) vulnerability exists in the name parameter of pages_add_acc_type.php in Code Astro Internet Banking System 2.0.0.

- [https://github.com/b1tm4r/CVE-2025-29018](https://github.com/b1tm4r/CVE-2025-29018) :  ![starts](https://img.shields.io/github/stars/b1tm4r/CVE-2025-29018.svg) ![forks](https://img.shields.io/github/forks/b1tm4r/CVE-2025-29018.svg)


## CVE-2025-26647
 Improper input validation in Windows Kerberos allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/groshi215/CVE-2025-26647-Exploit](https://github.com/groshi215/CVE-2025-26647-Exploit) :  ![starts](https://img.shields.io/github/stars/groshi215/CVE-2025-26647-Exploit.svg) ![forks](https://img.shields.io/github/forks/groshi215/CVE-2025-26647-Exploit.svg)


## CVE-2025-24985
 Integer overflow or wraparound in Windows Fast FAT Driver allows an unauthorized attacker to execute code locally.

- [https://github.com/airbus-cert/cve-2025-24985](https://github.com/airbus-cert/cve-2025-24985) :  ![starts](https://img.shields.io/github/stars/airbus-cert/cve-2025-24985.svg) ![forks](https://img.shields.io/github/forks/airbus-cert/cve-2025-24985.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/f8l124/CVE-2025-24813-POC](https://github.com/f8l124/CVE-2025-24813-POC) :  ![starts](https://img.shields.io/github/stars/f8l124/CVE-2025-24813-POC.svg) ![forks](https://img.shields.io/github/forks/f8l124/CVE-2025-24813-POC.svg)


## CVE-2025-24221
 This issue was addressed with improved data access restriction. This issue is fixed in visionOS 2.4, iOS 18.4 and iPadOS 18.4, iPadOS 17.7.6. Sensitive keychain data may be accessible from an iOS backup.

- [https://github.com/AnonymousDeveloper69/CVE-2025-24221](https://github.com/AnonymousDeveloper69/CVE-2025-24221) :  ![starts](https://img.shields.io/github/stars/AnonymousDeveloper69/CVE-2025-24221.svg) ![forks](https://img.shields.io/github/forks/AnonymousDeveloper69/CVE-2025-24221.svg)


## CVE-2024-56071
 Incorrect Privilege Assignment vulnerability in Mike Leembruggen Simple Dashboard allows Privilege Escalation.This issue affects Simple Dashboard: from n/a through 2.0.

- [https://github.com/Nxploited/CVE-2024-56071](https://github.com/Nxploited/CVE-2024-56071) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-56071.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-56071.svg)


## CVE-2024-55210
 An issue in TOTVS Framework (Linha Protheus) 12.1.2310 allows attackers to bypass multi-factor authentication (MFA) via a crafted websocket message.

- [https://github.com/c4cnm/CVE-2024-55210](https://github.com/c4cnm/CVE-2024-55210) :  ![starts](https://img.shields.io/github/stars/c4cnm/CVE-2024-55210.svg) ![forks](https://img.shields.io/github/forks/c4cnm/CVE-2024-55210.svg)


## CVE-2024-48887
 A  unverified password change vulnerability in Fortinet FortiSwitch GUI may allow a remote unauthenticated attacker to change admin passwords via a specially crafted request

- [https://github.com/IndominusRexes/CVE-2024-48887-Exploit](https://github.com/IndominusRexes/CVE-2024-48887-Exploit) :  ![starts](https://img.shields.io/github/stars/IndominusRexes/CVE-2024-48887-Exploit.svg) ![forks](https://img.shields.io/github/forks/IndominusRexes/CVE-2024-48887-Exploit.svg)
- [https://github.com/cybersecplayground/CVE-2024-48887-FortiSwitch-Exploit](https://github.com/cybersecplayground/CVE-2024-48887-FortiSwitch-Exploit) :  ![starts](https://img.shields.io/github/stars/cybersecplayground/CVE-2024-48887-FortiSwitch-Exploit.svg) ![forks](https://img.shields.io/github/forks/cybersecplayground/CVE-2024-48887-FortiSwitch-Exploit.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/ivanbg2004/ODH-BricksBuilder-CVE-2024-25600-THM](https://github.com/ivanbg2004/ODH-BricksBuilder-CVE-2024-25600-THM) :  ![starts](https://img.shields.io/github/stars/ivanbg2004/ODH-BricksBuilder-CVE-2024-25600-THM.svg) ![forks](https://img.shields.io/github/forks/ivanbg2004/ODH-BricksBuilder-CVE-2024-25600-THM.svg)


## CVE-2024-21513
AT:P: An attacker needs to be able to influence the input prompt, whilst the server is configured with the VectorSQLDatabaseChain plugin.

- [https://github.com/nskath/CVE-2024-21513](https://github.com/nskath/CVE-2024-21513) :  ![starts](https://img.shields.io/github/stars/nskath/CVE-2024-21513.svg) ![forks](https://img.shields.io/github/forks/nskath/CVE-2024-21513.svg)


## CVE-2024-3640
 An unquoted executable path exists in the Rockwell Automation FactoryTalk® Remote Access™ possibly resulting in remote code execution if exploited. While running the FTRA installer package, the executable path is not properly quoted, which could allow a threat actor to enter a malicious executable and run it as a System user. A threat actor needs admin privileges to exploit this vulnerability.

- [https://github.com/H1ng007/CVE-2024-3640_WafBypass](https://github.com/H1ng007/CVE-2024-3640_WafBypass) :  ![starts](https://img.shields.io/github/stars/H1ng007/CVE-2024-3640_WafBypass.svg) ![forks](https://img.shields.io/github/forks/H1ng007/CVE-2024-3640_WafBypass.svg)


## CVE-2023-39141
 webui-aria2 commit 4fe2e was discovered to contain a path traversal vulnerability.

- [https://github.com/MartiSabate/CVE-2023-39141-LFI-enumerator](https://github.com/MartiSabate/CVE-2023-39141-LFI-enumerator) :  ![starts](https://img.shields.io/github/stars/MartiSabate/CVE-2023-39141-LFI-enumerator.svg) ![forks](https://img.shields.io/github/forks/MartiSabate/CVE-2023-39141-LFI-enumerator.svg)


## CVE-2022-37932
 A potential security vulnerability has been identified in Hewlett Packard Enterprise OfficeConnect 1820, 1850, and 1920S Network switches. The vulnerability could be remotely exploited to allow authentication bypass. HPE has made the following software updates to resolve the vulnerability in Hewlett Packard Enterprise OfficeConnect 1820, 1850 and 1920S Network switches versions: Prior to PT.02.14; Prior to PC.01.22; Prior to PO.01.21; Prior to PD.02.22;

- [https://github.com/Tim-Hoekstra/CVE-2022-37932](https://github.com/Tim-Hoekstra/CVE-2022-37932) :  ![starts](https://img.shields.io/github/stars/Tim-Hoekstra/CVE-2022-37932.svg) ![forks](https://img.shields.io/github/forks/Tim-Hoekstra/CVE-2022-37932.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.

- [https://github.com/000pp/WSOB](https://github.com/000pp/WSOB) :  ![starts](https://img.shields.io/github/stars/000pp/WSOB.svg) ![forks](https://img.shields.io/github/forks/000pp/WSOB.svg)


## CVE-2019-9670
 mailboxd component in Synacor Zimbra Collaboration Suite 8.7.x before 8.7.11p10 has an XML External Entity injection (XXE) vulnerability, as demonstrated by Autodiscover/Autodiscover.xml.

- [https://github.com/000pp/zaber](https://github.com/000pp/zaber) :  ![starts](https://img.shields.io/github/stars/000pp/zaber.svg) ![forks](https://img.shields.io/github/forks/000pp/zaber.svg)
- [https://github.com/000pp/arbimz](https://github.com/000pp/arbimz) :  ![starts](https://img.shields.io/github/stars/000pp/arbimz.svg) ![forks](https://img.shields.io/github/forks/000pp/arbimz.svg)


## CVE-2017-1000486
 Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution

- [https://github.com/000pp/pwnfaces](https://github.com/000pp/pwnfaces) :  ![starts](https://img.shields.io/github/stars/000pp/pwnfaces.svg) ![forks](https://img.shields.io/github/forks/000pp/pwnfaces.svg)

