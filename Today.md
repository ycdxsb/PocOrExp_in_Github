# Update 2026-08-10
## CVE-2026-67620
 Flowise through 3.1.4 contains a server-side request forgery vulnerability in the SSRF guard implemented in httpSecurity.ts, where the DEFAULT_DENY_LIST omits the Oracle Cloud Infrastructure metadata endpoint 192.0.0.192 and the Alibaba Cloud metadata endpoint 100.100.100.200, allowing authenticated attackers to force the server to issue arbitrary GET requests to cloud instance metadata services. Attackers can send requests to the fetch-links API endpoint with a crafted URL parameter, bypassing deny-list validation including redirect-based bypasses, to reach instance metadata services and expose instance identity data and role credentials on Oracle Cloud Infrastructure or Alibaba Cloud deployments, with unauthenticated access possible when URL-fetching nodes exist in public chatflows.

- [https://github.com/abdugafforov-bobur/CVE-2026-67620-poc](https://github.com/abdugafforov-bobur/CVE-2026-67620-poc) :  ![starts](https://img.shields.io/github/stars/abdugafforov-bobur/CVE-2026-67620-poc.svg) ![forks](https://img.shields.io/github/forks/abdugafforov-bobur/CVE-2026-67620-poc.svg)


## CVE-2026-66493
 Joomla Extension - phoca.cz - Path Traversal vulnerability in Phoca Commander 1.0.0-6.1.3 - Improper limitation of paths for delete, copy and move actions lead to path traversal vulnerabilities.

- [https://github.com/toanln-cov/CVE-2026-66493](https://github.com/toanln-cov/CVE-2026-66493) :  ![starts](https://img.shields.io/github/stars/toanln-cov/CVE-2026-66493.svg) ![forks](https://img.shields.io/github/forks/toanln-cov/CVE-2026-66493.svg)


## CVE-2026-66492
 Joomla Extension - phoca.cz - Path Traversal vulnerability in Phoca Commander 1.0.0-6.1.3 - Improper limitation of paths in the file upload action lead to path a traversal vulnerability.

- [https://github.com/toanln-cov/CVE-2026-66492](https://github.com/toanln-cov/CVE-2026-66492) :  ![starts](https://img.shields.io/github/stars/toanln-cov/CVE-2026-66492.svg) ![forks](https://img.shields.io/github/forks/toanln-cov/CVE-2026-66492.svg)


## CVE-2026-66491
 Joomla Extension - phoca.cz - Arbitrary File Read in Phoca Commander 1.0.0-6.1.3 - Improper limitation of paths in the getSource function lead to an arbitrary file read vulnerability.

- [https://github.com/toanln-cov/CVE-2026-66491](https://github.com/toanln-cov/CVE-2026-66491) :  ![starts](https://img.shields.io/github/stars/toanln-cov/CVE-2026-66491.svg) ![forks](https://img.shields.io/github/forks/toanln-cov/CVE-2026-66491.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/4minx/CVE-2026-64638](https://github.com/4minx/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/4minx/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/4minx/CVE-2026-64638.svg)
- [https://github.com/HackSpeak/CVE-2026-64638](https://github.com/HackSpeak/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-64638.svg)
- [https://github.com/imbas007/CVE-2026-64638-POC](https://github.com/imbas007/CVE-2026-64638-POC) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2026-64638-POC.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2026-64638-POC.svg)
- [https://github.com/tc4dy/CVE-2026-64638-PoC-Exploit](https://github.com/tc4dy/CVE-2026-64638-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-64638-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-64638-PoC-Exploit.svg)
- [https://github.com/yogaGymn/XSS2Shell-CVE-2026-64638](https://github.com/yogaGymn/XSS2Shell-CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/yogaGymn/XSS2Shell-CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/yogaGymn/XSS2Shell-CVE-2026-64638.svg)
- [https://github.com/HORKimhab/CVE-2026-64638](https://github.com/HORKimhab/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-64638.svg)
- [https://github.com/Dungsocool/CVE-2026-64638](https://github.com/Dungsocool/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2026-64638.svg)
- [https://github.com/mohwahyudi/poc-CVE-2026-64638-](https://github.com/mohwahyudi/poc-CVE-2026-64638-) :  ![starts](https://img.shields.io/github/stars/mohwahyudi/poc-CVE-2026-64638-.svg) ![forks](https://img.shields.io/github/forks/mohwahyudi/poc-CVE-2026-64638-.svg)
- [https://github.com/jendmaoul/XSS2Shell-CVE-2026-64638](https://github.com/jendmaoul/XSS2Shell-CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/jendmaoul/XSS2Shell-CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/jendmaoul/XSS2Shell-CVE-2026-64638.svg)
- [https://github.com/MR-LeonardoGomes/XSS2Shell-CVE-2026-64638](https://github.com/MR-LeonardoGomes/XSS2Shell-CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/MR-LeonardoGomes/XSS2Shell-CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/MR-LeonardoGomes/XSS2Shell-CVE-2026-64638.svg)


## CVE-2026-64600
sequence counter changes across the ILOCK cycle.

- [https://github.com/masrikky/CVE-2026-64600-RefluXFS](https://github.com/masrikky/CVE-2026-64600-RefluXFS) :  ![starts](https://img.shields.io/github/stars/masrikky/CVE-2026-64600-RefluXFS.svg) ![forks](https://img.shields.io/github/forks/masrikky/CVE-2026-64600-RefluXFS.svg)


## CVE-2026-64561
far from ideal; that flaw will be addressed separately.

- [https://github.com/HackSpeak/CVE-2026-64561](https://github.com/HackSpeak/CVE-2026-64561) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-64561.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-64561.svg)
- [https://github.com/chuzhongyun/CVE-2026-64561-Kernel-Fix](https://github.com/chuzhongyun/CVE-2026-64561-Kernel-Fix) :  ![starts](https://img.shields.io/github/stars/chuzhongyun/CVE-2026-64561-Kernel-Fix.svg) ![forks](https://img.shields.io/github/forks/chuzhongyun/CVE-2026-64561-Kernel-Fix.svg)


## CVE-2026-63077
 In JetBrains TeamCity before 2026.1.3, 2025.11.7 unauthenticated remote code execution was possible via the agent polling protocol

- [https://github.com/AnggaTechI/CVE-2026-63077](https://github.com/AnggaTechI/CVE-2026-63077) :  ![starts](https://img.shields.io/github/stars/AnggaTechI/CVE-2026-63077.svg) ![forks](https://img.shields.io/github/forks/AnggaTechI/CVE-2026-63077.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/M4xSec/wp2shell-Exploit-Waf-Bypass](https://github.com/M4xSec/wp2shell-Exploit-Waf-Bypass) :  ![starts](https://img.shields.io/github/stars/M4xSec/wp2shell-Exploit-Waf-Bypass.svg) ![forks](https://img.shields.io/github/forks/M4xSec/wp2shell-Exploit-Waf-Bypass.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/M4xSec/wp2shell-Exploit-Waf-Bypass](https://github.com/M4xSec/wp2shell-Exploit-Waf-Bypass) :  ![starts](https://img.shields.io/github/stars/M4xSec/wp2shell-Exploit-Waf-Bypass.svg) ![forks](https://img.shields.io/github/forks/M4xSec/wp2shell-Exploit-Waf-Bypass.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/wxxsfxyzm/GhostLock-Galaxy](https://github.com/wxxsfxyzm/GhostLock-Galaxy) :  ![starts](https://img.shields.io/github/stars/wxxsfxyzm/GhostLock-Galaxy.svg) ![forks](https://img.shields.io/github/forks/wxxsfxyzm/GhostLock-Galaxy.svg)


## CVE-2026-27912
 Improper authorization in Windows Kerberos allows an authorized attacker to elevate privileges over an adjacent network.

- [https://github.com/mihat2/ResetNightmare-impacket](https://github.com/mihat2/ResetNightmare-impacket) :  ![starts](https://img.shields.io/github/stars/mihat2/ResetNightmare-impacket.svg) ![forks](https://img.shields.io/github/forks/mihat2/ResetNightmare-impacket.svg)


## CVE-2026-19195
 A vulnerability has been found in V-Secure Jingyun Antivirus 2.4.2.39. The affected element is an unknown function in the library ZyArk.sys of the component Kernel Driver. The manipulation leads to improper access controls. The attack needs to be performed locally. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/patrickt2017/CVE-2026-19195-PoC](https://github.com/patrickt2017/CVE-2026-19195-PoC) :  ![starts](https://img.shields.io/github/stars/patrickt2017/CVE-2026-19195-PoC.svg) ![forks](https://img.shields.io/github/forks/patrickt2017/CVE-2026-19195-PoC.svg)


## CVE-2026-19193
 A flaw has been found in Jiangmin Antivirus 21. Impacted is the function MessageNotifyCallback in the library kvcore.sys of the component Minifilter Port. Executing a manipulation can lead to improper access controls. The attack needs to be launched locally. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/patrickt2017/CVE-2026-19193-PoC](https://github.com/patrickt2017/CVE-2026-19193-PoC) :  ![starts](https://img.shields.io/github/stars/patrickt2017/CVE-2026-19193-PoC.svg) ![forks](https://img.shields.io/github/forks/patrickt2017/CVE-2026-19193-PoC.svg)


## CVE-2026-6000
 A vulnerability was found in code-projects Online Library Management System 1.0. Affected is an unknown function of the file /sql/library.sql of the component SQL Database Backup File Handler. Performing a manipulation results in information disclosure. The attack may be initiated remotely. The exploit has been made public and could be used.

- [https://github.com/gagaltotal/CVE-2026-60004-poc-gitea](https://github.com/gagaltotal/CVE-2026-60004-poc-gitea) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-60004-poc-gitea.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-60004-poc-gitea.svg)


## CVE-2026-3844
 The Breeze Cache plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'fetch_gravatar_from_remote' function in all versions up to, and including, 2.4.4. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. The vulnerability can only be exploited if "Host Files Locally - Gravatars" is enabled, which is disabled by default.

- [https://github.com/AnggaTechI/CVE-2026-3844](https://github.com/AnggaTechI/CVE-2026-3844) :  ![starts](https://img.shields.io/github/stars/AnggaTechI/CVE-2026-3844.svg) ![forks](https://img.shields.io/github/forks/AnggaTechI/CVE-2026-3844.svg)


## CVE-2025-48757
 An insufficient database Row-Level Security policy in Lovable through 2025-04-15 allows remote unauthenticated attackers to read or write to arbitrary database tables of generated sites. NOTE: this is disputed by the Supplier because each individual customer of the Lovable platform accepts a responsibility over protecting the data of their application.

- [https://github.com/boxed-dev/vibe-coding-security](https://github.com/boxed-dev/vibe-coding-security) :  ![starts](https://img.shields.io/github/stars/boxed-dev/vibe-coding-security.svg) ![forks](https://img.shields.io/github/forks/boxed-dev/vibe-coding-security.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)

