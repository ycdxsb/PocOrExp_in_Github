# Update 2025-04-07
## CVE-2025-32118
 Unrestricted Upload of File with Dangerous Type vulnerability in NiteoThemes CMP – Coming Soon & Maintenance allows Using Malicious Files. This issue affects CMP – Coming Soon & Maintenance: from n/a through 4.1.13.

- [https://github.com/Nxploited/CVE-2025-32118](https://github.com/Nxploited/CVE-2025-32118) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-32118.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-32118.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/lilil3333/Vite-CVE-2025-30208-EXP](https://github.com/lilil3333/Vite-CVE-2025-30208-EXP) :  ![starts](https://img.shields.io/github/stars/lilil3333/Vite-CVE-2025-30208-EXP.svg) ![forks](https://img.shields.io/github/forks/lilil3333/Vite-CVE-2025-30208-EXP.svg)


## CVE-2025-30065
Users are recommended to upgrade to version 1.15.1, which fixes the issue.

- [https://github.com/ron-imperva/CVE-2025-30065-PoC](https://github.com/ron-imperva/CVE-2025-30065-PoC) :  ![starts](https://img.shields.io/github/stars/ron-imperva/CVE-2025-30065-PoC.svg) ![forks](https://img.shields.io/github/forks/ron-imperva/CVE-2025-30065-PoC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/Balajih4kr/cve-2025-29927](https://github.com/Balajih4kr/cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/Balajih4kr/cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Balajih4kr/cve-2025-29927.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/AsaL1n/CVE-2025-24813](https://github.com/AsaL1n/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/AsaL1n/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/AsaL1n/CVE-2025-24813.svg)


## CVE-2025-1265
 An OS command injection vulnerability exists in Vinci Protocol Analyzer that could allow an attacker to escalate privileges and perform code execution on affected system.

- [https://github.com/ThoristKaw/Anydesk-Exploit-CVE-2025-12654-RCE-Builder](https://github.com/ThoristKaw/Anydesk-Exploit-CVE-2025-12654-RCE-Builder) :  ![starts](https://img.shields.io/github/stars/ThoristKaw/Anydesk-Exploit-CVE-2025-12654-RCE-Builder.svg) ![forks](https://img.shields.io/github/forks/ThoristKaw/Anydesk-Exploit-CVE-2025-12654-RCE-Builder.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoRay/CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2022-39299-Research.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)
- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2018-14714
 System command injection in appGet.cgi on ASUS RT-AC3200 version 3.0.0.4.382.50010 allows attackers to execute system commands via the "load_script" URL parameter.

- [https://github.com/ediop3SquadALT/TimeInjector](https://github.com/ediop3SquadALT/TimeInjector) :  ![starts](https://img.shields.io/github/stars/ediop3SquadALT/TimeInjector.svg) ![forks](https://img.shields.io/github/forks/ediop3SquadALT/TimeInjector.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/madanokr001/CVE-2011-2523](https://github.com/madanokr001/CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/madanokr001/CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/madanokr001/CVE-2011-2523.svg)

