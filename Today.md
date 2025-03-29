# Update 2025-03-29
## CVE-2025-30355
 Synapse is an open source Matrix homeserver implementation. A malicious server can craft events which, when received, prevent Synapse version up to 1.127.0 from federating with other servers. The vulnerability has been exploited in the wild and has been fixed in Synapse v1.127.1. No known workarounds are available.

- [https://github.com/ui-bootstrap/CVE-2025-30355](https://github.com/ui-bootstrap/CVE-2025-30355) :  ![starts](https://img.shields.io/github/stars/ui-bootstrap/CVE-2025-30355.svg) ![forks](https://img.shields.io/github/forks/ui-bootstrap/CVE-2025-30355.svg)


## CVE-2025-30349
 Horde IMP through 6.2.27, as used with Horde Application Framework through 5.2.23, allows XSS that leads to account takeover via a crafted text/html e-mail message with an onerror attribute (that may use base64-encoded JavaScript code), as exploited in the wild in March 2025.

- [https://github.com/natasaka/CVE-2025-30349](https://github.com/natasaka/CVE-2025-30349) :  ![starts](https://img.shields.io/github/stars/natasaka/CVE-2025-30349.svg) ![forks](https://img.shields.io/github/forks/natasaka/CVE-2025-30349.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/On1onss/CVE-2025-30208-LFI](https://github.com/On1onss/CVE-2025-30208-LFI) :  ![starts](https://img.shields.io/github/stars/On1onss/CVE-2025-30208-LFI.svg) ![forks](https://img.shields.io/github/forks/On1onss/CVE-2025-30208-LFI.svg)
- [https://github.com/LiChaser/CVE-2025-30208](https://github.com/LiChaser/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/LiChaser/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/LiChaser/CVE-2025-30208.svg)
- [https://github.com/4xura/CVE-2025-30108](https://github.com/4xura/CVE-2025-30108) :  ![starts](https://img.shields.io/github/stars/4xura/CVE-2025-30108.svg) ![forks](https://img.shields.io/github/forks/4xura/CVE-2025-30108.svg)
- [https://github.com/iSee857/CVE-2025-30208-PoC](https://github.com/iSee857/CVE-2025-30208-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-30208-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-30208-PoC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/KaztoRay/CVE-2025-29927-Research](https://github.com/KaztoRay/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2025-29927-Research.svg)
- [https://github.com/nocomp/CVE-2025-29927-scanner](https://github.com/nocomp/CVE-2025-29927-scanner) :  ![starts](https://img.shields.io/github/stars/nocomp/CVE-2025-29927-scanner.svg) ![forks](https://img.shields.io/github/forks/nocomp/CVE-2025-29927-scanner.svg)
- [https://github.com/aleongx/CVE-2025-29927_Scanner](https://github.com/aleongx/CVE-2025-29927_Scanner) :  ![starts](https://img.shields.io/github/stars/aleongx/CVE-2025-29927_Scanner.svg) ![forks](https://img.shields.io/github/forks/aleongx/CVE-2025-29927_Scanner.svg)
- [https://github.com/Nekicj/CVE-2025-29927-exploit](https://github.com/Nekicj/CVE-2025-29927-exploit) :  ![starts](https://img.shields.io/github/stars/Nekicj/CVE-2025-29927-exploit.svg) ![forks](https://img.shields.io/github/forks/Nekicj/CVE-2025-29927-exploit.svg)
- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)
- [https://github.com/jmbowes/NextSecureScan](https://github.com/jmbowes/NextSecureScan) :  ![starts](https://img.shields.io/github/stars/jmbowes/NextSecureScan.svg) ![forks](https://img.shields.io/github/forks/jmbowes/NextSecureScan.svg)
- [https://github.com/ferpalma21/Automated-Next.js-Security-Scanner-for-CVE-2025-29927](https://github.com/ferpalma21/Automated-Next.js-Security-Scanner-for-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ferpalma21/Automated-Next.js-Security-Scanner-for-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ferpalma21/Automated-Next.js-Security-Scanner-for-CVE-2025-29927.svg)
- [https://github.com/m2hcz/m2hcz-Next.js-security-flaw-CVE-2025-29927---PoC-exploit](https://github.com/m2hcz/m2hcz-Next.js-security-flaw-CVE-2025-29927---PoC-exploit) :  ![starts](https://img.shields.io/github/stars/m2hcz/m2hcz-Next.js-security-flaw-CVE-2025-29927---PoC-exploit.svg) ![forks](https://img.shields.io/github/forks/m2hcz/m2hcz-Next.js-security-flaw-CVE-2025-29927---PoC-exploit.svg)


## CVE-2025-29306
 An issue in FoxCMS v.1.2.5 allows a remote attacker to execute arbitrary code via the case display page in the index.html component.

- [https://github.com/somatrasss/CVE-2025-29306](https://github.com/somatrasss/CVE-2025-29306) :  ![starts](https://img.shields.io/github/stars/somatrasss/CVE-2025-29306.svg) ![forks](https://img.shields.io/github/forks/somatrasss/CVE-2025-29306.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/ThemeHackers/CVE-2025-24071](https://github.com/ThemeHackers/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-24071.svg)
- [https://github.com/rubbxalc/CVE-2025-24071](https://github.com/rubbxalc/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/rubbxalc/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/rubbxalc/CVE-2025-24071.svg)
- [https://github.com/Marcejr117/CVE-2025-24071_PoC](https://github.com/Marcejr117/CVE-2025-24071_PoC) :  ![starts](https://img.shields.io/github/stars/Marcejr117/CVE-2025-24071_PoC.svg) ![forks](https://img.shields.io/github/forks/Marcejr117/CVE-2025-24071_PoC.svg)


## CVE-2025-22783
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in SEO Squirrly SEO Plugin by Squirrly SEO allows SQL Injection.This issue affects SEO Plugin by Squirrly SEO: from n/a through 12.4.03.

- [https://github.com/DoTTak/CVE-2025-22783](https://github.com/DoTTak/CVE-2025-22783) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22783.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22783.svg)


## CVE-2025-22652
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in kendysond Payment Forms for Paystack allows SQL Injection.This issue affects Payment Forms for Paystack: from n/a through 4.0.1.

- [https://github.com/DoTTak/CVE-2025-22652](https://github.com/DoTTak/CVE-2025-22652) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22652.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22652.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps](https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps) :  ![starts](https://img.shields.io/github/stars/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg) ![forks](https://img.shields.io/github/forks/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg)
- [https://github.com/tuladhar/ingress-nightmare](https://github.com/tuladhar/ingress-nightmare) :  ![starts](https://img.shields.io/github/stars/tuladhar/ingress-nightmare.svg) ![forks](https://img.shields.io/github/forks/tuladhar/ingress-nightmare.svg)
- [https://github.com/0xBingo/CVE-2025-1974](https://github.com/0xBingo/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/0xBingo/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/0xBingo/CVE-2025-1974.svg)


## CVE-2024-9474
Cloud NGFW and Prisma Access are not impacted by this vulnerability.

- [https://github.com/worthytop/CVE-2024-9474](https://github.com/worthytop/CVE-2024-9474) :  ![starts](https://img.shields.io/github/stars/worthytop/CVE-2024-9474.svg) ![forks](https://img.shields.io/github/forks/worthytop/CVE-2024-9474.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/fabulouscounc/CVE-2024-4577-PHP-RCE](https://github.com/fabulouscounc/CVE-2024-4577-PHP-RCE) :  ![starts](https://img.shields.io/github/stars/fabulouscounc/CVE-2024-4577-PHP-RCE.svg) ![forks](https://img.shields.io/github/forks/fabulouscounc/CVE-2024-4577-PHP-RCE.svg)


## CVE-2023-45806
 Discourse is an open source platform for community discussion. Prior to version 3.1.3 of the `stable` branch and version 3.2.0.beta3 of the `beta` and `tests-passed` branches, if a user has been quoted and uses a `|` in their full name, they might be able to trigger a bug that generates a lot of duplicate content in all the posts they've been quoted by updating their full name again. Version 3.1.3 of the `stable` branch and version 3.2.0.beta3 of the `beta` and `tests-passed` branches contain a patch for this issue. No known workaround exists, although one can stop the "bleeding" by ensuring users only use alphanumeric characters in their full name field.

- [https://github.com/yksivaihde/discourse-CVE-2023-45806](https://github.com/yksivaihde/discourse-CVE-2023-45806) :  ![starts](https://img.shields.io/github/stars/yksivaihde/discourse-CVE-2023-45806.svg) ![forks](https://img.shields.io/github/forks/yksivaihde/discourse-CVE-2023-45806.svg)


## CVE-2023-26209
 A improper restriction of excessive authentication attempts vulnerability [CWE-307] in Fortinet FortiDeceptor 3.1.x and before allows  a remote unauthenticated attacker to partially exhaust CPU and memory via sending numerous HTTP requests to the login form.

- [https://github.com/cnetsec/CVE-2023-26209](https://github.com/cnetsec/CVE-2023-26209) :  ![starts](https://img.shields.io/github/stars/cnetsec/CVE-2023-26209.svg) ![forks](https://img.shields.io/github/forks/cnetsec/CVE-2023-26209.svg)


## CVE-2023-26208
 A improper restriction of excessive authentication attempts vulnerability [CWE-307] in Fortinet FortiAuthenticator 6.4.x and before allows  a remote unauthenticated attacker to partially exhaust CPU and memory via sending numerous HTTP requests to the login form.

- [https://github.com/cnetsec/CVE-2023-26208](https://github.com/cnetsec/CVE-2023-26208) :  ![starts](https://img.shields.io/github/stars/cnetsec/CVE-2023-26208.svg) ![forks](https://img.shields.io/github/forks/cnetsec/CVE-2023-26208.svg)


## CVE-2023-21608
 Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/carinewlimits/Adobe-Acrobat-Reader](https://github.com/carinewlimits/Adobe-Acrobat-Reader) :  ![starts](https://img.shields.io/github/stars/carinewlimits/Adobe-Acrobat-Reader.svg) ![forks](https://img.shields.io/github/forks/carinewlimits/Adobe-Acrobat-Reader.svg)


## CVE-2021-24019
 An insufficient session expiration vulnerability [CWE- 613] in FortiClientEMS versions 6.4.2 and below, 6.2.8 and below may allow an attacker to reuse the unexpired admin user session IDs to gain admin privileges, should the attacker be able to obtain that session ID (via other, hypothetical attacks)

- [https://github.com/cnetsec/CVE-2021-24019](https://github.com/cnetsec/CVE-2021-24019) :  ![starts](https://img.shields.io/github/stars/cnetsec/CVE-2021-24019.svg) ![forks](https://img.shields.io/github/forks/cnetsec/CVE-2021-24019.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/mr-won/WebLogic_CVE_2020_14882](https://github.com/mr-won/WebLogic_CVE_2020_14882) :  ![starts](https://img.shields.io/github/stars/mr-won/WebLogic_CVE_2020_14882.svg) ![forks](https://img.shields.io/github/forks/mr-won/WebLogic_CVE_2020_14882.svg)


## CVE-2020-0618
 A remote code execution vulnerability exists in Microsoft SQL Server Reporting Services when it incorrectly handles page requests, aka 'Microsoft SQL Server Reporting Services Remote Code Execution Vulnerability'.

- [https://github.com/N3xtGenH4cker/CVE-2020-0618_DETECTION](https://github.com/N3xtGenH4cker/CVE-2020-0618_DETECTION) :  ![starts](https://img.shields.io/github/stars/N3xtGenH4cker/CVE-2020-0618_DETECTION.svg) ![forks](https://img.shields.io/github/forks/N3xtGenH4cker/CVE-2020-0618_DETECTION.svg)


## CVE-2019-9978
 The social-warfare plugin before 3.5.3 for WordPress has stored XSS via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, as exploited in the wild in March 2019. This affects Social Warfare and Social Warfare Pro.

- [https://github.com/echoosso/CVE-2019-9978](https://github.com/echoosso/CVE-2019-9978) :  ![starts](https://img.shields.io/github/stars/echoosso/CVE-2019-9978.svg) ![forks](https://img.shields.io/github/forks/echoosso/CVE-2019-9978.svg)

