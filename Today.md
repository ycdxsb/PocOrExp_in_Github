# Update 2025-05-28
## CVE-2025-32421
 Next.js is a React framework for building full-stack web applications. Versions prior to 14.2.24 and 15.1.6 have a race-condition vulnerability. This issue only affects the Pages Router under certain misconfigurations, causing normal endpoints to serve `pageProps` data instead of standard HTML. This issue was patched in versions 15.1.6 and 14.2.24 by stripping the `x-now-route-matches` header from incoming requests. Applications hosted on Vercel's platform are not affected by this issue, as the platform does not cache responses based solely on `200 OK` status without explicit `cache-control` headers. Those who self-host Next.js deployments and are unable to upgrade immediately can mitigate this vulnerability by stripping the `x-now-route-matches` header from all incoming requests at the content development network and setting `cache-control: no-store` for all responses under risk. The maintainers of Next.js strongly recommend only caching responses with explicit cache-control headers.

- [https://github.com/zeroc00I/CVE-2025-32421](https://github.com/zeroc00I/CVE-2025-32421) :  ![starts](https://img.shields.io/github/stars/zeroc00I/CVE-2025-32421.svg) ![forks](https://img.shields.io/github/forks/zeroc00I/CVE-2025-32421.svg)


## CVE-2025-30397
 Access of resource using incompatible type ('type confusion') in Microsoft Scripting Engine allows an unauthorized attacker to execute code over a network.

- [https://github.com/Leviticus-Triage/ChromSploit-Framework](https://github.com/Leviticus-Triage/ChromSploit-Framework) :  ![starts](https://img.shields.io/github/stars/Leviticus-Triage/ChromSploit-Framework.svg) ![forks](https://img.shields.io/github/forks/Leviticus-Triage/ChromSploit-Framework.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/sagsooz/CVE-2025-29927](https://github.com/sagsooz/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sagsooz/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sagsooz/CVE-2025-29927.svg)


## CVE-2025-27363
 An out of bounds write exists in FreeType versions 2.13.0 and below (newer versions of FreeType are not vulnerable) when attempting to parse font subglyph structures related to TrueType GX and variable font files. The vulnerable code assigns a signed short value to an unsigned long and then adds a static value causing it to wrap around and allocate too small of a heap buffer. The code then writes up to 6 signed long integers out of bounds relative to this buffer. This may result in arbitrary code execution. This vulnerability may have been exploited in the wild.

- [https://github.com/ov3rf1ow/CVE-2025-27363](https://github.com/ov3rf1ow/CVE-2025-27363) :  ![starts](https://img.shields.io/github/stars/ov3rf1ow/CVE-2025-27363.svg) ![forks](https://img.shields.io/github/forks/ov3rf1ow/CVE-2025-27363.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC](https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC) :  ![starts](https://img.shields.io/github/stars/helidem/CVE-2025-24054_CVE-2025-24071-PoC.svg) ![forks](https://img.shields.io/github/forks/helidem/CVE-2025-24054_CVE-2025-24071-PoC.svg)
- [https://github.com/f4dee-backup/CVE-2025-24071](https://github.com/f4dee-backup/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/f4dee-backup/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/f4dee-backup/CVE-2025-24071.svg)


## CVE-2025-24054
 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC](https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC) :  ![starts](https://img.shields.io/github/stars/helidem/CVE-2025-24054_CVE-2025-24071-PoC.svg) ![forks](https://img.shields.io/github/forks/helidem/CVE-2025-24054_CVE-2025-24071-PoC.svg)


## CVE-2025-5196
 A vulnerability has been found in Wing FTP Server up to 7.4.3 and classified as critical. Affected by this vulnerability is an unknown functionality of the component Lua Admin Console. The manipulation leads to execution with unnecessary privileges. The attack can be launched remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. Upgrading to version 7.4.4 is able to address this issue. It is recommended to upgrade the affected component. The vendor explains: "[W]e do not consider it as a security vulnerability, because the system admin in WingFTP has full permissions [...], but you can suggest the user run WingFTP service as Normal User rather than SYSTEM/Root, it will be safer."

- [https://github.com/Nouvexr/Wing-FTP-Server-7.4.4-RCE-Authenticated](https://github.com/Nouvexr/Wing-FTP-Server-7.4.4-RCE-Authenticated) :  ![starts](https://img.shields.io/github/stars/Nouvexr/Wing-FTP-Server-7.4.4-RCE-Authenticated.svg) ![forks](https://img.shields.io/github/forks/Nouvexr/Wing-FTP-Server-7.4.4-RCE-Authenticated.svg)


## CVE-2025-4664
 Insufficient policy enforcement in Loader in Google Chrome prior to 136.0.7103.113 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Leviticus-Triage/ChromSploit-Framework](https://github.com/Leviticus-Triage/ChromSploit-Framework) :  ![starts](https://img.shields.io/github/stars/Leviticus-Triage/ChromSploit-Framework.svg) ![forks](https://img.shields.io/github/forks/Leviticus-Triage/ChromSploit-Framework.svg)


## CVE-2025-4389
 The Crawlomatic Multipage Scraper Post Generator plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the crawlomatic_generate_featured_image() function in all versions up to, and including, 2.6.8.1. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Yucaerin/CVE-2025-4389](https://github.com/Yucaerin/CVE-2025-4389) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-4389.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-4389.svg)


## CVE-2025-2907
 The Order Delivery Date WordPress plugin before 12.3.1 does not have authorization and CSRF checks when importing settings. Furthermore it also lacks proper checks to only update options relevant to the Order Delivery Date WordPress plugin before 12.3.1. This leads to attackers being able to modify the default_user_role to administrator and users_can_register, allowing them to register as an administrator of the site for complete site takeover.

- [https://github.com/Yucaerin/CVE-2025-2907](https://github.com/Yucaerin/CVE-2025-2907) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-2907.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-2907.svg)


## CVE-2025-2857
*This only affects Firefox on Windows. Other operating systems are unaffected.* This vulnerability affects Firefox  136.0.4, Firefox ESR  128.8.1, and Firefox ESR  115.21.1.

- [https://github.com/Leviticus-Triage/ChromSploit-Framework](https://github.com/Leviticus-Triage/ChromSploit-Framework) :  ![starts](https://img.shields.io/github/stars/Leviticus-Triage/ChromSploit-Framework.svg) ![forks](https://img.shields.io/github/forks/Leviticus-Triage/ChromSploit-Framework.svg)


## CVE-2025-2783
 Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 134.0.6998.177 allowed a remote attacker to perform a sandbox escape via a malicious file. (Chromium security severity: High)

- [https://github.com/Leviticus-Triage/ChromSploit-Framework](https://github.com/Leviticus-Triage/ChromSploit-Framework) :  ![starts](https://img.shields.io/github/stars/Leviticus-Triage/ChromSploit-Framework.svg) ![forks](https://img.shields.io/github/forks/Leviticus-Triage/ChromSploit-Framework.svg)


## CVE-2024-55591
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

- [https://github.com/UMChacker/CVE-2024-55591-POC](https://github.com/UMChacker/CVE-2024-55591-POC) :  ![starts](https://img.shields.io/github/stars/UMChacker/CVE-2024-55591-POC.svg) ![forks](https://img.shields.io/github/forks/UMChacker/CVE-2024-55591-POC.svg)


## CVE-2024-38014
 Windows Installer Elevation of Privilege Vulnerability

- [https://github.com/Naman2701B/CVE-2024-38014](https://github.com/Naman2701B/CVE-2024-38014) :  ![starts](https://img.shields.io/github/stars/Naman2701B/CVE-2024-38014.svg) ![forks](https://img.shields.io/github/forks/Naman2701B/CVE-2024-38014.svg)
- [https://github.com/Naman2701B/DLL-for-2024-38014](https://github.com/Naman2701B/DLL-for-2024-38014) :  ![starts](https://img.shields.io/github/stars/Naman2701B/DLL-for-2024-38014.svg) ![forks](https://img.shields.io/github/forks/Naman2701B/DLL-for-2024-38014.svg)


## CVE-2024-9465
 An SQL injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to reveal Expedition database contents, such as password hashes, usernames, device configurations, and device API keys. With this, attackers can also create and read arbitrary files on the Expedition system.

- [https://github.com/0gitusername/CVE-2024-9465](https://github.com/0gitusername/CVE-2024-9465) :  ![starts](https://img.shields.io/github/stars/0gitusername/CVE-2024-9465.svg) ![forks](https://img.shields.io/github/forks/0gitusername/CVE-2024-9465.svg)


## CVE-2020-14008
 Zoho ManageEngine Applications Manager 14710 and before allows an authenticated admin user to upload a vulnerable jar in a specific location, which leads to remote code execution.

- [https://github.com/JackHars/cve-2020-14008](https://github.com/JackHars/cve-2020-14008) :  ![starts](https://img.shields.io/github/stars/JackHars/cve-2020-14008.svg) ![forks](https://img.shields.io/github/forks/JackHars/cve-2020-14008.svg)


## CVE-1999-0524
 ICMP information such as (1) netmask and (2) timestamp is allowed from arbitrary hosts.

- [https://github.com/Ransc0rp1on/ICMP-Timestamp-POC](https://github.com/Ransc0rp1on/ICMP-Timestamp-POC) :  ![starts](https://img.shields.io/github/stars/Ransc0rp1on/ICMP-Timestamp-POC.svg) ![forks](https://img.shields.io/github/forks/Ransc0rp1on/ICMP-Timestamp-POC.svg)

