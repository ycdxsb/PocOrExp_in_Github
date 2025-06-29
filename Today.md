# Update 2025-06-29
## CVE-2025-32711
 Ai command injection in M365 Copilot allows an unauthorized attacker to disclose information over a network.

- [https://github.com/daryllundy/cve-2025-32711](https://github.com/daryllundy/cve-2025-32711) :  ![starts](https://img.shields.io/github/stars/daryllundy/cve-2025-32711.svg) ![forks](https://img.shields.io/github/forks/daryllundy/cve-2025-32711.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/ThemeHackers/CVE-2025-30208](https://github.com/ThemeHackers/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-30208.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/KaztoRay/CVE-2025-29927-Research](https://github.com/KaztoRay/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2025-29927-Research.svg)


## CVE-2025-20281
This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by submitting a crafted API request. A successful exploit could allow the attacker to obtain root privileges on an affected device.

- [https://github.com/abrewer251/CVE-2025-20281-2-Citrix-ISE-RCE](https://github.com/abrewer251/CVE-2025-20281-2-Citrix-ISE-RCE) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-20281-2-Citrix-ISE-RCE.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-20281-2-Citrix-ISE-RCE.svg)


## CVE-2025-1562
 The Recover WooCommerce Cart Abandonment, Newsletter, Email Marketing, Marketing Automation By FunnelKit plugin for WordPress is vulnerable to unauthorized arbitrary plugin installation due to a missing capability check on the install_or_activate_addon_plugins() function and a weak nonce hash in all versions up to, and including, 3.5.3. This makes it possible for unauthenticated attackers to install arbitrary plugins on the site that can be leveraged to further infect a vulnerable site.

- [https://github.com/gmh5225/CVE-2025-1562](https://github.com/gmh5225/CVE-2025-1562) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2025-1562.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2025-1562.svg)


## CVE-2024-27388
corresponding paths.

- [https://github.com/Mahesh-970/CVE-2024-27388_afterpatch](https://github.com/Mahesh-970/CVE-2024-27388_afterpatch) :  ![starts](https://img.shields.io/github/stars/Mahesh-970/CVE-2024-27388_afterpatch.svg) ![forks](https://img.shields.io/github/forks/Mahesh-970/CVE-2024-27388_afterpatch.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/Ikram124/CVE-2024-3094-analysis](https://github.com/Ikram124/CVE-2024-3094-analysis) :  ![starts](https://img.shields.io/github/stars/Ikram124/CVE-2024-3094-analysis.svg) ![forks](https://img.shields.io/github/forks/Ikram124/CVE-2024-3094-analysis.svg)


## CVE-2024-0986
 A vulnerability was found in Issabel PBX 4.0.0. It has been rated as critical. This issue affects some unknown processing of the file /index.php?menu=asterisk_cli of the component Asterisk-Cli. The manipulation of the argument Command leads to os command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-252251. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/gunzf0x/Issabel-PBX-4.0.0-RCE-Authenticated](https://github.com/gunzf0x/Issabel-PBX-4.0.0-RCE-Authenticated) :  ![starts](https://img.shields.io/github/stars/gunzf0x/Issabel-PBX-4.0.0-RCE-Authenticated.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/Issabel-PBX-4.0.0-RCE-Authenticated.svg)


## CVE-2024-0588
 The Paid Memberships Pro – Content Restriction, User Registration, & Paid Subscriptions plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 2.12.10. This is due to missing nonce validation on the pmpro_lifter_save_streamline_option() function. This makes it possible for unauthenticated attackers to enable the streamline setting with Lifter LMS via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/kodaichodai/CVE-2024-0588](https://github.com/kodaichodai/CVE-2024-0588) :  ![starts](https://img.shields.io/github/stars/kodaichodai/CVE-2024-0588.svg) ![forks](https://img.shields.io/github/forks/kodaichodai/CVE-2024-0588.svg)


## CVE-2024-0507
 An attacker with access to a Management Console user account with the editor role could escalate privileges through a command injection vulnerability in the Management Console. This vulnerability affected all versions of GitHub Enterprise Server and was fixed in versions 3.11.3, 3.10.5, 3.9.8, and 3.8.13 This vulnerability was reported via the GitHub Bug Bounty program.

- [https://github.com/convisolabs/CVE-2024-0507_CVE-2024-0200-github](https://github.com/convisolabs/CVE-2024-0507_CVE-2024-0200-github) :  ![starts](https://img.shields.io/github/stars/convisolabs/CVE-2024-0507_CVE-2024-0200-github.svg) ![forks](https://img.shields.io/github/forks/convisolabs/CVE-2024-0507_CVE-2024-0200-github.svg)


## CVE-2024-0352
 A vulnerability classified as critical was found in Likeshop up to 2.5.7.20210311. This vulnerability affects the function FileServer::userFormImage of the file server/application/api/controller/File.php of the component HTTP POST Request Handler. The manipulation of the argument file leads to unrestricted upload. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-250120.

- [https://github.com/Cappricio-Securities/CVE-2024-0352](https://github.com/Cappricio-Securities/CVE-2024-0352) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2024-0352.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2024-0352.svg)


## CVE-2024-0030
 In btif_to_bta_response of btif_gatt_util.cc, there is a possible out of bounds read due to an incorrect bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/uthrasri/system_bt_CVE-2024-0030](https://github.com/uthrasri/system_bt_CVE-2024-0030) :  ![starts](https://img.shields.io/github/stars/uthrasri/system_bt_CVE-2024-0030.svg) ![forks](https://img.shields.io/github/forks/uthrasri/system_bt_CVE-2024-0030.svg)


## CVE-2024-0012
Cloud NGFW and Prisma Access are not impacted by this vulnerability.

- [https://github.com/watchtowrlabs/palo-alto-panos-cve-2024-0012](https://github.com/watchtowrlabs/palo-alto-panos-cve-2024-0012) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/palo-alto-panos-cve-2024-0012.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/palo-alto-panos-cve-2024-0012.svg)
- [https://github.com/Sachinart/CVE-2024-0012-POC](https://github.com/Sachinart/CVE-2024-0012-POC) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2024-0012-POC.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2024-0012-POC.svg)
- [https://github.com/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC](https://github.com/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC) :  ![starts](https://img.shields.io/github/stars/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC.svg) ![forks](https://img.shields.io/github/forks/TalatumLabs/CVE-2024-0012_CVE-2024-9474_PoC.svg)
- [https://github.com/dcollaoa/cve-2024-0012-gui-poc](https://github.com/dcollaoa/cve-2024-0012-gui-poc) :  ![starts](https://img.shields.io/github/stars/dcollaoa/cve-2024-0012-gui-poc.svg) ![forks](https://img.shields.io/github/forks/dcollaoa/cve-2024-0012-gui-poc.svg)
- [https://github.com/XiaomingX/cve-2024-0012-poc](https://github.com/XiaomingX/cve-2024-0012-poc) :  ![starts](https://img.shields.io/github/stars/XiaomingX/cve-2024-0012-poc.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/cve-2024-0012-poc.svg)
- [https://github.com/iSee857/CVE-2024-0012-poc](https://github.com/iSee857/CVE-2024-0012-poc) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2024-0012-poc.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2024-0012-poc.svg)
- [https://github.com/0xjessie21/CVE-2024-0012](https://github.com/0xjessie21/CVE-2024-0012) :  ![starts](https://img.shields.io/github/stars/0xjessie21/CVE-2024-0012.svg) ![forks](https://img.shields.io/github/forks/0xjessie21/CVE-2024-0012.svg)
- [https://github.com/greaselovely/CVE-2024-0012](https://github.com/greaselovely/CVE-2024-0012) :  ![starts](https://img.shields.io/github/stars/greaselovely/CVE-2024-0012.svg) ![forks](https://img.shields.io/github/forks/greaselovely/CVE-2024-0012.svg)
- [https://github.com/Regent8SH/PanOsExploitMultitool](https://github.com/Regent8SH/PanOsExploitMultitool) :  ![starts](https://img.shields.io/github/stars/Regent8SH/PanOsExploitMultitool.svg) ![forks](https://img.shields.io/github/forks/Regent8SH/PanOsExploitMultitool.svg)
- [https://github.com/VegetableLasagne/CVE-2024-0012](https://github.com/VegetableLasagne/CVE-2024-0012) :  ![starts](https://img.shields.io/github/stars/VegetableLasagne/CVE-2024-0012.svg) ![forks](https://img.shields.io/github/forks/VegetableLasagne/CVE-2024-0012.svg)
- [https://github.com/punitdarji/Paloalto-CVE-2024-0012](https://github.com/punitdarji/Paloalto-CVE-2024-0012) :  ![starts](https://img.shields.io/github/stars/punitdarji/Paloalto-CVE-2024-0012.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Paloalto-CVE-2024-0012.svg)


## CVE-2023-30258
 Command Injection vulnerability in MagnusSolution magnusbilling 6.x and 7.x allows remote attackers to run arbitrary commands via unauthenticated HTTP request.

- [https://github.com/delldevmann/CVE-2023-30258](https://github.com/delldevmann/CVE-2023-30258) :  ![starts](https://img.shields.io/github/stars/delldevmann/CVE-2023-30258.svg) ![forks](https://img.shields.io/github/forks/delldevmann/CVE-2023-30258.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoRay/CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2022-39299-Research.svg)


## CVE-2022-20699
 Multiple vulnerabilities in Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers could allow an attacker to do any of the following: Execute arbitrary code Elevate privileges Execute arbitrary commands Bypass authentication and authorization protections Fetch and run unsigned software Cause denial of service (DoS) For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/rohankumardubey/CVE-2022-20699](https://github.com/rohankumardubey/CVE-2022-20699) :  ![starts](https://img.shields.io/github/stars/rohankumardubey/CVE-2022-20699.svg) ![forks](https://img.shields.io/github/forks/rohankumardubey/CVE-2022-20699.svg)


## CVE-2020-7378
 CRIXP OpenCRX version 4.30 and 5.0-20200717 and prior suffers from an unverified password change vulnerability. An attacker who is able to connect to the affected OpenCRX instance can change the password of any user, including admin-Standard, to any chosen value. This issue was resolved in version 5.0-20200904, released September 4, 2020.

- [https://github.com/loganpkinfosec/CVE-2020-7378](https://github.com/loganpkinfosec/CVE-2020-7378) :  ![starts](https://img.shields.io/github/stars/loganpkinfosec/CVE-2020-7378.svg) ![forks](https://img.shields.io/github/forks/loganpkinfosec/CVE-2020-7378.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/ArtemCyberLab/Project-Field-Analysis-and-Memory-Leak-Demonstration](https://github.com/ArtemCyberLab/Project-Field-Analysis-and-Memory-Leak-Demonstration) :  ![starts](https://img.shields.io/github/stars/ArtemCyberLab/Project-Field-Analysis-and-Memory-Leak-Demonstration.svg) ![forks](https://img.shields.io/github/forks/ArtemCyberLab/Project-Field-Analysis-and-Memory-Leak-Demonstration.svg)

