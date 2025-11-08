# Update 2025-11-08
## CVE-2025-64459
Django would like to thank cyberstan for reporting this issue.

- [https://github.com/rockmelodies/django_sqli_target_CVE-2025-64459](https://github.com/rockmelodies/django_sqli_target_CVE-2025-64459) :  ![starts](https://img.shields.io/github/stars/rockmelodies/django_sqli_target_CVE-2025-64459.svg) ![forks](https://img.shields.io/github/forks/rockmelodies/django_sqli_target_CVE-2025-64459.svg)


## CVE-2025-64458
Django would like to thank Seokchan Yoon for reporting this issue.

- [https://github.com/ch4n3-yoon/CVE-2025-64458-Demo](https://github.com/ch4n3-yoon/CVE-2025-64458-Demo) :  ![starts](https://img.shields.io/github/stars/ch4n3-yoon/CVE-2025-64458-Demo.svg) ![forks](https://img.shields.io/github/forks/ch4n3-yoon/CVE-2025-64458-Demo.svg)


## CVE-2025-64095
 DNN (formerly DotNetNuke) is an open-source web content management platform (CMS) in the Microsoft ecosystem. Prior to 10.1.1, the default HTML editor provider allows unauthenticated file uploads and images can overwrite existing files. An unauthenticated user can upload and replace existing files allowing defacing a website and combined with other issue, injection XSS payloads. This vulnerability is fixed in 10.1.1.

- [https://github.com/NationalServices/CVE-2025-64095-DotNetNuke-DNN_PoC](https://github.com/NationalServices/CVE-2025-64095-DotNetNuke-DNN_PoC) :  ![starts](https://img.shields.io/github/stars/NationalServices/CVE-2025-64095-DotNetNuke-DNN_PoC.svg) ![forks](https://img.shields.io/github/forks/NationalServices/CVE-2025-64095-DotNetNuke-DNN_PoC.svg)


## CVE-2025-63589
 A reflected XSS vulnerability exists in CMSimple_XH 1.8's index.php router when attacker-controlled path segments are not sanitized or encoded before being inserted into the generated HTML (navigation links, breadcrumbs, search form action, footer links). An attacker-controlled string placed in the URL path is reflected into multiple HTML elements, allowing execution of arbitrary JavaScript in victims' browsers visiting a crafted URL.

- [https://github.com/cybercrewinc/CVE-2025-63589](https://github.com/cybercrewinc/CVE-2025-63589) :  ![starts](https://img.shields.io/github/stars/cybercrewinc/CVE-2025-63589.svg) ![forks](https://img.shields.io/github/forks/cybercrewinc/CVE-2025-63589.svg)


## CVE-2025-63588
 An unauthenticated reflected cross-site scripting vulnerability in the query handling of CMSimpleXH allows remote attackers to inject and execute arbitrary JavaScript in a victim's browser via a crafted request (e.g., a maliciously crafted POST login). Successful exploitation may lead to theft of session cookies, credential disclosure, or other client-side impacts.

- [https://github.com/cybercrewinc/CVE-2025-63588](https://github.com/cybercrewinc/CVE-2025-63588) :  ![starts](https://img.shields.io/github/stars/cybercrewinc/CVE-2025-63588.svg) ![forks](https://img.shields.io/github/forks/cybercrewinc/CVE-2025-63588.svg)


## CVE-2025-63334
 PocketVJ CP PocketVJ-CP-v3 pvj version 3.9.1 contains an unauthenticated remote code execution vulnerability in the submit_opacity.php component. The application fails to sanitize user input in the opacityValue POST parameter before passing it to a shell command, allowing remote attackers to execute arbitrary commands with root privileges on the underlying system.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-63334](https://github.com/B1ack4sh/Blackash-CVE-2025-63334) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-63334.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-63334.svg)


## CVE-2025-63307
 alexusmai laravel-file-manager 3.3.1 is vulnerable to Cross Site Scripting (XSS). The application permits user-controlled upload, create, and rename of files to HTML and SVG types and serves those files inline without adequate content-type validation or output sanitization.

- [https://github.com/Theethat-Thamwasin/CVE-2025-63307](https://github.com/Theethat-Thamwasin/CVE-2025-63307) :  ![starts](https://img.shields.io/github/stars/Theethat-Thamwasin/CVE-2025-63307.svg) ![forks](https://img.shields.io/github/forks/Theethat-Thamwasin/CVE-2025-63307.svg)


## CVE-2025-59396
 The default configuration of WatchGuard Firebox devices through 2025-09-10 allows administrative access via SSH on port 4118 with the readwrite password for the admin account.

- [https://github.com/cyberbyte000/CVE-2025-59396](https://github.com/cyberbyte000/CVE-2025-59396) :  ![starts](https://img.shields.io/github/stars/cyberbyte000/CVE-2025-59396.svg) ![forks](https://img.shields.io/github/forks/cyberbyte000/CVE-2025-59396.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/crondenice/CVE-2025-59287](https://github.com/crondenice/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/crondenice/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/crondenice/CVE-2025-59287.svg)


## CVE-2025-54782
 Nest is a framework for building scalable Node.js server-side applications. In versions 0.2.0 and below, a critical Remote Code Execution (RCE) vulnerability was discovered in the @nestjs/devtools-integration package. When enabled, the package exposes a local development HTTP server with an API endpoint that uses an unsafe JavaScript sandbox (safe-eval-like implementation). Due to improper sandboxing and missing cross-origin protections, any malicious website visited by a developer can execute arbitrary code on their local machine. The package adds HTTP endpoints to a locally running NestJS development server. One of these endpoints, /inspector/graph/interact, accepts JSON input containing a code field and executes the provided code in a Node.js vm.runInNewContext sandbox. This is fixed in version 0.2.1.

- [https://github.com/DDestinys/CVE-2025-54782](https://github.com/DDestinys/CVE-2025-54782) :  ![starts](https://img.shields.io/github/stars/DDestinys/CVE-2025-54782.svg) ![forks](https://img.shields.io/github/forks/DDestinys/CVE-2025-54782.svg)


## CVE-2025-54236
 Adobe Commerce versions 2.4.9-alpha2, 2.4.8-p2, 2.4.7-p7, 2.4.6-p12, 2.4.5-p14, 2.4.4-p15 and earlier are affected by an Improper Input Validation vulnerability. A successful attacker can abuse this to achieve session takeover, increasing the confidentiality, and integrity impact to high. Exploitation of this issue does not require user interaction.

- [https://github.com/crondenice/CVE-2025-54236](https://github.com/crondenice/CVE-2025-54236) :  ![starts](https://img.shields.io/github/stars/crondenice/CVE-2025-54236.svg) ![forks](https://img.shields.io/github/forks/crondenice/CVE-2025-54236.svg)


## CVE-2025-31133
 runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7 and below, 1.3.0-rc.1 through 1.3.1, 1.4.0-rc.1 and 1.4.0-rc.2 files, runc would not perform sufficient verification that the source of the bind-mount (i.e., the container's /dev/null) was actually a real /dev/null inode when using the container's /dev/null to mask. This exposes two methods of attack:  an arbitrary mount gadget, leading to host information disclosure, host denial of service, container escape, or a bypassing of maskedPaths. This issue is fixed in versions 1.2.8, 1.3.3 and 1.4.0-rc.3.

- [https://github.com/sahar042/CVE-2025-31133](https://github.com/sahar042/CVE-2025-31133) :  ![starts](https://img.shields.io/github/stars/sahar042/CVE-2025-31133.svg) ![forks](https://img.shields.io/github/forks/sahar042/CVE-2025-31133.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927](https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg)


## CVE-2025-20354
This vulnerability is due to improper authentication mechanisms that are associated to specific Cisco Unified CCX features. An attacker could exploit this vulnerability by uploading a crafted file to an affected system through the Java RMI process. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system and elevate privileges to root.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-20354](https://github.com/B1ack4sh/Blackash-CVE-2025-20354) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-20354.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-20354.svg)
- [https://github.com/allinsthon/CVE-2025-20354](https://github.com/allinsthon/CVE-2025-20354) :  ![starts](https://img.shields.io/github/stars/allinsthon/CVE-2025-20354.svg) ![forks](https://img.shields.io/github/forks/allinsthon/CVE-2025-20354.svg)


## CVE-2025-6335
 A vulnerability was found in DedeCMS up to 5.7.2 and classified as critical. This issue affects some unknown processing of the file /include/dedetag.class.php of the component Template Handler. The manipulation of the argument notes leads to command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/hanianis/CVE-2025-63353](https://github.com/hanianis/CVE-2025-63353) :  ![starts](https://img.shields.io/github/stars/hanianis/CVE-2025-63353.svg) ![forks](https://img.shields.io/github/forks/hanianis/CVE-2025-63353.svg)


## CVE-2025-5664
 A vulnerability was found in FreeFloat FTP Server 1.0 and classified as critical. This issue affects some unknown processing of the component RESTART Command Handler. The manipulation leads to buffer overflow. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/0xBS0D27/CVE-2025-56643](https://github.com/0xBS0D27/CVE-2025-56643) :  ![starts](https://img.shields.io/github/stars/0xBS0D27/CVE-2025-56643.svg) ![forks](https://img.shields.io/github/forks/0xBS0D27/CVE-2025-56643.svg)


## CVE-2025-4859
 A vulnerability was found in D-Link DAP-2695 120b36r137_ALL_en_20210528. It has been rated as problematic. This issue affects some unknown processing of the file /adv_macbypass.php of the component MAC Bypass Settings Page. The manipulation of the argument f_mac leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/skolepc/CVE-2025-48593](https://github.com/skolepc/CVE-2025-48593) :  ![starts](https://img.shields.io/github/stars/skolepc/CVE-2025-48593.svg) ![forks](https://img.shields.io/github/forks/skolepc/CVE-2025-48593.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/gurleen-147/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability-PoC](https://github.com/gurleen-147/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability-PoC) :  ![starts](https://img.shields.io/github/stars/gurleen-147/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability-PoC.svg) ![forks](https://img.shields.io/github/forks/gurleen-147/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability-PoC.svg)


## CVE-2023-50290
Users are recommended to upgrade to version 9.3.0 or later, in which environment variables are not published via the Metrics API.

- [https://github.com/desaivinayak449/bug-bounty-reports-desai-vinayak](https://github.com/desaivinayak449/bug-bounty-reports-desai-vinayak) :  ![starts](https://img.shields.io/github/stars/desaivinayak449/bug-bounty-reports-desai-vinayak.svg) ![forks](https://img.shields.io/github/forks/desaivinayak449/bug-bounty-reports-desai-vinayak.svg)


## CVE-2023-22894
 Strapi through 4.5.5 allows attackers (with access to the admin panel) to discover sensitive user details by exploiting the query filter. The attacker can filter users by columns that contain sensitive information and infer a value from API responses. If the attacker has super admin access, then this can be exploited to discover the password hash and password reset token of all users. If the attacker has admin panel access to an account with permission to access the username and email of API users with a lower privileged role (e.g., Editor or Author), then this can be exploited to discover sensitive information for all API users but not other admin accounts.

- [https://github.com/maxntv/CVE-2023-22894-PoC](https://github.com/maxntv/CVE-2023-22894-PoC) :  ![starts](https://img.shields.io/github/stars/maxntv/CVE-2023-22894-PoC.svg) ![forks](https://img.shields.io/github/forks/maxntv/CVE-2023-22894-PoC.svg)


## CVE-2023-7024
 Heap buffer overflow in WebRTC in Google Chrome prior to 120.0.6099.129 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/aka76bm/chrome-emergency-update](https://github.com/aka76bm/chrome-emergency-update) :  ![starts](https://img.shields.io/github/stars/aka76bm/chrome-emergency-update.svg) ![forks](https://img.shields.io/github/forks/aka76bm/chrome-emergency-update.svg)
- [https://github.com/aka76bm/google-chrome-emergency-update](https://github.com/aka76bm/google-chrome-emergency-update) :  ![starts](https://img.shields.io/github/stars/aka76bm/google-chrome-emergency-update.svg) ![forks](https://img.shields.io/github/forks/aka76bm/google-chrome-emergency-update.svg)


## CVE-2022-21587
 Vulnerability in the Oracle Web Applications Desktop Integrator product of Oracle E-Business Suite (component: Upload). Supported versions that are affected are 12.2.3-12.2.11. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Web Applications Desktop Integrator. Successful attacks of this vulnerability can result in takeover of Oracle Web Applications Desktop Integrator. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/B1ack4sh/Blackash-CVE-2022-21587](https://github.com/B1ack4sh/Blackash-CVE-2022-21587) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2022-21587.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2022-21587.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/B1ack4sh/Blackash-CVE-2020-5902](https://github.com/B1ack4sh/Blackash-CVE-2020-5902) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2020-5902.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2020-5902.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/i-redbyte/android-badbinder-demo](https://github.com/i-redbyte/android-badbinder-demo) :  ![starts](https://img.shields.io/github/stars/i-redbyte/android-badbinder-demo.svg) ![forks](https://img.shields.io/github/forks/i-redbyte/android-badbinder-demo.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/arturomartinvegue/escalada-privilegios-kernel-exploit-dirty-cow](https://github.com/arturomartinvegue/escalada-privilegios-kernel-exploit-dirty-cow) :  ![starts](https://img.shields.io/github/stars/arturomartinvegue/escalada-privilegios-kernel-exploit-dirty-cow.svg) ![forks](https://img.shields.io/github/forks/arturomartinvegue/escalada-privilegios-kernel-exploit-dirty-cow.svg)

