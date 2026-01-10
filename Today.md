# Update 2026-01-10
## CVE-2026-21877
 n8n is an open source workflow automation platform. In versions 0.121.2 and below, an authenticated attacker may be able to execute malicious code using the n8n service. This could result in full compromise and can impact both self-hosted and n8n Cloud instances. This issue is fixed in version 1.121.3. Administrators can reduce exposure by disabling the Git node and limiting access for untrusted users, but upgrading to the latest version is recommended.

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21877](https://github.com/Ashwesker/Ashwesker-CVE-2026-21877) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21877.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21877.svg)


## CVE-2026-21876
 The OWASP core rule set (CRS) is a set of generic attack detection rules for use with compatible web application firewalls. Prior to versions 4.22.0 and 3.3.8, the current rule 922110 has a bug when processing multipart requests with multiple parts. When the first rule in a chain iterates over a collection (like `MULTIPART_PART_HEADERS`), the capture variables (`TX:0`, `TX:1`) get overwritten with each iteration. Only the last captured value is available to the chained rule, which means malicious charsets in earlier parts can be missed if a later part has a legitimate charset. Versions 4.22.0 and 3.3.8 patch the issue.

- [https://github.com/daytriftnewgen/CVE-2026-21876](https://github.com/daytriftnewgen/CVE-2026-21876) :  ![starts](https://img.shields.io/github/stars/daytriftnewgen/CVE-2026-21876.svg) ![forks](https://img.shields.io/github/forks/daytriftnewgen/CVE-2026-21876.svg)


## CVE-2026-21440
 AdonisJS is a TypeScript-first web framework. A Path Traversal vulnerability in AdonisJS multipart file handling may allow a remote attacker to write arbitrary files to arbitrary locations on the server filesystem. This impacts @adonisjs/bodyparser through version 10.1.1 and 11.x prerelease versions prior to 11.0.0-next.6. This issue has been patched in @adonisjs/bodyparser versions 10.1.2 and 11.0.0-next.6.

- [https://github.com/k0nnect/cve-2026-21440-writeup](https://github.com/k0nnect/cve-2026-21440-writeup) :  ![starts](https://img.shields.io/github/stars/k0nnect/cve-2026-21440-writeup.svg) ![forks](https://img.shields.io/github/forks/k0nnect/cve-2026-21440-writeup.svg)


## CVE-2025-68705
 RustFS is a distributed object storage system built in Rust. In versions 1.0.0-alpha.13 to 1.0.0-alpha.78, RustFS contains a path traversal vulnerability in the /rustfs/rpc/read_file_stream endpoint. This issue has been patched in version 1.0.0-alpha.79.

- [https://github.com/imjdl/CVE-2025-68705](https://github.com/imjdl/CVE-2025-68705) :  ![starts](https://img.shields.io/github/stars/imjdl/CVE-2025-68705.svg) ![forks](https://img.shields.io/github/forks/imjdl/CVE-2025-68705.svg)


## CVE-2025-68428
 jsPDF is a library to generate PDFs in JavaScript. Prior to version 4.0.0, user control of the first argument of the loadFile method in the node.js build allows local file inclusion/path traversal. If given the possibility to pass unsanitized paths to the loadFile method, a user can retrieve file contents of arbitrary files in the local file system the node process is running in. The file contents are included verbatim in the generated PDFs. Other affected methods are `addImage`, `html`, and `addFont`. Only the node.js builds of the library are affected, namely the `dist/jspdf.node.js` and `dist/jspdf.node.min.js` files. The vulnerability has been fixed in jsPDF@4.0.0. This version restricts file system access per default. This semver-major update does not introduce other breaking changes. Some workarounds areavailable. With recent node versions, jsPDF recommends using the `--permission` flag in production. The feature was introduced experimentally in v20.0.0 and is stable since v22.13.0/v23.5.0/v24.0.0. For older node versions, sanitize user-provided paths before passing them to jsPDF.

- [https://github.com/12nio/CVE-2025-68428_PoC](https://github.com/12nio/CVE-2025-68428_PoC) :  ![starts](https://img.shields.io/github/stars/12nio/CVE-2025-68428_PoC.svg) ![forks](https://img.shields.io/github/forks/12nio/CVE-2025-68428_PoC.svg)


## CVE-2025-67325
 Unrestricted file upload in the hotel review feature in QloApps versions 1.7.0 and earlier allows remote unauthenticated attackers to achieve remote code execution.

- [https://github.com/mr7s3d0/CVE-2025-67325](https://github.com/mr7s3d0/CVE-2025-67325) :  ![starts](https://img.shields.io/github/stars/mr7s3d0/CVE-2025-67325.svg) ![forks](https://img.shields.io/github/forks/mr7s3d0/CVE-2025-67325.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg)


## CVE-2025-65731
 An issue was discovered in D-Link Router DIR-605L (Hardware version F1; Firmware version: V6.02CN02) allowing an attacker with physical access to the UART pins to execute arbitrary commands due to presence of root terminal access on a serial interface without proper access control.

- [https://github.com/whitej3rry/CVE-2025-65731](https://github.com/whitej3rry/CVE-2025-65731) :  ![starts](https://img.shields.io/github/stars/whitej3rry/CVE-2025-65731.svg) ![forks](https://img.shields.io/github/forks/whitej3rry/CVE-2025-65731.svg)


## CVE-2025-65518
 Plesk Obsidian versions 8.0.1 through 18.0.73 are vulnerable to a Denial of Service (DoS) condition. The vulnerability exists in the get_password.php endpoint, where a crafted request containing a malicious payload can cause the affected web interface to continuously reload, rendering the service unavailable to legitimate users. An attacker can exploit this issue remotely without authentication, resulting in a persistent availability impact on the affected Plesk Obsidian instance.

- [https://github.com/Jainil-89/CVE-2025-65518](https://github.com/Jainil-89/CVE-2025-65518) :  ![starts](https://img.shields.io/github/stars/Jainil-89/CVE-2025-65518.svg) ![forks](https://img.shields.io/github/forks/Jainil-89/CVE-2025-65518.svg)


## CVE-2025-64459
Django would like to thank cyberstan for reporting this issue.

- [https://github.com/alxsourin/Helpdesk-Telecom-CVE-2025-64459](https://github.com/alxsourin/Helpdesk-Telecom-CVE-2025-64459) :  ![starts](https://img.shields.io/github/stars/alxsourin/Helpdesk-Telecom-CVE-2025-64459.svg) ![forks](https://img.shields.io/github/forks/alxsourin/Helpdesk-Telecom-CVE-2025-64459.svg)


## CVE-2025-61246
 indieka900 online-shopping-system-php 1.0 is vulnerable to SQL Injection in master/review_action.php via the proId parameter.

- [https://github.com/hackergovind/CVE-2025-61246](https://github.com/hackergovind/CVE-2025-61246) :  ![starts](https://img.shields.io/github/stars/hackergovind/CVE-2025-61246.svg) ![forks](https://img.shields.io/github/forks/hackergovind/CVE-2025-61246.svg)


## CVE-2025-59470
 This vulnerability allows a Backup Operator to perform remote code execution (RCE) as the postgres user by sending a malicious interval or order parameter.

- [https://github.com/b1gchoi/CVE-2025-59470](https://github.com/b1gchoi/CVE-2025-59470) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2025-59470.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2025-59470.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/momika233/CVE-2025-55182-bypass](https://github.com/momika233/CVE-2025-55182-bypass) :  ![starts](https://img.shields.io/github/stars/momika233/CVE-2025-55182-bypass.svg) ![forks](https://img.shields.io/github/forks/momika233/CVE-2025-55182-bypass.svg)
- [https://github.com/techgaun/cve-2025-55182-scanner](https://github.com/techgaun/cve-2025-55182-scanner) :  ![starts](https://img.shields.io/github/stars/techgaun/cve-2025-55182-scanner.svg) ![forks](https://img.shields.io/github/forks/techgaun/cve-2025-55182-scanner.svg)


## CVE-2025-54068
 Livewire is a full-stack framework for Laravel. In Livewire v3 up to and including v3.6.3, a vulnerability allows unauthenticated attackers to achieve remote command execution in specific scenarios. The issue stems from how certain component property updates are hydrated. This vulnerability is unique to Livewire v3 and does not affect prior major versions. Exploitation requires a component to be mounted and configured in a particular way, but does not require authentication or user interaction. This issue has been patched in Livewire v3.6.4. All users are strongly encouraged to upgrade to this version or later as soon as possible. No known workarounds are available.

- [https://github.com/flame-11/CVE-2025-54068-livewire](https://github.com/flame-11/CVE-2025-54068-livewire) :  ![starts](https://img.shields.io/github/stars/flame-11/CVE-2025-54068-livewire.svg) ![forks](https://img.shields.io/github/forks/flame-11/CVE-2025-54068-livewire.svg)


## CVE-2025-52691
 Successful exploitation of the vulnerability could allow an unauthenticated attacker to upload arbitrary files to any location on the mail server, potentially enabling remote code execution.

- [https://github.com/watchtowrlabs/watchTowr-vs-SmarterMail-CVE-2025-52691](https://github.com/watchtowrlabs/watchTowr-vs-SmarterMail-CVE-2025-52691) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-SmarterMail-CVE-2025-52691.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-SmarterMail-CVE-2025-52691.svg)


## CVE-2025-45805
 In phpgurukul Doctor Appointment Management System 1.0, an authenticated doctor user can inject arbitrary JavaScript code into their profile name. This payload is subsequently rendered without proper sanitization, when a user visits the website and selects the doctor to book an appointment.

- [https://github.com/mhsinj/CVE-2025-45805](https://github.com/mhsinj/CVE-2025-45805) :  ![starts](https://img.shields.io/github/stars/mhsinj/CVE-2025-45805.svg) ![forks](https://img.shields.io/github/forks/mhsinj/CVE-2025-45805.svg)


## CVE-2025-38352
anyway in this case.

- [https://github.com/Crime2/poc-CVE-2025-38352](https://github.com/Crime2/poc-CVE-2025-38352) :  ![starts](https://img.shields.io/github/stars/Crime2/poc-CVE-2025-38352.svg) ![forks](https://img.shields.io/github/forks/Crime2/poc-CVE-2025-38352.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)


## CVE-2025-6707
 Under certain conditions, an authenticated user request may execute with stale privileges following an intentional change by an authorized administrator. This issue affects MongoDB Server v5.0 version prior to 5.0.31, MongoDB Server v6.0 version prior to 6.0.24, MongoDB Server v7.0 version prior to 7.0.21 and MongoDB Server v8.0 version prior to 8.0.5.

- [https://github.com/teteco/CVE-2025-67070-Intelbras-CFTV-MFA-Bypass](https://github.com/teteco/CVE-2025-67070-Intelbras-CFTV-MFA-Bypass) :  ![starts](https://img.shields.io/github/stars/teteco/CVE-2025-67070-Intelbras-CFTV-MFA-Bypass.svg) ![forks](https://img.shields.io/github/forks/teteco/CVE-2025-67070-Intelbras-CFTV-MFA-Bypass.svg)


## CVE-2025-4802
 Untrusted LD_LIBRARY_PATH environment variable vulnerability in the GNU C Library version 2.27 to 2.38 allows attacker controlled loading of dynamically shared library in statically compiled setuid binaries that call dlopen (including internal dlopen calls after setlocale or calls to NSS functions such as getaddrinfo).

- [https://github.com/Betim-Hodza/CVE-2025-4802-Proof-of-Concept](https://github.com/Betim-Hodza/CVE-2025-4802-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/Betim-Hodza/CVE-2025-4802-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/Betim-Hodza/CVE-2025-4802-Proof-of-Concept.svg)


## CVE-2025-4595
 The FastSpring plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'fastspring/block-fastspringblocks-complete-product-catalog' block in all versions up to, and including, 3.0.1 due to insufficient input sanitization and output escaping on the 'color' attribute. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/surendrapuppala7/CVE-2025-45955](https://github.com/surendrapuppala7/CVE-2025-45955) :  ![starts](https://img.shields.io/github/stars/surendrapuppala7/CVE-2025-45955.svg) ![forks](https://img.shields.io/github/forks/surendrapuppala7/CVE-2025-45955.svg)


## CVE-2024-24401
 SQL Injection vulnerability in Nagios XI 2024R1.01 allows a remote attacker to execute arbitrary code via a crafted payload to the monitoringwizard.php component.

- [https://github.com/JIBEG-UNIX/CVE-2024-24401](https://github.com/JIBEG-UNIX/CVE-2024-24401) :  ![starts](https://img.shields.io/github/stars/JIBEG-UNIX/CVE-2024-24401.svg) ![forks](https://img.shields.io/github/forks/JIBEG-UNIX/CVE-2024-24401.svg)


## CVE-2024-0368
 The Hustle – Email Marketing, Lead Generation, Optins, Popups plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 7.8.3 via hardcoded API Keys. This makes it possible for unauthenticated attackers to extract sensitive data including PII.

- [https://github.com/RandomRobbieBF/CVE-2024-0368](https://github.com/RandomRobbieBF/CVE-2024-0368) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-0368.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-0368.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/Phaedrik/CVE-2023-23397-POC](https://github.com/Phaedrik/CVE-2023-23397-POC) :  ![starts](https://img.shields.io/github/stars/Phaedrik/CVE-2023-23397-POC.svg) ![forks](https://img.shields.io/github/forks/Phaedrik/CVE-2023-23397-POC.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoRay/CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2022-39299-Research.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/mishra0230/CVE-2022-30190-Follina](https://github.com/mishra0230/CVE-2022-30190-Follina) :  ![starts](https://img.shields.io/github/stars/mishra0230/CVE-2022-30190-Follina.svg) ![forks](https://img.shields.io/github/forks/mishra0230/CVE-2022-30190-Follina.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/ESSAFAR/Firewall-Rules](https://github.com/ESSAFAR/Firewall-Rules) :  ![starts](https://img.shields.io/github/stars/ESSAFAR/Firewall-Rules.svg) ![forks](https://img.shields.io/github/forks/ESSAFAR/Firewall-Rules.svg)


## CVE-2022-4782
 The ClickFunnels WordPress plugin through 3.1.1 does not validate and escape one of its shortcode attributes, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attack.

- [https://github.com/makmour/clickfunnels-zurich](https://github.com/makmour/clickfunnels-zurich) :  ![starts](https://img.shields.io/github/stars/makmour/clickfunnels-zurich.svg) ![forks](https://img.shields.io/github/forks/makmour/clickfunnels-zurich.svg)


## CVE-2022-3653
 Heap buffer overflow in Vulkan in Google Chrome prior to 107.0.5304.62 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/SpiralBL0CK/CVE-2022-3653](https://github.com/SpiralBL0CK/CVE-2022-3653) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2022-3653.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2022-3653.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/baktistr/cve-2021-43798-enum](https://github.com/baktistr/cve-2021-43798-enum) :  ![starts](https://img.shields.io/github/stars/baktistr/cve-2021-43798-enum.svg) ![forks](https://img.shields.io/github/forks/baktistr/cve-2021-43798-enum.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)
- [https://github.com/faizdotid/CVE-2021-41773](https://github.com/faizdotid/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/faizdotid/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/faizdotid/CVE-2021-41773.svg)


## CVE-2021-40346
 An integer overflow exists in HAProxy 2.0 through 2.5 in htx_add_header that can be exploited to perform an HTTP request smuggling attack, allowing an attacker to bypass all configured http-request HAProxy ACLs and possibly other ACLs.

- [https://github.com/BoianEduard/CVE-2021-40346](https://github.com/BoianEduard/CVE-2021-40346) :  ![starts](https://img.shields.io/github/stars/BoianEduard/CVE-2021-40346.svg) ![forks](https://img.shields.io/github/forks/BoianEduard/CVE-2021-40346.svg)


## CVE-2021-31166
 HTTP Protocol Stack Remote Code Execution Vulnerability

- [https://github.com/iranzai/CVE-2021-31166-exploit](https://github.com/iranzai/CVE-2021-31166-exploit) :  ![starts](https://img.shields.io/github/stars/iranzai/CVE-2021-31166-exploit.svg) ![forks](https://img.shields.io/github/forks/iranzai/CVE-2021-31166-exploit.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/smancke/CVE-2017-5638](https://github.com/smancke/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/smancke/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/smancke/CVE-2017-5638.svg)

