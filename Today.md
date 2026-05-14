# Update 2026-05-14
## CVE-2026-45321
 On 2026-05-11, between approximately 19:20 and 19:26 UTC, 84 malicious versions across 42 @tanstack/* packages were published to the npm registry. The publishes were authenticated via the legitimate GitHub Actions OIDC trusted-publisher binding for TanStack/router, but the publish workflow itself was not modified. The attacker chained three known vulnerability classes — a pull_request_target "Pwn Request" misconfiguration, GitHub Actions cache poisoning across the fork↔base trust boundary, and runtime memory extraction of the OIDC token from the Actions runner process — to publish credential-stealing malware under a trusted identity. Each affected package received exactly two malicious versions, published a few minutes apart.

- [https://github.com/Caixa-git/tanstack-shield](https://github.com/Caixa-git/tanstack-shield) :  ![starts](https://img.shields.io/github/stars/Caixa-git/tanstack-shield.svg) ![forks](https://img.shields.io/github/forks/Caixa-git/tanstack-shield.svg)
- [https://github.com/shayr1/shai-hulud-scan](https://github.com/shayr1/shai-hulud-scan) :  ![starts](https://img.shields.io/github/stars/shayr1/shai-hulud-scan.svg) ![forks](https://img.shields.io/github/forks/shayr1/shai-hulud-scan.svg)
- [https://github.com/qi-scape/scan-shai-hulud](https://github.com/qi-scape/scan-shai-hulud) :  ![starts](https://img.shields.io/github/stars/qi-scape/scan-shai-hulud.svg) ![forks](https://img.shields.io/github/forks/qi-scape/scan-shai-hulud.svg)
- [https://github.com/ry-allan/tanstack-compromise-checker](https://github.com/ry-allan/tanstack-compromise-checker) :  ![starts](https://img.shields.io/github/stars/ry-allan/tanstack-compromise-checker.svg) ![forks](https://img.shields.io/github/forks/ry-allan/tanstack-compromise-checker.svg)


## CVE-2026-45185
 Exim before 4.99.3, in certain GnuTLS configurations, has a remotely reachable use-after-free in the BDAT body parsing path. It is triggered when a client sends a TLS close_notify mid-body during a CHUNKING transfer, followed by a final cleartext byte on the same TCP connection. This can lead to heap corruption. An unauthenticated network attacker exploiting this vulnerability could execute arbitrary code.

- [https://github.com/liamromanis101/Dead.Letter-CVE-2026-45185](https://github.com/liamromanis101/Dead.Letter-CVE-2026-45185) :  ![starts](https://img.shields.io/github/stars/liamromanis101/Dead.Letter-CVE-2026-45185.svg) ![forks](https://img.shields.io/github/forks/liamromanis101/Dead.Letter-CVE-2026-45185.svg)


## CVE-2026-44262
 Scramble generates API documentation for Laravel project. From 0.13.2 to before 0.13.22, when documentation endpoints are publicly accessible and validation rules reference user-controlled input, request supplied data may be evaluated during documentation generation, leading to execution of arbitrary PHP code in the application context. This vulnerability is fixed in 0.13.22.

- [https://github.com/joshuavanderpoll/CVE-2026-44262](https://github.com/joshuavanderpoll/CVE-2026-44262) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2026-44262.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2026-44262.svg)


## CVE-2026-42141
 Xibo is an open source digital signage platform with a web content management system and Windows display player software. Prior to 4.4.1, an authenticated Server-Side Request Forgery (SSRF) vulnerability in the Xibo CMS allows users with Library upload permissions to make arbitrary HTTP requests from the CMS server to internal or external network resources. This can be exploited to scan internal infrastructure, access local cloud metadata endpoints (e.g., AWS IMDS), interact with internal services that lack authentication, or exfiltrate data. This vulnerability is fixed in 4.4.1.

- [https://github.com/H4zaz/CVE-2026-42141-xibo-ssrf](https://github.com/H4zaz/CVE-2026-42141-xibo-ssrf) :  ![starts](https://img.shields.io/github/stars/H4zaz/CVE-2026-42141-xibo-ssrf.svg) ![forks](https://img.shields.io/github/forks/H4zaz/CVE-2026-42141-xibo-ssrf.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/tc4dy/CVE-2026-41940-POC-Exploit](https://github.com/tc4dy/CVE-2026-41940-POC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-41940-POC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-41940-POC-Exploit.svg)


## CVE-2026-35455
 immich is a high performance self-hosted photo and video management solution. Prior to 2.7.0, sStored Cross-Site Scripting (XSS) in the 360° panorama viewer allows any authenticated user to execute arbitrary JavaScript in the browser of any other user who views the malicious panorama with the OCR overlay enabled. The attacker uploads an equirectangular image containing crafted text; OCR extracts it, and the panorama viewer renders it via innerHTML without sanitization. This enables session hijacking (via persistent API key creation), private photo exfiltration, and access to GPS location history and face biometric data. This vulnerability is fixed in 2.7.0.

- [https://github.com/emanuelepns/immich-exfiltration-demo](https://github.com/emanuelepns/immich-exfiltration-demo) :  ![starts](https://img.shields.io/github/stars/emanuelepns/immich-exfiltration-demo.svg) ![forks](https://img.shields.io/github/forks/emanuelepns/immich-exfiltration-demo.svg)


## CVE-2026-34621
 Acrobat Reader versions 24.001.30356, 26.001.21367 and earlier are affected by an Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/azefzafyoussef/CVE-2026-34621](https://github.com/azefzafyoussef/CVE-2026-34621) :  ![starts](https://img.shields.io/github/stars/azefzafyoussef/CVE-2026-34621.svg) ![forks](https://img.shields.io/github/forks/azefzafyoussef/CVE-2026-34621.svg)


## CVE-2026-33067
 SiYuan is a personal knowledge management system. Versions 3.6.0 and below render package metadata fields (displayName, description) using template literals without HTML escaping. A malicious package author can inject arbitrary HTML/JavaScript into these fields, which executes automatically when any user browses the Bazaar page. Because SiYuan's Electron configuration enables nodeIntegration: true with contextIsolation: false, this XSS escalates directly to full Remote Code Execution on the victim's operating system — with zero user interaction beyond opening the marketplace tab. This issue has been fixed in version 3.6.1.

- [https://github.com/Lopseg/cve-2026-33067](https://github.com/Lopseg/cve-2026-33067) :  ![starts](https://img.shields.io/github/stars/Lopseg/cve-2026-33067.svg) ![forks](https://img.shields.io/github/forks/Lopseg/cve-2026-33067.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/samanzamani/copy-fail-checker](https://github.com/samanzamani/copy-fail-checker) :  ![starts](https://img.shields.io/github/stars/samanzamani/copy-fail-checker.svg) ![forks](https://img.shields.io/github/forks/samanzamani/copy-fail-checker.svg)
- [https://github.com/Dullpurple-sloop726/CVE-2026-31431-Linux-Copy-Fail](https://github.com/Dullpurple-sloop726/CVE-2026-31431-Linux-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/Dullpurple-sloop726/CVE-2026-31431-Linux-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/Dullpurple-sloop726/CVE-2026-31431-Linux-Copy-Fail.svg)
- [https://github.com/xn0kkx/CVE-2026-31431_CopyFail_LinuxKernel_LPE](https://github.com/xn0kkx/CVE-2026-31431_CopyFail_LinuxKernel_LPE) :  ![starts](https://img.shields.io/github/stars/xn0kkx/CVE-2026-31431_CopyFail_LinuxKernel_LPE.svg) ![forks](https://img.shields.io/github/forks/xn0kkx/CVE-2026-31431_CopyFail_LinuxKernel_LPE.svg)


## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.

- [https://github.com/tc4dy/CVE-2026-29000-PoC-Exploit](https://github.com/tc4dy/CVE-2026-29000-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-29000-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-29000-PoC-Exploit.svg)


## CVE-2026-8161
 multiparty@4.2.3 and lower versions are vulnerable to denial of service via uncaught exception. By sending a multipart/form-data request with a field name that collides with an inherited Object.prototype property such as __proto__, constructor, or toString, the parser invokes .push() on the inherited prototype value rather than an array, throwing a TypeError that propagates as an uncaught exception and crashes the process. Impact: any service accepting multipart uploads via multiparty is affected. Workarounds: none. Upgrade to multiparty@4.3.0 or higher.

- [https://github.com/Ser0n-ath/multiparty-CVE-2026-8161](https://github.com/Ser0n-ath/multiparty-CVE-2026-8161) :  ![starts](https://img.shields.io/github/stars/Ser0n-ath/multiparty-CVE-2026-8161.svg) ![forks](https://img.shields.io/github/forks/Ser0n-ath/multiparty-CVE-2026-8161.svg)


## CVE-2026-6664
 An integer overflow in network packet parsing code in PgBouncer before 1.25.2 bypasses a boundary check and can lead to a crash. An unauthenticated remote attacker can crash PgBouncer with a malformed SCRAM authentication packet.

- [https://github.com/nicolasjulian/bouncer-overflow](https://github.com/nicolasjulian/bouncer-overflow) :  ![starts](https://img.shields.io/github/stars/nicolasjulian/bouncer-overflow.svg) ![forks](https://img.shields.io/github/forks/nicolasjulian/bouncer-overflow.svg)


## CVE-2026-5718
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file upload in versions up to, and including, 1.3.9.6. This is due to insufficient file type validation that occurs when custom blacklist types are configured, which replaces the default dangerous extension denylist instead of merging with it, and the wpcf7_antiscript_file_name() sanitization function being bypassed for filenames containing non-ASCII characters. This makes it possible for unauthenticated attackers to upload arbitrary files, such as PHP files, to the server, which can be leveraged to achieve remote code execution.

- [https://github.com/rootdirective-sec/cve-2026-5718-Lab](https://github.com/rootdirective-sec/cve-2026-5718-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/cve-2026-5718-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/cve-2026-5718-Lab.svg)


## CVE-2026-4255
 A DLL search order hijacking vulnerability in Thermalright TR-VISION HOME on Windows (64-bit) allows a local attacker to escalate privileges via DLL side-loading. The application loads certain dynamic-link library (DLL) dependencies using the default Windows search order, which includes directories that may be writable by non-privileged users.\n\n\n\nBecause these directories can be modified by unprivileged users, an attacker can place a malicious DLL with the same name as a legitimate dependency in a directory that is searched before trusted system locations. When the application is executed, which is always with administrative privileges, the malicious DLL is loaded instead of the legitimate library.\n\n\n\nThe application does not enforce restrictions on DLL loading locations and does not verify the integrity or digital signature of loaded libraries. As a result, attacker-controlled code may be executed within the security context of the application, allowing arbitrary code execution with elevated privileges.\n\n\n\nSuccessful exploitation requires that an attacker place a crafted malicious DLL in a user-writable directory that is included in the application's DLL search path and then cause the affected application to be executed. Once loaded, the malicious DLL runs with the same privileges as the application.\n\n\n\nThis issue affects \nTR-VISION HOME  versions up to and including 2.0.5.

- [https://github.com/Ard33/CVE-2026-4255](https://github.com/Ard33/CVE-2026-4255) :  ![starts](https://img.shields.io/github/stars/Ard33/CVE-2026-4255.svg) ![forks](https://img.shields.io/github/forks/Ard33/CVE-2026-4255.svg)


## CVE-2026-3888
 Local privilege escalation in snapd on Linux allows local attackers to get root privilege by re-creating snap's private /tmp directory when systemd-tmpfiles is configured to automatically clean up this directory. This issue affects Ubuntu 16.04 LTS, 18.04 LTS, 20.04 LTS, 22.04 LTS, and 24.04 LTS.

- [https://github.com/hewhomusntbenamed/CVE-2026-3888-fixed](https://github.com/hewhomusntbenamed/CVE-2026-3888-fixed) :  ![starts](https://img.shields.io/github/stars/hewhomusntbenamed/CVE-2026-3888-fixed.svg) ![forks](https://img.shields.io/github/forks/hewhomusntbenamed/CVE-2026-3888-fixed.svg)


## CVE-2026-3609
Cross reference to KVE 2023-5589 (https://krcert.or.kr)

- [https://github.com/BlackSnufkin/CredsHunter](https://github.com/BlackSnufkin/CredsHunter) :  ![starts](https://img.shields.io/github/stars/BlackSnufkin/CredsHunter.svg) ![forks](https://img.shields.io/github/forks/BlackSnufkin/CredsHunter.svg)


## CVE-2026-3105
Email us at security@mautic.org

- [https://github.com/campiotto/mautic-4.4-patches](https://github.com/campiotto/mautic-4.4-patches) :  ![starts](https://img.shields.io/github/stars/campiotto/mautic-4.4-patches.svg) ![forks](https://img.shields.io/github/forks/campiotto/mautic-4.4-patches.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/Z3ROROOT3R/CVE-2025-66478](https://github.com/Z3ROROOT3R/CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/Z3ROROOT3R/CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/Z3ROROOT3R/CVE-2025-66478.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2025-59366
Refer to the Security Update for ASUS Router Firmware section on the ASUS Security Advisory for more information.

- [https://github.com/murrez/ASUS-AiCloud-RCE](https://github.com/murrez/ASUS-AiCloud-RCE) :  ![starts](https://img.shields.io/github/stars/murrez/ASUS-AiCloud-RCE.svg) ![forks](https://img.shields.io/github/forks/murrez/ASUS-AiCloud-RCE.svg)


## CVE-2025-55184
 A pre-authentication denial of service vulnerability exists in React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints, which can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/bakhod1r/CVE-2025-55184](https://github.com/bakhod1r/CVE-2025-55184) :  ![starts](https://img.shields.io/github/stars/bakhod1r/CVE-2025-55184.svg) ![forks](https://img.shields.io/github/forks/bakhod1r/CVE-2025-55184.svg)


## CVE-2025-54236
 Adobe Commerce versions 2.4.9-alpha2, 2.4.8-p2, 2.4.7-p7, 2.4.6-p12, 2.4.5-p14, 2.4.4-p15 and earlier are affected by an Improper Input Validation vulnerability. A successful attacker can abuse this to achieve session takeover, increasing the confidentiality, and integrity impact to high. Exploitation of this issue does not require user interaction.

- [https://github.com/Jenderal92/magento-upload-auto-submit-zoneh](https://github.com/Jenderal92/magento-upload-auto-submit-zoneh) :  ![starts](https://img.shields.io/github/stars/Jenderal92/magento-upload-auto-submit-zoneh.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/magento-upload-auto-submit-zoneh.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)


## CVE-2025-2492
Refer to the 'ASUS Router AiCloud vulnerability' section on the ASUS Security Advisory for more information.

- [https://github.com/murrez/ASUS-AiCloud-RCE](https://github.com/murrez/ASUS-AiCloud-RCE) :  ![starts](https://img.shields.io/github/stars/murrez/ASUS-AiCloud-RCE.svg) ![forks](https://img.shields.io/github/forks/murrez/ASUS-AiCloud-RCE.svg)


## CVE-2024-52010
 Zoraxy is a general purpose HTTP reverse proxy and forwarding tool. A command injection vulnerability in the Web SSH feature allows an authenticated attacker to execute arbitrary commands as root on the host. Zoraxy has a Web SSH terminal feature that allows authenticated users to connect to SSH servers from their browsers. In HandleCreateProxySession the request to create an SSH session is handled. An attacker can exploit the username variable to escape from the bash command and inject arbitrary commands into sshCommand. This is possible, because, unlike hostname and port, the username is not validated or sanitized.

- [https://github.com/iuds/-CVE-2024-52010-](https://github.com/iuds/-CVE-2024-52010-) :  ![starts](https://img.shields.io/github/stars/iuds/-CVE-2024-52010-.svg) ![forks](https://img.shields.io/github/forks/iuds/-CVE-2024-52010-.svg)


## CVE-2024-44258
 This issue was addressed with improved handling of symlinks. This issue is fixed in iOS 17.7.1 and iPadOS 17.7.1, iOS 18.1 and iPadOS 18.1, tvOS 18.1, visionOS 2.1. Restoring a maliciously crafted backup file may lead to modification of protected system files.

- [https://github.com/fuzzlove/SparstanBoogie-CVE-2024-44258](https://github.com/fuzzlove/SparstanBoogie-CVE-2024-44258) :  ![starts](https://img.shields.io/github/stars/fuzzlove/SparstanBoogie-CVE-2024-44258.svg) ![forks](https://img.shields.io/github/forks/fuzzlove/SparstanBoogie-CVE-2024-44258.svg)


## CVE-2024-34568
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Themeqx LetterPress allows Stored XSS.This issue affects LetterPress: from n/a through 1.2.1.

- [https://github.com/sanupl/CVE-2024-34568](https://github.com/sanupl/CVE-2024-34568) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2024-34568.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2024-34568.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/y0naldez/CVE-2024-28397-Js2Py-RCE](https://github.com/y0naldez/CVE-2024-28397-Js2Py-RCE) :  ![starts](https://img.shields.io/github/stars/y0naldez/CVE-2024-28397-Js2Py-RCE.svg) ![forks](https://img.shields.io/github/forks/y0naldez/CVE-2024-28397-Js2Py-RCE.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/KaiHaoChen04/monikerlinktest](https://github.com/KaiHaoChen04/monikerlinktest) :  ![starts](https://img.shields.io/github/stars/KaiHaoChen04/monikerlinktest.svg) ![forks](https://img.shields.io/github/forks/KaiHaoChen04/monikerlinktest.svg)


## CVE-2024-12912
Refer to the '01/02/2025 ASUS Router AiCloud vulnerability' section on the ASUS Security Advisory for more information.

- [https://github.com/murrez/ASUS-AiCloud-RCE](https://github.com/murrez/ASUS-AiCloud-RCE) :  ![starts](https://img.shields.io/github/stars/murrez/ASUS-AiCloud-RCE.svg) ![forks](https://img.shields.io/github/forks/murrez/ASUS-AiCloud-RCE.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/rcribelar-nucleus/demo-php-cve-2024-2961](https://github.com/rcribelar-nucleus/demo-php-cve-2024-2961) :  ![starts](https://img.shields.io/github/stars/rcribelar-nucleus/demo-php-cve-2024-2961.svg) ![forks](https://img.shields.io/github/forks/rcribelar-nucleus/demo-php-cve-2024-2961.svg)


## CVE-2024-0582
 A memory leak flaw was found in the Linux kernel’s io_uring functionality in how a user registers a buffer ring with IORING_REGISTER_PBUF_RING, mmap() it, and then frees it. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/nanabingies/CVE-2024-0582](https://github.com/nanabingies/CVE-2024-0582) :  ![starts](https://img.shields.io/github/stars/nanabingies/CVE-2024-0582.svg) ![forks](https://img.shields.io/github/forks/nanabingies/CVE-2024-0582.svg)


## CVE-2023-20938
 In binder_transaction_buffer_release of binder.c, there is a possible use after free due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-257685302References: Upstream kernel

- [https://github.com/Cyb3rCr0wCC/cve-2023-20938](https://github.com/Cyb3rCr0wCC/cve-2023-20938) :  ![starts](https://img.shields.io/github/stars/Cyb3rCr0wCC/cve-2023-20938.svg) ![forks](https://img.shields.io/github/forks/Cyb3rCr0wCC/cve-2023-20938.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS = v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/SpeatX/ChamiloLMS-cve-2023-4220](https://github.com/SpeatX/ChamiloLMS-cve-2023-4220) :  ![starts](https://img.shields.io/github/stars/SpeatX/ChamiloLMS-cve-2023-4220.svg) ![forks](https://img.shields.io/github/forks/SpeatX/ChamiloLMS-cve-2023-4220.svg)


## CVE-2022-27666
 A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap objects and may cause a local privilege escalation threat.

- [https://github.com/ngtuonghung/CVE-2022-27666](https://github.com/ngtuonghung/CVE-2022-27666) :  ![starts](https://img.shields.io/github/stars/ngtuonghung/CVE-2022-27666.svg) ![forks](https://img.shields.io/github/forks/ngtuonghung/CVE-2022-27666.svg)


## CVE-2021-46080
 A Cross Site Request Forgery (CSRF) vulnerability exists in Vehicle Service Management System 1.0. An successful CSRF attacks leads to Stored Cross Site Scripting Vulnerability.

- [https://github.com/sanupl/CVE-2021-46080](https://github.com/sanupl/CVE-2021-46080) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46080.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46080.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-Cross-Site-Request-Forgery-CSRF-Leads-to-XSS](https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-Cross-Site-Request-Forgery-CSRF-Leads-to-XSS) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-Multiple-Cross-Site-Request-Forgery-CSRF-Leads-to-XSS.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-Multiple-Cross-Site-Request-Forgery-CSRF-Leads-to-XSS.svg)


## CVE-2021-46079
 An Unrestricted File Upload vulnerability exists in Sourcecodester Vehicle Service Management System 1.0. A remote attacker can upload malicious files leading to Html Injection.

- [https://github.com/sanupl/CVE-2021-46079](https://github.com/sanupl/CVE-2021-46079) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46079.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46079.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Html-Injection](https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Html-Injection) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Html-Injection.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Html-Injection.svg)


## CVE-2021-46078
 An Unrestricted File Upload vulnerability exists in Sourcecodester Vehicle Service Management System 1.0. A remote attacker can upload malicious files leading to a Stored Cross-Site Scripting vulnerability.

- [https://github.com/sanupl/CVE-2021-46078](https://github.com/sanupl/CVE-2021-46078) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46078.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46078.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Stored-Cross-Site-Scripting](https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Stored-Cross-Site-Scripting) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Stored-Cross-Site-Scripting.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Stored-Cross-Site-Scripting.svg)


## CVE-2021-46076
 Sourcecodester Vehicle Service Management System 1.0 is vulnerable to File upload. An attacker can upload a malicious php file in multiple endpoints it leading to Code Execution.

- [https://github.com/sanupl/CVE-2021-46076](https://github.com/sanupl/CVE-2021-46076) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46076.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46076.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Code-Execution](https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Code-Execution) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-Multiple-File-upload-Leads-to-Code-Execution.svg)


## CVE-2021-46075
 A Privilege Escalation vulnerability exists in Sourcecodester Vehicle Service Management System 1.0. Staff account users can access the admin resources and perform CRUD Operations.

- [https://github.com/sanupl/CVE-2021-46075](https://github.com/sanupl/CVE-2021-46075) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46075.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46075.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-Privilege-Escalation-Leads-to-CRUD-Operations](https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-Privilege-Escalation-Leads-to-CRUD-Operations) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-Multiple-Privilege-Escalation-Leads-to-CRUD-Operations.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-Multiple-Privilege-Escalation-Leads-to-CRUD-Operations.svg)


## CVE-2021-46074
 A Stored Cross Site Scripting (XSS) vulnerability exists in Sourcecodester Vehicle Service Management System 1.0 via the Settings Section in login panel.

- [https://github.com/sanupl/CVE-2021-46074](https://github.com/sanupl/CVE-2021-46074) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46074.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46074.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-Settings-Stored-Cross-Site-Scripting-XSS](https://github.com/sanupl/Vehicle-Service-Management-System-Settings-Stored-Cross-Site-Scripting-XSS) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-Settings-Stored-Cross-Site-Scripting-XSS.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-Settings-Stored-Cross-Site-Scripting-XSS.svg)


## CVE-2021-46073
 A Stored Cross Site Scripting (XSS) vulnerability exists in Sourcecodester Vehicle Service Management System 1.0 via the User List Section in login panel.

- [https://github.com/sanupl/CVE-2021-46073](https://github.com/sanupl/CVE-2021-46073) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46073.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46073.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-User-List-Stored-Cross-Site-Scripting-XSS](https://github.com/sanupl/Vehicle-Service-Management-System-User-List-Stored-Cross-Site-Scripting-XSS) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-User-List-Stored-Cross-Site-Scripting-XSS.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-User-List-Stored-Cross-Site-Scripting-XSS.svg)


## CVE-2021-46072
 A Stored Cross Site Scripting (XSS) vulnerability exists in Vehicle Service Management System 1.0 via the Service List Section in login panel.

- [https://github.com/sanupl/CVE-2021-46072](https://github.com/sanupl/CVE-2021-46072) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46072.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46072.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-Service-List-Stored-Cross-Site-Scripting-XSS](https://github.com/sanupl/Vehicle-Service-Management-System-Service-List-Stored-Cross-Site-Scripting-XSS) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-Service-List-Stored-Cross-Site-Scripting-XSS.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-Service-List-Stored-Cross-Site-Scripting-XSS.svg)


## CVE-2021-46071
 A Stored Cross Site Scripting (XSS) vulnerability exists in Vehicle Service Management System 1.0 via the Category List Section in login panel.

- [https://github.com/sanupl/CVE-2021-46071](https://github.com/sanupl/CVE-2021-46071) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46071.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46071.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-Category-List-Stored-Cross-Site-Scripting-XSS](https://github.com/sanupl/Vehicle-Service-Management-System-Category-List-Stored-Cross-Site-Scripting-XSS) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-Category-List-Stored-Cross-Site-Scripting-XSS.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-Category-List-Stored-Cross-Site-Scripting-XSS.svg)


## CVE-2021-46070
 A Stored Cross Site Scripting (XSS) vulnerability exists in Vehicle Service Management System 1.0 via the Service Requests Section in login panel.

- [https://github.com/sanupl/CVE-2021-46070](https://github.com/sanupl/CVE-2021-46070) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46070.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46070.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-Service-Requests-Stored-Cross-Site-Scripting-XSS](https://github.com/sanupl/Vehicle-Service-Management-System-Service-Requests-Stored-Cross-Site-Scripting-XSS) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-Service-Requests-Stored-Cross-Site-Scripting-XSS.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-Service-Requests-Stored-Cross-Site-Scripting-XSS.svg)


## CVE-2021-46069
 A Stored Cross Site Scripting (XSS) vulnerability exists in Vehicle Service Management System 1.0 via the Mechanic List Section in login panel.

- [https://github.com/sanupl/CVE-2021-46069](https://github.com/sanupl/CVE-2021-46069) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46069.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46069.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-Mechanic-List-Stored-Cross-Site-Scripting-XSS](https://github.com/sanupl/Vehicle-Service-Management-System-Mechanic-List-Stored-Cross-Site-Scripting-XSS) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-Mechanic-List-Stored-Cross-Site-Scripting-XSS.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-Mechanic-List-Stored-Cross-Site-Scripting-XSS.svg)


## CVE-2021-46068
 A Stored Cross Site Scripting (XSS) vulnerability exists in Vehicle Service Management System 1.0 via the My Account Section in login panel.

- [https://github.com/sanupl/CVE-2021-46068](https://github.com/sanupl/CVE-2021-46068) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46068.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46068.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-MyAccount-Stored-Cross-Site-Scripting-XSS](https://github.com/sanupl/Vehicle-Service-Management-System-MyAccount-Stored-Cross-Site-Scripting-XSS) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-MyAccount-Stored-Cross-Site-Scripting-XSS.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-MyAccount-Stored-Cross-Site-Scripting-XSS.svg)


## CVE-2021-46067
 In Vehicle Service Management System 1.0 an attacker can steal the cookies leading to Full Account Takeover.

- [https://github.com/sanupl/CVE-2021-46067](https://github.com/sanupl/CVE-2021-46067) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-46067.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-46067.svg)
- [https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-Cookie-Stealing-Leads-to-Full-Account-Takeover](https://github.com/sanupl/Vehicle-Service-Management-System-Multiple-Cookie-Stealing-Leads-to-Full-Account-Takeover) :  ![starts](https://img.shields.io/github/stars/sanupl/Vehicle-Service-Management-System-Multiple-Cookie-Stealing-Leads-to-Full-Account-Takeover.svg) ![forks](https://img.shields.io/github/forks/sanupl/Vehicle-Service-Management-System-Multiple-Cookie-Stealing-Leads-to-Full-Account-Takeover.svg)


## CVE-2021-45745
 A Stored Cross Site Scripting (XSS) vulnerability exists in Bludit 3.13.1 via the About Plugin in login panel.

- [https://github.com/sanupl/CVE-2021-45745](https://github.com/sanupl/CVE-2021-45745) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-45745.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-45745.svg)
- [https://github.com/sanupl/Bludit-3.13.1-About-Plugin-Stored-Cross-Site-Scripting-XSS](https://github.com/sanupl/Bludit-3.13.1-About-Plugin-Stored-Cross-Site-Scripting-XSS) :  ![starts](https://img.shields.io/github/stars/sanupl/Bludit-3.13.1-About-Plugin-Stored-Cross-Site-Scripting-XSS.svg) ![forks](https://img.shields.io/github/forks/sanupl/Bludit-3.13.1-About-Plugin-Stored-Cross-Site-Scripting-XSS.svg)


## CVE-2021-45744
 A Stored Cross Site Scripting (XSS) vulnerability exists in bludit 3.13.1 via the TAGS section in login panel.

- [https://github.com/sanupl/CVE-2021-45744](https://github.com/sanupl/CVE-2021-45744) :  ![starts](https://img.shields.io/github/stars/sanupl/CVE-2021-45744.svg) ![forks](https://img.shields.io/github/forks/sanupl/CVE-2021-45744.svg)
- [https://github.com/sanupl/Bludit-3.13.1-TAGS-Field-Stored-Cross-Site-Scripting-XSS](https://github.com/sanupl/Bludit-3.13.1-TAGS-Field-Stored-Cross-Site-Scripting-XSS) :  ![starts](https://img.shields.io/github/stars/sanupl/Bludit-3.13.1-TAGS-Field-Stored-Cross-Site-Scripting-XSS.svg) ![forks](https://img.shields.io/github/forks/sanupl/Bludit-3.13.1-TAGS-Field-Stored-Cross-Site-Scripting-XSS.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/paulameg/SimpleCTF-THM-Relatory](https://github.com/paulameg/SimpleCTF-THM-Relatory) :  ![starts](https://img.shields.io/github/stars/paulameg/SimpleCTF-THM-Relatory.svg) ![forks](https://img.shields.io/github/forks/paulameg/SimpleCTF-THM-Relatory.svg)


## CVE-2019-8451
 The /plugins/servlet/gadgets/makeRequest resource in Jira before version 8.4.0 allows remote attackers to access the content of internal network resources via a Server Side Request Forgery (SSRF) vulnerability due to a logic bug in the JiraWhitelist class.

- [https://github.com/iuds/CVE-2019-8451](https://github.com/iuds/CVE-2019-8451) :  ![starts](https://img.shields.io/github/stars/iuds/CVE-2019-8451.svg) ![forks](https://img.shields.io/github/forks/iuds/CVE-2019-8451.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/trinadh-dasari-cyber/eternalblue-ms17-010-research](https://github.com/trinadh-dasari-cyber/eternalblue-ms17-010-research) :  ![starts](https://img.shields.io/github/stars/trinadh-dasari-cyber/eternalblue-ms17-010-research.svg) ![forks](https://img.shields.io/github/forks/trinadh-dasari-cyber/eternalblue-ms17-010-research.svg)

