# Update 2026-01-06
## CVE-2026-21451
 Bagisto is an open source laravel eCommerce platform. A stored Cross-Site Scripting (XSS) vulnerability exists in Bagisto prior to version 2.3.10 within the CMS page editor. Although the platform normally attempts to sanitize `script` tags, the filtering can be bypassed by manipulating the raw HTTP POST request before submission. As a result, arbitrary JavaScript can be stored in the CMS content and executed whenever the page is viewed or edited. This exposes administrators to a high-severity risk, including complete account takeover, backend hijacking, and malicious script execution. Version 2.3.10 fixes the issue.

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21451](https://github.com/Ashwesker/Ashwesker-CVE-2026-21451) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21451.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21451.svg)


## CVE-2026-21445
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to version 1.7.0.dev45, multiple critical API endpoints in Langflow are missing authentication controls. The issue allows any unauthenticated user to access sensitive user conversation data, transaction histories, and perform destructive operations including message deletion. This affects endpoints handling personal data and system operations that should require proper authorization. Version 1.7.0.dev45 contains a patch.

- [https://github.com/chinaxploiter/CVE-2026-21445-PoC](https://github.com/chinaxploiter/CVE-2026-21445-PoC) :  ![starts](https://img.shields.io/github/stars/chinaxploiter/CVE-2026-21445-PoC.svg) ![forks](https://img.shields.io/github/forks/chinaxploiter/CVE-2026-21445-PoC.svg)


## CVE-2025-68926
 RustFS is a distributed object storage system built in Rust. In versions prior to 1.0.0-alpha.77, RustFS implements gRPC authentication using a hardcoded static token `"rustfs rpc"` that is publicly exposed in the source code repository, hardcoded on both client and server sides, non-configurable with no mechanism for token rotation, and universally valid across all RustFS deployments. Any attacker with network access to the gRPC port can authenticate using this publicly known token and execute privileged operations including data destruction, policy manipulation, and cluster configuration changes. Version 1.0.0-alpha.77 contains a fix for the issue.

- [https://github.com/Chocapikk/CVE-2025-68926](https://github.com/Chocapikk/CVE-2025-68926) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-68926.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-68926.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/Saad-Ayady/react2shellNSE](https://github.com/Saad-Ayady/react2shellNSE) :  ![starts](https://img.shields.io/github/stars/Saad-Ayady/react2shellNSE.svg) ![forks](https://img.shields.io/github/forks/Saad-Ayady/react2shellNSE.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/maronnjapan/claude-create-CVE-2025-29927](https://github.com/maronnjapan/claude-create-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/maronnjapan/claude-create-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/maronnjapan/claude-create-CVE-2025-29927.svg)
- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-27515
 Laravel is a web application framework. When using wildcard validation to validate a given file or image field (`files.*`), a user-crafted malicious request could potentially bypass the validation rules. This vulnerability is fixed in 11.44.1 and 12.1.1.

- [https://github.com/joaovicdev/EXPLOIT-CVE-2025-27515](https://github.com/joaovicdev/EXPLOIT-CVE-2025-27515) :  ![starts](https://img.shields.io/github/stars/joaovicdev/EXPLOIT-CVE-2025-27515.svg) ![forks](https://img.shields.io/github/forks/joaovicdev/EXPLOIT-CVE-2025-27515.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/keraattin/Mongobleed-Detector-CVE-2025-14847](https://github.com/keraattin/Mongobleed-Detector-CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/keraattin/Mongobleed-Detector-CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/keraattin/Mongobleed-Detector-CVE-2025-14847.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/x0da6h/POC-for-CVE-2025-9074](https://github.com/x0da6h/POC-for-CVE-2025-9074) :  ![starts](https://img.shields.io/github/stars/x0da6h/POC-for-CVE-2025-9074.svg) ![forks](https://img.shields.io/github/forks/x0da6h/POC-for-CVE-2025-9074.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/4daysday/cve-2025-8088](https://github.com/4daysday/cve-2025-8088) :  ![starts](https://img.shields.io/github/stars/4daysday/cve-2025-8088.svg) ![forks](https://img.shields.io/github/forks/4daysday/cve-2025-8088.svg)
- [https://github.com/pexlexity/WinRAR-CVE-2025-8088-Path-Traversal-PoC](https://github.com/pexlexity/WinRAR-CVE-2025-8088-Path-Traversal-PoC) :  ![starts](https://img.shields.io/github/stars/pexlexity/WinRAR-CVE-2025-8088-Path-Traversal-PoC.svg) ![forks](https://img.shields.io/github/forks/pexlexity/WinRAR-CVE-2025-8088-Path-Traversal-PoC.svg)
- [https://github.com/Shinkirou789/Cve-2025-8088-WinRar-vulnerability](https://github.com/Shinkirou789/Cve-2025-8088-WinRar-vulnerability) :  ![starts](https://img.shields.io/github/stars/Shinkirou789/Cve-2025-8088-WinRar-vulnerability.svg) ![forks](https://img.shields.io/github/forks/Shinkirou789/Cve-2025-8088-WinRar-vulnerability.svg)
- [https://github.com/nhattanhh/CVE-2025-8088](https://github.com/nhattanhh/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/nhattanhh/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/nhattanhh/CVE-2025-8088.svg)
- [https://github.com/ghostn4444/CVE-2025-8088](https://github.com/ghostn4444/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/ghostn4444/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/ghostn4444/CVE-2025-8088.svg)
- [https://github.com/hbesljx/CVE-2025-8088-EXP](https://github.com/hbesljx/CVE-2025-8088-EXP) :  ![starts](https://img.shields.io/github/stars/hbesljx/CVE-2025-8088-EXP.svg) ![forks](https://img.shields.io/github/forks/hbesljx/CVE-2025-8088-EXP.svg)


## CVE-2025-1485
 The Real Cookie Banner: GDPR & ePrivacy Cookie Consent WordPress plugin before 5.1.6, real-cookie-banner-pro WordPress plugin before 5.1.6 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup).

- [https://github.com/Ermensonx/CVE-2025-14857-MongoBleed](https://github.com/Ermensonx/CVE-2025-14857-MongoBleed) :  ![starts](https://img.shields.io/github/stars/Ermensonx/CVE-2025-14857-MongoBleed.svg) ![forks](https://img.shields.io/github/forks/Ermensonx/CVE-2025-14857-MongoBleed.svg)


## CVE-2024-55503
 An issue in termius before v.9.9.0 allows a local attacker to execute arbitrary code via a crafted script to the DYLD_INSERT_LIBRARIES component.

- [https://github.com/SyFi/CVE-2024-55503](https://github.com/SyFi/CVE-2024-55503) :  ![starts](https://img.shields.io/github/stars/SyFi/CVE-2024-55503.svg) ![forks](https://img.shields.io/github/forks/SyFi/CVE-2024-55503.svg)


## CVE-2024-45496
 A flaw was found in OpenShift. This issue occurs due to the misuse of elevated privileges in the OpenShift Container Platform's build process. During the build initialization step, the git-clone container is run with a privileged security context, allowing unrestricted access to the node. An attacker with developer-level access can provide a crafted .gitconfig file containing commands executed during the cloning process, leading to arbitrary command execution on the worker node. An attacker running code in a privileged container could escalate their permissions on the node running the container.

- [https://github.com/tevsho/cve-2024-45496](https://github.com/tevsho/cve-2024-45496) :  ![starts](https://img.shields.io/github/stars/tevsho/cve-2024-45496.svg) ![forks](https://img.shields.io/github/forks/tevsho/cve-2024-45496.svg)


## CVE-2024-36985
 In Splunk Enterprise versions below 9.2.2, 9.1.5, and 9.0.10, a low-privileged user that does not hold the admin or power Splunk roles could cause a Remote Code Execution through an external lookup that references the “splunk_archiver“ application.

- [https://github.com/LittleSuRii/CVE-2024-36985](https://github.com/LittleSuRii/CVE-2024-36985) :  ![starts](https://img.shields.io/github/stars/LittleSuRii/CVE-2024-36985.svg) ![forks](https://img.shields.io/github/forks/LittleSuRii/CVE-2024-36985.svg)


## CVE-2024-34351
 Next.js is a React framework that can provide building blocks to create web applications. A Server-Side Request Forgery (SSRF) vulnerability was identified in Next.js Server Actions. If the `Host` header is modified, and the below conditions are also met, an attacker may be able to make requests that appear to be originating from the Next.js application server itself. The required conditions are 1) Next.js is running in a self-hosted manner; 2) the Next.js application makes use of Server Actions; and 3) the Server Action performs a redirect to a relative path which starts with a `/`. This vulnerability was fixed in Next.js `14.1.1`.

- [https://github.com/Voorivex/CVE-2024-34351](https://github.com/Voorivex/CVE-2024-34351) :  ![starts](https://img.shields.io/github/stars/Voorivex/CVE-2024-34351.svg) ![forks](https://img.shields.io/github/forks/Voorivex/CVE-2024-34351.svg)
- [https://github.com/God4n/nextjs-CVE-2024-34351-_exploit](https://github.com/God4n/nextjs-CVE-2024-34351-_exploit) :  ![starts](https://img.shields.io/github/stars/God4n/nextjs-CVE-2024-34351-_exploit.svg) ![forks](https://img.shields.io/github/forks/God4n/nextjs-CVE-2024-34351-_exploit.svg)
- [https://github.com/avergnaud/Next.js_exploit_CVE-2024-34351](https://github.com/avergnaud/Next.js_exploit_CVE-2024-34351) :  ![starts](https://img.shields.io/github/stars/avergnaud/Next.js_exploit_CVE-2024-34351.svg) ![forks](https://img.shields.io/github/forks/avergnaud/Next.js_exploit_CVE-2024-34351.svg)
- [https://github.com/granita112/cve-2024-34351-tester](https://github.com/granita112/cve-2024-34351-tester) :  ![starts](https://img.shields.io/github/stars/granita112/cve-2024-34351-tester.svg) ![forks](https://img.shields.io/github/forks/granita112/cve-2024-34351-tester.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/h0w1tzxr/TryHack3M-Bricks-Heist](https://github.com/h0w1tzxr/TryHack3M-Bricks-Heist) :  ![starts](https://img.shields.io/github/stars/h0w1tzxr/TryHack3M-Bricks-Heist.svg) ![forks](https://img.shields.io/github/forks/h0w1tzxr/TryHack3M-Bricks-Heist.svg)


## CVE-2024-7387
 A flaw was found in openshift/builder. This vulnerability allows command injection via path traversal, where a malicious user can execute arbitrary commands on the OpenShift node running the builder container. When using the “Docker” strategy, executable files inside the privileged build container can be overridden using the `spec.source.secrets.secret.destinationDir` attribute of the `BuildConfig` definition. An attacker running code in a privileged container could escalate their permissions on the node running the container.

- [https://github.com/tevsho/cve-2024-7387](https://github.com/tevsho/cve-2024-7387) :  ![starts](https://img.shields.io/github/stars/tevsho/cve-2024-7387.svg) ![forks](https://img.shields.io/github/forks/tevsho/cve-2024-7387.svg)


## CVE-2023-46604
which fixes this issue.

- [https://github.com/RockyDesigne/SSP-Assignment-3-RCEYouLater](https://github.com/RockyDesigne/SSP-Assignment-3-RCEYouLater) :  ![starts](https://img.shields.io/github/stars/RockyDesigne/SSP-Assignment-3-RCEYouLater.svg) ![forks](https://img.shields.io/github/forks/RockyDesigne/SSP-Assignment-3-RCEYouLater.svg)


## CVE-2023-28205
 A use after free issue was addressed with improved memory management. This issue is fixed in Safari 16.4.1, iOS 15.7.5 and iPadOS 15.7.5, iOS 16.4.1 and iPadOS 16.4.1, macOS Ventura 13.3.1. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

- [https://github.com/seregonwar/uaf-2023-28205](https://github.com/seregonwar/uaf-2023-28205) :  ![starts](https://img.shields.io/github/stars/seregonwar/uaf-2023-28205.svg) ![forks](https://img.shields.io/github/forks/seregonwar/uaf-2023-28205.svg)


## CVE-2019-14206
 An Arbitrary File Deletion vulnerability in the Nevma Adaptive Images plugin before 0.6.67 for WordPress allows remote attackers to delete arbitrary files via the $REQUEST['adaptive-images-settings'] parameter in adaptive-images-script.php.

- [https://github.com/developerfred/cve-2019-14206-poc](https://github.com/developerfred/cve-2019-14206-poc) :  ![starts](https://img.shields.io/github/stars/developerfred/cve-2019-14206-poc.svg) ![forks](https://img.shields.io/github/forks/developerfred/cve-2019-14206-poc.svg)


## CVE-2017-9805
 The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.

- [https://github.com/Fl5xia/CVE-2017-9805](https://github.com/Fl5xia/CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/Fl5xia/CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/Fl5xia/CVE-2017-9805.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/JRrooot/CVE-2012-2982-Webmin-RCE](https://github.com/JRrooot/CVE-2012-2982-Webmin-RCE) :  ![starts](https://img.shields.io/github/stars/JRrooot/CVE-2012-2982-Webmin-RCE.svg) ![forks](https://img.shields.io/github/forks/JRrooot/CVE-2012-2982-Webmin-RCE.svg)

