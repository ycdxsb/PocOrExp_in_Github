## CVE-2025-64095
 DNN (formerly DotNetNuke) is an open-source web content management platform (CMS) in the Microsoft ecosystem. Prior to 10.1.1, the default HTML editor provider allows unauthenticated file uploads and images can overwrite existing files. An unauthenticated user can upload and replace existing files allowing defacing a website and combined with other issue, injection XSS payloads. This vulnerability is fixed in 10.1.1.



- [https://github.com/callinston/CVE-2025-64095](https://github.com/callinston/CVE-2025-64095) :  ![starts](https://img.shields.io/github/stars/callinston/CVE-2025-64095.svg) ![forks](https://img.shields.io/github/forks/callinston/CVE-2025-64095.svg)

- [https://github.com/h4x0r-dz/CVE-2025-64095---DNN-Unauthenticated-arbitrary-file-upload](https://github.com/h4x0r-dz/CVE-2025-64095---DNN-Unauthenticated-arbitrary-file-upload) :  ![starts](https://img.shields.io/github/stars/h4x0r-dz/CVE-2025-64095---DNN-Unauthenticated-arbitrary-file-upload.svg) ![forks](https://img.shields.io/github/forks/h4x0r-dz/CVE-2025-64095---DNN-Unauthenticated-arbitrary-file-upload.svg)

## CVE-2025-63298
 A path traversal vulnerability was identified in SourceCodester Pet Grooming Management System 1.0, affecting the admin/manage_website.php component. An authenticated user with administrative privileges can leverage this flaw by submitting a specially crafted POST request, enabling the deletion of arbitrary files on the web server or underlying operating system.



- [https://github.com/z3rObyte/CVE-2025-63298](https://github.com/z3rObyte/CVE-2025-63298) :  ![starts](https://img.shields.io/github/stars/z3rObyte/CVE-2025-63298.svg) ![forks](https://img.shields.io/github/forks/z3rObyte/CVE-2025-63298.svg)

## CVE-2025-62727
 Starlette is a lightweight ASGI framework/toolkit. Prior to 0.49.1 , an unauthenticated attacker can send a crafted HTTP Range header that triggers quadratic-time processing in Starlette's FileResponse Range parsing/merging logic. This enables CPU exhaustion per request, causing denial‑of‑service for endpoints serving files (e.g., StaticFiles or any use of FileResponse). This vulnerability is fixed in 0.49.1.



- [https://github.com/ch4n3-yoon/CVE-2025-62727-Demo](https://github.com/ch4n3-yoon/CVE-2025-62727-Demo) :  ![starts](https://img.shields.io/github/stars/ch4n3-yoon/CVE-2025-62727-Demo.svg) ![forks](https://img.shields.io/github/forks/ch4n3-yoon/CVE-2025-62727-Demo.svg)

## CVE-2025-62527
 Taguette is an open source qualitative research tool. An issue has been discovered in Taguette versions prior to 1.5.0. It was possible for an attacker to request password reset email containing a malicious link, allowing the attacker to set the email if clicked by the victim. This issue has been patched in version 1.5.0.



- [https://github.com/Mitchellzhou1/CVE_2025_62527_PoC](https://github.com/Mitchellzhou1/CVE_2025_62527_PoC) :  ![starts](https://img.shields.io/github/stars/Mitchellzhou1/CVE_2025_62527_PoC.svg) ![forks](https://img.shields.io/github/forks/Mitchellzhou1/CVE_2025_62527_PoC.svg)

## CVE-2025-62518
 astral-tokio-tar is a tar archive reading/writing library for async Rust. Versions of astral-tokio-tar prior to 0.5.6 contain a boundary parsing vulnerability that allows attackers to smuggle additional archive entries by exploiting inconsistent PAX/ustar header handling. When processing archives with PAX-extended headers containing size overrides, the parser incorrectly advances stream position based on ustar header size (often zero) instead of the PAX-specified size, causing it to interpret file content as legitimate tar headers. This issue has been patched in version 0.5.6. There are no workarounds.



- [https://github.com/edera-dev/cve-tarmageddon](https://github.com/edera-dev/cve-tarmageddon) :  ![starts](https://img.shields.io/github/stars/edera-dev/cve-tarmageddon.svg) ![forks](https://img.shields.io/github/forks/edera-dev/cve-tarmageddon.svg)

## CVE-2025-62506
 MinIO is a high-performance object storage system. In all versions prior to RELEASE.2025-10-15T17-29-55Z, a privilege escalation vulnerability allows service accounts and STS (Security Token Service) accounts with restricted session policies to bypass their inline policy restrictions when performing operations on their own account, specifically when creating new service accounts for the same user. The vulnerability exists in the IAM policy validation logic where the code incorrectly relied on the DenyOnly argument when validating session policies for restricted accounts. When a session policy is present, the system should validate that the action is allowed by the session policy, not just that it is not denied. An attacker with valid credentials for a restricted service or STS account can create a new service account for itself without policy restrictions, resulting in a new service account with full parent privileges instead of being restricted by the inline policy. This allows the attacker to access buckets and objects beyond their intended restrictions and modify, delete, or create objects outside their authorized scope. The vulnerability is fixed in version RELEASE.2025-10-15T17-29-55Z.



- [https://github.com/yoshino-s/CVE-2025-62506](https://github.com/yoshino-s/CVE-2025-62506) :  ![starts](https://img.shields.io/github/stars/yoshino-s/CVE-2025-62506.svg) ![forks](https://img.shields.io/github/forks/yoshino-s/CVE-2025-62506.svg)

## CVE-2025-62481
 Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing Administration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Marketing.  Successful attacks of this vulnerability can result in takeover of Oracle Marketing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/rxerium/CVE-2025-53072-CVE-2025-62481](https://github.com/rxerium/CVE-2025-53072-CVE-2025-62481) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-53072-CVE-2025-62481.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-53072-CVE-2025-62481.svg)

- [https://github.com/AshrafZaryouh/CVE-2025-53072-CVE-2025-62481](https://github.com/AshrafZaryouh/CVE-2025-53072-CVE-2025-62481) :  ![starts](https://img.shields.io/github/stars/AshrafZaryouh/CVE-2025-53072-CVE-2025-62481.svg) ![forks](https://img.shields.io/github/forks/AshrafZaryouh/CVE-2025-53072-CVE-2025-62481.svg)

## CVE-2025-62410
 In versions before 20.0.2, it was found that --disallow-code-generation-from-strings is not sufficient for isolating untrusted JavaScript in happy-dom. The untrusted script and the rest of the application still run in the same Isolate/process, so attackers can deploy prototype pollution payloads to hijack important references like "process" in the example below, or to hijack control flow via flipping checks of undefined property. This vulnerability is due to an incomplete fix for CVE-2025-61927. The vulnerability is fixed in 20.0.2.



- [https://github.com/SubZeroHackerz/CVE-2025-62410](https://github.com/SubZeroHackerz/CVE-2025-62410) :  ![starts](https://img.shields.io/github/stars/SubZeroHackerz/CVE-2025-62410.svg) ![forks](https://img.shields.io/github/forks/SubZeroHackerz/CVE-2025-62410.svg)

## CVE-2025-62376
 pwn.college DOJO is an education platform for learning cybersecurity. In versions up to and including commit 781d91157cfc234a434d0bab45cbcf97894c642e, the /workspace endpoint contains an improper authentication vulnerability that allows an attacker to access any active Windows VM without proper authorization. The vulnerability occurs in the view_desktop function where the user is retrieved via a URL parameter without verifying that the requester has administrative privileges. An attacker can supply any user ID and arbitrary password in the request parameters to impersonate another user. When requesting a Windows desktop service, the function does not validate the supplied password before generating access credentials, allowing the attacker to obtain an iframe source URL that grants full access to the target user's Windows VM. This impacts all users with active Windows VMs, as an attacker can access and modify data on the Windows machine and in the home directory of the associated Linux machine via the Z: drive. This issue has been patched in commit 467db0b9ea0d9a929dc89b41f6eb59f7cfc68bef. No known workarounds exist.



- [https://github.com/ghostroots/CVE-2025-62376](https://github.com/ghostroots/CVE-2025-62376) :  ![starts](https://img.shields.io/github/stars/ghostroots/CVE-2025-62376.svg) ![forks](https://img.shields.io/github/forks/ghostroots/CVE-2025-62376.svg)

## CVE-2025-62168
 Squid is a caching proxy for the Web. In Squid versions prior to 7.2, a failure to redact HTTP authentication credentials in error handling allows information disclosure. The vulnerability allows a script to bypass browser security protections and learn the credentials a trusted client uses to authenticate. This potentially allows a remote client to identify security tokens or credentials used internally by a web application using Squid for backend load balancing. These attacks do not require Squid to be configured with HTTP authentication. The vulnerability is fixed in version 7.2. As a workaround, disable debug information in administrator mailto links generated by Squid by configuring squid.conf with email_err_data off.



- [https://github.com/monzaviman/CVE-2025-62168](https://github.com/monzaviman/CVE-2025-62168) :  ![starts](https://img.shields.io/github/stars/monzaviman/CVE-2025-62168.svg) ![forks](https://img.shields.io/github/forks/monzaviman/CVE-2025-62168.svg)

## CVE-2025-61984
 ssh in OpenSSH before 10.1 allows control characters in usernames that originate from certain possibly untrusted sources, potentially leading to code execution when a ProxyCommand is used. The untrusted sources are the command line and %-sequence expansion of a configuration file. (A configuration file that provides a complete literal username is not categorized as an untrusted source.)



- [https://github.com/dgl/cve-2025-61984-poc](https://github.com/dgl/cve-2025-61984-poc) :  ![starts](https://img.shields.io/github/stars/dgl/cve-2025-61984-poc.svg) ![forks](https://img.shields.io/github/forks/dgl/cve-2025-61984-poc.svg)

- [https://github.com/ThanhCT-CyX/Test-CVE-2025-61984](https://github.com/ThanhCT-CyX/Test-CVE-2025-61984) :  ![starts](https://img.shields.io/github/stars/ThanhCT-CyX/Test-CVE-2025-61984.svg) ![forks](https://img.shields.io/github/forks/ThanhCT-CyX/Test-CVE-2025-61984.svg)

- [https://github.com/flyskyfire/cve-2025-61984-poc](https://github.com/flyskyfire/cve-2025-61984-poc) :  ![starts](https://img.shields.io/github/stars/flyskyfire/cve-2025-61984-poc.svg) ![forks](https://img.shields.io/github/forks/flyskyfire/cve-2025-61984-poc.svg)

## CVE-2025-61932
 Lanscope Endpoint Manager (On-Premises) (Client program (MR) and Detection agent (DA)) improperly verifies the origin of incoming requests, allowing an attacker to execute arbitrary code by sending specially crafted packets.



- [https://github.com/allinsthon/CVE-2025-61932](https://github.com/allinsthon/CVE-2025-61932) :  ![starts](https://img.shields.io/github/stars/allinsthon/CVE-2025-61932.svg) ![forks](https://img.shields.io/github/forks/allinsthon/CVE-2025-61932.svg)

## CVE-2025-61884
 Vulnerability in the Oracle Configurator product of Oracle E-Business Suite (component: Runtime UI).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Configurator.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle Configurator accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).



- [https://github.com/rxerium/CVE-2025-61882-CVE-2025-61884](https://github.com/rxerium/CVE-2025-61882-CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-61882-CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-61882-CVE-2025-61884.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-61884](https://github.com/B1ack4sh/Blackash-CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-61884.svg)

- [https://github.com/siddu7575/CVE-2025-61882-CVE-2025-61884](https://github.com/siddu7575/CVE-2025-61882-CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/siddu7575/CVE-2025-61882-CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/siddu7575/CVE-2025-61882-CVE-2025-61884.svg)

- [https://github.com/AshrafZaryouh/CVE-2025-61884-At-a-Glance](https://github.com/AshrafZaryouh/CVE-2025-61884-At-a-Glance) :  ![starts](https://img.shields.io/github/stars/AshrafZaryouh/CVE-2025-61884-At-a-Glance.svg) ![forks](https://img.shields.io/github/forks/AshrafZaryouh/CVE-2025-61884-At-a-Glance.svg)

- [https://github.com/pakagronglb/oracle-security-breaches-analysis-case-study](https://github.com/pakagronglb/oracle-security-breaches-analysis-case-study) :  ![starts](https://img.shields.io/github/stars/pakagronglb/oracle-security-breaches-analysis-case-study.svg) ![forks](https://img.shields.io/github/forks/pakagronglb/oracle-security-breaches-analysis-case-study.svg)

## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/watchtowrlabs/watchTowr-vs-Oracle-E-Business-Suite-CVE-2025-61882](https://github.com/watchtowrlabs/watchTowr-vs-Oracle-E-Business-Suite-CVE-2025-61882) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Oracle-E-Business-Suite-CVE-2025-61882.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Oracle-E-Business-Suite-CVE-2025-61882.svg)

- [https://github.com/rxerium/CVE-2025-61882-CVE-2025-61884](https://github.com/rxerium/CVE-2025-61882-CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-61882-CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-61882-CVE-2025-61884.svg)

- [https://github.com/zerozenxlabs/CVE-2025-61882-Oracle-EBS](https://github.com/zerozenxlabs/CVE-2025-61882-Oracle-EBS) :  ![starts](https://img.shields.io/github/stars/zerozenxlabs/CVE-2025-61882-Oracle-EBS.svg) ![forks](https://img.shields.io/github/forks/zerozenxlabs/CVE-2025-61882-Oracle-EBS.svg)

- [https://github.com/Sachinart/CVE-2025-61882](https://github.com/Sachinart/CVE-2025-61882) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2025-61882.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2025-61882.svg)

- [https://github.com/RootAid/CVE-2025-61882](https://github.com/RootAid/CVE-2025-61882) :  ![starts](https://img.shields.io/github/stars/RootAid/CVE-2025-61882.svg) ![forks](https://img.shields.io/github/forks/RootAid/CVE-2025-61882.svg)

- [https://github.com/BattalionX/http-oracle-ebs-cve-2025-61882.nse](https://github.com/BattalionX/http-oracle-ebs-cve-2025-61882.nse) :  ![starts](https://img.shields.io/github/stars/BattalionX/http-oracle-ebs-cve-2025-61882.nse.svg) ![forks](https://img.shields.io/github/forks/BattalionX/http-oracle-ebs-cve-2025-61882.nse.svg)

- [https://github.com/AdityaBhatt3010/CVE-2025-61882-Oracle-E-Business-Suite-Pre-Auth-RCE-Exploit](https://github.com/AdityaBhatt3010/CVE-2025-61882-Oracle-E-Business-Suite-Pre-Auth-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-61882-Oracle-E-Business-Suite-Pre-Auth-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-61882-Oracle-E-Business-Suite-Pre-Auth-RCE-Exploit.svg)

- [https://github.com/siddu7575/CVE-2025-61882-CVE-2025-61884](https://github.com/siddu7575/CVE-2025-61882-CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/siddu7575/CVE-2025-61882-CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/siddu7575/CVE-2025-61882-CVE-2025-61884.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-61882](https://github.com/B1ack4sh/Blackash-CVE-2025-61882) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-61882.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-61882.svg)

- [https://github.com/GhoStZA-debug/CVE-2025-61882](https://github.com/GhoStZA-debug/CVE-2025-61882) :  ![starts](https://img.shields.io/github/stars/GhoStZA-debug/CVE-2025-61882.svg) ![forks](https://img.shields.io/github/forks/GhoStZA-debug/CVE-2025-61882.svg)

- [https://github.com/MindflareX/CVE-2025-61882-POC](https://github.com/MindflareX/CVE-2025-61882-POC) :  ![starts](https://img.shields.io/github/stars/MindflareX/CVE-2025-61882-POC.svg) ![forks](https://img.shields.io/github/forks/MindflareX/CVE-2025-61882-POC.svg)

- [https://github.com/AshrafZaryouh/CVE-2025-61882-Executive-Summary](https://github.com/AshrafZaryouh/CVE-2025-61882-Executive-Summary) :  ![starts](https://img.shields.io/github/stars/AshrafZaryouh/CVE-2025-61882-Executive-Summary.svg) ![forks](https://img.shields.io/github/forks/AshrafZaryouh/CVE-2025-61882-Executive-Summary.svg)

## CVE-2025-61777
 Flag Forge is a Capture The Flag (CTF) platform. Starting in version 2.0.0 and prior to version 2.3.2, the `/api/admin/badge-templates` (GET) and `/api/admin/badge-templates/create` (POST) endpoints previously allowed access without authentication or authorization. This could have enabled unauthorized users to retrieve all badge templates and sensitive metadata (createdBy, createdAt, updatedAt) and/or create arbitrary badge templates in the database. This could lead to data exposure, database pollution, or abuse of the badge system. The issue has been fixed in FlagForge v2.3.2. GET, POST, UPDATE, and DELETE endpoints now require authentication. Authorization checks ensure only admins can access and modify badge templates. No reliable workarounds are available.



- [https://github.com/0x0w1z/CVE-2025-61777](https://github.com/0x0w1z/CVE-2025-61777) :  ![starts](https://img.shields.io/github/stars/0x0w1z/CVE-2025-61777.svg) ![forks](https://img.shields.io/github/forks/0x0w1z/CVE-2025-61777.svg)

## CVE-2025-61622
 Deserialization of untrusted data in python in pyfory versions 0.12.0 through 0.12.2, or the legacy pyfury versions from 0.1.0 through 0.10.3: allows arbitrary code execution. An application is vulnerable if it reads pyfory serialized data from untrusted sources. An attacker can craft a data stream that selects pickle-fallback serializer during deserialization, leading to the execution of `pickle.loads`, which is vulnerable to remote code execution.

Users are recommended to upgrade to pyfory version 0.12.3 or later, which has removed pickle fallback serializer and thus fixes this issue.



- [https://github.com/fa1consec/cve_2025_61622_poc](https://github.com/fa1consec/cve_2025_61622_poc) :  ![starts](https://img.shields.io/github/stars/fa1consec/cve_2025_61622_poc.svg) ![forks](https://img.shields.io/github/forks/fa1consec/cve_2025_61622_poc.svg)

## CVE-2025-61481
 An issue in MikroTik RouterOS v.7.14.2 and SwOS v.2.18 exposes the WebFig management interface over cleartext HTTP by default, allowing an on-path attacker to execute injected JavaScript in the administrator’s browser and intercept credentials.



- [https://github.com/B1ack4sh/Blackash-CVE-2025-61481](https://github.com/B1ack4sh/Blackash-CVE-2025-61481) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-61481.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-61481.svg)

- [https://github.com/codetombs/CVE-2025-61481](https://github.com/codetombs/CVE-2025-61481) :  ![starts](https://img.shields.io/github/stars/codetombs/CVE-2025-61481.svg) ![forks](https://img.shields.io/github/forks/codetombs/CVE-2025-61481.svg)

## CVE-2025-61456
 A Cross-Site Scripting (XSS) vulnerability exists in Bhabishya-123 E-commerce 1.0, specifically within the index endpoint. Unsanitized input in the /index parameter is directly reflected back into the response HTML, allowing attackers to execute arbitrary JavaScript in the browser of a user who visits a malicious link or submits a crafted request.



- [https://github.com/tansique-17/CVE-2025-61456](https://github.com/tansique-17/CVE-2025-61456) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-61456.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-61456.svg)

## CVE-2025-61455
 SQL Injection vulnerability exists in Bhabishya-123 E-commerce 1.0, specifically within the signup.inc.php endpoint. The application directly incorporates unsanitized user inputs into SQL queries, allowing unauthenticated attackers to bypass authentication and gain full access.



- [https://github.com/tansique-17/CVE-2025-61455](https://github.com/tansique-17/CVE-2025-61455) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-61455.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-61455.svg)

## CVE-2025-61454
 A Cross-Site Scripting (XSS) vulnerability exists in Bhabishya-123 E-commerce 1.0, specifically within the search endpoint. Unsanitized input in the /search parameter is directly reflected back into the response HTML, allowing attackers to execute arbitrary JavaScript in the browser of a user who visits a malicious link or submits a crafted request.



- [https://github.com/tansique-17/CVE-2025-61454](https://github.com/tansique-17/CVE-2025-61454) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-61454.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-61454.svg)

## CVE-2025-61319
 ReNgine thru 2.2.0 is vulnerable to a Stored Cross-Site Scripting (XSS) vulnerability in the Vulnerabilities module. When scanning a target with an XSS payload, the unsanitized payload is rendered in the ReNgine web UI, resulting in arbitrary JavaScript execution in the victim's browser. This can be abused to steal session cookies, perform unauthorized actions, or compromise the ReNgine administrator's account.



- [https://github.com/AmalJafarzade/CVE-2025-61319](https://github.com/AmalJafarzade/CVE-2025-61319) :  ![starts](https://img.shields.io/github/stars/AmalJafarzade/CVE-2025-61319.svg) ![forks](https://img.shields.io/github/forks/AmalJafarzade/CVE-2025-61319.svg)

## CVE-2025-61303
 Hatching Triage Sandbox Windows 10 build 2004 (2025-08-14) and Windows 10 LTSC 2021(2025-08-14) contains a vulnerability in its Windows behavioral analysis engine that allows a submitted malware sample to evade detection and cause denial-of-analysis. The vulnerability is triggered when a sample recursively spawns a large number of child processes, generating high log volume and exhausting system resources. As a result, key malicious behavior, including PowerShell execution and reverse shell activity, may not be recorded or reported, misleading analysts and compromising the integrity and availability of sandboxed analysis results.



- [https://github.com/eGkritsis/CVE-2025-61303](https://github.com/eGkritsis/CVE-2025-61303) :  ![starts](https://img.shields.io/github/stars/eGkritsis/CVE-2025-61303.svg) ![forks](https://img.shields.io/github/forks/eGkritsis/CVE-2025-61303.svg)

## CVE-2025-61301
 Denial-of-analysis in reporting/mongodb.py and reporting/jsondump.py in CAPEv2 (commit 52e4b43, on 2025-05-17) allows attackers who can submit samples to cause incomplete or missing behavioral analysis reports by generating deeply nested or oversized behavior data that trigger MongoDB BSON limits or orjson recursion errors when the sample executes in the sandbox.



- [https://github.com/eGkritsis/CVE-2025-61301](https://github.com/eGkritsis/CVE-2025-61301) :  ![starts](https://img.shields.io/github/stars/eGkritsis/CVE-2025-61301.svg) ![forks](https://img.shields.io/github/forks/eGkritsis/CVE-2025-61301.svg)

## CVE-2025-61196
 An issue in BusinessNext CRMnext v.10.8.3.0 allows a remote attacker to execute arbitrary code via the comments input parameter.



- [https://github.com/zsamamah/CVE-2025-61196](https://github.com/zsamamah/CVE-2025-61196) :  ![starts](https://img.shields.io/github/stars/zsamamah/CVE-2025-61196.svg) ![forks](https://img.shields.io/github/forks/zsamamah/CVE-2025-61196.svg)

## CVE-2025-61183
 Cross Site Scripting in vaahcms v.2.3.1 allows a remote attacker to execute arbitrary code via upload method in the storeAvatar() method of UserBase.php



- [https://github.com/thawphone/CVE-2025-61183](https://github.com/thawphone/CVE-2025-61183) :  ![starts](https://img.shields.io/github/stars/thawphone/CVE-2025-61183.svg) ![forks](https://img.shields.io/github/forks/thawphone/CVE-2025-61183.svg)

## CVE-2025-61156
 Incorrect access control in the kernel driver of ThreatFire System Monitor v4.7.0.53 allows attackers to escalate privileges and execute arbitrary commands via an insecure IOCTL.



- [https://github.com/D7EAD/CVE-2025-61156](https://github.com/D7EAD/CVE-2025-61156) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2025-61156.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2025-61156.svg)

## CVE-2025-61155
 Hotta Studio GameDriverX64.sys 7.23.4.7, a signed kernel-mode anti-cheat driver, allows local attackers to cause a denial of service by crashing arbitrary processes via sending crafted IOCTL requests.



- [https://github.com/pollotherunner/CVE-2025-61155](https://github.com/pollotherunner/CVE-2025-61155) :  ![starts](https://img.shields.io/github/stars/pollotherunner/CVE-2025-61155.svg) ![forks](https://img.shields.io/github/forks/pollotherunner/CVE-2025-61155.svg)

## CVE-2025-60880
 An authenticated stored XSS vulnerability exists in the Bagisto 2.3.6 admin panel's product creation path, allowing an attacker to upload a crafted SVG file containing malicious JavaScript code. This vulnerability can be exploited by an authenticated admin user to execute arbitrary JavaScript in the browser, potentially leading to session hijacking, data theft, or unauthorized actions.



- [https://github.com/Shenal01/CVE-2025-60880](https://github.com/Shenal01/CVE-2025-60880) :  ![starts](https://img.shields.io/github/stars/Shenal01/CVE-2025-60880.svg) ![forks](https://img.shields.io/github/forks/Shenal01/CVE-2025-60880.svg)

## CVE-2025-60852
 A CSV Injection vulnerability existed in Instant Developer Foundation versions prior to 25.0.9600. Applications built with affected versions of the framework did not properly sanitize user-controlled input before including it in CSV exports. This issue could lead to code execution on the system where the exported CSV file is opened.



- [https://github.com/valeriocassoni/CSV-Injection-in-Instant-Developer-Foundation-25.0-PoC](https://github.com/valeriocassoni/CSV-Injection-in-Instant-Developer-Foundation-25.0-PoC) :  ![starts](https://img.shields.io/github/stars/valeriocassoni/CSV-Injection-in-Instant-Developer-Foundation-25.0-PoC.svg) ![forks](https://img.shields.io/github/forks/valeriocassoni/CSV-Injection-in-Instant-Developer-Foundation-25.0-PoC.svg)

## CVE-2025-60791
 Easywork Enterprise 2.1.3.354 is vulnerable to Cleartext Storage of Sensitive Information in Memory. The application leaves valid device-bound license keys in process memory after a failed activation attempt. The keys can be obtained by attaching a debugger or analyzing the process/memory dump and then they can be used to activate the software on the same machine without purchasing.



- [https://github.com/Smarttfoxx/CVE-2025-60791](https://github.com/Smarttfoxx/CVE-2025-60791) :  ![starts](https://img.shields.io/github/stars/Smarttfoxx/CVE-2025-60791.svg) ![forks](https://img.shields.io/github/forks/Smarttfoxx/CVE-2025-60791.svg)

## CVE-2025-60787
 MotionEye v0.43.1b4 and before is vulnerable to OS Command Injection in configuration parameters such as image_file_name. Unsanitized user input is written to Motion configuration files, allowing remote authenticated attackers with admin access to achieve code execution when Motion is restarted.



- [https://github.com/prabhatverma47/CVE-2025-60787](https://github.com/prabhatverma47/CVE-2025-60787) :  ![starts](https://img.shields.io/github/stars/prabhatverma47/CVE-2025-60787.svg) ![forks](https://img.shields.io/github/forks/prabhatverma47/CVE-2025-60787.svg)

## CVE-2025-60751
 GeographicLib 2.5 is vulnerable to Buffer Overflow in GeoConvert DMS::InternalDecode.



- [https://github.com/zer0matt/CVE-2025-60751](https://github.com/zer0matt/CVE-2025-60751) :  ![starts](https://img.shields.io/github/stars/zer0matt/CVE-2025-60751.svg) ![forks](https://img.shields.io/github/forks/zer0matt/CVE-2025-60751.svg)

## CVE-2025-60749
 DLL Hijacking vulnerability in Trimble SketchUp desktop 2025 via crafted libcef.dll used by sketchup_webhelper.exe.



- [https://github.com/yawataa/CVE-2025-60749](https://github.com/yawataa/CVE-2025-60749) :  ![starts](https://img.shields.io/github/stars/yawataa/CVE-2025-60749.svg) ![forks](https://img.shields.io/github/forks/yawataa/CVE-2025-60749.svg)

## CVE-2025-60595
 SPH Engineering UgCS 5.13.0 is vulnerable to Arbitary code execution.



- [https://github.com/Clicksafeae/CVE-2025-60595](https://github.com/Clicksafeae/CVE-2025-60595) :  ![starts](https://img.shields.io/github/stars/Clicksafeae/CVE-2025-60595.svg) ![forks](https://img.shields.io/github/forks/Clicksafeae/CVE-2025-60595.svg)

## CVE-2025-60500
 QDocs Smart School Management System 7.1 allows authenticated users with roles such as "accountant" or "admin" to bypass file type restrictions in the media upload feature by abusing the alternate YouTube URL option. This logic flaw permits uploading of arbitrary PHP files, which are stored in a web-accessible directory.



- [https://github.com/H4zaz/CVE-2025-60500](https://github.com/H4zaz/CVE-2025-60500) :  ![starts](https://img.shields.io/github/stars/H4zaz/CVE-2025-60500.svg) ![forks](https://img.shields.io/github/forks/H4zaz/CVE-2025-60500.svg)

## CVE-2025-60425
 Nagios Fusion v2024R1.2 and v2024R2 does not invalidate already existing session tokens when the two-factor authentication mechanism is enabled, allowing attackers to perform a session hijacking attack.



- [https://github.com/aakashtyal/Session-Persistence-After-Enabling-2FA-CVE-2025-60425](https://github.com/aakashtyal/Session-Persistence-After-Enabling-2FA-CVE-2025-60425) :  ![starts](https://img.shields.io/github/stars/aakashtyal/Session-Persistence-After-Enabling-2FA-CVE-2025-60425.svg) ![forks](https://img.shields.io/github/forks/aakashtyal/Session-Persistence-After-Enabling-2FA-CVE-2025-60425.svg)

## CVE-2025-60424
 A lack of rate limiting in the OTP verification component of Nagios Fusion v2024R1.2 and v2024R2 allows attackers to bypass authentication via a bruteforce attack.



- [https://github.com/aakashtyal/2FA-Bypass-using-a-Brute-Force-Attack-CVE-2025-60424](https://github.com/aakashtyal/2FA-Bypass-using-a-Brute-Force-Attack-CVE-2025-60424) :  ![starts](https://img.shields.io/github/stars/aakashtyal/2FA-Bypass-using-a-Brute-Force-Attack-CVE-2025-60424.svg) ![forks](https://img.shields.io/github/forks/aakashtyal/2FA-Bypass-using-a-Brute-Force-Attack-CVE-2025-60424.svg)

## CVE-2025-60378
 Stored HTML injection in RISE Ultimate Project Manager & CRM allows authenticated users to inject arbitrary HTML into invoices and messages. Injected content renders in emails, PDFs, and messaging/chat modules sent to clients or team members, enabling phishing, credential theft, and business email compromise. Automated recurring invoices and messaging amplify the risk by distributing malicious content to multiple recipients.



- [https://github.com/ajansha/CVE-2025-60378](https://github.com/ajansha/CVE-2025-60378) :  ![starts](https://img.shields.io/github/stars/ajansha/CVE-2025-60378.svg) ![forks](https://img.shields.io/github/forks/ajansha/CVE-2025-60378.svg)

## CVE-2025-60375
 The authentication mechanism in Perfex CRM before 3.3.1 allows attackers to bypass login credentials due to insufficient server-side validation. By sending empty username and password parameters in the login request, an attacker can gain unauthorized access to user accounts, including administrative accounts, without providing valid credentials.



- [https://github.com/AhamedYaseen03/CVE-2025-60375](https://github.com/AhamedYaseen03/CVE-2025-60375) :  ![starts](https://img.shields.io/github/stars/AhamedYaseen03/CVE-2025-60375.svg) ![forks](https://img.shields.io/github/forks/AhamedYaseen03/CVE-2025-60375.svg)

- [https://github.com/ajansha/CVE-2025-60375](https://github.com/ajansha/CVE-2025-60375) :  ![starts](https://img.shields.io/github/stars/ajansha/CVE-2025-60375.svg) ![forks](https://img.shields.io/github/forks/ajansha/CVE-2025-60375.svg)

## CVE-2025-60374
 Stored Cross-Site Scripting (XSS) in Perfex CRM chatbot before 3.3.1 allows attackers to inject arbitrary HTML/JavaScript. The payload is executed in the browsers of users viewing the chat, resulting in client-side code execution, potential session token theft, and other malicious actions. A different vulnerability than CVE-2024-8867.



- [https://github.com/ajansha/CVE-2025-60374](https://github.com/ajansha/CVE-2025-60374) :  ![starts](https://img.shields.io/github/stars/ajansha/CVE-2025-60374.svg) ![forks](https://img.shields.io/github/forks/ajansha/CVE-2025-60374.svg)

## CVE-2025-60349
 An issue was discovered in Prevx v3.0.5.220 allowing attackers to cause a denial of service via sending IOCTL code 0x22E044 to the pxscan.sys driver. Any processes listed under registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\pxscan\Files will be terminated.



- [https://github.com/djackreuter/CVE-2025-60349](https://github.com/djackreuter/CVE-2025-60349) :  ![starts](https://img.shields.io/github/stars/djackreuter/CVE-2025-60349.svg) ![forks](https://img.shields.io/github/forks/djackreuter/CVE-2025-60349.svg)

## CVE-2025-59934
 Formbricks is an open source qualtrics alternative. Prior to version 4.0.1, Formbricks is missing JWT signature verification. This vulnerability stems from a token validation routine that only decodes JWTs (jwt.decode) without verifying their signatures. Both the email verification token login path and the password reset server action use the same validator, which does not check the token’s signature, expiration, issuer, or audience. If an attacker learns the victim’s actual user.id, they can craft an arbitrary JWT with an alg: "none" header and use it to authenticate and reset the victim’s password. This issue has been patched in version 4.0.1.



- [https://github.com/suriryuk/cve-2025-59934](https://github.com/suriryuk/cve-2025-59934) :  ![starts](https://img.shields.io/github/stars/suriryuk/cve-2025-59934.svg) ![forks](https://img.shields.io/github/forks/suriryuk/cve-2025-59934.svg)

## CVE-2025-59932
 Flag Forge is a Capture The Flag (CTF) platform. From versions 2.0.0 to before 2.3.1, the /api/resources endpoint previously allowed POST and DELETE requests without proper authentication or authorization. This could have enabled unauthorized users to create, modify, or delete resources on the platform. The issue has been fixed in FlagForge version 2.3.1.



- [https://github.com/At0mXploit/CVE-2025-59843-CVE-2025-59932](https://github.com/At0mXploit/CVE-2025-59843-CVE-2025-59932) :  ![starts](https://img.shields.io/github/stars/At0mXploit/CVE-2025-59843-CVE-2025-59932.svg) ![forks](https://img.shields.io/github/forks/At0mXploit/CVE-2025-59843-CVE-2025-59932.svg)

## CVE-2025-59843
 Flag Forge is a Capture The Flag (CTF) platform. From versions 2.0.0 to before 2.3.1, the public endpoint /api/user/[username] returns user email addresses in its JSON response. The problem has been patched in FlagForge version 2.3.1. The fix removes email addresses from public API responses while keeping the endpoint publicly accessible. Users should upgrade to version 2.3.1 or later to eliminate exposure. There are no workarounds for this vulnerability.



- [https://github.com/At0mXploit/CVE-2025-59843-CVE-2025-59932](https://github.com/At0mXploit/CVE-2025-59843-CVE-2025-59932) :  ![starts](https://img.shields.io/github/stars/At0mXploit/CVE-2025-59843-CVE-2025-59932.svg) ![forks](https://img.shields.io/github/forks/At0mXploit/CVE-2025-59843-CVE-2025-59932.svg)

## CVE-2025-59713
 Snipe-IT before 8.1.18 allows unsafe deserialization.



- [https://github.com/synacktiv/CVE-2025-59712_CVE-2025-59713](https://github.com/synacktiv/CVE-2025-59712_CVE-2025-59713) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2025-59712_CVE-2025-59713.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2025-59712_CVE-2025-59713.svg)

## CVE-2025-59712
 Snipe-IT before 8.1.18 allows XSS.



- [https://github.com/synacktiv/CVE-2025-59712_CVE-2025-59713](https://github.com/synacktiv/CVE-2025-59712_CVE-2025-59713) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2025-59712_CVE-2025-59713.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2025-59712_CVE-2025-59713.svg)

## CVE-2025-59489
 Unity Runtime before 2025-10-02 on Android, Windows, macOS, and Linux allows argument injection that can result in loading of library code from an unintended location. If an application was built with a version of Unity Editor that had the vulnerable Unity Runtime code, then an adversary may be able to execute code on, and exfiltrate confidential information from, the machine on which that application is running. NOTE: product status is provided for Unity Editor because that is the information available from the Supplier. However, updating Unity Editor typically does not address the effects of the vulnerability; instead, it is necessary to rebuild and redeploy all affected applications.



- [https://github.com/GithubKillsMyOpsec/CVE-2025-59489-POC](https://github.com/GithubKillsMyOpsec/CVE-2025-59489-POC) :  ![starts](https://img.shields.io/github/stars/GithubKillsMyOpsec/CVE-2025-59489-POC.svg) ![forks](https://img.shields.io/github/forks/GithubKillsMyOpsec/CVE-2025-59489-POC.svg)

- [https://github.com/taptap/cve-2025-59489](https://github.com/taptap/cve-2025-59489) :  ![starts](https://img.shields.io/github/stars/taptap/cve-2025-59489.svg) ![forks](https://img.shields.io/github/forks/taptap/cve-2025-59489.svg)

- [https://github.com/moTorky/mhl_cve_2025_59489](https://github.com/moTorky/mhl_cve_2025_59489) :  ![starts](https://img.shields.io/github/stars/moTorky/mhl_cve_2025_59489.svg) ![forks](https://img.shields.io/github/forks/moTorky/mhl_cve_2025_59489.svg)

- [https://github.com/AdriianFdz/Exploit-CVE-2025-59489](https://github.com/AdriianFdz/Exploit-CVE-2025-59489) :  ![starts](https://img.shields.io/github/stars/AdriianFdz/Exploit-CVE-2025-59489.svg) ![forks](https://img.shields.io/github/forks/AdriianFdz/Exploit-CVE-2025-59489.svg)

## CVE-2025-59424
 LinkAce is a self-hosted archive to collect website links. Prior to 2.3.1, a Stored Cross-Site Scripting (XSS) vulnerability has been identified on the /system/audit page. The application fails to properly sanitize the username field before it is rendered in the audit log. An authenticated attacker can set a malicious JavaScript payload as their username. When an action performed by this user is recorded (e.g., generate or revoke an API token), the payload is stored in the database. The script is then executed in the browser of any user, particularly administrators, who views the /system/audit page. This vulnerability is fixed in 2.3.1.



- [https://github.com/JOOJIII/CVE-2025-59424](https://github.com/JOOJIII/CVE-2025-59424) :  ![starts](https://img.shields.io/github/stars/JOOJIII/CVE-2025-59424.svg) ![forks](https://img.shields.io/github/forks/JOOJIII/CVE-2025-59424.svg)

## CVE-2025-59377
 feiskyer mcp-kubernetes-server through 0.1.11 allows OS command injection, even in read-only mode, via /mcp/kubectl because shell=True is used. NOTE: this is unrelated to mcp-server-kubernetes and CVE-2025-53355.



- [https://github.com/william31212/CVE-Requests-1896609](https://github.com/william31212/CVE-Requests-1896609) :  ![starts](https://img.shields.io/github/stars/william31212/CVE-Requests-1896609.svg) ![forks](https://img.shields.io/github/forks/william31212/CVE-Requests-1896609.svg)

## CVE-2025-59376
 feiskyer mcp-kubernetes-server through 0.1.11 does not consider chained commands in the implementation of --disable-write and --disable-delete, e.g., it allows a "kubectl version; kubectl delete pod" command because the first word (i.e., "version") is not a write or delete operation.



- [https://github.com/william31212/CVE-Requests-1896609](https://github.com/william31212/CVE-Requests-1896609) :  ![starts](https://img.shields.io/github/stars/william31212/CVE-Requests-1896609.svg) ![forks](https://img.shields.io/github/forks/william31212/CVE-Requests-1896609.svg)

## CVE-2025-59359
 The cleanTcs mutation in Chaos Controller Manager is vulnerable to OS command injection. In conjunction with CVE-2025-59358, this allows  unauthenticated in-cluster attackers to perform remote code execution across the cluster.



- [https://github.com/mrk336/Cluster-Chaos-Exploiting-CVE-2025-59359-for-Kubernetes-Takeover](https://github.com/mrk336/Cluster-Chaos-Exploiting-CVE-2025-59359-for-Kubernetes-Takeover) :  ![starts](https://img.shields.io/github/stars/mrk336/Cluster-Chaos-Exploiting-CVE-2025-59359-for-Kubernetes-Takeover.svg) ![forks](https://img.shields.io/github/forks/mrk336/Cluster-Chaos-Exploiting-CVE-2025-59359-for-Kubernetes-Takeover.svg)

## CVE-2025-59342
 esm.sh is a nobuild content delivery network(CDN) for modern web development. In 136 and earlier, a path-traversal flaw in the handling of the X-Zone-Id HTTP header allows an attacker to cause the application to write files outside the intended storage location. The header value is used to build a filesystem path but is not properly canonicalized or restricted to the application’s storage base directory. As a result, supplying ../ sequences in X-Zone-Id causes files to be written to arbitrary directories.



- [https://github.com/byteReaper77/CVE-2025-59342](https://github.com/byteReaper77/CVE-2025-59342) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-59342.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-59342.svg)

## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.



- [https://github.com/jiansiting/CVE-2025-59287](https://github.com/jiansiting/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/jiansiting/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/jiansiting/CVE-2025-59287.svg)

- [https://github.com/mubix/Find-WSUS](https://github.com/mubix/Find-WSUS) :  ![starts](https://img.shields.io/github/stars/mubix/Find-WSUS.svg) ![forks](https://img.shields.io/github/forks/mubix/Find-WSUS.svg)

- [https://github.com/Lupovis/Honeypot-for-CVE-2025-59287-WSUS](https://github.com/Lupovis/Honeypot-for-CVE-2025-59287-WSUS) :  ![starts](https://img.shields.io/github/stars/Lupovis/Honeypot-for-CVE-2025-59287-WSUS.svg) ![forks](https://img.shields.io/github/forks/Lupovis/Honeypot-for-CVE-2025-59287-WSUS.svg)

- [https://github.com/garvitv14/CVE-2025-59287](https://github.com/garvitv14/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/garvitv14/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/garvitv14/CVE-2025-59287.svg)

- [https://github.com/tecxx/CVE-2025-59287-WSUS](https://github.com/tecxx/CVE-2025-59287-WSUS) :  ![starts](https://img.shields.io/github/stars/tecxx/CVE-2025-59287-WSUS.svg) ![forks](https://img.shields.io/github/forks/tecxx/CVE-2025-59287-WSUS.svg)

- [https://github.com/mrk336/Breaking-the-Update-Chain-Inside-CVE-2025-59287-and-the-WSUS-RCE-Threat](https://github.com/mrk336/Breaking-the-Update-Chain-Inside-CVE-2025-59287-and-the-WSUS-RCE-Threat) :  ![starts](https://img.shields.io/github/stars/mrk336/Breaking-the-Update-Chain-Inside-CVE-2025-59287-and-the-WSUS-RCE-Threat.svg) ![forks](https://img.shields.io/github/forks/mrk336/Breaking-the-Update-Chain-Inside-CVE-2025-59287-and-the-WSUS-RCE-Threat.svg)

- [https://github.com/fsanzmoya/wsus_CVE-2025-59287](https://github.com/fsanzmoya/wsus_CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/fsanzmoya/wsus_CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/fsanzmoya/wsus_CVE-2025-59287.svg)

- [https://github.com/QurtiDev/WSUS-CVE-2025-59287-RCE](https://github.com/QurtiDev/WSUS-CVE-2025-59287-RCE) :  ![starts](https://img.shields.io/github/stars/QurtiDev/WSUS-CVE-2025-59287-RCE.svg) ![forks](https://img.shields.io/github/forks/QurtiDev/WSUS-CVE-2025-59287-RCE.svg)

- [https://github.com/AdityaBhatt3010/CVE-2025-59287-When-your-patch-server-becomes-the-attack-vector](https://github.com/AdityaBhatt3010/CVE-2025-59287-When-your-patch-server-becomes-the-attack-vector) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-59287-When-your-patch-server-becomes-the-attack-vector.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-59287-When-your-patch-server-becomes-the-attack-vector.svg)

- [https://github.com/esteban11121/WSUS-RCE-Mitigation-59287](https://github.com/esteban11121/WSUS-RCE-Mitigation-59287) :  ![starts](https://img.shields.io/github/stars/esteban11121/WSUS-RCE-Mitigation-59287.svg) ![forks](https://img.shields.io/github/forks/esteban11121/WSUS-RCE-Mitigation-59287.svg)

- [https://github.com/FurkanKAYAPINAR/CVE-2025-59287](https://github.com/FurkanKAYAPINAR/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/FurkanKAYAPINAR/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/FurkanKAYAPINAR/CVE-2025-59287.svg)

- [https://github.com/0xBruno/WSUSploit.NET](https://github.com/0xBruno/WSUSploit.NET) :  ![starts](https://img.shields.io/github/stars/0xBruno/WSUSploit.NET.svg) ![forks](https://img.shields.io/github/forks/0xBruno/WSUSploit.NET.svg)

- [https://github.com/0x7556/CVE-2025-59287](https://github.com/0x7556/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/0x7556/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/0x7556/CVE-2025-59287.svg)

- [https://github.com/keeganparr1/CVE-2025-59287-hawktrace](https://github.com/keeganparr1/CVE-2025-59287-hawktrace) :  ![starts](https://img.shields.io/github/stars/keeganparr1/CVE-2025-59287-hawktrace.svg) ![forks](https://img.shields.io/github/forks/keeganparr1/CVE-2025-59287-hawktrace.svg)

- [https://github.com/RadzaRr/WSUSResponder](https://github.com/RadzaRr/WSUSResponder) :  ![starts](https://img.shields.io/github/stars/RadzaRr/WSUSResponder.svg) ![forks](https://img.shields.io/github/forks/RadzaRr/WSUSResponder.svg)

## CVE-2025-59230
 Improper access control in Windows Remote Access Connection Manager allows an authorized attacker to elevate privileges locally.



- [https://github.com/stalker110119/CVE-2025-59230](https://github.com/stalker110119/CVE-2025-59230) :  ![starts](https://img.shields.io/github/stars/stalker110119/CVE-2025-59230.svg) ![forks](https://img.shields.io/github/forks/stalker110119/CVE-2025-59230.svg)

## CVE-2025-59214
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.



- [https://github.com/rubenformation/CVE-2025-50154](https://github.com/rubenformation/CVE-2025-50154) :  ![starts](https://img.shields.io/github/stars/rubenformation/CVE-2025-50154.svg) ![forks](https://img.shields.io/github/forks/rubenformation/CVE-2025-50154.svg)

## CVE-2025-58789
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Themeisle WP Full Stripe Free allows SQL Injection. This issue affects WP Full Stripe Free: from n/a through 8.3.0.



- [https://github.com/quetuan03/CVE-2025-58789](https://github.com/quetuan03/CVE-2025-58789) :  ![starts](https://img.shields.io/github/stars/quetuan03/CVE-2025-58789.svg) ![forks](https://img.shields.io/github/forks/quetuan03/CVE-2025-58789.svg)

## CVE-2025-58788
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Saad Iqbal License Manager for WooCommerce allows Blind SQL Injection. This issue affects License Manager for WooCommerce: from n/a through 3.0.12.



- [https://github.com/quetuan03/CVE-2025-58788](https://github.com/quetuan03/CVE-2025-58788) :  ![starts](https://img.shields.io/github/stars/quetuan03/CVE-2025-58788.svg) ![forks](https://img.shields.io/github/forks/quetuan03/CVE-2025-58788.svg)

## CVE-2025-58780
 index.em7 in ScienceLogic SL1 before 12.1.1 allows SQL Injection via a parameter in a request. NOTE: this is disputed by the Supplier because it "inaccurately describes the vulnerability."



- [https://github.com/SexyShoelessGodofWar/CVE-2025-58780](https://github.com/SexyShoelessGodofWar/CVE-2025-58780) :  ![starts](https://img.shields.io/github/stars/SexyShoelessGodofWar/CVE-2025-58780.svg) ![forks](https://img.shields.io/github/forks/SexyShoelessGodofWar/CVE-2025-58780.svg)

## CVE-2025-58444
 The MCP inspector is a developer tool for testing and debugging MCP servers. A cross-site scripting issue was reported in versions of the MCP Inspector local development tool prior to 0.16.6 when connecting to untrusted remote MCP servers with a malicious redirect URI. This could be leveraged to interact directly with the inspector proxy to trigger arbitrary command execution. Users are advised to update to 0.16.6 to resolve this issue.



- [https://github.com/intbjw/Inspector-xss-poc](https://github.com/intbjw/Inspector-xss-poc) :  ![starts](https://img.shields.io/github/stars/intbjw/Inspector-xss-poc.svg) ![forks](https://img.shields.io/github/forks/intbjw/Inspector-xss-poc.svg)

## CVE-2025-58443
 FOG is a free open-source cloning/imaging/rescue suite/inventory management system. Versions 1.5.10.1673 and below contain an authentication bypass vulnerability. It is possible for an attacker to perform an unauthenticated DB dump where they could pull a full SQL DB without credentials. A fix is expected to be released 9/15/2025. To address this vulnerability immediately, upgrade to the latest version of either the dev-branch or working-1.6 branch. This will patch the issue for users concerned about immediate exposure. See the FOG Project documentation for step-by-step upgrade instructions: https://docs.fogproject.org/en/latest/install-fog-server#choosing-a-fog-version.



- [https://github.com/casp3r0x0/CVE-2025-58443](https://github.com/casp3r0x0/CVE-2025-58443) :  ![starts](https://img.shields.io/github/stars/casp3r0x0/CVE-2025-58443.svg) ![forks](https://img.shields.io/github/forks/casp3r0x0/CVE-2025-58443.svg)

## CVE-2025-58440
 The unisharp/laravel-filemanager is a separate project, unrelated to laravel-filemanager.



- [https://github.com/ph-hitachi/CVE-2025-58440](https://github.com/ph-hitachi/CVE-2025-58440) :  ![starts](https://img.shields.io/github/stars/ph-hitachi/CVE-2025-58440.svg) ![forks](https://img.shields.io/github/forks/ph-hitachi/CVE-2025-58440.svg)

## CVE-2025-58180
 OctoPrint provides a web interface for controlling consumer 3D printers. OctoPrint versions up until and including 1.11.2 contain a vulnerability that allows an authenticated attacker to upload a file under a specially crafted filename that will allow arbitrary command execution if said filename becomes included in a command defined in a system event handler and said event gets triggered. If no event handlers executing system commands with uploaded filenames as parameters have been configured, this vulnerability does not have an impact. The vulnerability is patched in version 1.11.3. As a workaround, OctoPrint administrators who have event handlers configured that include any kind of filename based placeholders should disable those by setting their `enabled` property to `False` or unchecking the "Enabled" checkbox in the GUI based Event Manager. Alternatively, OctoPrint administrators should set `feature.enforceReallyUniversalFilenames` to `true` in `config.yaml` and restart OctoPrint, then vet the existing uploads and make sure to delete any suspicious looking files. As always, OctoPrint administrators are advised to not expose OctoPrint on hostile networks like the public internet, and to vet who has access to their instance.



- [https://github.com/prabhatverma47/CVE-2025-58180](https://github.com/prabhatverma47/CVE-2025-58180) :  ![starts](https://img.shields.io/github/stars/prabhatverma47/CVE-2025-58180.svg) ![forks](https://img.shields.io/github/forks/prabhatverma47/CVE-2025-58180.svg)

## CVE-2025-57926
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in WP Chill Passster allows Stored XSS. This issue affects Passster: from n/a through 4.2.18.



- [https://github.com/quetuan03/CVE-2025-57926](https://github.com/quetuan03/CVE-2025-57926) :  ![starts](https://img.shields.io/github/stars/quetuan03/CVE-2025-57926.svg) ![forks](https://img.shields.io/github/forks/quetuan03/CVE-2025-57926.svg)

## CVE-2025-57833
 An issue was discovered in Django 4.2 before 4.2.24, 5.1 before 5.1.12, and 5.2 before 5.2.6. FilteredRelation is subject to SQL injection in column aliases, using a suitably crafted dictionary, with dictionary expansion, as the **kwargs passed QuerySet.annotate() or QuerySet.alias().



- [https://github.com/loic-houchi/Django-faille-CVE-2025-57833_test](https://github.com/loic-houchi/Django-faille-CVE-2025-57833_test) :  ![starts](https://img.shields.io/github/stars/loic-houchi/Django-faille-CVE-2025-57833_test.svg) ![forks](https://img.shields.io/github/forks/loic-houchi/Django-faille-CVE-2025-57833_test.svg)

- [https://github.com/ianoboyle/CVE-2025-57833](https://github.com/ianoboyle/CVE-2025-57833) :  ![starts](https://img.shields.io/github/stars/ianoboyle/CVE-2025-57833.svg) ![forks](https://img.shields.io/github/forks/ianoboyle/CVE-2025-57833.svg)

- [https://github.com/Mkway/CVE-2025-57833](https://github.com/Mkway/CVE-2025-57833) :  ![starts](https://img.shields.io/github/stars/Mkway/CVE-2025-57833.svg) ![forks](https://img.shields.io/github/forks/Mkway/CVE-2025-57833.svg)

## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.



- [https://github.com/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819](https://github.com/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819.svg)

- [https://github.com/brokendreamsclub/CVE-2025-57819](https://github.com/brokendreamsclub/CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/brokendreamsclub/CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/brokendreamsclub/CVE-2025-57819.svg)

- [https://github.com/rxerium/CVE-2025-57819](https://github.com/rxerium/CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-57819.svg)

- [https://github.com/net-hex/CVE-2025-57819](https://github.com/net-hex/CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/net-hex/CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/net-hex/CVE-2025-57819.svg)

- [https://github.com/ImBIOS/lab-cve-2025-57819](https://github.com/ImBIOS/lab-cve-2025-57819) :  ![starts](https://img.shields.io/github/stars/ImBIOS/lab-cve-2025-57819.svg) ![forks](https://img.shields.io/github/forks/ImBIOS/lab-cve-2025-57819.svg)

- [https://github.com/xV4nd3Rx/CVE-2025-57819_FreePBX-PoC](https://github.com/xV4nd3Rx/CVE-2025-57819_FreePBX-PoC) :  ![starts](https://img.shields.io/github/stars/xV4nd3Rx/CVE-2025-57819_FreePBX-PoC.svg) ![forks](https://img.shields.io/github/forks/xV4nd3Rx/CVE-2025-57819_FreePBX-PoC.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-57819](https://github.com/B1ack4sh/Blackash-CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-57819.svg)

- [https://github.com/orange0Mint/CVE-2025-57819_FreePBX](https://github.com/orange0Mint/CVE-2025-57819_FreePBX) :  ![starts](https://img.shields.io/github/stars/orange0Mint/CVE-2025-57819_FreePBX.svg) ![forks](https://img.shields.io/github/forks/orange0Mint/CVE-2025-57819_FreePBX.svg)

- [https://github.com/Sucuri-Labs/CVE-2025-57819-ioc-check](https://github.com/Sucuri-Labs/CVE-2025-57819-ioc-check) :  ![starts](https://img.shields.io/github/stars/Sucuri-Labs/CVE-2025-57819-ioc-check.svg) ![forks](https://img.shields.io/github/forks/Sucuri-Labs/CVE-2025-57819-ioc-check.svg)

- [https://github.com/MuhammadWaseem29/SQL-Injection-and-RCE_CVE-2025-57819](https://github.com/MuhammadWaseem29/SQL-Injection-and-RCE_CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/SQL-Injection-and-RCE_CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/SQL-Injection-and-RCE_CVE-2025-57819.svg)

## CVE-2025-57773
 DataEase is an open source business intelligence and data visualization tool. Prior to version 2.10.12, because DB2 parameters are not filtered, a JNDI injection attack can be directly launched. JNDI triggers an AspectJWeaver deserialization attack, writing to various files. This vulnerability requires commons-collections 4.x and aspectjweaver-1.9.22.jar. The vulnerability has been fixed in version 2.10.12.



- [https://github.com/B1ack4sh/Blackash-CVE-2025-57773](https://github.com/B1ack4sh/Blackash-CVE-2025-57773) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-57773.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-57773.svg)

## CVE-2025-57576
 PHPGurukul Online Shopping Portal 2.1 is vulnerable to Cross Site Scripting (XSS) in /admin/updateorder.php.



- [https://github.com/p0et08/DWrwq](https://github.com/p0et08/DWrwq) :  ![starts](https://img.shields.io/github/stars/p0et08/DWrwq.svg) ![forks](https://img.shields.io/github/forks/p0et08/DWrwq.svg)

## CVE-2025-57520
 A Cross Site Scripting (XSS) vulnerability exists in Decap CMS thru 3.8.3. Input fields such as body, tags, title, and description are not properly sanitized before being rendered in the content preview pane. This enables an attacker to inject arbitrary JavaScript which executes whenever a user views the preview panel. The vulnerability affects multiple input vectors and does not require user interaction beyond viewing the affected content.



- [https://github.com/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-](https://github.com/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-) :  ![starts](https://img.shields.io/github/stars/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-.svg) ![forks](https://img.shields.io/github/forks/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-.svg)

## CVE-2025-57515
 A SQL injection vulnerability has been identified in Uniclare Student Portal v2. This flaw allows remote attackers to inject arbitrary SQL commands via vulnerable input fields, enabling the execution of time-delay functions to infer database responses.



- [https://github.com/sanchitsahni/CVE-2025-57515](https://github.com/sanchitsahni/CVE-2025-57515) :  ![starts](https://img.shields.io/github/stars/sanchitsahni/CVE-2025-57515.svg) ![forks](https://img.shields.io/github/forks/sanchitsahni/CVE-2025-57515.svg)

## CVE-2025-57483
 A reflected cross-site scripting (XSS) vulnerability in tawk.to chatbox widget v4 allows attackers to execute arbitrary Javascript in the context of the user's browser via injecting a crafted payload into the vulnerable parameter.



- [https://github.com/Jainil-89/CVE](https://github.com/Jainil-89/CVE) :  ![starts](https://img.shields.io/github/stars/Jainil-89/CVE.svg) ![forks](https://img.shields.io/github/forks/Jainil-89/CVE.svg)

## CVE-2025-57457
 An OS Command Injection vulnerability in the Admin panel in Curo UC300 5.42.1.7.1.63R1 allows local attackers to inject arbitrary OS Commands via the "IP Addr" parameter.



- [https://github.com/restdone/CVE-2025-57457](https://github.com/restdone/CVE-2025-57457) :  ![starts](https://img.shields.io/github/stars/restdone/CVE-2025-57457.svg) ![forks](https://img.shields.io/github/forks/restdone/CVE-2025-57457.svg)

## CVE-2025-57428
 Default credentials in Each Italy Wireless Mini Router WIRELESS-N 300M v28K.MiniRouter.20190211 allows attackers to gain access to the debug shell exposed via Telnet on Port 23 and execute hardware-level flash and register manipulation commands.



- [https://github.com/5ulfur/CVE-2025-57428](https://github.com/5ulfur/CVE-2025-57428) :  ![starts](https://img.shields.io/github/stars/5ulfur/CVE-2025-57428.svg) ![forks](https://img.shields.io/github/forks/5ulfur/CVE-2025-57428.svg)

## CVE-2025-57392
 BenimPOS Masaustu 3.0.x is affected by insecure file permissions. The application installation directory grants Everyone and BUILTIN\Users groups FILE_ALL_ACCESS, allowing local users to replace or modify .exe and .dll files. This may lead to privilege escalation or arbitrary code execution upon launch by another user or elevated context.



- [https://github.com/meisterlos/CVE-2025-57392](https://github.com/meisterlos/CVE-2025-57392) :  ![starts](https://img.shields.io/github/stars/meisterlos/CVE-2025-57392.svg) ![forks](https://img.shields.io/github/forks/meisterlos/CVE-2025-57392.svg)

## CVE-2025-57389
 A reflected cross-site scripting (XSS) vulnerability in the /admin/system/packages endpoint of Luci OpenWRT v18.06.2 allows attackers to execute arbitrary Javascript in the context of a user's browser via a crafted payload. This vulnerability was fixed in OpenWRT v19.07.0.



- [https://github.com/amalcew/CVE-2025-57389](https://github.com/amalcew/CVE-2025-57389) :  ![starts](https://img.shields.io/github/stars/amalcew/CVE-2025-57389.svg) ![forks](https://img.shields.io/github/forks/amalcew/CVE-2025-57389.svg)

## CVE-2025-57203
 MagicProject AI version 9.1 is affected by a Cross-Site Scripting (XSS) vulnerability within the chatbot generation feature available to authenticated admin users. The vulnerability resides in the prompt parameter submitted to the /dashboard/user/generator/generate-stream endpoint via a multipart/form-data POST request. Due to insufficient input sanitization, attackers can inject HTML-based JavaScript payloads. This payload is stored and rendered unsanitized in subsequent views, leading to execution in other users' browsers when they access affected content. This issue allows an authenticated attacker to execute arbitrary JavaScript in the context of another user, potentially leading to session hijacking, privilege escalation, data exfiltration, or administrative account takeover. The application does not implement a Content Security Policy (CSP) or adequate input filtering to prevent such attacks. A fix should include proper sanitization, output encoding, and strong CSP enforcement to mitigate exploitation.



- [https://github.com/xchg-rax-rax/AvTech-PoCs](https://github.com/xchg-rax-rax/AvTech-PoCs) :  ![starts](https://img.shields.io/github/stars/xchg-rax-rax/AvTech-PoCs.svg) ![forks](https://img.shields.io/github/forks/xchg-rax-rax/AvTech-PoCs.svg)

## CVE-2025-57176
 The rfpiped service on TCP port 555 in Ceragon Networks / Siklu Communication EtherHaul series (8010TX and 1200FX tested) Firmware 7.4.0 through 10.7.3 allows unauthenticated file uploads to any writable location on the device. File upload packets use weak encryption (metadata only) with file contents transmitted in cleartext. No authentication or path validation is performed.



- [https://github.com/semaja22/CVE-2025-57176](https://github.com/semaja22/CVE-2025-57176) :  ![starts](https://img.shields.io/github/stars/semaja22/CVE-2025-57176.svg) ![forks](https://img.shields.io/github/forks/semaja22/CVE-2025-57176.svg)

## CVE-2025-57174
 An issue was discovered in Siklu Communications Etherhaul 8010TX and 1200FX devices, Firmware 7.4.0 through 10.7.3 and possibly other previous versions. The rfpiped service listening on TCP port 555 which uses static AES encryption keys hardcoded in the binary. These keys are identical across all devices, allowing attackers to craft encrypted packets that execute arbitrary commands without authentication. This is a failed patch for CVE-2017-7318. This issue may affect other Etherhaul series devices with shared firmware.



- [https://github.com/semaja22/CVE-2025-57174](https://github.com/semaja22/CVE-2025-57174) :  ![starts](https://img.shields.io/github/stars/semaja22/CVE-2025-57174.svg) ![forks](https://img.shields.io/github/forks/semaja22/CVE-2025-57174.svg)

## CVE-2025-57055
 WonderCMS 3.5.0 is vulnerable to Server-Side Request Forgery (SSRF) in the custom module installation functionality. An authenticated administrator can supply a malicious URL via the pluginThemeUrl POST parameter. The server fetches the provided URL using curl_exec() without sufficient validation, allowing the attacker to force internal or external HTTP requests.



- [https://github.com/thawphone/CVE-2025-57055](https://github.com/thawphone/CVE-2025-57055) :  ![starts](https://img.shields.io/github/stars/thawphone/CVE-2025-57055.svg) ![forks](https://img.shields.io/github/forks/thawphone/CVE-2025-57055.svg)

## CVE-2025-56819
 An issue in Datart v.1.0.0-rc.3 allows a remote attacker to execute arbitrary code via the INIT connection parameter.



- [https://github.com/xyyzxc/CVE-2025-56819](https://github.com/xyyzxc/CVE-2025-56819) :  ![starts](https://img.shields.io/github/stars/xyyzxc/CVE-2025-56819.svg) ![forks](https://img.shields.io/github/forks/xyyzxc/CVE-2025-56819.svg)

## CVE-2025-56815
 Datart 1.0.0-rc.3 is vulnerable to Directory Traversal in the POST /viz/image interface, since the server directly uses MultipartFile.transferTo() to save the uploaded file to a path controllable by the user, and lacks strict verification of the file name.



- [https://github.com/xiaoxiaoranxxx/CVE-2025-56815](https://github.com/xiaoxiaoranxxx/CVE-2025-56815) :  ![starts](https://img.shields.io/github/stars/xiaoxiaoranxxx/CVE-2025-56815.svg) ![forks](https://img.shields.io/github/forks/xiaoxiaoranxxx/CVE-2025-56815.svg)

## CVE-2025-56807
 A cross-site scripting (XSS) vulnerability in FairSketch RISE Ultimate Project Manager & CRM 3.9.4 allows an administrator to store a JavaScript payload using the file explorer in the admin dashboard when creating new folders.



- [https://github.com/aqwainfosec/CVE-2025-56807](https://github.com/aqwainfosec/CVE-2025-56807) :  ![starts](https://img.shields.io/github/stars/aqwainfosec/CVE-2025-56807.svg) ![forks](https://img.shields.io/github/forks/aqwainfosec/CVE-2025-56807.svg)

## CVE-2025-56803
 Figma Desktop for Windows version 125.6.5 contains a command injection vulnerability in the local plugin loader. An attacker can execute arbitrary OS commands by setting a crafted build field in the plugin's manifest.json. This field is passed to child_process.exec without validation, leading to possible RCE. NOTE: this is disputed by the Supplier because the behavior only allows a local user to attack himself via a local plugin. The local build procedure, which is essential to the attack, is not executed for plugins shared to the Figma Community.



- [https://github.com/shinyColumn/CVE-2025-56803](https://github.com/shinyColumn/CVE-2025-56803) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-56803.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-56803.svg)

## CVE-2025-56802
 The Reolink desktop application uses a hard-coded and predictable AES encryption key to encrypt user configuration files allowing attackers with local access to decrypt sensitive application data stored in %APPDATA%. A different vulnerability than CVE-2025-56801. NOTE: the Supplier's position is that material is not hardcoded and is instead randomly generated on each installation of the application.



- [https://github.com/shinyColumn/CVE-2025-56802](https://github.com/shinyColumn/CVE-2025-56802) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-56802.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-56802.svg)

## CVE-2025-56801
 The Reolink Desktop Application 8.18.12 contains hardcoded credentials as the Initialization Vector (IV) in its AES-CFB encryption implementation allowing attackers with access to the application environment to reliably decrypt encrypted configuration data. NOTE: the Supplier's position is that material is not hardcoded and is instead randomly generated on each installation of the application.



- [https://github.com/shinyColumn/CVE-2025-56801](https://github.com/shinyColumn/CVE-2025-56801) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-56801.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-56801.svg)

## CVE-2025-56800
 Reolink desktop application 8.18.12 contains a vulnerability in its local authentication mechanism. The application implements lock screen password logic entirely on the client side using JavaScript within an Electron resource file. Because the password is stored and returned via a modifiable JavaScript property(a.settingsManager.lockScreenPassword), an attacker can patch the return value to bypass authentication. NOTE: this is disputed by the Supplier because the lock-screen bypass would only occur if the local user modified his own instance of the application.



- [https://github.com/shinyColumn/CVE-2025-56800](https://github.com/shinyColumn/CVE-2025-56800) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-56800.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-56800.svg)

## CVE-2025-56799
 Reolink desktop application 8.18.12 contains a command injection vulnerability in its scheduled cache-clearing mechanism via a crafted folder name. NOTE: this is disputed by the Supplier because a crafted folder name would arise only if the local user were attacking himself.



- [https://github.com/shinyColumn/CVE-2025-56799](https://github.com/shinyColumn/CVE-2025-56799) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-56799.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-56799.svg)

## CVE-2025-56795
 Mealie 3.0.1 and earlier is vulnerable to Stored Cross-Site Scripting (XSS) in the recipe creation functionality. Unsanitized user input in the "note" and "text" fields of the "/api/recipes/{recipe_name}" endpoint is rendered in the frontend without proper escaping leading to persistent XSS.



- [https://github.com/B1tBreaker/CVE-2025-56795](https://github.com/B1tBreaker/CVE-2025-56795) :  ![starts](https://img.shields.io/github/stars/B1tBreaker/CVE-2025-56795.svg) ![forks](https://img.shields.io/github/forks/B1tBreaker/CVE-2025-56795.svg)

## CVE-2025-56764
 Trivision NC-227WF firmware 5.80 (build 20141010) login mechanism reveals whether a username exists or not by returning different error messages ("Unknown user" vs. "Wrong password"), allowing an attacker to enumerate valid usernames.



- [https://github.com/Remenis/CVE-2025-56764-trivision-nc227wf](https://github.com/Remenis/CVE-2025-56764-trivision-nc227wf) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-56764-trivision-nc227wf.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-56764-trivision-nc227wf.svg)

## CVE-2025-56762
 Paracrawl KeOPs v2 is vulnerable to Cross Site Scripting (XSS) in error.php.



- [https://github.com/Shaunak-Chatterjee/CVE-2025-56762](https://github.com/Shaunak-Chatterjee/CVE-2025-56762) :  ![starts](https://img.shields.io/github/stars/Shaunak-Chatterjee/CVE-2025-56762.svg) ![forks](https://img.shields.io/github/forks/Shaunak-Chatterjee/CVE-2025-56762.svg)

## CVE-2025-56608
 The SourceCodester Android application "Corona Virus Tracker App India" 1.0 uses MD5 for digest authentication in `OkHttpClientWrapper.java`. The `handleDigest()` function employs `MessageDigest.getInstance("MD5")` to hash credentials. MD5 is a broken cryptographic algorithm known to allow hash collisions. This makes the authentication mechanism vulnerable to replay, spoofing, or brute-force attacks, potentially leading to unauthorized access. The vulnerability corresponds to CWE-327 and aligns with OWASP M5: Insufficient Cryptography and MASVS MSTG-CRYPTO-4.



- [https://github.com/anonaninda/Aninda-security-advisories](https://github.com/anonaninda/Aninda-security-advisories) :  ![starts](https://img.shields.io/github/stars/anonaninda/Aninda-security-advisories.svg) ![forks](https://img.shields.io/github/forks/anonaninda/Aninda-security-advisories.svg)

## CVE-2025-56515
 File upload vulnerability in Fiora chat application 1.0.0 through user avatar upload functionality. The application fails to validate SVG file content, allowing malicious SVG files with embedded foreignObject elements containing iframe tags and JavaScript event handlers (onmouseover) to be uploaded and stored. When rendered, these SVG files execute arbitrary JavaScript, enabling attackers to steal user sessions, cookies, and perform unauthorized actions in the context of users viewing affected profiles.



- [https://github.com/Kov404/CVE-2025-56515](https://github.com/Kov404/CVE-2025-56515) :  ![starts](https://img.shields.io/github/stars/Kov404/CVE-2025-56515.svg) ![forks](https://img.shields.io/github/forks/Kov404/CVE-2025-56515.svg)

## CVE-2025-56514
 Cross Site Scripting (XSS) vulnerability in Fiora chat application 1.0.0 allows executes arbitrary JavaScript when malicious SVG files are rendered by other users.



- [https://github.com/Kov404/CVE-2025-56514](https://github.com/Kov404/CVE-2025-56514) :  ![starts](https://img.shields.io/github/stars/Kov404/CVE-2025-56514.svg) ![forks](https://img.shields.io/github/forks/Kov404/CVE-2025-56514.svg)

## CVE-2025-56450
 Log2Space Subscriber Management Software 1.1 is vulnerable to unauthenticated SQL injection via the `lead_id` parameter in the `/l2s/api/selfcareLeadHistory` endpoint. A remote attacker can exploit this by sending a specially crafted POST request, resulting in the execution of arbitrary SQL queries. The backend fails to sanitize the user input, allowing enumeration of database schemas, table names, and potentially leading to full database compromise.



- [https://github.com/apboss123/CVE-2025-56450](https://github.com/apboss123/CVE-2025-56450) :  ![starts](https://img.shields.io/github/stars/apboss123/CVE-2025-56450.svg) ![forks](https://img.shields.io/github/forks/apboss123/CVE-2025-56450.svg)

## CVE-2025-56435
 SQL Injection vulnerability in FoxCMS v1.2.6 and before allows a remote attacker to execute arbitrary code via the. file /DataBackup.php and the operation on the parameter id.



- [https://github.com/Jingyi-u/-CVE-2025-56435](https://github.com/Jingyi-u/-CVE-2025-56435) :  ![starts](https://img.shields.io/github/stars/Jingyi-u/-CVE-2025-56435.svg) ![forks](https://img.shields.io/github/forks/Jingyi-u/-CVE-2025-56435.svg)

## CVE-2025-56399
 alexusmai laravel-file-manager 3.3.1 and before allows an authenticated attacker to achieve Remote Code Execution (RCE) through a crafted file upload. A file with a '.png` extension containing PHP code can be uploaded via the file manager interface. Although the upload appears to fail client-side validation, the file is still saved on the server. The attacker can then use the rename API to change the file extension to `.php`, and upon accessing it via a public URL, the server executes the embedded code.



- [https://github.com/Theethat-Thamwasin/CVE-2025-56399](https://github.com/Theethat-Thamwasin/CVE-2025-56399) :  ![starts](https://img.shields.io/github/stars/Theethat-Thamwasin/CVE-2025-56399.svg) ![forks](https://img.shields.io/github/forks/Theethat-Thamwasin/CVE-2025-56399.svg)

## CVE-2025-56383
 Notepad++ v8.8.3 has a DLL hijacking vulnerability, which can replace the original DLL file to execute malicious code. NOTE: this is disputed by multiple parties because the behavior only occurs when a user installs the product into a directory tree that allows write access by arbitrary unprivileged users.



- [https://github.com/zer0t0/CVE-2025-56383-Proof-of-Concept](https://github.com/zer0t0/CVE-2025-56383-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/zer0t0/CVE-2025-56383-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/zer0t0/CVE-2025-56383-Proof-of-Concept.svg)

## CVE-2025-56381
 ERPNEXT v15.67.0 was discovered to contain multiple SQL injection vulnerabilities in the /api/method/frappe.desk.reportview.get endpoint via the order_by and group_by parameters.



- [https://github.com/MoAlali/CVE-2025-56381](https://github.com/MoAlali/CVE-2025-56381) :  ![starts](https://img.shields.io/github/stars/MoAlali/CVE-2025-56381.svg) ![forks](https://img.shields.io/github/forks/MoAlali/CVE-2025-56381.svg)

## CVE-2025-56380
 Frappe Framework v15.72.4 was discovered to contain a SQL injection vulnerability via the fieldname parameter in the frappe.client.get_value API endpoint and a crafted script to the fieldname parameter



- [https://github.com/MoAlali/CVE-2025-56380](https://github.com/MoAlali/CVE-2025-56380) :  ![starts](https://img.shields.io/github/stars/MoAlali/CVE-2025-56380.svg) ![forks](https://img.shields.io/github/forks/MoAlali/CVE-2025-56380.svg)

## CVE-2025-56379
 A stored cross-site scripting (XSS) vulnerability in the blog post feature of ERPNEXT v15.67.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the content field.



- [https://github.com/MoAlali/CVE-2025-56379](https://github.com/MoAlali/CVE-2025-56379) :  ![starts](https://img.shields.io/github/stars/MoAlali/CVE-2025-56379.svg) ![forks](https://img.shields.io/github/forks/MoAlali/CVE-2025-56379.svg)

## CVE-2025-56311
 In Shenzhen C-Data Technology Co. FD602GW-DX-R410 (firmware v2.2.14), the web management interface contains an authenticated CSRF vulnerability on the reboot endpoint (/boaform/admin/formReboot). An attacker can craft a malicious webpage that, when visited by an authenticated administrator, causes the router to reboot without explicit user consent. This lack of CSRF protection on a sensitive administrative function can lead to denial of service by disrupting network availability.



- [https://github.com/wrathfulDiety/CVE-2025-56311](https://github.com/wrathfulDiety/CVE-2025-56311) :  ![starts](https://img.shields.io/github/stars/wrathfulDiety/CVE-2025-56311.svg) ![forks](https://img.shields.io/github/forks/wrathfulDiety/CVE-2025-56311.svg)

## CVE-2025-56243
 A Cross-Site Scripting (XSS) vulnerability was found in the register.php page of PuneethReddyHC Event Management System 1.0, where the event_id GET parameter is improperly handled. An attacker can craft a malicious URL to execute arbitrary JavaScript in the victim s browser by injecting code into this parameter.



- [https://github.com/hafizgemilang/CVE-2025-56243](https://github.com/hafizgemilang/CVE-2025-56243) :  ![starts](https://img.shields.io/github/stars/hafizgemilang/CVE-2025-56243.svg) ![forks](https://img.shields.io/github/forks/hafizgemilang/CVE-2025-56243.svg)

## CVE-2025-56224
 A lack of rate limiting in the One-Time Password (OTP) verification endpoint of SigningHub v8.6.8 allows attackers to bypass verification via a bruteforce attack.



- [https://github.com/saykino/CVE-2025-56224](https://github.com/saykino/CVE-2025-56224) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56224.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56224.svg)

## CVE-2025-56223
 A lack of rate limiting in the component /Home/UploadStreamDocument of SigningHub v8.6.8 allows attackers to cause a Denial of Service (DoS) via uploading an excessive number of files.



- [https://github.com/saykino/CVE-2025-56223](https://github.com/saykino/CVE-2025-56223) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56223.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56223.svg)

## CVE-2025-56221
 A lack of rate limiting in the login mechanism of SigningHub v8.6.8 allows attackers to bypass authentication via a brute force attack.



- [https://github.com/saykino/CVE-2025-56221](https://github.com/saykino/CVE-2025-56221) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56221.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56221.svg)

## CVE-2025-56219
 Incorrect access control in SigningHub v8.6.8 allows attackers to arbitrarily add user accounts without any rate limiting. This can lead to a resource exhaustion and a Denial of Service (DoS) when an excessively large number of user accounts are created.



- [https://github.com/saykino/CVE-2025-56219](https://github.com/saykino/CVE-2025-56219) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56219.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56219.svg)

## CVE-2025-56218
 An arbitrary file upload vulnerability in SigningHub v8.6.8 allows attackers to execute arbitrary code via uploading a crafted PDF file.



- [https://github.com/saykino/CVE-2025-56218](https://github.com/saykino/CVE-2025-56218) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56218.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56218.svg)

## CVE-2025-56132
 LiquidFiles filetransfer server is vulnerable to a user enumeration issue in its password reset functionality. The application returns distinguishable responses for valid and invalid email addresses, allowing unauthenticated attackers to determine the existence of user accounts. Version 4.2 introduces user-based lockout mechanisms to mitigate brute-force attacks, user enumeration remains possible by default. In versions prior to 4.2, no such user-level protection is in place, only basic IP-based rate limiting is enforced. This IP-based protection can be bypassed by distributing requests across multiple IPs (e.g., rotating IP or proxies). Effectively bypassing both login and password reset security controls. Successful exploitation allows an attacker to enumerate valid email addresses registered for the application, increasing the risk of follow-up attacks such as password spraying.



- [https://github.com/fredericgoossens/CVE-2025-56132-Liquidfiles](https://github.com/fredericgoossens/CVE-2025-56132-Liquidfiles) :  ![starts](https://img.shields.io/github/stars/fredericgoossens/CVE-2025-56132-Liquidfiles.svg) ![forks](https://img.shields.io/github/forks/fredericgoossens/CVE-2025-56132-Liquidfiles.svg)

## CVE-2025-56019
 An insecure permission vulnerability exists in the Agasta Easytouch+ version 9.3.97 The device allows unauthorized mobile applications to connect via Bluetooth Low Energy (BLE) without authentication. Once an unauthorized connection is established, legitimate applications are unable to connect, causing a denial of service. The attack requires proximity to the device, making it exploitable from an adjacent network location.



- [https://github.com/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019](https://github.com/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019) :  ![starts](https://img.shields.io/github/stars/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019.svg) ![forks](https://img.shields.io/github/forks/Yashodhanvivek/Agatsa-EasyTouch-Plus---CVE-2025-56019.svg)

## CVE-2025-55998
 A cross-site scripting (XSS) vulnerability in Smart Search & Filter Shopify and BigCommerce apps allows a remote attacker to execute arbitrary JavaScript in the web browser of a user, by including a malicious payload into several filter parameter



- [https://github.com/Ocmenog/CVE-2025-55998](https://github.com/Ocmenog/CVE-2025-55998) :  ![starts](https://img.shields.io/github/stars/Ocmenog/CVE-2025-55998.svg) ![forks](https://img.shields.io/github/forks/Ocmenog/CVE-2025-55998.svg)

## CVE-2025-55996
 Viber Desktop 25.6.0 is vulnerable to HTML Injection via the text parameter of the message compose/forward interface



- [https://github.com/thawkhant/viber-desktop-html-injection](https://github.com/thawkhant/viber-desktop-html-injection) :  ![starts](https://img.shields.io/github/stars/thawkhant/viber-desktop-html-injection.svg) ![forks](https://img.shields.io/github/forks/thawkhant/viber-desktop-html-injection.svg)

## CVE-2025-55972
 A TCL Smart TV running a vulnerable UPnP/DLNA MediaRenderer implementation is affected by a remote, unauthenticated Denial of Service (DoS) condition. By sending a flood of malformed or oversized SetAVTransportURI SOAP requests to the UPnP control endpoint, an attacker can cause the device to become unresponsive. This denial persists as long as the attack continues and affects all forms of TV operation. Manual user control and even reboots do not restore functionality unless the flood stops.



- [https://github.com/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport](https://github.com/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport) :  ![starts](https://img.shields.io/github/stars/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg) ![forks](https://img.shields.io/github/forks/Szym0n13k/CVE-2025-55972-Remote-Unauthenticated-Denial-of-Service-DoS-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg)

## CVE-2025-55971
 TCL 65C655 Smart TV, running firmware version V8-R75PT01-LF1V269.001116 (Android TV, Kernel 5.4.242+), is vulnerable to a blind, unauthenticated Server-Side Request Forgery (SSRF) vulnerability via the UPnP MediaRenderer service (AVTransport:1). The device accepts unauthenticated SetAVTransportURI SOAP requests over TCP/16398 and attempts to retrieve externally referenced URIs, including attacker-controlled payloads. The blind SSRF allows for sending requests on behalf of the TV, which can be leveraged to probe for other internal or external services accessible by the device (e.g., 127.0.0.1:16XXX, LAN services, or internet targets), potentially enabling additional exploit chains.



- [https://github.com/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport](https://github.com/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport) :  ![starts](https://img.shields.io/github/stars/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg) ![forks](https://img.shields.io/github/forks/Szym0n13k/CVE-2025-55971-Blind-Unauthenticated-SSRF-in-TCL-Smart-TV-UPnP-DLNA-AVTransport.svg)

## CVE-2025-55903
 A HTML injection vulnerability exists in Perfex CRM v3.3.1. The application fails to sanitize user input in the "Bill To" address field within the estimate module. As a result, arbitrary HTML can be injected and rendered unescaped in client-facing documents.



- [https://github.com/ajansha/CVE-2025-55903](https://github.com/ajansha/CVE-2025-55903) :  ![starts](https://img.shields.io/github/stars/ajansha/CVE-2025-55903.svg) ![forks](https://img.shields.io/github/forks/ajansha/CVE-2025-55903.svg)

## CVE-2025-55888
 Cross-Site Scripting (XSS) vulnerability was discovered in the Ajax transaction manager endpoint of ARD. An attacker can intercept the Ajax response and inject malicious JavaScript into the accountName field. This input is not properly sanitized or encoded when rendered, allowing script execution in the context of users browsers. This flaw could lead to session hijacking, cookie theft, and other malicious actions.



- [https://github.com/0xZeroSec/CVE-2025-55888](https://github.com/0xZeroSec/CVE-2025-55888) :  ![starts](https://img.shields.io/github/stars/0xZeroSec/CVE-2025-55888.svg) ![forks](https://img.shields.io/github/forks/0xZeroSec/CVE-2025-55888.svg)

## CVE-2025-55887
 Cross-Site Scripting (XSS) vulnerability was discovered in the meal reservation service ARD. The vulnerability exists in the transactionID GET parameter on the transaction confirmation page. Due to improper input validation and output encoding, an attacker can inject malicious JavaScript code that is executed in the context of a user s browser. This can lead to session hijacking, theft of cookies, and other malicious actions performed on behalf of the victim.



- [https://github.com/0xZeroSec/CVE-2025-55887](https://github.com/0xZeroSec/CVE-2025-55887) :  ![starts](https://img.shields.io/github/stars/0xZeroSec/CVE-2025-55887.svg) ![forks](https://img.shields.io/github/forks/0xZeroSec/CVE-2025-55887.svg)

## CVE-2025-55886
 An Insecure Direct Object Reference (IDOR) vulnerability was discovered in ARD. The flaw exists in the `fe_uid` parameter of the payment history API endpoint. An authenticated attacker can manipulate this parameter to access the payment history of other users without authorization.



- [https://github.com/0xZeroSec/CVE-2025-55886](https://github.com/0xZeroSec/CVE-2025-55886) :  ![starts](https://img.shields.io/github/stars/0xZeroSec/CVE-2025-55886.svg) ![forks](https://img.shields.io/github/forks/0xZeroSec/CVE-2025-55886.svg)

## CVE-2025-55885
 SQL Injection vulnerability in Alpes Recherche et Developpement ARD GEC en Lign before v.2025-04-23 allows a remote attacker to escalate privileges via the GET parameters in index.php



- [https://github.com/0xZeroSec/CVE-2025-55885](https://github.com/0xZeroSec/CVE-2025-55885) :  ![starts](https://img.shields.io/github/stars/0xZeroSec/CVE-2025-55885.svg) ![forks](https://img.shields.io/github/forks/0xZeroSec/CVE-2025-55885.svg)

## CVE-2025-55780
 A null pointer dereference occurs in the function break_word_for_overflow_wrap() in MuPDF 1.26.4 when rendering a malformed EPUB document. Specifically, the function calls fz_html_split_flow() to split a FLOW_WORD node, but does not check if node-next is valid before accessing node-next-overflow_wrap, resulting in a crash if the split fails or returns a partial node chain.



- [https://github.com/ISH2YU/CVE-2025-55780](https://github.com/ISH2YU/CVE-2025-55780) :  ![starts](https://img.shields.io/github/stars/ISH2YU/CVE-2025-55780.svg) ![forks](https://img.shields.io/github/forks/ISH2YU/CVE-2025-55780.svg)

## CVE-2025-55763
 Buffer Overflow in the URI parser of CivetWeb 1.14 through 1.16 (latest) allows a remote attacker to achieve remote code execution via a crafted HTTP request. This vulnerability is triggered during request processing and may allow an attacker to corrupt heap memory, potentially leading to denial of service or arbitrary code execution.



- [https://github.com/krispybyte/CVE-2025-55763](https://github.com/krispybyte/CVE-2025-55763) :  ![starts](https://img.shields.io/github/stars/krispybyte/CVE-2025-55763.svg) ![forks](https://img.shields.io/github/forks/krispybyte/CVE-2025-55763.svg)

## CVE-2025-55752
 Relative Path Traversal vulnerability in Apache Tomcat.

The fix for bug 60013 introduced a regression where the       rewritten URL was normalized before it was decoded. This introduced the       possibility that, for rewrite rules that rewrite query parameters to the       URL, an attacker could manipulate the request URI to bypass security       constraints including the protection for /WEB-INF/ and /META-INF/. If PUT requests were also enabled then malicious files could be uploaded leading to remote code execution. PUT requests are normally limited to trusted users and it is considered unlikely that PUT requests would be enabled in conjunction with a rewrite that manipulated the URI.



This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.10, from 10.1.0-M1 through 10.1.44, from 9.0.0.M11 through 9.0.108.

The following versions were EOL at the time the CVE was created but are 
known to be affected: 8.5.6 though 8.5.100. Other, older, EOL versions may also be affected.
Users are recommended to upgrade to version 11.0.11 or later, 10.1.45 or later or 9.0.109 or later, which fix the issue.



- [https://github.com/masahiro331/CVE-2025-55752](https://github.com/masahiro331/CVE-2025-55752) :  ![starts](https://img.shields.io/github/stars/masahiro331/CVE-2025-55752.svg) ![forks](https://img.shields.io/github/forks/masahiro331/CVE-2025-55752.svg)

- [https://github.com/TAM-K592/CVE-2025-55752](https://github.com/TAM-K592/CVE-2025-55752) :  ![starts](https://img.shields.io/github/stars/TAM-K592/CVE-2025-55752.svg) ![forks](https://img.shields.io/github/forks/TAM-K592/CVE-2025-55752.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-55752](https://github.com/B1ack4sh/Blackash-CVE-2025-55752) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-55752.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-55752.svg)

## CVE-2025-55746
 Directus is a real-time API and App dashboard for managing SQL database content. From 10.8.0 to before 11.9.3, a vulnerability exists in the file update mechanism which allows an unauthenticated actor to modify existing files with arbitrary contents (without changes being applied to the files' database-resident metadata) and / or upload new files, with arbitrary content and extensions, which won't show up in the Directus UI. This vulnerability is fixed in 11.9.3.



- [https://github.com/r4bbit-r4/directus-preso](https://github.com/r4bbit-r4/directus-preso) :  ![starts](https://img.shields.io/github/stars/r4bbit-r4/directus-preso.svg) ![forks](https://img.shields.io/github/forks/r4bbit-r4/directus-preso.svg)

## CVE-2025-55668
 Session Fixation vulnerability in Apache Tomcat via rewrite valve.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.7, from 10.1.0-M1 through 10.1.41, from 9.0.0.M1 through 9.0.105.
Older, EOL versions may also be affected.

Users are recommended to upgrade to version 11.0.8, 10.1.42 or 9.0.106, which fix the issue.



- [https://github.com/gregk4sec/CVE-2025-55668](https://github.com/gregk4sec/CVE-2025-55668) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-55668.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-55668.svg)

## CVE-2025-55580
 SolidInvoice version 2.3.7 is vulnerable to a stored cross-site scripting (XSS) issue in the Clients module. An authenticated attacker can inject JavaScript that executes in other users' browsers when the Clients page is viewed. The vulnerability is fixed in version 2.3.8.



- [https://github.com/ddobrev25/CVE-2025-55580](https://github.com/ddobrev25/CVE-2025-55580) :  ![starts](https://img.shields.io/github/stars/ddobrev25/CVE-2025-55580.svg) ![forks](https://img.shields.io/github/forks/ddobrev25/CVE-2025-55580.svg)

## CVE-2025-55579
 SolidInvoice version 2.3.7 is vulnerable to a Stored Cross-Site Scripting (XSS) issue in the Tax Rates functionality. The vulnerability is fixed in version 2.3.8.



- [https://github.com/ddobrev25/CVE-2025-55579](https://github.com/ddobrev25/CVE-2025-55579) :  ![starts](https://img.shields.io/github/stars/ddobrev25/CVE-2025-55579.svg) ![forks](https://img.shields.io/github/forks/ddobrev25/CVE-2025-55579.svg)

## CVE-2025-55575
 SQL Injection vulnerability in SMM Panel 3.1 allowing remote attackers to gain sensitive information via a crafted HTTP request with action=service_detail.



- [https://github.com/Aether-0/CVE-2025-55575](https://github.com/Aether-0/CVE-2025-55575) :  ![starts](https://img.shields.io/github/stars/Aether-0/CVE-2025-55575.svg) ![forks](https://img.shields.io/github/forks/Aether-0/CVE-2025-55575.svg)

## CVE-2025-55315
 Inconsistent interpretation of http requests ('http request/response smuggling') in ASP.NET Core allows an authorized attacker to bypass a security feature over a network.



- [https://github.com/sirredbeard/CVE-2025-55315-repro](https://github.com/sirredbeard/CVE-2025-55315-repro) :  ![starts](https://img.shields.io/github/stars/sirredbeard/CVE-2025-55315-repro.svg) ![forks](https://img.shields.io/github/forks/sirredbeard/CVE-2025-55315-repro.svg)

- [https://github.com/nickcopi/CVE-2025-55315-detection-playground](https://github.com/nickcopi/CVE-2025-55315-detection-playground) :  ![starts](https://img.shields.io/github/stars/nickcopi/CVE-2025-55315-detection-playground.svg) ![forks](https://img.shields.io/github/forks/nickcopi/CVE-2025-55315-detection-playground.svg)

- [https://github.com/7huukdlnkjkjba/CVE-2025-55315-](https://github.com/7huukdlnkjkjba/CVE-2025-55315-) :  ![starts](https://img.shields.io/github/stars/7huukdlnkjkjba/CVE-2025-55315-.svg) ![forks](https://img.shields.io/github/forks/7huukdlnkjkjba/CVE-2025-55315-.svg)

- [https://github.com/RootAid/CVE-2025-55315](https://github.com/RootAid/CVE-2025-55315) :  ![starts](https://img.shields.io/github/stars/RootAid/CVE-2025-55315.svg) ![forks](https://img.shields.io/github/forks/RootAid/CVE-2025-55315.svg)

- [https://github.com/jlinebau/CVE-2025-55315-Scanner-Monitor](https://github.com/jlinebau/CVE-2025-55315-Scanner-Monitor) :  ![starts](https://img.shields.io/github/stars/jlinebau/CVE-2025-55315-Scanner-Monitor.svg) ![forks](https://img.shields.io/github/forks/jlinebau/CVE-2025-55315-Scanner-Monitor.svg)

## CVE-2025-55287
 Genealogy is a family tree PHP application. Prior to 4.4.0, Authenticated Stored Cross-Site Scripting (XSS) vulnerability was identified in the Genealogy application. Authenticated attackers could run arbitrary JavaScript in another user’s session, leading to session hijacking, data theft, and UI manipulation. This vulnerability is fixed in 4.4.0.



- [https://github.com/Eternalvalhalla/CVE-2025-55287-POC](https://github.com/Eternalvalhalla/CVE-2025-55287-POC) :  ![starts](https://img.shields.io/github/stars/Eternalvalhalla/CVE-2025-55287-POC.svg) ![forks](https://img.shields.io/github/forks/Eternalvalhalla/CVE-2025-55287-POC.svg)

## CVE-2025-55234
 SMB Server might be susceptible to relay attacks depending on the configuration. An attacker who successfully exploited these vulnerabilities could perform relay attacks and make the users subject to elevation of privilege attacks.
The SMB Server already supports mechanisms for hardening against relay attacks:

SMB Server signing
SMB Server Extended Protection for Authentication (EPA)

Microsoft is releasing this CVE to provide customers with audit capabilities to help them to assess their environment and to identify any potential device or software incompatibility issues before deploying SMB Server hardening measures that protect against relay attacks.
If you have not already enabled SMB Server hardening measures, we advise customers to take the following actions to be protected from these relay attacks:

Assess your environment by utilizing the audit capabilities that we are exposing in the September 2025 security updates.  See Support for Audit Events to deploy SMB Server Hardening—SMB Server Signing &amp; SMB Server EPA.
Adopt appropriate SMB Server hardening measures.



- [https://github.com/mrk336/CVE-2025-55234](https://github.com/mrk336/CVE-2025-55234) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2025-55234.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2025-55234.svg)

- [https://github.com/h4xnz/CVE-2025-55234-POC](https://github.com/h4xnz/CVE-2025-55234-POC) :  ![starts](https://img.shields.io/github/stars/h4xnz/CVE-2025-55234-POC.svg) ![forks](https://img.shields.io/github/forks/h4xnz/CVE-2025-55234-POC.svg)

- [https://github.com/mrk336/Patch-the-Path-CVE-2025-55234-Detection-Defense](https://github.com/mrk336/Patch-the-Path-CVE-2025-55234-Detection-Defense) :  ![starts](https://img.shields.io/github/stars/mrk336/Patch-the-Path-CVE-2025-55234-Detection-Defense.svg) ![forks](https://img.shields.io/github/forks/mrk336/Patch-the-Path-CVE-2025-55234-Detection-Defense.svg)

## CVE-2025-55188
 7-Zip before 25.01 does not always properly handle symbolic links during extraction.



- [https://github.com/hunters-sec/CVE-2025-55188-7z-exploit](https://github.com/hunters-sec/CVE-2025-55188-7z-exploit) :  ![starts](https://img.shields.io/github/stars/hunters-sec/CVE-2025-55188-7z-exploit.svg) ![forks](https://img.shields.io/github/forks/hunters-sec/CVE-2025-55188-7z-exploit.svg)

- [https://github.com/lunbun/CVE-2025-55188](https://github.com/lunbun/CVE-2025-55188) :  ![starts](https://img.shields.io/github/stars/lunbun/CVE-2025-55188.svg) ![forks](https://img.shields.io/github/forks/lunbun/CVE-2025-55188.svg)

## CVE-2025-55160
 ImageMagick is free and open-source software used for editing and manipulating digital images. Prior to versions 6.9.13-27 and 7.1.2-1, there is undefined behavior (function-type-mismatch) in splay tree cloning callback. This results in a deterministic abort under UBSan (DoS in sanitizer builds), with no crash in a non-sanitized build. This issue has been patched in versions 6.9.13-27 and 7.1.2-1.



- [https://github.com/Yuri08loveElaina/imagemagick-2025-poc](https://github.com/Yuri08loveElaina/imagemagick-2025-poc) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/imagemagick-2025-poc.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/imagemagick-2025-poc.svg)

## CVE-2025-55154
 ImageMagick is free and open-source software used for editing and manipulating digital images. Prior to versions 6.9.13-27 and 7.1.2-1, the magnified size calculations in ReadOneMNGIMage (in coders/png.c) are unsafe and can overflow, leading to memory corruption. This issue has been patched in versions 6.9.13-27 and 7.1.2-1.



- [https://github.com/Yuri08loveElaina/imagemagick-2025-poc](https://github.com/Yuri08loveElaina/imagemagick-2025-poc) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/imagemagick-2025-poc.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/imagemagick-2025-poc.svg)

## CVE-2025-55005
 ImageMagick is free and open-source software used for editing and manipulating digital images. Prior to version 7.1.2-1, when preparing to transform from Log to sRGB colorspaces, the logmap construction fails to handle cases where the reference-black or reference-white value is larger than 1024. This leads to corrupting memory beyond the end of the allocated logmap buffer. This issue has been patched in version 7.1.2-1.



- [https://github.com/Yuri08loveElaina/imagemagick-2025-poc](https://github.com/Yuri08loveElaina/imagemagick-2025-poc) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/imagemagick-2025-poc.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/imagemagick-2025-poc.svg)

## CVE-2025-55004
 ImageMagick is free and open-source software used for editing and manipulating digital images. Prior to version 7.1.2-1, ImageMagick is vulnerable to heap-buffer overflow read around the handling of images with separate alpha channels when performing image magnification in ReadOneMNGIMage. This can likely be used to leak subsequent memory contents into the output image. This issue has been patched in version 7.1.2-1.



- [https://github.com/Yuri08loveElaina/imagemagick-2025-poc](https://github.com/Yuri08loveElaina/imagemagick-2025-poc) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/imagemagick-2025-poc.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/imagemagick-2025-poc.svg)

## CVE-2025-54988
 Critical XXE in Apache Tika (tika-parser-pdf-module) in Apache Tika 1.13 through and including 3.2.1 on all platforms allows an attacker to carry out XML External Entity injection via a crafted XFA file inside of a PDF. An attacker may be able to read sensitive data or trigger malicious requests to internal resources or third-party servers. Note that the tika-parser-pdf-module is used as a dependency in several Tika packages including at least: tika-parsers-standard-modules, tika-parsers-standard-package, tika-app, tika-grpc and tika-server-standard.

Users are recommended to upgrade to version 3.2.2, which fixes this issue.



- [https://github.com/mgthuramoemyint/POC-CVE-2025-54988](https://github.com/mgthuramoemyint/POC-CVE-2025-54988) :  ![starts](https://img.shields.io/github/stars/mgthuramoemyint/POC-CVE-2025-54988.svg) ![forks](https://img.shields.io/github/forks/mgthuramoemyint/POC-CVE-2025-54988.svg)

## CVE-2025-54962
 /edit-user in webserver in OpenPLC Runtime 3 through 9cd8f1b allows authenticated users to upload arbitrary files (such as .html or .svg), and these are then publicly accessible under the /static URI.



- [https://github.com/Eyodav/CVE-2025-54962](https://github.com/Eyodav/CVE-2025-54962) :  ![starts](https://img.shields.io/github/stars/Eyodav/CVE-2025-54962.svg) ![forks](https://img.shields.io/github/forks/Eyodav/CVE-2025-54962.svg)

## CVE-2025-54957
 An issue was discovered in Dolby UDC 4.5 through 4.13. A crash of the DD+ decoder process can occur when a malformed DD+ bitstream is processed. When Evolution data is processed by evo_priv.c from the DD+ bitstream, the decoder writes that data into a buffer. The length calculation for a write can overflow due to an integer wraparound. This can lead to the allocated buffer being too small, and the out-of-bounds check of the subsequent write to be ineffective, leading to an out-of-bounds write.



- [https://github.com/AlphabugX/CVE-2025-54957](https://github.com/AlphabugX/CVE-2025-54957) :  ![starts](https://img.shields.io/github/stars/AlphabugX/CVE-2025-54957.svg) ![forks](https://img.shields.io/github/forks/AlphabugX/CVE-2025-54957.svg)

## CVE-2025-54918
 Improper authentication in Windows NTLM allows an authorized attacker to elevate privileges over a network.



- [https://github.com/mrk336/From-Foothold-to-Domain-Admin-Weaponizing-CVE-2025-54918-in-Real-World-DevOps](https://github.com/mrk336/From-Foothold-to-Domain-Admin-Weaponizing-CVE-2025-54918-in-Real-World-DevOps) :  ![starts](https://img.shields.io/github/stars/mrk336/From-Foothold-to-Domain-Admin-Weaponizing-CVE-2025-54918-in-Real-World-DevOps.svg) ![forks](https://img.shields.io/github/forks/mrk336/From-Foothold-to-Domain-Admin-Weaponizing-CVE-2025-54918-in-Real-World-DevOps.svg)

## CVE-2025-54914
 Azure Networking Elevation of Privilege Vulnerability



- [https://github.com/Ash1996x/CVE-2025-54914-PoC](https://github.com/Ash1996x/CVE-2025-54914-PoC) :  ![starts](https://img.shields.io/github/stars/Ash1996x/CVE-2025-54914-PoC.svg) ![forks](https://img.shields.io/github/forks/Ash1996x/CVE-2025-54914-PoC.svg)

- [https://github.com/mrk336/Azure-Networking-Privilege-Escalation-Exploit-CVE-2025-54914](https://github.com/mrk336/Azure-Networking-Privilege-Escalation-Exploit-CVE-2025-54914) :  ![starts](https://img.shields.io/github/stars/mrk336/Azure-Networking-Privilege-Escalation-Exploit-CVE-2025-54914.svg) ![forks](https://img.shields.io/github/forks/mrk336/Azure-Networking-Privilege-Escalation-Exploit-CVE-2025-54914.svg)

## CVE-2025-54897
 Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a network.



- [https://github.com/themaxlpalfaboy/CVE-2025-54897-LAB](https://github.com/themaxlpalfaboy/CVE-2025-54897-LAB) :  ![starts](https://img.shields.io/github/stars/themaxlpalfaboy/CVE-2025-54897-LAB.svg) ![forks](https://img.shields.io/github/forks/themaxlpalfaboy/CVE-2025-54897-LAB.svg)

## CVE-2025-54887
 jwe is a Ruby implementation of the RFC 7516 JSON Web Encryption (JWE) standard. In versions 1.1.0 and below, authentication tags of encrypted JWEs can be brute forced, which may result in loss of confidentiality for those JWEs and provide ways to craft arbitrary JWEs. This puts users at risk because JWEs can be modified to decrypt to an arbitrary value, decrypted by observing parsing differences and the GCM internal GHASH key can be recovered. Users are affected by this vulnerability even if they do not use an AES-GCM encryption algorithm for their JWEs. As the GHASH key may have been leaked, users must rotate the encryption keys after upgrading. This issue is fixed in version 1.1.1.



- [https://github.com/shinigami-777/PoC_CVE-2025-54887](https://github.com/shinigami-777/PoC_CVE-2025-54887) :  ![starts](https://img.shields.io/github/stars/shinigami-777/PoC_CVE-2025-54887.svg) ![forks](https://img.shields.io/github/forks/shinigami-777/PoC_CVE-2025-54887.svg)

## CVE-2025-54874
 OpenJPEG is an open-source JPEG 2000 codec. In OpenJPEG from 2.5.1 through 2.5.3, a call to opj_jp2_read_header may lead to OOB heap memory write when the data stream p_stream is too short and p_image is not initialized.



- [https://github.com/cyhe50/cve-2025-54874-poc](https://github.com/cyhe50/cve-2025-54874-poc) :  ![starts](https://img.shields.io/github/stars/cyhe50/cve-2025-54874-poc.svg) ![forks](https://img.shields.io/github/forks/cyhe50/cve-2025-54874-poc.svg)

## CVE-2025-54794
 Claude Code is an agentic coding tool. In versions below 0.2.111, a path validation flaw using prefix matching instead of canonical path comparison, makes it possible to bypass directory restrictions and access files outside the CWD. Successful exploitation depends on the presence of (or ability to create) a directory with the same prefix as the CWD and the ability to add untrusted content into a Claude Code context window. This is fixed in version 0.2.111.



- [https://github.com/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back](https://github.com/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-54794-Hijacking-Claude-AI-with-a-Prompt-Injection-The-Jailbreak-That-Talked-Back.svg)

## CVE-2025-54793
 Astro is a web framework for content-driven websites. In versions 5.2.0 through 5.12.7, there is an Open Redirect vulnerability in the trailing slash redirection logic when handling paths with double slashes. This allows an attacker to redirect users to arbitrary external domains by crafting URLs such as https://mydomain.com//malicious-site.com/. This increases the risk of phishing and other social engineering attacks. This affects sites that use on-demand rendering (SSR) with the Node or Cloudflare adapters. It does not affect static sites, or sites deployed to Netlify or Vercel. This issue is fixed in version 5.12.8. To work around this issue at the network level, block outgoing redirect responses with a Location header value that starts with `//`.



- [https://github.com/Bhuvanesh-Murdoch2005/ict279-cve-2025-54793](https://github.com/Bhuvanesh-Murdoch2005/ict279-cve-2025-54793) :  ![starts](https://img.shields.io/github/stars/Bhuvanesh-Murdoch2005/ict279-cve-2025-54793.svg) ![forks](https://img.shields.io/github/forks/Bhuvanesh-Murdoch2005/ict279-cve-2025-54793.svg)

## CVE-2025-54782
 Nest is a framework for building scalable Node.js server-side applications. In versions 0.2.0 and below, a critical Remote Code Execution (RCE) vulnerability was discovered in the @nestjs/devtools-integration package. When enabled, the package exposes a local development HTTP server with an API endpoint that uses an unsafe JavaScript sandbox (safe-eval-like implementation). Due to improper sandboxing and missing cross-origin protections, any malicious website visited by a developer can execute arbitrary code on their local machine. The package adds HTTP endpoints to a locally running NestJS development server. One of these endpoints, /inspector/graph/interact, accepts JSON input containing a code field and executes the provided code in a Node.js vm.runInNewContext sandbox. This is fixed in version 0.2.1.



- [https://github.com/vxaretra/CVE-2025-54782](https://github.com/vxaretra/CVE-2025-54782) :  ![starts](https://img.shields.io/github/stars/vxaretra/CVE-2025-54782.svg) ![forks](https://img.shields.io/github/forks/vxaretra/CVE-2025-54782.svg)

## CVE-2025-54769
 An authenticated, read-only user can upload a file and perform a directory traversal to have the uploaded file placed in a location of their choosing.  This can be used to overwrite existing PERL modules within the application to achieve remote code execution (RCE) by an attacker.



- [https://github.com/byteReaper77/CVE-2025-54769](https://github.com/byteReaper77/CVE-2025-54769) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-54769.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-54769.svg)

## CVE-2025-54726
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Miguel Useche JS Archive List allows SQL Injection. This issue affects JS Archive List: from n/a through n/a.



- [https://github.com/RandomRobbieBF/CVE-2025-54726](https://github.com/RandomRobbieBF/CVE-2025-54726) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-54726.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-54726.svg)

## CVE-2025-54677
 Unrestricted Upload of File with Dangerous Type vulnerability in vcita Online Booking & Scheduling Calendar for WordPress by vcita allows Using Malicious Files. This issue affects Online Booking & Scheduling Calendar for WordPress by vcita: from n/a through 4.5.3.



- [https://github.com/quetuan03/CVE-2025-54677](https://github.com/quetuan03/CVE-2025-54677) :  ![starts](https://img.shields.io/github/stars/quetuan03/CVE-2025-54677.svg) ![forks](https://img.shields.io/github/forks/quetuan03/CVE-2025-54677.svg)

## CVE-2025-54589
 Copyparty is a portable file server. In versions 1.18.6 and below, when accessing the recent uploads page at `/?ru`, users can filter the results using an input field at the top. This field appends a filter parameter to the URL, which reflects its value directly into a `script` block without proper escaping, allowing for reflected Cross-Site Scripting (XSS) and can be exploited against both authenticated and unauthenticated users. This is fixed in version 1.18.7.



- [https://github.com/byteReaper77/CVE-2025-54589](https://github.com/byteReaper77/CVE-2025-54589) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-54589.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-54589.svg)

## CVE-2025-54574
 Squid is a caching proxy for the Web. In versions 6.3 and below, Squid is vulnerable to a heap buffer overflow and possible remote code execution attack when processing URN due to incorrect buffer management. This has been fixed in version 6.4. To work around this issue, disable URN access permissions.



- [https://github.com/B1ack4sh/Blackash-CVE-2025-54574](https://github.com/B1ack4sh/Blackash-CVE-2025-54574) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-54574.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-54574.svg)

## CVE-2025-54554
 tiaudit in Tera Insights tiCrypt before 2025-07-17 allows unauthenticated REST API requests that reveal sensitive information about the underlying SQL queries and database structure.



- [https://github.com/Aman-Parmar/CVE-2025-54554](https://github.com/Aman-Parmar/CVE-2025-54554) :  ![starts](https://img.shields.io/github/stars/Aman-Parmar/CVE-2025-54554.svg) ![forks](https://img.shields.io/github/forks/Aman-Parmar/CVE-2025-54554.svg)

## CVE-2025-54424
 1Panel is a web interface and MCP Server that manages websites, files, containers, databases, and LLMs on a Linux server. In versions 2.0.5 and below, the HTTPS protocol used for communication between the Core and Agent endpoints has incomplete certificate verification during certificate validation, leading to unauthorized interface access. Due to the presence of numerous command execution or high-privilege interfaces in 1Panel, this results in Remote Code Execution (RCE). This is fixed in version 2.0.6. The CVE has been translated from Simplified Chinese using GitHub Copilot.



- [https://github.com/Mr-xn/CVE-2025-54424](https://github.com/Mr-xn/CVE-2025-54424) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2025-54424.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2025-54424.svg)

- [https://github.com/hophtien/CVE-2025-54424](https://github.com/hophtien/CVE-2025-54424) :  ![starts](https://img.shields.io/github/stars/hophtien/CVE-2025-54424.svg) ![forks](https://img.shields.io/github/forks/hophtien/CVE-2025-54424.svg)

## CVE-2025-54381
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. In versions 1.4.0 until 1.4.19, the file upload processing system contains an SSRF vulnerability that allows unauthenticated remote attackers to force the server to make arbitrary HTTP requests. The vulnerability stems from the multipart form data and JSON request handlers, which automatically download files from user-provided URLs without validating whether those URLs point to internal network addresses, cloud metadata endpoints, or other restricted resources. The documentation explicitly promotes this URL-based file upload feature, making it an intended design that exposes all deployed services to SSRF attacks by default. Version 1.4.19 contains a patch for the issue.



- [https://github.com/B1ack4sh/Blackash-CVE-2025-54381](https://github.com/B1ack4sh/Blackash-CVE-2025-54381) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-54381.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-54381.svg)

- [https://github.com/rockmelodies/bentoml_CVE-2025-54381](https://github.com/rockmelodies/bentoml_CVE-2025-54381) :  ![starts](https://img.shields.io/github/stars/rockmelodies/bentoml_CVE-2025-54381.svg) ![forks](https://img.shields.io/github/forks/rockmelodies/bentoml_CVE-2025-54381.svg)

## CVE-2025-54352
 WordPress 3.5 through 6.8.2 allows remote attackers to guess titles of private and draft posts via pingback.ping XML-RPC requests. NOTE: the Supplier is not changing this behavior.



- [https://github.com/yohannslm/CVE-2025-54352](https://github.com/yohannslm/CVE-2025-54352) :  ![starts](https://img.shields.io/github/stars/yohannslm/CVE-2025-54352.svg) ![forks](https://img.shields.io/github/forks/yohannslm/CVE-2025-54352.svg)

- [https://github.com/limmmw/CVE-2025-54352](https://github.com/limmmw/CVE-2025-54352) :  ![starts](https://img.shields.io/github/stars/limmmw/CVE-2025-54352.svg) ![forks](https://img.shields.io/github/forks/limmmw/CVE-2025-54352.svg)

## CVE-2025-54313
 eslint-config-prettier 8.10.1, 9.1.1, 10.1.6, and 10.1.7 has embedded malicious code for a supply chain compromise. Installing an affected package executes an install.js file that launches the node-gyp.dll malware on Windows.



- [https://github.com/nihilor/cve-2025-54313](https://github.com/nihilor/cve-2025-54313) :  ![starts](https://img.shields.io/github/stars/nihilor/cve-2025-54313.svg) ![forks](https://img.shields.io/github/forks/nihilor/cve-2025-54313.svg)

- [https://github.com/ShinP451/scavenger_scanner](https://github.com/ShinP451/scavenger_scanner) :  ![starts](https://img.shields.io/github/stars/ShinP451/scavenger_scanner.svg) ![forks](https://img.shields.io/github/forks/ShinP451/scavenger_scanner.svg)

## CVE-2025-54309
 CrushFTP 10 before 10.8.5 and 11 before 11.3.4_23, when the DMZ proxy feature is not used, mishandles AS2 validation and consequently allows remote attackers to obtain admin access via HTTPS, as exploited in the wild in July 2025.



- [https://github.com/watchtowrlabs/watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309](https://github.com/watchtowrlabs/watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-CrushFTP-Authentication-Bypass-CVE-2025-54309.svg)

- [https://github.com/issamjr/CVE-2025-54309-EXPLOIT](https://github.com/issamjr/CVE-2025-54309-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-54309-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-54309-EXPLOIT.svg)

- [https://github.com/brokendreamsclub/CVE-2025-54309](https://github.com/brokendreamsclub/CVE-2025-54309) :  ![starts](https://img.shields.io/github/stars/brokendreamsclub/CVE-2025-54309.svg) ![forks](https://img.shields.io/github/forks/brokendreamsclub/CVE-2025-54309.svg)

- [https://github.com/foregenix/CVE-2025-54309](https://github.com/foregenix/CVE-2025-54309) :  ![starts](https://img.shields.io/github/stars/foregenix/CVE-2025-54309.svg) ![forks](https://img.shields.io/github/forks/foregenix/CVE-2025-54309.svg)

- [https://github.com/chin-tech/CrushFTP_CVE-2025-54309](https://github.com/chin-tech/CrushFTP_CVE-2025-54309) :  ![starts](https://img.shields.io/github/stars/chin-tech/CrushFTP_CVE-2025-54309.svg) ![forks](https://img.shields.io/github/forks/chin-tech/CrushFTP_CVE-2025-54309.svg)

- [https://github.com/whisperer1290/CVE-2025-54309__Enhanced_exploit](https://github.com/whisperer1290/CVE-2025-54309__Enhanced_exploit) :  ![starts](https://img.shields.io/github/stars/whisperer1290/CVE-2025-54309__Enhanced_exploit.svg) ![forks](https://img.shields.io/github/forks/whisperer1290/CVE-2025-54309__Enhanced_exploit.svg)

## CVE-2025-54253
 Adobe Experience Manager versions 6.5.23 and earlier are affected by a Misconfiguration vulnerability that could result in arbitrary code execution. An attacker could leverage this vulnerability to bypass security mechanisms and execute code. Exploitation of this issue does not require user interaction and scope is changed.



- [https://github.com/Shivshantp/CVE-2025-54253-Exploit-Demo](https://github.com/Shivshantp/CVE-2025-54253-Exploit-Demo) :  ![starts](https://img.shields.io/github/stars/Shivshantp/CVE-2025-54253-Exploit-Demo.svg) ![forks](https://img.shields.io/github/forks/Shivshantp/CVE-2025-54253-Exploit-Demo.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-54253](https://github.com/B1ack4sh/Blackash-CVE-2025-54253) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-54253.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-54253.svg)

- [https://github.com/25145hg654511135gfhfkr8488r8r8r8r8r/test2](https://github.com/25145hg654511135gfhfkr8488r8r8r8r8r/test2) :  ![starts](https://img.shields.io/github/stars/25145hg654511135gfhfkr8488r8r8r8r8r/test2.svg) ![forks](https://img.shields.io/github/forks/25145hg654511135gfhfkr8488r8r8r8r8r/test2.svg)

- [https://github.com/jm7knz/CVE-2025-54253-Exploit-Demo](https://github.com/jm7knz/CVE-2025-54253-Exploit-Demo) :  ![starts](https://img.shields.io/github/stars/jm7knz/CVE-2025-54253-Exploit-Demo.svg) ![forks](https://img.shields.io/github/forks/jm7knz/CVE-2025-54253-Exploit-Demo.svg)

- [https://github.com/25145hg654511135gfhfkr8488r8r8r8r8r/test](https://github.com/25145hg654511135gfhfkr8488r8r8r8r8r/test) :  ![starts](https://img.shields.io/github/stars/25145hg654511135gfhfkr8488r8r8r8r8r/test.svg) ![forks](https://img.shields.io/github/forks/25145hg654511135gfhfkr8488r8r8r8r8r/test.svg)

## CVE-2025-54236
 Adobe Commerce versions 2.4.9-alpha2, 2.4.8-p2, 2.4.7-p7, 2.4.6-p12, 2.4.5-p14, 2.4.4-p15 and earlier are affected by an Improper Input Validation vulnerability. A successful attacker can abuse this to achieve session takeover, increasing the confidentiality, and integrity impact to high. Exploitation of this issue does not require user interaction.



- [https://github.com/amalpvatayam67/day01-sessionreaper-lab](https://github.com/amalpvatayam67/day01-sessionreaper-lab) :  ![starts](https://img.shields.io/github/stars/amalpvatayam67/day01-sessionreaper-lab.svg) ![forks](https://img.shields.io/github/forks/amalpvatayam67/day01-sessionreaper-lab.svg)

- [https://github.com/wubinworks/magento2-session-reaper-patch](https://github.com/wubinworks/magento2-session-reaper-patch) :  ![starts](https://img.shields.io/github/stars/wubinworks/magento2-session-reaper-patch.svg) ![forks](https://img.shields.io/github/forks/wubinworks/magento2-session-reaper-patch.svg)

## CVE-2025-54135
 Cursor is a code editor built for programming with AI. Cursor allows writing in-workspace files with no user approval in versions below 1.3.9, If the file is a dotfile, editing it requires approval but creating a new one doesn't. Hence, if sensitive MCP files, such as the .cursor/mcp.json file don't already exist in the workspace, an attacker can chain a indirect prompt injection vulnerability to hijack the context to write to the settings file and trigger RCE on the victim without user approval. This is fixed in version 1.3.9.



- [https://github.com/anntsmart/CVE-2025-54135](https://github.com/anntsmart/CVE-2025-54135) :  ![starts](https://img.shields.io/github/stars/anntsmart/CVE-2025-54135.svg) ![forks](https://img.shields.io/github/forks/anntsmart/CVE-2025-54135.svg)

- [https://github.com/hn1e13/test-mcp](https://github.com/hn1e13/test-mcp) :  ![starts](https://img.shields.io/github/stars/hn1e13/test-mcp.svg) ![forks](https://img.shields.io/github/forks/hn1e13/test-mcp.svg)

## CVE-2025-54110
 Integer overflow or wraparound in Windows Kernel allows an authorized attacker to elevate privileges locally.



- [https://github.com/ByteHawkSec/CVE-2025-54110-POC](https://github.com/ByteHawkSec/CVE-2025-54110-POC) :  ![starts](https://img.shields.io/github/stars/ByteHawkSec/CVE-2025-54110-POC.svg) ![forks](https://img.shields.io/github/forks/ByteHawkSec/CVE-2025-54110-POC.svg)

## CVE-2025-54106
 Integer overflow or wraparound in Windows Routing and Remote Access Service (RRAS) allows an unauthorized attacker to execute code over a network.



- [https://github.com/DExplo1ted/CVE-2025-54106-POC](https://github.com/DExplo1ted/CVE-2025-54106-POC) :  ![starts](https://img.shields.io/github/stars/DExplo1ted/CVE-2025-54106-POC.svg) ![forks](https://img.shields.io/github/forks/DExplo1ted/CVE-2025-54106-POC.svg)

## CVE-2025-53964
 GoldenDict 1.5.0 and 1.5.1 has an exposed dangerous method that allows reading and modifying files when a user adds a crafted dictionary and then searches for any term included in that dictionary.



- [https://github.com/tigr78/CVE-2025-53964](https://github.com/tigr78/CVE-2025-53964) :  ![starts](https://img.shields.io/github/stars/tigr78/CVE-2025-53964.svg) ![forks](https://img.shields.io/github/forks/tigr78/CVE-2025-53964.svg)

## CVE-2025-53833
 LaRecipe is an application that allows users to create documentation with Markdown inside a Laravel app. Versions prior to 2.8.1 are vulnerable to Server-Side Template Injection (SSTI), which could potentially lead to Remote Code Execution (RCE) in vulnerable configurations. Attackers could execute arbitrary commands on the server, access sensitive environment variables, and/or escalate access depending on server configuration. Users are strongly advised to upgrade to version v2.8.1 or later to receive a patch.



- [https://github.com/B1ack4sh/Blackash-CVE-2025-53833](https://github.com/B1ack4sh/Blackash-CVE-2025-53833) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-53833.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-53833.svg)

## CVE-2025-53786
 On April 18th 2025, Microsoft announced Exchange Server Security Changes for Hybrid Deployments and accompanying non-security Hot Fix. Microsoft made these changes in the general interest of improving the security of hybrid Exchange deployments. Following further investigation, Microsoft identified specific security implications tied to the guidance and configuration steps outlined in the April announcement. Microsoft is issuing CVE-2025-53786 to document a vulnerability that is addressed by taking the steps documented with the April 18th announcement. Microsoft strongly recommends reading the information, installing the April 2025 (or later) Hot Fix and implementing the changes in your Exchange Server and hybrid environment.



- [https://github.com/vincentdthe/CVE-2025-53786](https://github.com/vincentdthe/CVE-2025-53786) :  ![starts](https://img.shields.io/github/stars/vincentdthe/CVE-2025-53786.svg) ![forks](https://img.shields.io/github/forks/vincentdthe/CVE-2025-53786.svg)

## CVE-2025-53773
 Improper neutralization of special elements used in a command ('command injection') in GitHub Copilot and Visual Studio allows an unauthorized attacker to execute code locally.



- [https://github.com/B1ack4sh/Blackash-CVE-2025-53773](https://github.com/B1ack4sh/Blackash-CVE-2025-53773) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-53773.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-53773.svg)

## CVE-2025-53772
 Deserialization of untrusted data in Web Deploy allows an authorized attacker to execute code over a network.



- [https://github.com/fortihack/CVE-2025-53772](https://github.com/fortihack/CVE-2025-53772) :  ![starts](https://img.shields.io/github/stars/fortihack/CVE-2025-53772.svg) ![forks](https://img.shields.io/github/forks/fortihack/CVE-2025-53772.svg)

- [https://github.com/Momollax/CVE-2025-53772-IIS-WebDeploy-RCE](https://github.com/Momollax/CVE-2025-53772-IIS-WebDeploy-RCE) :  ![starts](https://img.shields.io/github/stars/Momollax/CVE-2025-53772-IIS-WebDeploy-RCE.svg) ![forks](https://img.shields.io/github/forks/Momollax/CVE-2025-53772-IIS-WebDeploy-RCE.svg)

- [https://github.com/go-bi/CVE-2025-53772-](https://github.com/go-bi/CVE-2025-53772-) :  ![starts](https://img.shields.io/github/stars/go-bi/CVE-2025-53772-.svg) ![forks](https://img.shields.io/github/forks/go-bi/CVE-2025-53772-.svg)

## CVE-2025-53771
 Improper authentication in Microsoft Office SharePoint allows an unauthorized attacker to perform spoofing over a network.



- [https://github.com/unk9vvn/sharepoint-toolpane](https://github.com/unk9vvn/sharepoint-toolpane) :  ![starts](https://img.shields.io/github/stars/unk9vvn/sharepoint-toolpane.svg) ![forks](https://img.shields.io/github/forks/unk9vvn/sharepoint-toolpane.svg)

- [https://github.com/zach115th/ToolShellFinder](https://github.com/zach115th/ToolShellFinder) :  ![starts](https://img.shields.io/github/stars/zach115th/ToolShellFinder.svg) ![forks](https://img.shields.io/github/forks/zach115th/ToolShellFinder.svg)

## CVE-2025-53770
 Deserialization of untrusted data in on-premises Microsoft SharePoint Server allows an unauthorized attacker to execute code over a network.
Microsoft is aware that an exploit for CVE-2025-53770 exists in the wild.
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.



- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance](https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg)

- [https://github.com/soltanali0/CVE-2025-53770-Exploit](https://github.com/soltanali0/CVE-2025-53770-Exploit) :  ![starts](https://img.shields.io/github/stars/soltanali0/CVE-2025-53770-Exploit.svg) ![forks](https://img.shields.io/github/forks/soltanali0/CVE-2025-53770-Exploit.svg)

- [https://github.com/MuhammadWaseem29/CVE-2025-53770](https://github.com/MuhammadWaseem29/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-53770.svg)

- [https://github.com/kaizensecurity/CVE-2025-53770](https://github.com/kaizensecurity/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/kaizensecurity/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/kaizensecurity/CVE-2025-53770.svg)

- [https://github.com/hazcod/CVE-2025-53770](https://github.com/hazcod/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/hazcod/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/hazcod/CVE-2025-53770.svg)

- [https://github.com/ZephrFish/CVE-2025-53770-Scanner](https://github.com/ZephrFish/CVE-2025-53770-Scanner) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2025-53770-Scanner.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2025-53770-Scanner.svg)

- [https://github.com/3a7/CVE-2025-53770](https://github.com/3a7/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/3a7/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/3a7/CVE-2025-53770.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-53770](https://github.com/B1ack4sh/Blackash-CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-53770.svg)

- [https://github.com/unk9vvn/sharepoint-toolpane](https://github.com/unk9vvn/sharepoint-toolpane) :  ![starts](https://img.shields.io/github/stars/unk9vvn/sharepoint-toolpane.svg) ![forks](https://img.shields.io/github/forks/unk9vvn/sharepoint-toolpane.svg)

- [https://github.com/exfil0/CVE-2025-53770](https://github.com/exfil0/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/exfil0/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/exfil0/CVE-2025-53770.svg)

- [https://github.com/saladin0x1/CVE-2025-53770](https://github.com/saladin0x1/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/saladin0x1/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/saladin0x1/CVE-2025-53770.svg)

- [https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-sharepoint-cve-2025-53770](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-sharepoint-cve-2025-53770) :  ![starts](https://img.shields.io/github/stars/Bluefire-Redteam-Cybersecurity/bluefire-sharepoint-cve-2025-53770.svg) ![forks](https://img.shields.io/github/forks/Bluefire-Redteam-Cybersecurity/bluefire-sharepoint-cve-2025-53770.svg)

- [https://github.com/AdityaBhatt3010/CVE-2025-53770-SharePoint-Zero-Day-Variant-Exploited-for-Full-RCE](https://github.com/AdityaBhatt3010/CVE-2025-53770-SharePoint-Zero-Day-Variant-Exploited-for-Full-RCE) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-53770-SharePoint-Zero-Day-Variant-Exploited-for-Full-RCE.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-53770-SharePoint-Zero-Day-Variant-Exploited-for-Full-RCE.svg)

- [https://github.com/Sec-Dan/CVE-2025-53770-Scanner](https://github.com/Sec-Dan/CVE-2025-53770-Scanner) :  ![starts](https://img.shields.io/github/stars/Sec-Dan/CVE-2025-53770-Scanner.svg) ![forks](https://img.shields.io/github/forks/Sec-Dan/CVE-2025-53770-Scanner.svg)

- [https://github.com/Immersive-Labs-Sec/SharePoint-CVE-2025-53770-POC](https://github.com/Immersive-Labs-Sec/SharePoint-CVE-2025-53770-POC) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/SharePoint-CVE-2025-53770-POC.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/SharePoint-CVE-2025-53770-POC.svg)

- [https://github.com/tripoloski1337/CVE-2025-53770-scanner](https://github.com/tripoloski1337/CVE-2025-53770-scanner) :  ![starts](https://img.shields.io/github/stars/tripoloski1337/CVE-2025-53770-scanner.svg) ![forks](https://img.shields.io/github/forks/tripoloski1337/CVE-2025-53770-scanner.svg)

- [https://github.com/imbas007/CVE-2025-53770-Vulnerable-Scanner](https://github.com/imbas007/CVE-2025-53770-Vulnerable-Scanner) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-53770-Vulnerable-Scanner.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-53770-Vulnerable-Scanner.svg)

- [https://github.com/0xh3g4z1/CVE-2025-53770-SharePoint-RCE](https://github.com/0xh3g4z1/CVE-2025-53770-SharePoint-RCE) :  ![starts](https://img.shields.io/github/stars/0xh3g4z1/CVE-2025-53770-SharePoint-RCE.svg) ![forks](https://img.shields.io/github/forks/0xh3g4z1/CVE-2025-53770-SharePoint-RCE.svg)

- [https://github.com/Rabbitbong/OurSharePoint-CVE-2025-53770](https://github.com/Rabbitbong/OurSharePoint-CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/Rabbitbong/OurSharePoint-CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/Rabbitbong/OurSharePoint-CVE-2025-53770.svg)

- [https://github.com/paolokappa/SharePointSecurityMonitor](https://github.com/paolokappa/SharePointSecurityMonitor) :  ![starts](https://img.shields.io/github/stars/paolokappa/SharePointSecurityMonitor.svg) ![forks](https://img.shields.io/github/forks/paolokappa/SharePointSecurityMonitor.svg)

- [https://github.com/0xray5c68616e37/cve-2025-53770](https://github.com/0xray5c68616e37/cve-2025-53770) :  ![starts](https://img.shields.io/github/stars/0xray5c68616e37/cve-2025-53770.svg) ![forks](https://img.shields.io/github/forks/0xray5c68616e37/cve-2025-53770.svg)

- [https://github.com/RukshanaAlikhan/CVE-2025-53770](https://github.com/RukshanaAlikhan/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/RukshanaAlikhan/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/RukshanaAlikhan/CVE-2025-53770.svg)

- [https://github.com/ghostn4444/CVE-2025-53770](https://github.com/ghostn4444/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/ghostn4444/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/ghostn4444/CVE-2025-53770.svg)

- [https://github.com/daryllundy/CVE-2025-53770](https://github.com/daryllundy/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/daryllundy/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/daryllundy/CVE-2025-53770.svg)

- [https://github.com/r3xbugbounty/CVE-2025-53770](https://github.com/r3xbugbounty/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/r3xbugbounty/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/r3xbugbounty/CVE-2025-53770.svg)

- [https://github.com/Agampreet-Singh/CVE-2025-53770](https://github.com/Agampreet-Singh/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/Agampreet-Singh/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/Agampreet-Singh/CVE-2025-53770.svg)

- [https://github.com/nisargsuthar/suricata-rule-CVE-2025-53770](https://github.com/nisargsuthar/suricata-rule-CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/nisargsuthar/suricata-rule-CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/nisargsuthar/suricata-rule-CVE-2025-53770.svg)

- [https://github.com/Udyz/CVE-2025-53770-Exploit](https://github.com/Udyz/CVE-2025-53770-Exploit) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2025-53770-Exploit.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2025-53770-Exploit.svg)

- [https://github.com/fentnttntnt/CVE-2025-53770](https://github.com/fentnttntnt/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/fentnttntnt/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/fentnttntnt/CVE-2025-53770.svg)

- [https://github.com/0x-crypt/CVE-2025-53770-Scanner](https://github.com/0x-crypt/CVE-2025-53770-Scanner) :  ![starts](https://img.shields.io/github/stars/0x-crypt/CVE-2025-53770-Scanner.svg) ![forks](https://img.shields.io/github/forks/0x-crypt/CVE-2025-53770-Scanner.svg)

- [https://github.com/grupooruss/CVE-2025-53770-Checker](https://github.com/grupooruss/CVE-2025-53770-Checker) :  ![starts](https://img.shields.io/github/stars/grupooruss/CVE-2025-53770-Checker.svg) ![forks](https://img.shields.io/github/forks/grupooruss/CVE-2025-53770-Checker.svg)

- [https://github.com/go-bi/sharepoint-CVE-2025-53770](https://github.com/go-bi/sharepoint-CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/go-bi/sharepoint-CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/go-bi/sharepoint-CVE-2025-53770.svg)

- [https://github.com/bitsalv/ToolShell-Honeypot](https://github.com/bitsalv/ToolShell-Honeypot) :  ![starts](https://img.shields.io/github/stars/bitsalv/ToolShell-Honeypot.svg) ![forks](https://img.shields.io/github/forks/bitsalv/ToolShell-Honeypot.svg)

- [https://github.com/behnamvanda/CVE-2025-53770-Checker](https://github.com/behnamvanda/CVE-2025-53770-Checker) :  ![starts](https://img.shields.io/github/stars/behnamvanda/CVE-2025-53770-Checker.svg) ![forks](https://img.shields.io/github/forks/behnamvanda/CVE-2025-53770-Checker.svg)

- [https://github.com/siag-itsec/CVE-2025-53770-Hunting](https://github.com/siag-itsec/CVE-2025-53770-Hunting) :  ![starts](https://img.shields.io/github/stars/siag-itsec/CVE-2025-53770-Hunting.svg) ![forks](https://img.shields.io/github/forks/siag-itsec/CVE-2025-53770-Hunting.svg)

- [https://github.com/GreenForceNetworks/Toolshell_CVE-2025-53770](https://github.com/GreenForceNetworks/Toolshell_CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/GreenForceNetworks/Toolshell_CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/GreenForceNetworks/Toolshell_CVE-2025-53770.svg)

- [https://github.com/bharath-cyber-root/sharepoint-toolshell-cve-2025-53770](https://github.com/bharath-cyber-root/sharepoint-toolshell-cve-2025-53770) :  ![starts](https://img.shields.io/github/stars/bharath-cyber-root/sharepoint-toolshell-cve-2025-53770.svg) ![forks](https://img.shields.io/github/forks/bharath-cyber-root/sharepoint-toolshell-cve-2025-53770.svg)

- [https://github.com/BirdsAreFlyingCameras/CVE-2025-53770_Raw-HTTP-Request-Generator](https://github.com/BirdsAreFlyingCameras/CVE-2025-53770_Raw-HTTP-Request-Generator) :  ![starts](https://img.shields.io/github/stars/BirdsAreFlyingCameras/CVE-2025-53770_Raw-HTTP-Request-Generator.svg) ![forks](https://img.shields.io/github/forks/BirdsAreFlyingCameras/CVE-2025-53770_Raw-HTTP-Request-Generator.svg)

- [https://github.com/harryhaxor/CVE-2025-53770-SharePoint-Deserialization-RCE-PoC](https://github.com/harryhaxor/CVE-2025-53770-SharePoint-Deserialization-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/harryhaxor/CVE-2025-53770-SharePoint-Deserialization-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/harryhaxor/CVE-2025-53770-SharePoint-Deserialization-RCE-PoC.svg)

- [https://github.com/CyprianAtsyor/ToolShell-CVE-2025-53770-SharePoint-Exploit-Lab-LetsDefend](https://github.com/CyprianAtsyor/ToolShell-CVE-2025-53770-SharePoint-Exploit-Lab-LetsDefend) :  ![starts](https://img.shields.io/github/stars/CyprianAtsyor/ToolShell-CVE-2025-53770-SharePoint-Exploit-Lab-LetsDefend.svg) ![forks](https://img.shields.io/github/forks/CyprianAtsyor/ToolShell-CVE-2025-53770-SharePoint-Exploit-Lab-LetsDefend.svg)

- [https://github.com/zach115th/ToolShellFinder](https://github.com/zach115th/ToolShellFinder) :  ![starts](https://img.shields.io/github/stars/zach115th/ToolShellFinder.svg) ![forks](https://img.shields.io/github/forks/zach115th/ToolShellFinder.svg)

- [https://github.com/Michaael01/LetsDefend--SOC-342-CVE-2025-53770-SharePoint-Exploit-ToolShell](https://github.com/Michaael01/LetsDefend--SOC-342-CVE-2025-53770-SharePoint-Exploit-ToolShell) :  ![starts](https://img.shields.io/github/stars/Michaael01/LetsDefend--SOC-342-CVE-2025-53770-SharePoint-Exploit-ToolShell.svg) ![forks](https://img.shields.io/github/forks/Michaael01/LetsDefend--SOC-342-CVE-2025-53770-SharePoint-Exploit-ToolShell.svg)

- [https://github.com/bossnick98/-SOC342---CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-and-RCE](https://github.com/bossnick98/-SOC342---CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-and-RCE) :  ![starts](https://img.shields.io/github/stars/bossnick98/-SOC342---CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-and-RCE.svg) ![forks](https://img.shields.io/github/forks/bossnick98/-SOC342---CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-and-RCE.svg)

- [https://github.com/victormbogu1/LetsDefend-SOC342-CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-andRCE-EventID-320](https://github.com/victormbogu1/LetsDefend-SOC342-CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-andRCE-EventID-320) :  ![starts](https://img.shields.io/github/stars/victormbogu1/LetsDefend-SOC342-CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-andRCE-EventID-320.svg) ![forks](https://img.shields.io/github/forks/victormbogu1/LetsDefend-SOC342-CVE-2025-53770-SharePoint-ToolShell-Auth-Bypass-andRCE-EventID-320.svg)

- [https://github.com/n1chr0x/ZeroPoint](https://github.com/n1chr0x/ZeroPoint) :  ![starts](https://img.shields.io/github/stars/n1chr0x/ZeroPoint.svg) ![forks](https://img.shields.io/github/forks/n1chr0x/ZeroPoint.svg)

## CVE-2025-53766
 Heap-based buffer overflow in Windows GDI+ allows an unauthorized attacker to execute code over a network.



- [https://github.com/rich98/cve_2025_53766](https://github.com/rich98/cve_2025_53766) :  ![starts](https://img.shields.io/github/stars/rich98/cve_2025_53766.svg) ![forks](https://img.shields.io/github/forks/rich98/cve_2025_53766.svg)

## CVE-2025-53694
 Exposure of Sensitive Information to an Unauthorized Actor vulnerability in Sitecore Sitecore Experience Manager (XM), Sitecore Experience Platform (XP).This issue affects Sitecore Experience Manager (XM): from 9.2 through 10.4; Experience Platform (XP): from 9.2 through 10.4.



- [https://github.com/brokendreamsclub/CVE-2025-53694](https://github.com/brokendreamsclub/CVE-2025-53694) :  ![starts](https://img.shields.io/github/stars/brokendreamsclub/CVE-2025-53694.svg) ![forks](https://img.shields.io/github/forks/brokendreamsclub/CVE-2025-53694.svg)

- [https://github.com/brokendreamsclub/CVE-2025-53694-to-CVE-2025-53691](https://github.com/brokendreamsclub/CVE-2025-53694-to-CVE-2025-53691) :  ![starts](https://img.shields.io/github/stars/brokendreamsclub/CVE-2025-53694-to-CVE-2025-53691.svg) ![forks](https://img.shields.io/github/forks/brokendreamsclub/CVE-2025-53694-to-CVE-2025-53691.svg)

## CVE-2025-53693
 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') vulnerability in Sitecore Sitecore Experience Manager (XM), Sitecore Experience Platform (XP) allows Cache Poisoning.This issue affects Sitecore Experience Manager (XM): from 9.0 through 9.3, from 10.0 through 10.4; Experience Platform (XP): from 9.0 through 9.3, from 10.0 through 10.4.



- [https://github.com/brokendreamsclub/CVE-2025-53693](https://github.com/brokendreamsclub/CVE-2025-53693) :  ![starts](https://img.shields.io/github/stars/brokendreamsclub/CVE-2025-53693.svg) ![forks](https://img.shields.io/github/forks/brokendreamsclub/CVE-2025-53693.svg)

## CVE-2025-53691
 Deserialization of Untrusted Data vulnerability in Sitecore Experience Manager (XM), Sitecore Experience Platform (XP) allows Remote Code Execution (RCE).This issue affects Experience Manager (XM): from 9.0 through 9.3, from 10.0 through 10.4; Experience Platform (XP): from 9.0 through 9.3, from 10.0 through 10.4.



- [https://github.com/brokendreamsclub/CVE-2025-53691](https://github.com/brokendreamsclub/CVE-2025-53691) :  ![starts](https://img.shields.io/github/stars/brokendreamsclub/CVE-2025-53691.svg) ![forks](https://img.shields.io/github/forks/brokendreamsclub/CVE-2025-53691.svg)

- [https://github.com/brokendreamsclub/CVE-2025-53694-to-CVE-2025-53691](https://github.com/brokendreamsclub/CVE-2025-53694-to-CVE-2025-53691) :  ![starts](https://img.shields.io/github/stars/brokendreamsclub/CVE-2025-53694-to-CVE-2025-53691.svg) ![forks](https://img.shields.io/github/forks/brokendreamsclub/CVE-2025-53694-to-CVE-2025-53691.svg)

## CVE-2025-53690
 Deserialization of Untrusted Data vulnerability in Sitecore Experience Manager (XM), Sitecore Experience Platform (XP) allows Code Injection.This issue affects Experience Manager (XM): through 9.0; Experience Platform (XP): through 9.0.



- [https://github.com/rxerium/CVE-2025-53690](https://github.com/rxerium/CVE-2025-53690) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-53690.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-53690.svg)

- [https://github.com/m0d0ri205/CVE-2025-53690-Analysis](https://github.com/m0d0ri205/CVE-2025-53690-Analysis) :  ![starts](https://img.shields.io/github/stars/m0d0ri205/CVE-2025-53690-Analysis.svg) ![forks](https://img.shields.io/github/forks/m0d0ri205/CVE-2025-53690-Analysis.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-53690](https://github.com/B1ack4sh/Blackash-CVE-2025-53690) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-53690.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-53690.svg)

## CVE-2025-53652
 Jenkins Git Parameter Plugin 439.vb_0e46ca_14534 and earlier does not validate that the Git parameter value submitted to the build matches one of the offered choices, allowing attackers with Item/Build permission to inject arbitrary values into Git parameters.



- [https://github.com/pl4tyz/CVE-2025-53652-Jenkins-Git-Parameter-Analysis](https://github.com/pl4tyz/CVE-2025-53652-Jenkins-Git-Parameter-Analysis) :  ![starts](https://img.shields.io/github/stars/pl4tyz/CVE-2025-53652-Jenkins-Git-Parameter-Analysis.svg) ![forks](https://img.shields.io/github/forks/pl4tyz/CVE-2025-53652-Jenkins-Git-Parameter-Analysis.svg)

## CVE-2025-53640
 Indico is an event management system that uses Flask-Multipass, a multi-backend authentication system for Flask. Starting in version 2.2 and prior to version 3.3.7, an endpoint used to display details of users listed in certain fields (such as ACLs) could be misused to dump basic user details (such as name, affiliation and email) in bulk. Version 3.3.7 fixes the issue. Owners of instances that allow everyone to create a user account, who wish to truly restrict access to these user details, should consider restricting user search to managers. As a workaround, it is possible to restrict access to the affected endpoints (e.g. in the webserver config), but doing so would break certain form fields which could no longer show the details of the users listed in those fields, so upgrading instead is highly recommended.



- [https://github.com/rafaelcorvino1/CVE-2025-53640](https://github.com/rafaelcorvino1/CVE-2025-53640) :  ![starts](https://img.shields.io/github/stars/rafaelcorvino1/CVE-2025-53640.svg) ![forks](https://img.shields.io/github/forks/rafaelcorvino1/CVE-2025-53640.svg)

## CVE-2025-53632
 Chall-Manager is a platform-agnostic system able to start Challenges on Demand of a player. When decoding a scenario (i.e. a zip archive), the path of the file to write is not checked, potentially leading to zip slips. Exploitation does not require authentication nor authorization, so anyone can exploit it. It should nonetheless not be exploitable as it is highly recommended to bury Chall-Manager deep within the infrastructure due to its large capabilities, so no users could reach the system. Patch has been implemented by commit 47d188f and shipped in v0.1.4.



- [https://github.com/pandatix/CVE-2025-53632](https://github.com/pandatix/CVE-2025-53632) :  ![starts](https://img.shields.io/github/stars/pandatix/CVE-2025-53632.svg) ![forks](https://img.shields.io/github/forks/pandatix/CVE-2025-53632.svg)

## CVE-2025-53547
 Helm is a package manager for Charts for Kubernetes. Prior to 3.18.4, a specially crafted Chart.yaml file along with a specially linked Chart.lock file can lead to local code execution when dependencies are updated. Fields in a Chart.yaml file, that are carried over to a Chart.lock file when dependencies are updated and this file is written, can be crafted in a way that can cause execution if that same content were in a file that is executed (e.g., a bash.rc file or shell script). If the Chart.lock file is symlinked to one of these files updating dependencies will write the lock file content to the symlinked file. This can lead to unwanted execution. Helm warns of the symlinked file but did not stop execution due to symlinking. This issue has been resolved in Helm v3.18.4.



- [https://github.com/DVKunion/CVE-2025-53547-POC](https://github.com/DVKunion/CVE-2025-53547-POC) :  ![starts](https://img.shields.io/github/stars/DVKunion/CVE-2025-53547-POC.svg) ![forks](https://img.shields.io/github/forks/DVKunion/CVE-2025-53547-POC.svg)

## CVE-2025-53533
 Pi-hole Admin Interface is a web interface for managing Pi-hole, a network-level advertisement and internet tracker blocking application. Pi-hole Admin Interface versions 6.2.1 and earlier are vulnerable to reflected cross-site scripting (XSS) via a malformed URL path. The 404 error page includes the requested path in the class attribute of the body tag without proper sanitization or escaping. An attacker can craft a URL containing an onload attribute that will execute arbitrary JavaScript code in the browser when a victim visits the malicious link. If an attacker sends a crafted pi-hole link to a victim and the victim visits it, attacker-controlled JavaScript code is executed in the browser of the victim. This has been patched in version 6.3.



- [https://github.com/moezbouzayani9/Pi-hole-XSS-CVE-2025-53533](https://github.com/moezbouzayani9/Pi-hole-XSS-CVE-2025-53533) :  ![starts](https://img.shields.io/github/stars/moezbouzayani9/Pi-hole-XSS-CVE-2025-53533.svg) ![forks](https://img.shields.io/github/forks/moezbouzayani9/Pi-hole-XSS-CVE-2025-53533.svg)

## CVE-2025-53367
 DjVuLibre is a GPL implementation of DjVu, a web-centric format for distributing documents and images. Prior to version 3.5.29, the MMRDecoder::scanruns method is affected by an OOB-write vulnerability, because it does not check that the xr pointer stays within the bounds of the allocated buffer. This can lead to writes beyond the allocated memory, resulting in a heap corruption condition. An out-of-bounds read with pr is also possible for the same reason. This issue has been patched in version 3.5.29.



- [https://github.com/kevinbackhouse/DjVuLibre-poc-CVE-2025-53367](https://github.com/kevinbackhouse/DjVuLibre-poc-CVE-2025-53367) :  ![starts](https://img.shields.io/github/stars/kevinbackhouse/DjVuLibre-poc-CVE-2025-53367.svg) ![forks](https://img.shields.io/github/forks/kevinbackhouse/DjVuLibre-poc-CVE-2025-53367.svg)

## CVE-2025-53072
 Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing Administration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Marketing.  Successful attacks of this vulnerability can result in takeover of Oracle Marketing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/rxerium/CVE-2025-53072-CVE-2025-62481](https://github.com/rxerium/CVE-2025-53072-CVE-2025-62481) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-53072-CVE-2025-62481.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-53072-CVE-2025-62481.svg)

- [https://github.com/AshrafZaryouh/CVE-2025-53072-CVE-2025-62481](https://github.com/AshrafZaryouh/CVE-2025-53072-CVE-2025-62481) :  ![starts](https://img.shields.io/github/stars/AshrafZaryouh/CVE-2025-53072-CVE-2025-62481.svg) ![forks](https://img.shields.io/github/forks/AshrafZaryouh/CVE-2025-53072-CVE-2025-62481.svg)

## CVE-2025-52970
 A improper handling of parameters in Fortinet FortiWeb versions 7.6.3 and below, versions 7.4.7 and below, versions 7.2.10 and below, and 7.0.10 and below may allow an unauthenticated remote attacker with non-public information pertaining to the device and targeted user to gain admin privileges on the device via a specially crafted request.



- [https://github.com/34zY/CVE-2025-52970](https://github.com/34zY/CVE-2025-52970) :  ![starts](https://img.shields.io/github/stars/34zY/CVE-2025-52970.svg) ![forks](https://img.shields.io/github/forks/34zY/CVE-2025-52970.svg)

- [https://github.com/Hex00-0x4/FortiWeb-CVE-2025-52970-Authentication-Bypass](https://github.com/Hex00-0x4/FortiWeb-CVE-2025-52970-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/Hex00-0x4/FortiWeb-CVE-2025-52970-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/Hex00-0x4/FortiWeb-CVE-2025-52970-Authentication-Bypass.svg)

- [https://github.com/imbas007/POC-CVE-2025-52970](https://github.com/imbas007/POC-CVE-2025-52970) :  ![starts](https://img.shields.io/github/stars/imbas007/POC-CVE-2025-52970.svg) ![forks](https://img.shields.io/github/forks/imbas007/POC-CVE-2025-52970.svg)

## CVE-2025-52915
 K7RKScan.sys 23.0.0.10, part of the K7 Security Anti-Malware suite, allows an admin-privileged user to send crafted IOCTL requests to terminate processes that are protected through a third-party implementation. This is caused by insufficient caller validation in the driver's IOCTL handler, enabling unauthorized processes to perform those actions in kernel space. Successful exploitation can lead to denial of service by disrupting critical third-party services or applications.



- [https://github.com/BlackSnufkin/BYOVD](https://github.com/BlackSnufkin/BYOVD) :  ![starts](https://img.shields.io/github/stars/BlackSnufkin/BYOVD.svg) ![forks](https://img.shields.io/github/forks/BlackSnufkin/BYOVD.svg)

- [https://github.com/diego-tella/CVE-2025-1055-poc](https://github.com/diego-tella/CVE-2025-1055-poc) :  ![starts](https://img.shields.io/github/stars/diego-tella/CVE-2025-1055-poc.svg) ![forks](https://img.shields.io/github/forks/diego-tella/CVE-2025-1055-poc.svg)

## CVE-2025-52914
 A vulnerability in the Suite Applications Services component of Mitel MiCollab 10.0 through SP1 FP1 (10.0.1.101) could allow an authenticated attacker to conduct a SQL Injection attack due to insufficient validation of user input. A successful exploit could allow an attacker to execute arbitrary SQL database commands.



- [https://github.com/rxerium/CVE-2025-52914](https://github.com/rxerium/CVE-2025-52914) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-52914.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-52914.svg)

## CVE-2025-52689
 Successful exploitation of the vulnerability could allow an unauthenticated attacker to obtain a valid session ID with administrator privileges by spoofing the login request, potentially allowing the attacker to modify the behaviour of the access point.



- [https://github.com/UltimateHG/CVE-2025-52689-PoC](https://github.com/UltimateHG/CVE-2025-52689-PoC) :  ![starts](https://img.shields.io/github/stars/UltimateHG/CVE-2025-52689-PoC.svg) ![forks](https://img.shields.io/github/forks/UltimateHG/CVE-2025-52689-PoC.svg)

## CVE-2025-52688
 Successful exploitation of the vulnerability could allow an attacker to inject commands with root privileges on the access point, potentially leading to the loss of confidentiality, integrity, availability, and full control of the access point.



- [https://github.com/joelczk/CVE-2025-52688](https://github.com/joelczk/CVE-2025-52688) :  ![starts](https://img.shields.io/github/stars/joelczk/CVE-2025-52688.svg) ![forks](https://img.shields.io/github/forks/joelczk/CVE-2025-52688.svg)

## CVE-2025-52488
 DNN (formerly DotNetNuke) is an open-source web content management platform (CMS) in the Microsoft ecosystem. In versions 6.0.0 to before 10.0.1, DNN.PLATFORM allows a specially crafted series of malicious interaction to potentially expose NTLM hashes to a third party SMB server. This issue has been patched in version 10.0.1.



- [https://github.com/SystemVll/CVE-2025-52488](https://github.com/SystemVll/CVE-2025-52488) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2025-52488.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2025-52488.svg)

## CVE-2025-52392
 Soosyze CMS 2.0 allows brute-force login attacks via the /user/login endpoint due to missing rate-limiting and lockout mechanisms. An attacker can repeatedly submit login attempts without restrictions, potentially gaining unauthorized administrative access. This vulnerability corresponds to CWE-307: Improper Restriction of Excessive Authentication Attempts.



- [https://github.com/137f/Soosyze-CMS-2.0---CVE-2025-52392](https://github.com/137f/Soosyze-CMS-2.0---CVE-2025-52392) :  ![starts](https://img.shields.io/github/stars/137f/Soosyze-CMS-2.0---CVE-2025-52392.svg) ![forks](https://img.shields.io/github/forks/137f/Soosyze-CMS-2.0---CVE-2025-52392.svg)

## CVE-2025-52389
 An Insecure Direct Object Reference (IDOR) in Envasadora H2O Eireli - Soda Cristal v40.20.4 allows authenticated attackers to access sensitive data for other users via a crafted HTTP request.



- [https://github.com/milamrk/CVE-2025-52389](https://github.com/milamrk/CVE-2025-52389) :  ![starts](https://img.shields.io/github/stars/milamrk/CVE-2025-52389.svg) ![forks](https://img.shields.io/github/forks/milamrk/CVE-2025-52389.svg)

- [https://github.com/ktr4ck3r/CVE-2025-52389](https://github.com/ktr4ck3r/CVE-2025-52389) :  ![starts](https://img.shields.io/github/stars/ktr4ck3r/CVE-2025-52389.svg) ![forks](https://img.shields.io/github/forks/ktr4ck3r/CVE-2025-52389.svg)

## CVE-2025-52385
 An issue in Studio 3T v.2025.1.0 and before allows a remote attacker to execute arbitrary code via a crafted payload to the child_process module



- [https://github.com/Kov404/CVE-2025-52385](https://github.com/Kov404/CVE-2025-52385) :  ![starts](https://img.shields.io/github/stars/Kov404/CVE-2025-52385.svg) ![forks](https://img.shields.io/github/forks/Kov404/CVE-2025-52385.svg)

## CVE-2025-52357
 Cross-Site Scripting (XSS) vulnerability exists in the ping diagnostic feature of FiberHome FD602GW-DX-R410 router (firmware V2.2.14), allowing an authenticated attacker to execute arbitrary JavaScript code in the context of the router s web interface. The vulnerability is triggered via user-supplied input in the ping form field, which fails to sanitize special characters. This can be exploited to hijack sessions or escalate privileges through social engineering or browser-based attacks.



- [https://github.com/wrathfulDiety/CVE-2025-52357](https://github.com/wrathfulDiety/CVE-2025-52357) :  ![starts](https://img.shields.io/github/stars/wrathfulDiety/CVE-2025-52357.svg) ![forks](https://img.shields.io/github/forks/wrathfulDiety/CVE-2025-52357.svg)

## CVE-2025-52289
 A Broken Access Control vulnerability in MagnusBilling v7.8.5.3 allows newly registered users to gain escalated privileges by sending a crafted request to /mbilling/index.php/user/save to set their account status fom "pending" to "active" without requiring administrator approval.



- [https://github.com/Madhav-Bhardwaj/CVE-2025-52289](https://github.com/Madhav-Bhardwaj/CVE-2025-52289) :  ![starts](https://img.shields.io/github/stars/Madhav-Bhardwaj/CVE-2025-52289.svg) ![forks](https://img.shields.io/github/forks/Madhav-Bhardwaj/CVE-2025-52289.svg)

- [https://github.com/Whit3-d3viL-hacker/CVE-2025-52289](https://github.com/Whit3-d3viL-hacker/CVE-2025-52289) :  ![starts](https://img.shields.io/github/stars/Whit3-d3viL-hacker/CVE-2025-52289.svg) ![forks](https://img.shields.io/github/forks/Whit3-d3viL-hacker/CVE-2025-52289.svg)

## CVE-2025-52136
 In EMQX before 5.8.6, administrators can install arbitrary novel plugins via the Dashboard web interface. NOTE: the Supplier's position is that this is the intended behavior; however, 5.8.6 adds a defense-in-depth feature in which a plugin's acceptability (for later Dashboard installation) is set by the "emqx ctl plugins allow" CLI command.



- [https://github.com/f1r3K0/CVE-2025-52136](https://github.com/f1r3K0/CVE-2025-52136) :  ![starts](https://img.shields.io/github/stars/f1r3K0/CVE-2025-52136.svg) ![forks](https://img.shields.io/github/forks/f1r3K0/CVE-2025-52136.svg)

## CVE-2025-52122
 Freeform 5.0.0 to before 5.10.16, a plugin for CraftCMS, contains an Server-side template injection (SSTI) vulnerability, resulting in arbitrary code injection for all users that have access to editing a form (submission title).



- [https://github.com/TimTrademark/CVE-2025-52122](https://github.com/TimTrademark/CVE-2025-52122) :  ![starts](https://img.shields.io/github/stars/TimTrademark/CVE-2025-52122.svg) ![forks](https://img.shields.io/github/forks/TimTrademark/CVE-2025-52122.svg)

## CVE-2025-52099
 Integer Overflow vulnerability in SQLite SQLite3 v.3.50.0 allows a remote attacker to cause a denial of service via the setupLookaside function



- [https://github.com/SCREAMBBY/CVE-2025-52099](https://github.com/SCREAMBBY/CVE-2025-52099) :  ![starts](https://img.shields.io/github/stars/SCREAMBBY/CVE-2025-52099.svg) ![forks](https://img.shields.io/github/forks/SCREAMBBY/CVE-2025-52099.svg)

## CVE-2025-52078
 File upload vulnerability in Writebot AI Content Generator SaaS React Template thru 4.0.0, allowing remote attackers to gain escalated privileges via a crafted POST request to the /file-upload endpoint.



- [https://github.com/Yucaerin/CVE-2025-52078](https://github.com/Yucaerin/CVE-2025-52078) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-52078.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-52078.svg)

## CVE-2025-52021
 A SQL Injection vulnerability exists in the edit_product.php file of PuneethReddyHC Online Shopping System Advanced 1.0. The product_id GET parameter is unsafely passed to a SQL query without proper validation or parameterization.



- [https://github.com/hafizgemilang/CVE-2025-52021](https://github.com/hafizgemilang/CVE-2025-52021) :  ![starts](https://img.shields.io/github/stars/hafizgemilang/CVE-2025-52021.svg) ![forks](https://img.shields.io/github/forks/hafizgemilang/CVE-2025-52021.svg)

## CVE-2025-51970
 A SQL Injection vulnerability exists in the action.php endpoint of PuneethReddyHC Online Shopping System Advanced 1.0 due to improper sanitization of user-supplied input in the keyword POST parameter.



- [https://github.com/M4xIq/CVE-2025-51970](https://github.com/M4xIq/CVE-2025-51970) :  ![starts](https://img.shields.io/github/stars/M4xIq/CVE-2025-51970.svg) ![forks](https://img.shields.io/github/forks/M4xIq/CVE-2025-51970.svg)

## CVE-2025-51869
 Insecure Direct Object Reference (IDOR) vulnerability in Liner thru 2025-06-03 allows attackers to gain sensitive information via crafted space_id, thread_id, and message_id parameters to the v1/space/{space_id}/thread/{thread_id}/message/{message_id} endpoint.



- [https://github.com/Secsys-FDU/CVE-2025-51869](https://github.com/Secsys-FDU/CVE-2025-51869) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51869.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51869.svg)

## CVE-2025-51868
 Insecure Direct Object Reference (IDOR) vulnerability in Dippy (chat.dippy.ai) v2 allows attackers to gain sensitive information via the conversation_id parameter to the conversation_history endpoint.



- [https://github.com/Secsys-FDU/CVE-2025-51868](https://github.com/Secsys-FDU/CVE-2025-51868) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51868.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51868.svg)

## CVE-2025-51867
 Insecure Direct Object Reference (IDOR) vulnerability in Deepfiction AI (deepfiction.ai) thru June 3, 2025, allowing attackers to chat with the LLM using other users' credits via sensitive information gained by the /browse/stories endpoint.



- [https://github.com/Secsys-FDU/CVE-2025-51867](https://github.com/Secsys-FDU/CVE-2025-51867) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51867.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51867.svg)

## CVE-2025-51865
 Ai2 playground web service (playground.allenai.org) LLM chat through 2025-06-03 is vulnerable to Insecure Direct Object Reference (IDOR), allowing attackers to gain sensitvie information via enumerating thread keys in the URL.



- [https://github.com/Secsys-FDU/CVE-2025-51865](https://github.com/Secsys-FDU/CVE-2025-51865) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51865.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51865.svg)

## CVE-2025-51864
 A reflected cross-site scripting (XSS) vulnerability exists in AIBOX LLM chat (chat.aibox365.cn) through 2025-05-27, allowing attackers to hijack accounts through stolen JWT tokens.



- [https://github.com/Secsys-FDU/CVE-2025-51864](https://github.com/Secsys-FDU/CVE-2025-51864) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51864.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51864.svg)

## CVE-2025-51863
 Self Cross Site Scripting (XSS) vulnerability in ChatGPT Unli (ChatGPTUnli.com) thru 2025-05-26 allows attackers to execute arbitrary code via a crafted SVG file to the chat interface.



- [https://github.com/Secsys-FDU/CVE-2025-51863](https://github.com/Secsys-FDU/CVE-2025-51863) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51863.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51863.svg)

## CVE-2025-51862
 Insecure Direct Object Reference (IDOR) vulnerability in TelegAI (telegai.com) thru 2025-05-26 in its chat component. An attacker can exploit this IDOR to tamper other users' conversation. Additionally, malicious contents and XSS payloads can be injected, leading to phishing attack, user spoofing and account hijacking via XSS.



- [https://github.com/Secsys-FDU/CVE-2025-51862](https://github.com/Secsys-FDU/CVE-2025-51862) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51862.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51862.svg)

## CVE-2025-51860
 Stored Cross-Site Scripting (XSS) in TelegAI (telegai.com) 2025-05-26 in its chat component and character container component. An attacker can achieve arbitrary client-side script execution by crafting an AI Character with SVG XSS payloads in either description, greeting, example dialog, or system prompt(instructing the LLM to embed XSS payload in its chat response). When a user interacts with such a malicious AI Character or just browse its profile, the script executes in the user's browser. Successful exploitation can lead to the theft of sensitive information, such as session tokens, potentially resulting in account hijacking.



- [https://github.com/Secsys-FDU/CVE-2025-51860](https://github.com/Secsys-FDU/CVE-2025-51860) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51860.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51860.svg)

## CVE-2025-51859
 Stored Cross-Site Scripting (XSS) vulnerability in Chaindesk thru 2025-05-26 in its agent chat component. An attacker can achieve arbitrary client-side script execution by crafting an AI agent whose system prompt instructs the underlying Large Language Model (LLM) to embed malicious script payloads (e.g., SVG-based XSS) into its chat responses. When a user interacts with such a malicious agent or accesses a direct link to a conversation containing an XSS payload, the script executes in the user's browser. Successful exploitation can lead to the theft of sensitive information, such as JWT session tokens, potentially resulting in account hijacking.



- [https://github.com/Secsys-FDU/CVE-2025-51859](https://github.com/Secsys-FDU/CVE-2025-51859) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51859.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51859.svg)

## CVE-2025-51858
 Self Cross-Site Scripting (XSS) vulnerability in ChatPlayground.ai through 2025-05-24, allows attackers to execute arbitrary code and gain sensitive information via a crafted SVG file contents sent through the chat component.



- [https://github.com/Secsys-FDU/CVE-2025-51858](https://github.com/Secsys-FDU/CVE-2025-51858) :  ![starts](https://img.shields.io/github/stars/Secsys-FDU/CVE-2025-51858.svg) ![forks](https://img.shields.io/github/forks/Secsys-FDU/CVE-2025-51858.svg)

## CVE-2025-51726
 CyberGhostVPNSetup.exe (Windows installer) is signed using the weak cryptographic hash algorithm SHA-1, which is vulnerable to collision attacks. This allows a malicious actor to craft a fake installer with a forged SHA-1 certificate that may still be accepted by Windows signature verification mechanisms, particularly on systems without strict SmartScreen or trust policy enforcement. Additionally, the installer lacks High Entropy Address Space Layout Randomization (ASLR), as confirmed by BinSkim (BA2015 rule) and repeated WinDbg analysis. The binary consistently loads into predictable memory ranges, increasing the success rate of memory corruption exploits. These two misconfigurations, when combined, significantly lower the bar for successful supply-chain style attacks or privilege escalation through fake installers.



- [https://github.com/meisterlos/CVE-2025-51726](https://github.com/meisterlos/CVE-2025-51726) :  ![starts](https://img.shields.io/github/stars/meisterlos/CVE-2025-51726.svg) ![forks](https://img.shields.io/github/forks/meisterlos/CVE-2025-51726.svg)

## CVE-2025-51643
 Meitrack T366G-L GPS Tracker devices contain an SPI flash chip (Winbond 25Q64JVSIQ) that is accessible without authentication or tamper protection. An attacker with physical access to the device can use a standard SPI programmer to extract the firmware using flashrom. This results in exposure of sensitive configuration data such as APN credentials, backend server information, and network parameter



- [https://github.com/NastyCrow/CVE-2025-51643](https://github.com/NastyCrow/CVE-2025-51643) :  ![starts](https://img.shields.io/github/stars/NastyCrow/CVE-2025-51643.svg) ![forks](https://img.shields.io/github/forks/NastyCrow/CVE-2025-51643.svg)

## CVE-2025-51591
 A Server-Side Request Forgery (SSRF) in JGM Pandoc v3.6.4 allows attackers to gain access to and compromise the whole infrastructure via injecting a crafted iframe.



- [https://github.com/Malayke/CVE-2025-51591-Pandoc-SSRF-POC](https://github.com/Malayke/CVE-2025-51591-Pandoc-SSRF-POC) :  ![starts](https://img.shields.io/github/stars/Malayke/CVE-2025-51591-Pandoc-SSRF-POC.svg) ![forks](https://img.shields.io/github/forks/Malayke/CVE-2025-51591-Pandoc-SSRF-POC.svg)

## CVE-2025-51586
 An issue was discoverd in file controllers/admin/AdminLoginController.php in PrestaShop before 8.2.1 allowing attackers to gain sensitive information via the reset password feature.



- [https://github.com/7h30th3r0n3/CVE-2025-51586-PrestaShop-PoC](https://github.com/7h30th3r0n3/CVE-2025-51586-PrestaShop-PoC) :  ![starts](https://img.shields.io/github/stars/7h30th3r0n3/CVE-2025-51586-PrestaShop-PoC.svg) ![forks](https://img.shields.io/github/forks/7h30th3r0n3/CVE-2025-51586-PrestaShop-PoC.svg)

## CVE-2025-51529
 Incorrect Access Control in the AJAX endpoint functionality in jonkastonka Cookies and Content Security Policy plugin through version 2.29 allows remote attackers to cause a denial of service (database server resource exhaustion) via unlimited database write operations to the wp_ajax_nopriv_cacsp_insert_consent_data endpoint.



- [https://github.com/piotrmaciejbednarski/CVE-2025-51529](https://github.com/piotrmaciejbednarski/CVE-2025-51529) :  ![starts](https://img.shields.io/github/stars/piotrmaciejbednarski/CVE-2025-51529.svg) ![forks](https://img.shields.io/github/forks/piotrmaciejbednarski/CVE-2025-51529.svg)

## CVE-2025-51495
 An integer overflow vulnerability exists in the WebSocket component of Mongoose 7.5 thru 7.17. By sending a specially crafted WebSocket request, an attacker can cause the application to crash. If downstream vendors integrate this component improperly, the issue may lead to a buffer overflow.



- [https://github.com/cainiao159357/CVE-2025-51495](https://github.com/cainiao159357/CVE-2025-51495) :  ![starts](https://img.shields.io/github/stars/cainiao159357/CVE-2025-51495.svg) ![forks](https://img.shields.io/github/forks/cainiao159357/CVE-2025-51495.svg)

## CVE-2025-51482
 Remote Code Execution in letta.server.rest_api.routers.v1.tools.run_tool_from_source in letta-ai Letta 0.7.12 allows remote attackers to execute arbitrary Python code and system commands via crafted payloads to the /v1/tools/run endpoint, bypassing intended sandbox restrictions.



- [https://github.com/Kai-One001/Letta-CVE-2025-51482-RCE](https://github.com/Kai-One001/Letta-CVE-2025-51482-RCE) :  ![starts](https://img.shields.io/github/stars/Kai-One001/Letta-CVE-2025-51482-RCE.svg) ![forks](https://img.shields.io/github/forks/Kai-One001/Letta-CVE-2025-51482-RCE.svg)

## CVE-2025-51411
 A reflected cross-site scripting (XSS) vulnerability exists in Institute-of-Current-Students v1.0 via the email parameter in the /postquerypublic endpoint. The application fails to properly sanitize user input before reflecting it in the HTML response. This allows unauthenticated attackers to inject and execute arbitrary JavaScript code in the context of the victim's browser by tricking them into visiting a crafted URL or submitting a malicious form. Successful exploitation may lead to session hijacking, credential theft, or other client-side attacks.



- [https://github.com/tansique-17/CVE-2025-51411](https://github.com/tansique-17/CVE-2025-51411) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-51411.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-51411.svg)

## CVE-2025-51403
 A stored cross-site scripting (XSS) vulnerability in the department assignment editing module of of Live Helper Chat v4.60 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the Alias Nick parameter.



- [https://github.com/Thewhiteevil/CVE-2025-51403](https://github.com/Thewhiteevil/CVE-2025-51403) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51403.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51403.svg)

## CVE-2025-51401
 A stored cross-site scripting (XSS) vulnerability in the chat transfer function of Live Helper Chat v4.60 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the operator name parameter.



- [https://github.com/Thewhiteevil/CVE-2025-51401](https://github.com/Thewhiteevil/CVE-2025-51401) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51401.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51401.svg)

## CVE-2025-51400
 A stored cross-site scripting (XSS) vulnerability in the Personal Canned Messages of Live Helper Chat v4.60 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload.



- [https://github.com/Thewhiteevil/CVE-2025-51400](https://github.com/Thewhiteevil/CVE-2025-51400) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51400.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51400.svg)

## CVE-2025-51398
 A stored cross-site scripting (XSS) vulnerability in the Facebook registration page of Live Helper Chat v4.60 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the Name parameter.



- [https://github.com/Thewhiteevil/CVE-2025-51398](https://github.com/Thewhiteevil/CVE-2025-51398) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51398.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51398.svg)

## CVE-2025-51397
 A stored cross-site scripting (XSS) vulnerability in the Facebook Chat module of Live Helper Chat v4.60 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the Surname parameter under the Recipient' Lists.



- [https://github.com/Thewhiteevil/CVE-2025-51397](https://github.com/Thewhiteevil/CVE-2025-51397) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51397.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51397.svg)

## CVE-2025-51396
 A stored cross-site scripting (XSS) vulnerability in Live Helper Chat v4.60 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the Telegram Bot Username parameter.



- [https://github.com/Thewhiteevil/CVE-2025-51396](https://github.com/Thewhiteevil/CVE-2025-51396) :  ![starts](https://img.shields.io/github/stars/Thewhiteevil/CVE-2025-51396.svg) ![forks](https://img.shields.io/github/forks/Thewhiteevil/CVE-2025-51396.svg)

## CVE-2025-51385
 D-LINK DI-8200 16.07.26A1 is vulnerable to Buffer Overflow in the yyxz_dlink_asp function via the id parameter.



- [https://github.com/saarcastified/CVE-2023-51385---OpenSSH-ProxyCommand-Injection-PoC](https://github.com/saarcastified/CVE-2023-51385---OpenSSH-ProxyCommand-Injection-PoC) :  ![starts](https://img.shields.io/github/stars/saarcastified/CVE-2023-51385---OpenSSH-ProxyCommand-Injection-PoC.svg) ![forks](https://img.shields.io/github/forks/saarcastified/CVE-2023-51385---OpenSSH-ProxyCommand-Injection-PoC.svg)

## CVE-2025-51040
 Electrolink FM/DAB/TV Transmitter Web Management System Unauthorized access vulnerability via the /FrameSetCore.html endpoint in Electrolink 500W, 1kW, 2kW Medium DAB Transmitter Web v01.09, v01.08, v01.07, and Display v1.4, v1.2.



- [https://github.com/p0et08/Electrolink-FM-DAB-TV](https://github.com/p0et08/Electrolink-FM-DAB-TV) :  ![starts](https://img.shields.io/github/stars/p0et08/Electrolink-FM-DAB-TV.svg) ![forks](https://img.shields.io/github/forks/p0et08/Electrolink-FM-DAB-TV.svg)

## CVE-2025-51006
 Within tcpreplay's tcprewrite, a double free vulnerability has been identified in the dlt_linuxsll2_cleanup() function in plugins/dlt_linuxsll2/linuxsll2.c. This vulnerability is triggered when tcpedit_dlt_cleanup() indirectly invokes the cleanup routine multiple times on the same memory region. By supplying a specifically crafted pcap file to the tcprewrite binary, a local attacker can exploit this flaw to cause a Denial of Service (DoS) via memory corruption.



- [https://github.com/sy460129/CVE-2025-51006](https://github.com/sy460129/CVE-2025-51006) :  ![starts](https://img.shields.io/github/stars/sy460129/CVE-2025-51006.svg) ![forks](https://img.shields.io/github/forks/sy460129/CVE-2025-51006.svg)

## CVE-2025-51005
 A heap-buffer-overflow vulnerability exists in the tcpliveplay utility of the tcpreplay-4.5.1. When a crafted pcap file is processed, the program incorrectly handles memory in the checksum calculation logic at do_checksum_math_liveplay in tcpliveplay.c, leading to a possible denial of service.



- [https://github.com/sy460129/CVE-2025-51005](https://github.com/sy460129/CVE-2025-51005) :  ![starts](https://img.shields.io/github/stars/sy460129/CVE-2025-51005.svg) ![forks](https://img.shields.io/github/forks/sy460129/CVE-2025-51005.svg)

## CVE-2025-50944
 An issue was discovered in the method push.lite.avtech.com.MySSLSocketFactoryNew.checkServerTrusted in AVTECH EagleEyes 2.0.0. The custom X509TrustManager used in checkServerTrusted only checks the certificate's expiration date, skipping proper TLS chain validation.



- [https://github.com/shinyColumn/CVE-2025-50944](https://github.com/shinyColumn/CVE-2025-50944) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-50944.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-50944.svg)

## CVE-2025-50867
 A SQL Injection vulnerability exists in the takeassessment2.php endpoint of the CloudClassroom-PHP-Project 1.0, where the Q5 POST parameter is directly embedded in SQL statements without sanitization.



- [https://github.com/SacX-7/CVE-2025-50867](https://github.com/SacX-7/CVE-2025-50867) :  ![starts](https://img.shields.io/github/stars/SacX-7/CVE-2025-50867.svg) ![forks](https://img.shields.io/github/forks/SacX-7/CVE-2025-50867.svg)

## CVE-2025-50866
 CloudClassroom-PHP-Project 1.0 contains a reflected Cross-site Scripting (XSS) vulnerability in the email parameter of the postquerypublic endpoint. Improper sanitization allows an attacker to inject arbitrary JavaScript code that executes in the context of the user s browser, potentially leading to session hijacking or phishing attacks.



- [https://github.com/SacX-7/CVE-2025-50866](https://github.com/SacX-7/CVE-2025-50866) :  ![starts](https://img.shields.io/github/stars/SacX-7/CVE-2025-50866.svg) ![forks](https://img.shields.io/github/forks/SacX-7/CVE-2025-50866.svg)

## CVE-2025-50777
 The firmware of the AZIOT 2MP Full HD Smart Wi-Fi CCTV Home Security Camera (version V1.00.02) contains an Incorrect Access Control vulnerability that allows local attackers to gain root shell access. Once accessed, the device exposes critical data including Wi-Fi credentials and ONVIF service credentials stored in plaintext, enabling further compromise of the network and connected systems.



- [https://github.com/veereshgadige/aziot-cctv-cve-2025-50777](https://github.com/veereshgadige/aziot-cctv-cve-2025-50777) :  ![starts](https://img.shields.io/github/stars/veereshgadige/aziot-cctv-cve-2025-50777.svg) ![forks](https://img.shields.io/github/forks/veereshgadige/aziot-cctv-cve-2025-50777.svg)

## CVE-2025-50754
 Unisite CMS version 5.0 contains a stored Cross-Site Scripting (XSS) vulnerability in the "Report" functionality. A malicious script submitted by an attacker is rendered in the admin panel when viewed by an administrator. This allows attackers to hijack the admin session and, by leveraging the template editor, upload and execute a PHP web shell on the server, leading to full remote code execution.



- [https://github.com/furk4nyildiz/CVE-2025-50754-PoC](https://github.com/furk4nyildiz/CVE-2025-50754-PoC) :  ![starts](https://img.shields.io/github/stars/furk4nyildiz/CVE-2025-50754-PoC.svg) ![forks](https://img.shields.io/github/forks/furk4nyildiz/CVE-2025-50754-PoC.svg)

## CVE-2025-50675
 GPMAW 14, a bioinformatics software, has a critical vulnerability related to insecure file permissions in its installation directory. The directory is accessible with full read, write, and execute permissions for all users, allowing unprivileged users to manipulate files within the directory, including executable files like GPMAW3.exe, Fragment.exe, and the uninstaller GPsetup64_17028.exe. An attacker with user-level access can exploit this misconfiguration by replacing or modifying the uninstaller (GPsetup64_17028.exe) with a malicious version. While the application itself runs in the user's context, the uninstaller is typically executed with administrative privileges when an administrator attempts to uninstall the software. By exploiting this flaw, an attacker could gain administrative privileges and execute arbitrary code in the context of the admin, resulting in privilege escalation.



- [https://github.com/LukeSec/CVE-2025-50675-GPMAW-Permissions](https://github.com/LukeSec/CVE-2025-50675-GPMAW-Permissions) :  ![starts](https://img.shields.io/github/stars/LukeSec/CVE-2025-50675-GPMAW-Permissions.svg) ![forks](https://img.shields.io/github/forks/LukeSec/CVE-2025-50675-GPMAW-Permissions.svg)

## CVE-2025-50592
 Cross site scripting vulnerability in seacms before 13.2 via the vid parameter to Upload/js/player/dmplayer/player.



- [https://github.com/1515601525/CVE-2025-50592](https://github.com/1515601525/CVE-2025-50592) :  ![starts](https://img.shields.io/github/stars/1515601525/CVE-2025-50592.svg) ![forks](https://img.shields.io/github/forks/1515601525/CVE-2025-50592.svg)

## CVE-2025-50565
 Doubo ERP 1.0 has an SQL injection vulnerability due to a lack of filtering of user input, which can be remotely initiated by an attacker.



- [https://github.com/OoO7ce/CVE-2025-50565](https://github.com/OoO7ce/CVE-2025-50565) :  ![starts](https://img.shields.io/github/stars/OoO7ce/CVE-2025-50565.svg) ![forks](https://img.shields.io/github/forks/OoO7ce/CVE-2025-50565.svg)

## CVE-2025-50505
 Clash Verge Rev thru 2.2.3 forces the installation of system services(clash-verge-service) by default and exposes key functions through the unauthorized HTTP API `/start_clash`, allowing local users to submit arbitrary bin_path parameters and pass them directly to the service process for execution, resulting in local privilege escalation.



- [https://github.com/bron1e/CVE-2025-50505](https://github.com/bron1e/CVE-2025-50505) :  ![starts](https://img.shields.io/github/stars/bron1e/CVE-2025-50505.svg) ![forks](https://img.shields.io/github/forks/bron1e/CVE-2025-50505.svg)

## CVE-2025-50481
 A cross-site scripting (XSS) vulnerability in the component /blog/blogpost/add of Mezzanine CMS v6.1.0 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into a blog post.



- [https://github.com/kevinpdicks/Mezzanine-CMS-6.1.0-XSS](https://github.com/kevinpdicks/Mezzanine-CMS-6.1.0-XSS) :  ![starts](https://img.shields.io/github/stars/kevinpdicks/Mezzanine-CMS-6.1.0-XSS.svg) ![forks](https://img.shields.io/github/forks/kevinpdicks/Mezzanine-CMS-6.1.0-XSS.svg)

## CVE-2025-50472
 The modelscope/ms-swift library thru 2.6.1 is vulnerable to arbitrary code execution through deserialization of untrusted data within the `load_model_meta()` function of the `ModelFileSystemCache()` class. Attackers can execute arbitrary code and commands by crafting a malicious serialized `.mdl` payload, exploiting the use of `pickle.load()` on data from potentially untrusted sources. This vulnerability allows for remote code execution (RCE) by deceiving victims into loading a seemingly harmless checkpoint during a normal training process, thereby enabling attackers to execute arbitrary code on the targeted machine. Note that the payload file is a hidden file, making it difficult for the victim to detect tampering. More importantly, during the model training process, after the `.mdl` file is loaded and executes arbitrary code, the normal training process remains unaffected'meaning the user remains unaware of the arbitrary code execution.



- [https://github.com/xhjy2020/CVE-2025-50472](https://github.com/xhjy2020/CVE-2025-50472) :  ![starts](https://img.shields.io/github/stars/xhjy2020/CVE-2025-50472.svg) ![forks](https://img.shields.io/github/forks/xhjy2020/CVE-2025-50472.svg)

## CVE-2025-50461
 A deserialization vulnerability exists in Volcengine's verl 3.0.0, specifically in the scripts/model_merger.py script when using the "fsdp" backend. The script calls torch.load() with weights_only=False on user-supplied .pt files, allowing attackers to execute arbitrary code if a maliciously crafted model file is loaded. An attacker can exploit this by convincing a victim to download and place a malicious model file in a local directory with a specific filename pattern. This vulnerability may lead to arbitrary code execution with the privileges of the user running the script.



- [https://github.com/Anchor0221/CVE-2025-50461](https://github.com/Anchor0221/CVE-2025-50461) :  ![starts](https://img.shields.io/github/stars/Anchor0221/CVE-2025-50461.svg) ![forks](https://img.shields.io/github/forks/Anchor0221/CVE-2025-50461.svg)

## CVE-2025-50460
 A remote code execution (RCE) vulnerability exists in the ms-swift project version 3.3.0 due to unsafe deserialization in tests/run.py using yaml.load() from the PyYAML library (versions = 5.3.1). If an attacker can control the content of the YAML configuration file passed to the --run_config parameter, arbitrary code can be executed during deserialization. This can lead to full system compromise. The vulnerability is triggered when a malicious YAML file is loaded, allowing the execution of arbitrary Python commands such as os.system(). It is recommended to upgrade PyYAML to version 5.4 or higher, and to use yaml.safe_load() to mitigate the issue.



- [https://github.com/Anchor0221/CVE-2025-50460](https://github.com/Anchor0221/CVE-2025-50460) :  ![starts](https://img.shields.io/github/stars/Anchor0221/CVE-2025-50460.svg) ![forks](https://img.shields.io/github/forks/Anchor0221/CVE-2025-50460.svg)

## CVE-2025-50428
 In RaspAP raspap-webgui 3.3.2 and earlier, a command injection vulnerability exists in the includes/hostapd.php script. The vulnerability is due to improper sanitizing of user input passed via the interface parameter.



- [https://github.com/security-smarttecs/cve-2025-50428](https://github.com/security-smarttecs/cve-2025-50428) :  ![starts](https://img.shields.io/github/stars/security-smarttecs/cve-2025-50428.svg) ![forks](https://img.shields.io/github/forks/security-smarttecs/cve-2025-50428.svg)

## CVE-2025-50422
 Cairo through 1.18.4, as used in Poppler through 25.08.0, has an "unscaled-face == NULL" assertion failure for _cairo_ft_unscaled_font_fini in cairo-ft-font.c.



- [https://github.com/Landw-hub/CVE-2025-50422](https://github.com/Landw-hub/CVE-2025-50422) :  ![starts](https://img.shields.io/github/stars/Landw-hub/CVE-2025-50422.svg) ![forks](https://img.shields.io/github/forks/Landw-hub/CVE-2025-50422.svg)

## CVE-2025-50420
 An issue in the pdfseparate utility of freedesktop poppler v25.04.0 allows attackers to cause an infinite recursion via supplying a crafted PDF file. This can lead to a Denial of Service (DoS).



- [https://github.com/Landw-hub/CVE-2025-50420](https://github.com/Landw-hub/CVE-2025-50420) :  ![starts](https://img.shields.io/github/stars/Landw-hub/CVE-2025-50420.svg) ![forks](https://img.shields.io/github/forks/Landw-hub/CVE-2025-50420.svg)

## CVE-2025-50383
 alextselegidis Easy!Appointments v1.5.1 was discovered to contain a SQL injection vulnerability via the order_by parameter.



- [https://github.com/Abdullah4eb/CVE-2025-50383](https://github.com/Abdullah4eb/CVE-2025-50383) :  ![starts](https://img.shields.io/github/stars/Abdullah4eb/CVE-2025-50383.svg) ![forks](https://img.shields.io/github/forks/Abdullah4eb/CVE-2025-50383.svg)

## CVE-2025-50341
 A Boolean-based SQL injection vulnerability was discovered in Axelor 5.2.4 via the _domain parameter. An attacker can manipulate the SQL query logic and determine true/false conditions, potentially leading to data exposure or further exploitation.



- [https://github.com/millad7/Axelor-vulnerability-CVE-2025-50341](https://github.com/millad7/Axelor-vulnerability-CVE-2025-50341) :  ![starts](https://img.shields.io/github/stars/millad7/Axelor-vulnerability-CVE-2025-50341.svg) ![forks](https://img.shields.io/github/forks/millad7/Axelor-vulnerability-CVE-2025-50341.svg)

## CVE-2025-50340
 An Insecure Direct Object Reference (IDOR) vulnerability was discovered in SOGo Webmail thru 5.6.0, allowing an authenticated user to send emails on behalf of other users by manipulating a user-controlled identifier in the email-sending request. The server fails to verify whether the authenticated user is authorized to use the specified sender identity, resulting in unauthorized message delivery as another user. This can lead to impersonation, phishing, or unauthorized communication within the system. NOTE: this is disputed by the Supplier because the only effective way to prevent this sender spoofing is on the SMTP server, not within a client such as SOGo.



- [https://github.com/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340](https://github.com/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340) :  ![starts](https://img.shields.io/github/stars/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340.svg) ![forks](https://img.shields.io/github/forks/millad7/SOGo_web_mail-vulnerability-CVE-2025-50340.svg)

## CVE-2025-50286
 A Remote Code Execution (RCE) vulnerability in Grav CMS v1.7.48 allows an authenticated admin to upload a malicious plugin via the /admin/tools/direct-install interface. Once uploaded, the plugin is automatically extracted and loaded, allowing arbitrary PHP code execution and reverse shell access.



- [https://github.com/binneko/CVE-2025-50286](https://github.com/binneko/CVE-2025-50286) :  ![starts](https://img.shields.io/github/stars/binneko/CVE-2025-50286.svg) ![forks](https://img.shields.io/github/forks/binneko/CVE-2025-50286.svg)

## CVE-2025-50154
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.



- [https://github.com/rubenformation/CVE-2025-50154](https://github.com/rubenformation/CVE-2025-50154) :  ![starts](https://img.shields.io/github/stars/rubenformation/CVE-2025-50154.svg) ![forks](https://img.shields.io/github/forks/rubenformation/CVE-2025-50154.svg)

- [https://github.com/zenzue/CVE-2025-50154](https://github.com/zenzue/CVE-2025-50154) :  ![starts](https://img.shields.io/github/stars/zenzue/CVE-2025-50154.svg) ![forks](https://img.shields.io/github/forks/zenzue/CVE-2025-50154.svg)

- [https://github.com/Ash1996x/CVE-2025-50154-Aggressor-Script](https://github.com/Ash1996x/CVE-2025-50154-Aggressor-Script) :  ![starts](https://img.shields.io/github/stars/Ash1996x/CVE-2025-50154-Aggressor-Script.svg) ![forks](https://img.shields.io/github/forks/Ash1996x/CVE-2025-50154-Aggressor-Script.svg)

## CVE-2025-50110
 An issue was discovered in the method push.lite.avtech.com.AvtechLib.GetHttpsResponse in AVTECH EagleEyes Lite 2.0.0, the GetHttpsResponse method transmits sensitive information - including internal server URLs, account IDs, passwords, and device tokens - as plaintext query parameters over HTTPS



- [https://github.com/shinyColumn/CVE-2025-50110](https://github.com/shinyColumn/CVE-2025-50110) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-50110.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-50110.svg)

## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.



- [https://github.com/raminfp/redis_exploit](https://github.com/raminfp/redis_exploit) :  ![starts](https://img.shields.io/github/stars/raminfp/redis_exploit.svg) ![forks](https://img.shields.io/github/forks/raminfp/redis_exploit.svg)

- [https://github.com/dwisiswant0/CVE-2025-49844](https://github.com/dwisiswant0/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/CVE-2025-49844.svg)

- [https://github.com/Yuri08loveElaina/CVE-2025-49844](https://github.com/Yuri08loveElaina/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-49844.svg)

- [https://github.com/lastvocher/redis-CVE-2025-49844](https://github.com/lastvocher/redis-CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/lastvocher/redis-CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/lastvocher/redis-CVE-2025-49844.svg)

- [https://github.com/pedrorichil/CVE-2025-49844](https://github.com/pedrorichil/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/pedrorichil/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/pedrorichil/CVE-2025-49844.svg)

- [https://github.com/saneki/cve-2025-49844](https://github.com/saneki/cve-2025-49844) :  ![starts](https://img.shields.io/github/stars/saneki/cve-2025-49844.svg) ![forks](https://img.shields.io/github/forks/saneki/cve-2025-49844.svg)

- [https://github.com/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner](https://github.com/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner) :  ![starts](https://img.shields.io/github/stars/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner.svg) ![forks](https://img.shields.io/github/forks/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner.svg)

- [https://github.com/MiclelsonCN/CVE-2025-49844_POC](https://github.com/MiclelsonCN/CVE-2025-49844_POC) :  ![starts](https://img.shields.io/github/stars/MiclelsonCN/CVE-2025-49844_POC.svg) ![forks](https://img.shields.io/github/forks/MiclelsonCN/CVE-2025-49844_POC.svg)

- [https://github.com/angelusrivera/CVE-2025-49844](https://github.com/angelusrivera/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/angelusrivera/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/angelusrivera/CVE-2025-49844.svg)

- [https://github.com/srozb/reditrap](https://github.com/srozb/reditrap) :  ![starts](https://img.shields.io/github/stars/srozb/reditrap.svg) ![forks](https://img.shields.io/github/forks/srozb/reditrap.svg)

- [https://github.com/ksnnd32/redis_exploit](https://github.com/ksnnd32/redis_exploit) :  ![starts](https://img.shields.io/github/stars/ksnnd32/redis_exploit.svg) ![forks](https://img.shields.io/github/forks/ksnnd32/redis_exploit.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-49844](https://github.com/B1ack4sh/Blackash-CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-49844.svg)

- [https://github.com/elyasbassir/CVE-2025-49844](https://github.com/elyasbassir/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/elyasbassir/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/elyasbassir/CVE-2025-49844.svg)

- [https://github.com/Zain3311/CVE-2025-49844](https://github.com/Zain3311/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/Zain3311/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/Zain3311/CVE-2025-49844.svg)

- [https://github.com/gopinaath/CVE-2025-49844-discovery](https://github.com/gopinaath/CVE-2025-49844-discovery) :  ![starts](https://img.shields.io/github/stars/gopinaath/CVE-2025-49844-discovery.svg) ![forks](https://img.shields.io/github/forks/gopinaath/CVE-2025-49844-discovery.svg)

- [https://github.com/imbas007/CVE-2025-49844-Vulnerability-Scanner](https://github.com/imbas007/CVE-2025-49844-Vulnerability-Scanner) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-49844-Vulnerability-Scanner.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-49844-Vulnerability-Scanner.svg)

## CVE-2025-49706
 Improper authentication in Microsoft Office SharePoint allows an unauthorized attacker to perform spoofing over a network.



- [https://github.com/AdityaBhatt3010/CVE-2025-49706-SharePoint-Spoofing-Vulnerability-Under-Active-Exploitation](https://github.com/AdityaBhatt3010/CVE-2025-49706-SharePoint-Spoofing-Vulnerability-Under-Active-Exploitation) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-49706-SharePoint-Spoofing-Vulnerability-Under-Active-Exploitation.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-49706-SharePoint-Spoofing-Vulnerability-Under-Active-Exploitation.svg)

- [https://github.com/AdityaBhatt3010/CVE-2025-53770-SharePoint-Zero-Day-Variant-Exploited-for-Full-RCE](https://github.com/AdityaBhatt3010/CVE-2025-53770-SharePoint-Zero-Day-Variant-Exploited-for-Full-RCE) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-53770-SharePoint-Zero-Day-Variant-Exploited-for-Full-RCE.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-53770-SharePoint-Zero-Day-Variant-Exploited-for-Full-RCE.svg)

- [https://github.com/RukshanaAlikhan/CVE-2025-53770](https://github.com/RukshanaAlikhan/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/RukshanaAlikhan/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/RukshanaAlikhan/CVE-2025-53770.svg)

- [https://github.com/fentnttntnt/CVE-2025-53770](https://github.com/fentnttntnt/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/fentnttntnt/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/fentnttntnt/CVE-2025-53770.svg)

## CVE-2025-49667
 Double free in Windows Win32K - ICOMP allows an authorized attacker to elevate privileges locally.



- [https://github.com/Yuri08loveElaina/CVE-2025-49667](https://github.com/Yuri08loveElaina/CVE-2025-49667) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-49667.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-49667.svg)

## CVE-2025-49619
 Skyvern through 0.1.85 is vulnerable to server-side template injection (SSTI) in the Prompt field of workflow blocks such as the Navigation v2 Block. Improper sanitization of Jinja2 template input allows authenticated users to inject crafted expressions that are evaluated on the server, leading to blind remote code execution (RCE).



- [https://github.com/cristibtz/CVE-2025-49619](https://github.com/cristibtz/CVE-2025-49619) :  ![starts](https://img.shields.io/github/stars/cristibtz/CVE-2025-49619.svg) ![forks](https://img.shields.io/github/forks/cristibtz/CVE-2025-49619.svg)

## CVE-2025-49596
 The MCP inspector is a developer tool for testing and debugging MCP servers. Versions of MCP Inspector below 0.14.1 are vulnerable to remote code execution due to lack of authentication between the Inspector client and proxy, allowing unauthenticated requests to launch MCP commands over stdio. Users should immediately upgrade to version 0.14.1 or later to address these vulnerabilities.



- [https://github.com/ashiqrehan-21/MCP-Inspector-CVE-2025-49596](https://github.com/ashiqrehan-21/MCP-Inspector-CVE-2025-49596) :  ![starts](https://img.shields.io/github/stars/ashiqrehan-21/MCP-Inspector-CVE-2025-49596.svg) ![forks](https://img.shields.io/github/forks/ashiqrehan-21/MCP-Inspector-CVE-2025-49596.svg)

## CVE-2025-49553
 Adobe Connect versions 12.9 and earlier are affected by a DOM-based Cross-Site Scripting (XSS) vulnerability that could be exploited by an attacker to execute malicious scripts in a victim's browser. Exploitation of this issue requires user interaction in that a victim must navigate to a crafted web page. A successful attacker can abuse this to achieve session takeover, increasing the confidentiality and integrity impact as high. Scope is changed.



- [https://github.com/glitchhawks/CVE-2025-49553](https://github.com/glitchhawks/CVE-2025-49553) :  ![starts](https://img.shields.io/github/stars/glitchhawks/CVE-2025-49553.svg) ![forks](https://img.shields.io/github/forks/glitchhawks/CVE-2025-49553.svg)

- [https://github.com/silentexploitexe/CVE-2025-49553](https://github.com/silentexploitexe/CVE-2025-49553) :  ![starts](https://img.shields.io/github/stars/silentexploitexe/CVE-2025-49553.svg) ![forks](https://img.shields.io/github/forks/silentexploitexe/CVE-2025-49553.svg)

## CVE-2025-49493
 Akamai CloudTest before 60 2025.06.02 (12988) allows file inclusion via XML External Entity (XXE) injection.



- [https://github.com/SystemVll/CVE-2025-49493](https://github.com/SystemVll/CVE-2025-49493) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2025-49493.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2025-49493.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-49493](https://github.com/B1ack4sh/Blackash-CVE-2025-49493) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-49493.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-49493.svg)

- [https://github.com/Soham-id/2025hvv](https://github.com/Soham-id/2025hvv) :  ![starts](https://img.shields.io/github/stars/Soham-id/2025hvv.svg) ![forks](https://img.shields.io/github/forks/Soham-id/2025hvv.svg)

## CVE-2025-49388
 Incorrect Privilege Assignment vulnerability in kamleshyadav Miraculous Core Plugin allows Privilege Escalation. This issue affects Miraculous Core Plugin: from n/a through 2.0.7.



- [https://github.com/Nxploited/CVE-2025-49388](https://github.com/Nxploited/CVE-2025-49388) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-49388.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-49388.svg)

## CVE-2025-49223
 billboard.js before 3.15.1 was discovered to contain a prototype pollution via the function generate, which could allow attackers to execute arbitrary code or cause a Denial of Service (DoS) via injecting arbitrary properties.



- [https://github.com/louay-075/CVE-2025-49223-BillboardJS-PoC](https://github.com/louay-075/CVE-2025-49223-BillboardJS-PoC) :  ![starts](https://img.shields.io/github/stars/louay-075/CVE-2025-49223-BillboardJS-PoC.svg) ![forks](https://img.shields.io/github/forks/louay-075/CVE-2025-49223-BillboardJS-PoC.svg)

## CVE-2025-49203
 Not used



- [https://github.com/ImTheCopilotNow/CVE-2025-492030](https://github.com/ImTheCopilotNow/CVE-2025-492030) :  ![starts](https://img.shields.io/github/stars/ImTheCopilotNow/CVE-2025-492030.svg) ![forks](https://img.shields.io/github/forks/ImTheCopilotNow/CVE-2025-492030.svg)

## CVE-2025-49202
 Not used



- [https://github.com/ImTheCopilotNow/CVE-2025-492026](https://github.com/ImTheCopilotNow/CVE-2025-492026) :  ![starts](https://img.shields.io/github/stars/ImTheCopilotNow/CVE-2025-492026.svg) ![forks](https://img.shields.io/github/forks/ImTheCopilotNow/CVE-2025-492026.svg)

- [https://github.com/ImTheCopilotNow/CVE-2025-492025](https://github.com/ImTheCopilotNow/CVE-2025-492025) :  ![starts](https://img.shields.io/github/stars/ImTheCopilotNow/CVE-2025-492025.svg) ![forks](https://img.shields.io/github/forks/ImTheCopilotNow/CVE-2025-492025.svg)

## CVE-2025-49144
 Notepad++ is a free and open-source source code editor. In versions 8.8.1 and prior, a privilege escalation vulnerability exists in the Notepad++ v8.8.1 installer that allows unprivileged users to gain SYSTEM-level privileges through insecure executable search paths. An attacker could use social engineering or clickjacking to trick users into downloading both the legitimate installer and a malicious executable to the same directory (typically Downloads folder - which is known as Vulnerable directory). Upon running the installer, the attack executes automatically with SYSTEM privileges. This issue has been fixed and will be released in version 8.8.2.



- [https://github.com/TheTorjanCaptain/CVE-2025-49144_PoC](https://github.com/TheTorjanCaptain/CVE-2025-49144_PoC) :  ![starts](https://img.shields.io/github/stars/TheTorjanCaptain/CVE-2025-49144_PoC.svg) ![forks](https://img.shields.io/github/forks/TheTorjanCaptain/CVE-2025-49144_PoC.svg)

- [https://github.com/b0ySie7e/Notepad-8.8.1_CVE-2025-49144](https://github.com/b0ySie7e/Notepad-8.8.1_CVE-2025-49144) :  ![starts](https://img.shields.io/github/stars/b0ySie7e/Notepad-8.8.1_CVE-2025-49144.svg) ![forks](https://img.shields.io/github/forks/b0ySie7e/Notepad-8.8.1_CVE-2025-49144.svg)

- [https://github.com/Vr00mm/CVE-2025-49144](https://github.com/Vr00mm/CVE-2025-49144) :  ![starts](https://img.shields.io/github/stars/Vr00mm/CVE-2025-49144.svg) ![forks](https://img.shields.io/github/forks/Vr00mm/CVE-2025-49144.svg)

- [https://github.com/0xCZR1/cve-2025-49144](https://github.com/0xCZR1/cve-2025-49144) :  ![starts](https://img.shields.io/github/stars/0xCZR1/cve-2025-49144.svg) ![forks](https://img.shields.io/github/forks/0xCZR1/cve-2025-49144.svg)

- [https://github.com/onniio/CVE-2025-49144](https://github.com/onniio/CVE-2025-49144) :  ![starts](https://img.shields.io/github/stars/onniio/CVE-2025-49144.svg) ![forks](https://img.shields.io/github/forks/onniio/CVE-2025-49144.svg)

- [https://github.com/timsonner/CVE-2025-49144-Research](https://github.com/timsonner/CVE-2025-49144-Research) :  ![starts](https://img.shields.io/github/stars/timsonner/CVE-2025-49144-Research.svg) ![forks](https://img.shields.io/github/forks/timsonner/CVE-2025-49144-Research.svg)

- [https://github.com/ammarm0010/CVE-2025-49144_PoC](https://github.com/ammarm0010/CVE-2025-49144_PoC) :  ![starts](https://img.shields.io/github/stars/ammarm0010/CVE-2025-49144_PoC.svg) ![forks](https://img.shields.io/github/forks/ammarm0010/CVE-2025-49144_PoC.svg)

- [https://github.com/assad12341/notepad-v8.8.1-LPE-CVE-](https://github.com/assad12341/notepad-v8.8.1-LPE-CVE-) :  ![starts](https://img.shields.io/github/stars/assad12341/notepad-v8.8.1-LPE-CVE-.svg) ![forks](https://img.shields.io/github/forks/assad12341/notepad-v8.8.1-LPE-CVE-.svg)

## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.



- [https://github.com/Zen-kun04/CVE-2025-49132](https://github.com/Zen-kun04/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/Zen-kun04/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/Zen-kun04/CVE-2025-49132.svg)

- [https://github.com/qiaojojo/CVE-2025-49132_poc](https://github.com/qiaojojo/CVE-2025-49132_poc) :  ![starts](https://img.shields.io/github/stars/qiaojojo/CVE-2025-49132_poc.svg) ![forks](https://img.shields.io/github/forks/qiaojojo/CVE-2025-49132_poc.svg)

- [https://github.com/63square/CVE-2025-49132](https://github.com/63square/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/63square/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/63square/CVE-2025-49132.svg)

- [https://github.com/pxxdrobits/CVE-2025-49132](https://github.com/pxxdrobits/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/pxxdrobits/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/pxxdrobits/CVE-2025-49132.svg)

- [https://github.com/0xtensho/CVE-2025-49132-poc](https://github.com/0xtensho/CVE-2025-49132-poc) :  ![starts](https://img.shields.io/github/stars/0xtensho/CVE-2025-49132-poc.svg) ![forks](https://img.shields.io/github/forks/0xtensho/CVE-2025-49132-poc.svg)

- [https://github.com/WebSafety-2tina/CVE-2025-49132](https://github.com/WebSafety-2tina/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/WebSafety-2tina/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/WebSafety-2tina/CVE-2025-49132.svg)

- [https://github.com/melonlonmeo/CVE-2025-49132](https://github.com/melonlonmeo/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/melonlonmeo/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/melonlonmeo/CVE-2025-49132.svg)

- [https://github.com/GRodolphe/CVE-2025-49132_poc](https://github.com/GRodolphe/CVE-2025-49132_poc) :  ![starts](https://img.shields.io/github/stars/GRodolphe/CVE-2025-49132_poc.svg) ![forks](https://img.shields.io/github/forks/GRodolphe/CVE-2025-49132_poc.svg)

- [https://github.com/typicalsmc/CVE-2025-49132-PoC](https://github.com/typicalsmc/CVE-2025-49132-PoC) :  ![starts](https://img.shields.io/github/stars/typicalsmc/CVE-2025-49132-PoC.svg) ![forks](https://img.shields.io/github/forks/typicalsmc/CVE-2025-49132-PoC.svg)

## CVE-2025-49125
 Authentication Bypass Using an Alternate Path or Channel vulnerability in Apache Tomcat.  When using PreResources or PostResources mounted other than at the root of the web application, it was possible to access those resources via an unexpected path. That path was likely not to be protected by the same security constraints as the expected path, allowing those security constraints to be bypassed.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.7, from 10.1.0-M1 through 10.1.41, from 9.0.0.M1 through 9.0.105.
The following versions were EOL at the time the CVE was created but are 
known to be affected: 8.5.0 through 8.5.100. Other, older, EOL versions 
may also be affected.


Users are recommended to upgrade to version 11.0.8, 10.1.42 or 9.0.106, which fix the issue.



- [https://github.com/gregk4sec/CVE-2025-49125](https://github.com/gregk4sec/CVE-2025-49125) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-49125.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-49125.svg)

## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.



- [https://github.com/fearsoff-org/CVE-2025-49113](https://github.com/fearsoff-org/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/fearsoff-org/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/fearsoff-org/CVE-2025-49113.svg)

- [https://github.com/hakaioffsec/CVE-2025-49113-exploit](https://github.com/hakaioffsec/CVE-2025-49113-exploit) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2025-49113-exploit.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2025-49113-exploit.svg)

- [https://github.com/00xCanelo/CVE-2025-49113](https://github.com/00xCanelo/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/00xCanelo/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/00xCanelo/CVE-2025-49113.svg)

- [https://github.com/BiiTts/Roundcube-CVE-2025-49113](https://github.com/BiiTts/Roundcube-CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/BiiTts/Roundcube-CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/BiiTts/Roundcube-CVE-2025-49113.svg)

- [https://github.com/rxerium/CVE-2025-49113](https://github.com/rxerium/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-49113.svg)

- [https://github.com/issamjr/CVE-2025-49113-Scanner](https://github.com/issamjr/CVE-2025-49113-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-49113-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-49113-Scanner.svg)

- [https://github.com/rasool13x/exploit-CVE-2025-49113](https://github.com/rasool13x/exploit-CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/rasool13x/exploit-CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/rasool13x/exploit-CVE-2025-49113.svg)

- [https://github.com/SyFi/CVE-2025-49113](https://github.com/SyFi/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/SyFi/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/SyFi/CVE-2025-49113.svg)

- [https://github.com/Ademking/CVE-2025-49113-nuclei-template](https://github.com/Ademking/CVE-2025-49113-nuclei-template) :  ![starts](https://img.shields.io/github/stars/Ademking/CVE-2025-49113-nuclei-template.svg) ![forks](https://img.shields.io/github/forks/Ademking/CVE-2025-49113-nuclei-template.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-49113](https://github.com/B1ack4sh/Blackash-CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-49113.svg)

- [https://github.com/Yuri08loveElaina/CVE-2025-49113](https://github.com/Yuri08loveElaina/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-49113.svg)

- [https://github.com/Joelp03/CVE-2025-49113](https://github.com/Joelp03/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/Joelp03/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/Joelp03/CVE-2025-49113.svg)

- [https://github.com/l4f2s4/CVE-2025-49113_exploit_cookies](https://github.com/l4f2s4/CVE-2025-49113_exploit_cookies) :  ![starts](https://img.shields.io/github/stars/l4f2s4/CVE-2025-49113_exploit_cookies.svg) ![forks](https://img.shields.io/github/forks/l4f2s4/CVE-2025-49113_exploit_cookies.svg)

- [https://github.com/Zwique/CVE-2025-49113](https://github.com/Zwique/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/Zwique/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/Zwique/CVE-2025-49113.svg)

- [https://github.com/AC8999/CVE-2025-49113](https://github.com/AC8999/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/AC8999/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/AC8999/CVE-2025-49113.svg)

- [https://github.com/hackmelocal/CVE-2025-49113-Simulation](https://github.com/hackmelocal/CVE-2025-49113-Simulation) :  ![starts](https://img.shields.io/github/stars/hackmelocal/CVE-2025-49113-Simulation.svg) ![forks](https://img.shields.io/github/forks/hackmelocal/CVE-2025-49113-Simulation.svg)

- [https://github.com/LeakForge/CVE-2025-49113](https://github.com/LeakForge/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/LeakForge/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/LeakForge/CVE-2025-49113.svg)

- [https://github.com/5kr1pt/Roundcube_CVE-2025-49113](https://github.com/5kr1pt/Roundcube_CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/5kr1pt/Roundcube_CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/5kr1pt/Roundcube_CVE-2025-49113.svg)

- [https://github.com/punitdarji/roundcube-cve-2025-49113](https://github.com/punitdarji/roundcube-cve-2025-49113) :  ![starts](https://img.shields.io/github/stars/punitdarji/roundcube-cve-2025-49113.svg) ![forks](https://img.shields.io/github/forks/punitdarji/roundcube-cve-2025-49113.svg)

- [https://github.com/SteamPunk424/CVE-2025-49113-Roundcube-RCE-PHP](https://github.com/SteamPunk424/CVE-2025-49113-Roundcube-RCE-PHP) :  ![starts](https://img.shields.io/github/stars/SteamPunk424/CVE-2025-49113-Roundcube-RCE-PHP.svg) ![forks](https://img.shields.io/github/forks/SteamPunk424/CVE-2025-49113-Roundcube-RCE-PHP.svg)

- [https://github.com/CyberQuestor-infosec/CVE-2025-49113-Roundcube_1.6.10](https://github.com/CyberQuestor-infosec/CVE-2025-49113-Roundcube_1.6.10) :  ![starts](https://img.shields.io/github/stars/CyberQuestor-infosec/CVE-2025-49113-Roundcube_1.6.10.svg) ![forks](https://img.shields.io/github/forks/CyberQuestor-infosec/CVE-2025-49113-Roundcube_1.6.10.svg)

- [https://github.com/Zuack55/Roundcube-1.6.10-Post-Auth-RCE-CVE-2025-49113-](https://github.com/Zuack55/Roundcube-1.6.10-Post-Auth-RCE-CVE-2025-49113-) :  ![starts](https://img.shields.io/github/stars/Zuack55/Roundcube-1.6.10-Post-Auth-RCE-CVE-2025-49113-.svg) ![forks](https://img.shields.io/github/forks/Zuack55/Roundcube-1.6.10-Post-Auth-RCE-CVE-2025-49113-.svg)

## CVE-2025-49029
 Improper Control of Generation of Code ('Code Injection') vulnerability in bitto.Kazi Custom Login And Signup Widget allows Code Injection.This issue affects Custom Login And Signup Widget: from n/a through 1.0.



- [https://github.com/Nxploited/CVE-2025-49029](https://github.com/Nxploited/CVE-2025-49029) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-49029.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-49029.svg)

## CVE-2025-49002
 DataEase is an open source business intelligence and data visualization tool. Versions prior to version 2.10.10 have a flaw in the patch for CVE-2025-32966 that allow the patch to be bypassed through case insensitivity because INIT and RUNSCRIPT are prohibited. The vulnerability has been fixed in v2.10.10. No known workarounds are available.



- [https://github.com/jiuzui129-arch/CVE-2025-49002](https://github.com/jiuzui129-arch/CVE-2025-49002) :  ![starts](https://img.shields.io/github/stars/jiuzui129-arch/CVE-2025-49002.svg) ![forks](https://img.shields.io/github/forks/jiuzui129-arch/CVE-2025-49002.svg)

- [https://github.com/Feng-Huang-0520/DataEase_Postgresql_JDBC_Bypass-CVE-2025-49002](https://github.com/Feng-Huang-0520/DataEase_Postgresql_JDBC_Bypass-CVE-2025-49002) :  ![starts](https://img.shields.io/github/stars/Feng-Huang-0520/DataEase_Postgresql_JDBC_Bypass-CVE-2025-49002.svg) ![forks](https://img.shields.io/github/forks/Feng-Huang-0520/DataEase_Postgresql_JDBC_Bypass-CVE-2025-49002.svg)

## CVE-2025-48988
 Allocation of Resources Without Limits or Throttling vulnerability in Apache Tomcat.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.7, from 10.1.0-M1 through 10.1.41, from 9.0.0.M1 through 9.0.105.
The following versions were EOL at the time the CVE was created but are 
known to be affected: 8.5.0 though 8.5.100. Other, older, EOL versions 
may also be affected.


Users are recommended to upgrade to version 11.0.8, 10.1.42 or 9.0.106, which fix the issue.



- [https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988](https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988) :  ![starts](https://img.shields.io/github/stars/nankuo/CVE-2025-48976_CVE-2025-48988.svg) ![forks](https://img.shields.io/github/forks/nankuo/CVE-2025-48976_CVE-2025-48988.svg)

- [https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976](https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976) :  ![starts](https://img.shields.io/github/stars/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg) ![forks](https://img.shields.io/github/forks/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg)

## CVE-2025-48976
 Allocation of resources for multipart headers with insufficient limits enabled a DoS vulnerability in Apache Commons FileUpload.

This issue affects Apache Commons FileUpload: from 1.0 before 1.6; from 2.0.0-M1 before 2.0.0-M4.

Users are recommended to upgrade to versions 1.6 or 2.0.0-M4, which fix the issue.



- [https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988](https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988) :  ![starts](https://img.shields.io/github/stars/nankuo/CVE-2025-48976_CVE-2025-48988.svg) ![forks](https://img.shields.io/github/forks/nankuo/CVE-2025-48976_CVE-2025-48988.svg)

- [https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976](https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976) :  ![starts](https://img.shields.io/github/stars/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg) ![forks](https://img.shields.io/github/forks/Samb102/POC-CVE-2025-48988-CVE-2025-48976.svg)

## CVE-2025-48924
 Uncontrolled Recursion vulnerability in Apache Commons Lang.

This issue affects Apache Commons Lang: Starting with commons-lang:commons-lang 2.0 to 2.6, and, from org.apache.commons:commons-lang3 3.0 before 3.18.0.

The methods ClassUtils.getClass(...) can throw StackOverflowError on very long inputs. Because an Error is usually not handled by applications and libraries, a 
StackOverflowError could cause an application to stop.

Users are recommended to upgrade to version 3.18.0, which fixes the issue.



- [https://github.com/njawalkar/apache-commons-lang2](https://github.com/njawalkar/apache-commons-lang2) :  ![starts](https://img.shields.io/github/stars/njawalkar/apache-commons-lang2.svg) ![forks](https://img.shields.io/github/forks/njawalkar/apache-commons-lang2.svg)

## CVE-2025-48828
 Certain vBulletin versions might allow attackers to execute arbitrary PHP code by abusing Template Conditionals in the template engine. By crafting template code in an alternative PHP function invocation syntax, such as the "var_dump"("test") syntax, attackers can bypass security checks and execute arbitrary PHP code, as exploited in the wild in May 2025.



- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance](https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg)

- [https://github.com/ill-deed/vBulletin-CVE-2025-48828-Multi-target](https://github.com/ill-deed/vBulletin-CVE-2025-48828-Multi-target) :  ![starts](https://img.shields.io/github/stars/ill-deed/vBulletin-CVE-2025-48828-Multi-target.svg) ![forks](https://img.shields.io/github/forks/ill-deed/vBulletin-CVE-2025-48828-Multi-target.svg)

## CVE-2025-48827
 vBulletin 5.0.0 through 5.7.5 and 6.0.0 through 6.0.3 allows unauthenticated users to invoke protected API controllers' methods when running on PHP 8.1 or later, as demonstrated by the /api.php?method=protectedMethod pattern, as exploited in the wild in May 2025.



- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance](https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-48827](https://github.com/0xgh057r3c0n/CVE-2025-48827) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-48827.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-48827.svg)

- [https://github.com/SystemVll/CVE-2025-48827](https://github.com/SystemVll/CVE-2025-48827) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2025-48827.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2025-48827.svg)

- [https://github.com/wiseep/CVE-2025-48827](https://github.com/wiseep/CVE-2025-48827) :  ![starts](https://img.shields.io/github/stars/wiseep/CVE-2025-48827.svg) ![forks](https://img.shields.io/github/forks/wiseep/CVE-2025-48827.svg)

## CVE-2025-48799
 Improper link resolution before file access ('link following') in Windows Update Service allows an authorized attacker to elevate privileges locally.



- [https://github.com/Wh04m1001/CVE-2025-48799](https://github.com/Wh04m1001/CVE-2025-48799) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/CVE-2025-48799.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/CVE-2025-48799.svg)

- [https://github.com/painoob/CVE-2025-48799](https://github.com/painoob/CVE-2025-48799) :  ![starts](https://img.shields.io/github/stars/painoob/CVE-2025-48799.svg) ![forks](https://img.shields.io/github/forks/painoob/CVE-2025-48799.svg)

- [https://github.com/gmh5225/CVE-2025-48799-](https://github.com/gmh5225/CVE-2025-48799-) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2025-48799-.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2025-48799-.svg)

## CVE-2025-48708
 gs_lib_ctx_stash_sanitized_arg in base/gslibctx.c in Artifex Ghostscript before 10.05.1 lacks argument sanitization for the # case. A created PDF document includes its password in cleartext.



- [https://github.com/B1tBreaker/CVE-2025-48708](https://github.com/B1tBreaker/CVE-2025-48708) :  ![starts](https://img.shields.io/github/stars/B1tBreaker/CVE-2025-48708.svg) ![forks](https://img.shields.io/github/forks/B1tBreaker/CVE-2025-48708.svg)

## CVE-2025-48703
 CWP (aka Control Web Panel or CentOS Web Panel) before 0.9.8.1205 allows unauthenticated remote code execution via shell metacharacters in the t_total parameter in a filemanager changePerm request. A valid non-root username must be known.



- [https://github.com/Skynoxk/CVE-2025-48703](https://github.com/Skynoxk/CVE-2025-48703) :  ![starts](https://img.shields.io/github/stars/Skynoxk/CVE-2025-48703.svg) ![forks](https://img.shields.io/github/forks/Skynoxk/CVE-2025-48703.svg)

- [https://github.com/itstarsec/CVE-2025-48703](https://github.com/itstarsec/CVE-2025-48703) :  ![starts](https://img.shields.io/github/stars/itstarsec/CVE-2025-48703.svg) ![forks](https://img.shields.io/github/forks/itstarsec/CVE-2025-48703.svg)

## CVE-2025-48561
 In multiple locations, there is a possible way to access data displayed on the screen due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.



- [https://github.com/demining/Pixnapping-Attack-on-Android](https://github.com/demining/Pixnapping-Attack-on-Android) :  ![starts](https://img.shields.io/github/stars/demining/Pixnapping-Attack-on-Android.svg) ![forks](https://img.shields.io/github/forks/demining/Pixnapping-Attack-on-Android.svg)

## CVE-2025-48543
 In multiple locations, there is a possible way to escape chrome sandbox to attack android system_server due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.



- [https://github.com/gamesarchive/CVE-2025-48543](https://github.com/gamesarchive/CVE-2025-48543) :  ![starts](https://img.shields.io/github/stars/gamesarchive/CVE-2025-48543.svg) ![forks](https://img.shields.io/github/forks/gamesarchive/CVE-2025-48543.svg)

## CVE-2025-48466
 Successful exploitation of the vulnerability could allow an unauthenticated, remote attacker to send Modbus TCP packets to manipulate Digital Outputs, potentially allowing remote control of relay channel which may lead to operational or safety risks.



- [https://github.com/shipcod3/CVE-2025-48466](https://github.com/shipcod3/CVE-2025-48466) :  ![starts](https://img.shields.io/github/stars/shipcod3/CVE-2025-48466.svg) ![forks](https://img.shields.io/github/forks/shipcod3/CVE-2025-48466.svg)

## CVE-2025-48461
 Successful exploitation of the vulnerability could allow an unauthenticated attacker to conduct brute force guessing and account takeover as the session cookies are predictable, potentially allowing the attackers to gain root, admin or user access and reset passwords.



- [https://github.com/joelczk/CVE-2025-48461](https://github.com/joelczk/CVE-2025-48461) :  ![starts](https://img.shields.io/github/stars/joelczk/CVE-2025-48461.svg) ![forks](https://img.shields.io/github/forks/joelczk/CVE-2025-48461.svg)

## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.



- [https://github.com/acheong08/CVE-2025-48384](https://github.com/acheong08/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/acheong08/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/acheong08/CVE-2025-48384.svg)

- [https://github.com/liamg/CVE-2025-48384](https://github.com/liamg/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/liamg/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/liamg/CVE-2025-48384.svg)

- [https://github.com/IK-20211125/CVE-2025-48384](https://github.com/IK-20211125/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/IK-20211125/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/IK-20211125/CVE-2025-48384.svg)

- [https://github.com/beishanxueyuan/CVE-2025-48384-test](https://github.com/beishanxueyuan/CVE-2025-48384-test) :  ![starts](https://img.shields.io/github/stars/beishanxueyuan/CVE-2025-48384-test.svg) ![forks](https://img.shields.io/github/forks/beishanxueyuan/CVE-2025-48384-test.svg)

- [https://github.com/vinieger/vinieger-CVE-2025-48384-Dockerfile](https://github.com/vinieger/vinieger-CVE-2025-48384-Dockerfile) :  ![starts](https://img.shields.io/github/stars/vinieger/vinieger-CVE-2025-48384-Dockerfile.svg) ![forks](https://img.shields.io/github/forks/vinieger/vinieger-CVE-2025-48384-Dockerfile.svg)

- [https://github.com/liamg/CVE-2025-48384-submodule](https://github.com/liamg/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/liamg/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/liamg/CVE-2025-48384-submodule.svg)

- [https://github.com/fishyyh/CVE-2025-48384](https://github.com/fishyyh/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/fishyyh/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/fishyyh/CVE-2025-48384.svg)

- [https://github.com/fishyyh/CVE-2025-48384-POC](https://github.com/fishyyh/CVE-2025-48384-POC) :  ![starts](https://img.shields.io/github/stars/fishyyh/CVE-2025-48384-POC.svg) ![forks](https://img.shields.io/github/forks/fishyyh/CVE-2025-48384-POC.svg)

- [https://github.com/testdjshan/CVE-2025-48384](https://github.com/testdjshan/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/testdjshan/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/testdjshan/CVE-2025-48384.svg)

- [https://github.com/EdwardYeIntrix/CVE-2025-48384-Scanner](https://github.com/EdwardYeIntrix/CVE-2025-48384-Scanner) :  ![starts](https://img.shields.io/github/stars/EdwardYeIntrix/CVE-2025-48384-Scanner.svg) ![forks](https://img.shields.io/github/forks/EdwardYeIntrix/CVE-2025-48384-Scanner.svg)

- [https://github.com/s41r4j/CVE-2025-48384-submodule](https://github.com/s41r4j/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/s41r4j/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/s41r4j/CVE-2025-48384-submodule.svg)

- [https://github.com/jacobholtz/CVE-2025-48384-poc](https://github.com/jacobholtz/CVE-2025-48384-poc) :  ![starts](https://img.shields.io/github/stars/jacobholtz/CVE-2025-48384-poc.svg) ![forks](https://img.shields.io/github/forks/jacobholtz/CVE-2025-48384-poc.svg)

- [https://github.com/arun1033/CVE-2025-48384](https://github.com/arun1033/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/arun1033/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/arun1033/CVE-2025-48384.svg)

- [https://github.com/f1shh/CVE-2025-48384](https://github.com/f1shh/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/f1shh/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/f1shh/CVE-2025-48384.svg)

- [https://github.com/p1026/CVE-2025-48384](https://github.com/p1026/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/p1026/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/p1026/CVE-2025-48384.svg)

- [https://github.com/altm4n/cve-2025-48384](https://github.com/altm4n/cve-2025-48384) :  ![starts](https://img.shields.io/github/stars/altm4n/cve-2025-48384.svg) ![forks](https://img.shields.io/github/forks/altm4n/cve-2025-48384.svg)

- [https://github.com/fluoworite/CVE-2025-48384](https://github.com/fluoworite/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/fluoworite/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/fluoworite/CVE-2025-48384.svg)

- [https://github.com/beishanxueyuan/CVE-2025-48384](https://github.com/beishanxueyuan/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/beishanxueyuan/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/beishanxueyuan/CVE-2025-48384.svg)

- [https://github.com/ppd520/CVE-2025-48384](https://github.com/ppd520/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/ppd520/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/ppd520/CVE-2025-48384.svg)

- [https://github.com/elprogramadorgt/CVE-2025-48384](https://github.com/elprogramadorgt/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/elprogramadorgt/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/elprogramadorgt/CVE-2025-48384.svg)

- [https://github.com/NigelX/CVE-2025-48384](https://github.com/NigelX/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/NigelX/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/NigelX/CVE-2025-48384.svg)

- [https://github.com/replicatorbot/CVE-2025-48384](https://github.com/replicatorbot/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/replicatorbot/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/replicatorbot/CVE-2025-48384.svg)

- [https://github.com/s41r4j/CVE-2025-48384](https://github.com/s41r4j/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/s41r4j/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/s41r4j/CVE-2025-48384.svg)

- [https://github.com/admin-ping/CVE-2025-48384-RCE](https://github.com/admin-ping/CVE-2025-48384-RCE) :  ![starts](https://img.shields.io/github/stars/admin-ping/CVE-2025-48384-RCE.svg) ![forks](https://img.shields.io/github/forks/admin-ping/CVE-2025-48384-RCE.svg)

- [https://github.com/fluoworite/CVE-2025-48384-sub](https://github.com/fluoworite/CVE-2025-48384-sub) :  ![starts](https://img.shields.io/github/stars/fluoworite/CVE-2025-48384-sub.svg) ![forks](https://img.shields.io/github/forks/fluoworite/CVE-2025-48384-sub.svg)

- [https://github.com/eliox01/CVE-2025-48384](https://github.com/eliox01/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/eliox01/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/eliox01/CVE-2025-48384.svg)

- [https://github.com/mukesh-610/cve-2025-48384](https://github.com/mukesh-610/cve-2025-48384) :  ![starts](https://img.shields.io/github/stars/mukesh-610/cve-2025-48384.svg) ![forks](https://img.shields.io/github/forks/mukesh-610/cve-2025-48384.svg)

- [https://github.com/altm4n/cve-2025-48384-hub](https://github.com/altm4n/cve-2025-48384-hub) :  ![starts](https://img.shields.io/github/stars/altm4n/cve-2025-48384-hub.svg) ![forks](https://img.shields.io/github/forks/altm4n/cve-2025-48384-hub.svg)

- [https://github.com/Anezatraa/CVE-2025-48384-submodule](https://github.com/Anezatraa/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/Anezatraa/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/Anezatraa/CVE-2025-48384-submodule.svg)

- [https://github.com/mukesh-610/cve-2025-48384-exploit](https://github.com/mukesh-610/cve-2025-48384-exploit) :  ![starts](https://img.shields.io/github/stars/mukesh-610/cve-2025-48384-exploit.svg) ![forks](https://img.shields.io/github/forks/mukesh-610/cve-2025-48384-exploit.svg)

- [https://github.com/nguyentranbaotran/cve-2025-48384-poc](https://github.com/nguyentranbaotran/cve-2025-48384-poc) :  ![starts](https://img.shields.io/github/stars/nguyentranbaotran/cve-2025-48384-poc.svg) ![forks](https://img.shields.io/github/forks/nguyentranbaotran/cve-2025-48384-poc.svg)

- [https://github.com/replicatorbot/CVE-2025-48384-POC](https://github.com/replicatorbot/CVE-2025-48384-POC) :  ![starts](https://img.shields.io/github/stars/replicatorbot/CVE-2025-48384-POC.svg) ![forks](https://img.shields.io/github/forks/replicatorbot/CVE-2025-48384-POC.svg)

- [https://github.com/MarcoTondolo/cve-2025-48384-poc](https://github.com/MarcoTondolo/cve-2025-48384-poc) :  ![starts](https://img.shields.io/github/stars/MarcoTondolo/cve-2025-48384-poc.svg) ![forks](https://img.shields.io/github/forks/MarcoTondolo/cve-2025-48384-poc.svg)

- [https://github.com/simplyfurious/CVE-2025-48384-submodule_test](https://github.com/simplyfurious/CVE-2025-48384-submodule_test) :  ![starts](https://img.shields.io/github/stars/simplyfurious/CVE-2025-48384-submodule_test.svg) ![forks](https://img.shields.io/github/forks/simplyfurious/CVE-2025-48384-submodule_test.svg)

- [https://github.com/butyraldehyde/CVE-2025-48384-PoC](https://github.com/butyraldehyde/CVE-2025-48384-PoC) :  ![starts](https://img.shields.io/github/stars/butyraldehyde/CVE-2025-48384-PoC.svg) ![forks](https://img.shields.io/github/forks/butyraldehyde/CVE-2025-48384-PoC.svg)

- [https://github.com/jacobholtz/CVE-2025-48384-submodule](https://github.com/jacobholtz/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/jacobholtz/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/jacobholtz/CVE-2025-48384-submodule.svg)

- [https://github.com/kallydev/cve-2025-48384-hook](https://github.com/kallydev/cve-2025-48384-hook) :  ![starts](https://img.shields.io/github/stars/kallydev/cve-2025-48384-hook.svg) ![forks](https://img.shields.io/github/forks/kallydev/cve-2025-48384-hook.svg)

- [https://github.com/ECHO6789/CVE-2025-48384-submodule](https://github.com/ECHO6789/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/ECHO6789/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/ECHO6789/CVE-2025-48384-submodule.svg)

- [https://github.com/greatyy/CVE-2025-48384-p](https://github.com/greatyy/CVE-2025-48384-p) :  ![starts](https://img.shields.io/github/stars/greatyy/CVE-2025-48384-p.svg) ![forks](https://img.shields.io/github/forks/greatyy/CVE-2025-48384-p.svg)

- [https://github.com/butyraldehyde/CVE-2025-48384-PoC-Part2](https://github.com/butyraldehyde/CVE-2025-48384-PoC-Part2) :  ![starts](https://img.shields.io/github/stars/butyraldehyde/CVE-2025-48384-PoC-Part2.svg) ![forks](https://img.shields.io/github/forks/butyraldehyde/CVE-2025-48384-PoC-Part2.svg)

## CVE-2025-48148
 Unrestricted Upload of File with Dangerous Type vulnerability in StoreKeeper B.V. StoreKeeper for WooCommerce allows Using Malicious Files. This issue affects StoreKeeper for WooCommerce: from n/a through 14.4.4.



- [https://github.com/Nxploited/CVE-2025-48148](https://github.com/Nxploited/CVE-2025-48148) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-48148.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-48148.svg)

## CVE-2025-48129
 Incorrect Privilege Assignment vulnerability in Holest Engineering Spreadsheet Price Changer for WooCommerce and WP E-commerce – Light allows Privilege Escalation. This issue affects Spreadsheet Price Changer for WooCommerce and WP E-commerce – Light: from n/a through 2.4.37.



- [https://github.com/Nxploited/CVE-2025-48129](https://github.com/Nxploited/CVE-2025-48129) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-48129.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-48129.svg)

## CVE-2025-47987
 Heap-based buffer overflow in Windows Cred SSProvider Protocol allows an authorized attacker to elevate privileges locally.



- [https://github.com/Kryptoenix/CVE-2025-47987_PoC](https://github.com/Kryptoenix/CVE-2025-47987_PoC) :  ![starts](https://img.shields.io/github/stars/Kryptoenix/CVE-2025-47987_PoC.svg) ![forks](https://img.shields.io/github/forks/Kryptoenix/CVE-2025-47987_PoC.svg)

## CVE-2025-47917
 Mbed TLS before 3.6.4 allows a use-after-free in certain situations of applications that are developed in accordance with the documentation. The function mbedtls_x509_string_to_names() takes a head argument that is documented as an output argument. The documentation does not suggest that the function will free that pointer; however, the function does call mbedtls_asn1_free_named_data_list() on that argument, which performs a deep free(). As a result, application code that uses this function (relying only on documented behavior) is likely to still hold pointers to the memory blocks that were freed, resulting in a high risk of use-after-free or double-free. In particular, the two sample programs x509/cert_write and x509/cert_req are affected (use-after-free if the san string contains more than one DN).



- [https://github.com/byteReaper77/CVE-2025-47917](https://github.com/byteReaper77/CVE-2025-47917) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-47917.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-47917.svg)

## CVE-2025-47827
 In IGEL OS before 11, Secure Boot can be bypassed because the igel-flash-driver module improperly verifies a cryptographic signature. Ultimately, a crafted root filesystem can be mounted from an unverified SquashFS image.



- [https://github.com/Zedeldi/CVE-2025-47827](https://github.com/Zedeldi/CVE-2025-47827) :  ![starts](https://img.shields.io/github/stars/Zedeldi/CVE-2025-47827.svg) ![forks](https://img.shields.io/github/forks/Zedeldi/CVE-2025-47827.svg)

## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.



- [https://github.com/4m3rr0r/CVE-2025-47812-poc](https://github.com/4m3rr0r/CVE-2025-47812-poc) :  ![starts](https://img.shields.io/github/stars/4m3rr0r/CVE-2025-47812-poc.svg) ![forks](https://img.shields.io/github/forks/4m3rr0r/CVE-2025-47812-poc.svg)

- [https://github.com/0xcan1337/CVE-2025-47812-poC](https://github.com/0xcan1337/CVE-2025-47812-poC) :  ![starts](https://img.shields.io/github/stars/0xcan1337/CVE-2025-47812-poC.svg) ![forks](https://img.shields.io/github/forks/0xcan1337/CVE-2025-47812-poC.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-47812](https://github.com/0xgh057r3c0n/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-47812.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-47812](https://github.com/B1ack4sh/Blackash-CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-47812.svg)

- [https://github.com/r0otk3r/CVE-2025-47812](https://github.com/r0otk3r/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2025-47812.svg)

- [https://github.com/rxerium/CVE-2025-47812](https://github.com/rxerium/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-47812.svg)

- [https://github.com/pevinkumar10/CVE-2025-47812](https://github.com/pevinkumar10/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/pevinkumar10/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/pevinkumar10/CVE-2025-47812.svg)

- [https://github.com/blindma1den/CVE-2025-47812](https://github.com/blindma1den/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/blindma1den/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/blindma1den/CVE-2025-47812.svg)

- [https://github.com/CTY-Research-1/CVE-2025-47812_Lab_environment](https://github.com/CTY-Research-1/CVE-2025-47812_Lab_environment) :  ![starts](https://img.shields.io/github/stars/CTY-Research-1/CVE-2025-47812_Lab_environment.svg) ![forks](https://img.shields.io/github/forks/CTY-Research-1/CVE-2025-47812_Lab_environment.svg)

- [https://github.com/ill-deed/WingFTP-CVE-2025-47812-illdeed](https://github.com/ill-deed/WingFTP-CVE-2025-47812-illdeed) :  ![starts](https://img.shields.io/github/stars/ill-deed/WingFTP-CVE-2025-47812-illdeed.svg) ![forks](https://img.shields.io/github/forks/ill-deed/WingFTP-CVE-2025-47812-illdeed.svg)

## CVE-2025-47646
 Weak Password Recovery Mechanism for Forgotten Password vulnerability in Gilblas Ngunte Possi PSW Front-end Login &amp; Registration allows Password Recovery Exploitation. This issue affects PSW Front-end Login &amp; Registration: from n/a through 1.13.



- [https://github.com/Nxploited/CVE-2025-47646](https://github.com/Nxploited/CVE-2025-47646) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-47646.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-47646.svg)

- [https://github.com/RootHarpy/CVE-2025-47646](https://github.com/RootHarpy/CVE-2025-47646) :  ![starts](https://img.shields.io/github/stars/RootHarpy/CVE-2025-47646.svg) ![forks](https://img.shields.io/github/forks/RootHarpy/CVE-2025-47646.svg)

## CVE-2025-47577
 Unrestricted Upload of File with Dangerous Type vulnerability in TemplateInvaders TI WooCommerce Wishlist allows Upload a Web Shell to a Web Server.This issue affects TI WooCommerce Wishlist: from n/a before 2.10.0.



- [https://github.com/Yucaerin/CVE-2025-47577](https://github.com/Yucaerin/CVE-2025-47577) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-47577.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-47577.svg)

- [https://github.com/sug4r-wr41th/CVE-2025-47577](https://github.com/sug4r-wr41th/CVE-2025-47577) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2025-47577.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2025-47577.svg)

## CVE-2025-47550
 Unrestricted Upload of File with Dangerous Type vulnerability in Themefic Instantio allows Upload a Web Shell to a Web Server.

This issue affects Instantio: from n/a through 3.3.16.



- [https://github.com/d0n601/CVE-2025-47550](https://github.com/d0n601/CVE-2025-47550) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-47550.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-47550.svg)

## CVE-2025-47549
 Unrestricted Upload of File with Dangerous Type vulnerability in Themefic BEAF allows Upload a Web Shell to a Web Server.

This issue affects BEAF: from n/a through 4.6.10.



- [https://github.com/d0n601/CVE-2025-47549](https://github.com/d0n601/CVE-2025-47549) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-47549.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-47549.svg)

## CVE-2025-47539
 Incorrect Privilege Assignment vulnerability in Themewinter Eventin allows Privilege Escalation. This issue affects Eventin: from n/a through 4.0.26.



- [https://github.com/Nxploited/CVE-2025-47539](https://github.com/Nxploited/CVE-2025-47539) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-47539.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-47539.svg)

## CVE-2025-47533
 Cross-Site Request Forgery (CSRF) vulnerability in Iqonic Design Graphina allows PHP Local File Inclusion. This issue affects Graphina: from n/a through 3.0.4.



- [https://github.com/zs1n/CVE-2024-47533](https://github.com/zs1n/CVE-2024-47533) :  ![starts](https://img.shields.io/github/stars/zs1n/CVE-2024-47533.svg) ![forks](https://img.shields.io/github/forks/zs1n/CVE-2024-47533.svg)

## CVE-2025-47423
 Personal Weather Station Dashboard 12_lts allows unauthenticated remote attackers to read arbitrary files via ../ directory traversal in the test parameter to /others/_test.php, as demonstrated by reading the server's private SSL key in cleartext.



- [https://github.com/Haluka92/CVE-2025-47423](https://github.com/Haluka92/CVE-2025-47423) :  ![starts](https://img.shields.io/github/stars/Haluka92/CVE-2025-47423.svg) ![forks](https://img.shields.io/github/forks/Haluka92/CVE-2025-47423.svg)

## CVE-2025-47256
 Libxmp through 4.6.2 has a stack-based buffer overflow in depack_pha in loaders/prowizard/pha.c via a malformed Pha format tracker module in a .mod file.



- [https://github.com/SexyShoelessGodofWar/CVE-2025-47256](https://github.com/SexyShoelessGodofWar/CVE-2025-47256) :  ![starts](https://img.shields.io/github/stars/SexyShoelessGodofWar/CVE-2025-47256.svg) ![forks](https://img.shields.io/github/forks/SexyShoelessGodofWar/CVE-2025-47256.svg)

## CVE-2025-47228
 In the Production Environment extension in Netmake ScriptCase through 9.12.006 (23), shell injection in the SSH connection settings allows authenticated attackers to execute system commands via crafted HTTP requests.



- [https://github.com/synacktiv/CVE-2025-47227_CVE-2025-47228](https://github.com/synacktiv/CVE-2025-47227_CVE-2025-47228) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2025-47227_CVE-2025-47228.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2025-47227_CVE-2025-47228.svg)

## CVE-2025-47227
 In the Production Environment extension in Netmake ScriptCase through 9.12.006 (23), the Administrator password reset mechanism is mishandled. Making both a GET and a POST request to login.php.is sufficient. An unauthenticated attacker can then bypass authentication via administrator account takeover.



- [https://github.com/synacktiv/CVE-2025-47227_CVE-2025-47228](https://github.com/synacktiv/CVE-2025-47227_CVE-2025-47228) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2025-47227_CVE-2025-47228.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2025-47227_CVE-2025-47228.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-47227](https://github.com/B1ack4sh/Blackash-CVE-2025-47227) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-47227.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-47227.svg)

## CVE-2025-47226
 Grokability Snipe-IT before 8.1.0 has incorrect authorization for accessing asset information.



- [https://github.com/koyomihack00/CVE-2025-47226](https://github.com/koyomihack00/CVE-2025-47226) :  ![starts](https://img.shields.io/github/stars/koyomihack00/CVE-2025-47226.svg) ![forks](https://img.shields.io/github/forks/koyomihack00/CVE-2025-47226.svg)

## CVE-2025-47181
 Improper link resolution before file access ('link following') in Microsoft Edge (Chromium-based) allows an authorized attacker to elevate privileges locally.



- [https://github.com/encrypter15/CVE-2025-47181](https://github.com/encrypter15/CVE-2025-47181) :  ![starts](https://img.shields.io/github/stars/encrypter15/CVE-2025-47181.svg) ![forks](https://img.shields.io/github/forks/encrypter15/CVE-2025-47181.svg)

## CVE-2025-47178
 Improper neutralization of special elements used in an sql command ('sql injection') in Microsoft Configuration Manager allows an authorized attacker to execute code over an adjacent network.



- [https://github.com/synacktiv/CVE-2025-47178](https://github.com/synacktiv/CVE-2025-47178) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2025-47178.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2025-47178.svg)

## CVE-2025-47176
 '.../...//' in Microsoft Office Outlook allows an authorized attacker to execute code locally.



- [https://github.com/mahyarx/CVE-2025-47176](https://github.com/mahyarx/CVE-2025-47176) :  ![starts](https://img.shields.io/github/stars/mahyarx/CVE-2025-47176.svg) ![forks](https://img.shields.io/github/forks/mahyarx/CVE-2025-47176.svg)

## CVE-2025-47175
 Use after free in Microsoft Office PowerPoint allows an unauthorized attacker to execute code locally.



- [https://github.com/mbanyamer/mbanyamer-Microsoft-PowerPoint-Use-After-Free-Remote-Code-Execution-RCE](https://github.com/mbanyamer/mbanyamer-Microsoft-PowerPoint-Use-After-Free-Remote-Code-Execution-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/mbanyamer-Microsoft-PowerPoint-Use-After-Free-Remote-Code-Execution-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/mbanyamer-Microsoft-PowerPoint-Use-After-Free-Remote-Code-Execution-RCE.svg)

## CVE-2025-46822
 OsamaTaher/Java-springboot-codebase is a collection of Java and Spring Boot code snippets, applications, and projects. Prior to commit c835c6f7799eacada4c0fc77e0816f250af01ad2, insufficient path traversal mechanisms make absolute path traversal possible. This vulnerability allows unauthorized access to sensitive internal files. Commit c835c6f7799eacada4c0fc77e0816f250af01ad2 contains a patch for the issue.



- [https://github.com/d3sca/CVE-2025-46822](https://github.com/d3sca/CVE-2025-46822) :  ![starts](https://img.shields.io/github/stars/d3sca/CVE-2025-46822.svg) ![forks](https://img.shields.io/github/forks/d3sca/CVE-2025-46822.svg)

## CVE-2025-46819
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted LUA script to read out-of-bound data or crash the server and subsequent denial of service. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to block a script by restricting both the EVAL and FUNCTION command families.



- [https://github.com/dwisiswant0/CVE-2025-46819](https://github.com/dwisiswant0/CVE-2025-46819) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/CVE-2025-46819.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/CVE-2025-46819.svg)

## CVE-2025-46818
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate different LUA objects and potentially run their own code in the context of another user. The problem exists in all versions of Redis with LUA scripting. This issue is fixed in version 8.2.2. A workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing LUA scripts. This can be done using ACL to block a script by restricting both the EVAL and FUNCTION command families.



- [https://github.com/dwisiswant0/CVE-2025-46818](https://github.com/dwisiswant0/CVE-2025-46818) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/CVE-2025-46818.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/CVE-2025-46818.svg)

## CVE-2025-46817
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to cause an integer overflow and potentially lead to remote code execution The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2.



- [https://github.com/dwisiswant0/CVE-2025-46817](https://github.com/dwisiswant0/CVE-2025-46817) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/CVE-2025-46817.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/CVE-2025-46817.svg)

- [https://github.com/slayerkkkk/CVE-2025-46817-PoC](https://github.com/slayerkkkk/CVE-2025-46817-PoC) :  ![starts](https://img.shields.io/github/stars/slayerkkkk/CVE-2025-46817-PoC.svg) ![forks](https://img.shields.io/github/forks/slayerkkkk/CVE-2025-46817-PoC.svg)

## CVE-2025-46816
 goshs is a SimpleHTTPServer written in Go. Starting in version 0.3.4 and prior to version 1.0.5, running goshs without arguments makes it possible for anyone to execute commands on the server. The function `dispatchReadPump` does not checks the option cli `-c`, thus allowing anyone to execute arbitrary command through the use of websockets. Version 1.0.5 fixes the issue.



- [https://github.com/Guilhem7/CVE-2025-46816](https://github.com/Guilhem7/CVE-2025-46816) :  ![starts](https://img.shields.io/github/stars/Guilhem7/CVE-2025-46816.svg) ![forks](https://img.shields.io/github/forks/Guilhem7/CVE-2025-46816.svg)

## CVE-2025-46811
 A Missing Authorization vulnerability in SUSE Linux Manager allows anyone with the ability to connect to port 443 of SUSE Manager is able to run any command as root on any client. This issue affects Container suse/manager/5.0/x86_64/server:5.0.5.7.30.1: from ? before 5.0.27-150600.3.33.1; Image SLES15-SP4-Manager-Server-4-3-BYOS: from ? before 4.3.87-150400.3.110.2; Image SLES15-SP4-Manager-Server-4-3-BYOS-Azure: from ? before 4.3.87-150400.3.110.2; Image SLES15-SP4-Manager-Server-4-3-BYOS-EC2: from ? before 4.3.87-150400.3.110.2; Image SLES15-SP4-Manager-Server-4-3-BYOS-GCE: from ? before 4.3.87-150400.3.110.2; SUSE Manager Server Module 4.3: from ? before 4.3.87-150400.3.110.2.



- [https://github.com/b-L-x/CVE-2025-46811](https://github.com/b-L-x/CVE-2025-46811) :  ![starts](https://img.shields.io/github/stars/b-L-x/CVE-2025-46811.svg) ![forks](https://img.shields.io/github/forks/b-L-x/CVE-2025-46811.svg)

## CVE-2025-46731
 Craft is a content management system. Versions of Craft CMS on the 4.x branch prior to 4.14.13 and on the 5.x branch prior to 5.6.16 contains a potential remote code execution vulnerability via Twig SSTI. One must have administrator access and `ALLOW_ADMIN_CHANGES` must be enabled for this to work. Users should update to the patched versions 4.14.13 or 5.6.15 to mitigate the issue.



- [https://github.com/singetu0096/CVE-2025-46731](https://github.com/singetu0096/CVE-2025-46731) :  ![starts](https://img.shields.io/github/stars/singetu0096/CVE-2025-46731.svg) ![forks](https://img.shields.io/github/forks/singetu0096/CVE-2025-46731.svg)

## CVE-2025-46721
 nosurf is cross-site request forgery (CSRF) protection middleware for Go. A vulnerability in versions prior to 1.2.0 allows an attacker who controls content on the target site, or on a subdomain of the target site (either via XSS, or otherwise) to bypass CSRF checks and issue requests on user's behalf. Due to misuse of the Go `net/http` library, nosurf categorizes all incoming requests as plain-text HTTP requests, in which case the `Referer` header is not checked to have the same origin as the target webpage. If the attacker has control over HTML contents on either the target website (e.g. `example.com`), or on a website hosted on a subdomain of the target (e.g. `attacker.example.com`), they will also be able to manipulate cookies set for the target website. By acquiring the secret CSRF token from the cookie, or overriding the cookie with a new token known to the attacker, `attacker.example.com` is able to craft cross-site requests to `example.com`. A patch for the issue was released in nosurf 1.2.0. In lieu of upgrading to a patched version of nosurf, users may additionally use another HTTP middleware to ensure that a non-safe HTTP request is coming from the same origin (e.g. by requiring a `Sec-Fetch-Site: same-origin` header in the request).



- [https://github.com/justinas/nosurf-cve-2025-46721](https://github.com/justinas/nosurf-cve-2025-46721) :  ![starts](https://img.shields.io/github/stars/justinas/nosurf-cve-2025-46721.svg) ![forks](https://img.shields.io/github/forks/justinas/nosurf-cve-2025-46721.svg)

## CVE-2025-46701
 Improper Handling of Case Sensitivity vulnerability in Apache Tomcat's GCI servlet allows security constraint bypass of security constraints that apply to the pathInfo component of a URI mapped to the CGI servlet.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.6, from 10.1.0-M1 through 10.1.40, from 9.0.0.M1 through 9.0.104.
The following versions were EOL at the time the CVE was created but are 
known to be affected: 8.5.0 though 8.5.100. Other, older, EOL versions 
may also be affected.


Users are recommended to upgrade to version 11.0.7, 10.1.41 or 9.0.105, which fixes the issue.



- [https://github.com/gregk4sec/CVE-2025-46701](https://github.com/gregk4sec/CVE-2025-46701) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-46701.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-46701.svg)

## CVE-2025-46657
 Karaz Karazal through 2025-04-14 allows reflected XSS via the lang parameter to the default URI.



- [https://github.com/nov-1337/CVE-2025-46657](https://github.com/nov-1337/CVE-2025-46657) :  ![starts](https://img.shields.io/github/stars/nov-1337/CVE-2025-46657.svg) ![forks](https://img.shields.io/github/forks/nov-1337/CVE-2025-46657.svg)

## CVE-2025-46408
 An issue was discovered in the methods push.lite.avtech.com.AvtechLib.GetHttpsResponse and push.lite.avtech.com.Push_HttpService.getNewHttpClient in AVTECH EagleEyes 2.0.0. The methods set ALLOW_ALL_HOSTNAME_VERIFIER, bypassing domain validation.



- [https://github.com/shinyColumn/CVE-2025-46408](https://github.com/shinyColumn/CVE-2025-46408) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-46408.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-46408.svg)

## CVE-2025-46271
 UNI-NMS-Lite is vulnerable to a command injection attack that could 
allow an unauthenticated attacker to read or manipulate device data.



- [https://github.com/1Altruist/CVE-2025-46271-Reverse-Shell-PoC](https://github.com/1Altruist/CVE-2025-46271-Reverse-Shell-PoC) :  ![starts](https://img.shields.io/github/stars/1Altruist/CVE-2025-46271-Reverse-Shell-PoC.svg) ![forks](https://img.shields.io/github/forks/1Altruist/CVE-2025-46271-Reverse-Shell-PoC.svg)

## CVE-2025-46206
 An issue in Artifex mupdf 1.25.6, 1.25.5 allows a remote attacker to cause a denial of service via an infinite recursion in the `mutool clean` utility. When processing a crafted PDF file containing cyclic /Next references in the outline structure, the `strip_outline()` function enters infinite recursion



- [https://github.com/Landw-hub/CVE-2025-46206](https://github.com/Landw-hub/CVE-2025-46206) :  ![starts](https://img.shields.io/github/stars/Landw-hub/CVE-2025-46206.svg) ![forks](https://img.shields.io/github/forks/Landw-hub/CVE-2025-46206.svg)

## CVE-2025-46204
 An issue in Unifiedtransform v2.0 allows a remote attacker to escalate privileges via the /course/edit/{id} endpoint.



- [https://github.com/spbavarva/CVE-2025-46204](https://github.com/spbavarva/CVE-2025-46204) :  ![starts](https://img.shields.io/github/stars/spbavarva/CVE-2025-46204.svg) ![forks](https://img.shields.io/github/forks/spbavarva/CVE-2025-46204.svg)

## CVE-2025-46203
 An issue in Unifiedtransform v2.0 allows a remote attacker to escalate privileges via the /students/edit/{id} endpoint.



- [https://github.com/spbavarva/CVE-2025-46203](https://github.com/spbavarva/CVE-2025-46203) :  ![starts](https://img.shields.io/github/stars/spbavarva/CVE-2025-46203.svg) ![forks](https://img.shields.io/github/forks/spbavarva/CVE-2025-46203.svg)

## CVE-2025-46178
 Cross-Site Scripting (XSS) vulnerability exists in askquery.php via the eid parameter in the CloudClassroom PHP Project. This allows remote attackers to inject arbitrary JavaScript in the context of a victim s browser session by sending a crafted URL, leading to session hijacking or defacement.



- [https://github.com/SacX-7/CVE-2025-46178](https://github.com/SacX-7/CVE-2025-46178) :  ![starts](https://img.shields.io/github/stars/SacX-7/CVE-2025-46178.svg) ![forks](https://img.shields.io/github/forks/SacX-7/CVE-2025-46178.svg)

## CVE-2025-46173
 code-projects Online Exam Mastering System 1.0 is vulnerable to Cross Site Scripting (XSS) via the name field in the feedback form.



- [https://github.com/pruthuraut/CVE-2025-46173](https://github.com/pruthuraut/CVE-2025-46173) :  ![starts](https://img.shields.io/github/stars/pruthuraut/CVE-2025-46173.svg) ![forks](https://img.shields.io/github/forks/pruthuraut/CVE-2025-46173.svg)

## CVE-2025-46171
 vBulletin 3.8.7 is vulnerable to a denial-of-service condition via the misc.php?do=buddylist endpoint. If an authenticated user has a sufficiently large buddy list, processing the list can consume excessive memory, exhausting system resources and crashing the forum.



- [https://github.com/oiyl/CVE-2025-46171](https://github.com/oiyl/CVE-2025-46171) :  ![starts](https://img.shields.io/github/stars/oiyl/CVE-2025-46171.svg) ![forks](https://img.shields.io/github/forks/oiyl/CVE-2025-46171.svg)

## CVE-2025-46157
 An issue in EfroTech Time Trax v.1.0 allows a remote attacker to execute arbitrary code via the file attachment function in the leave request form



- [https://github.com/morphine009/CVE-2025-46157](https://github.com/morphine009/CVE-2025-46157) :  ![starts](https://img.shields.io/github/stars/morphine009/CVE-2025-46157.svg) ![forks](https://img.shields.io/github/forks/morphine009/CVE-2025-46157.svg)

## CVE-2025-46099
 In Pluck CMS 4.7.20-dev, an authenticated attacker can upload or create a crafted PHP file under the albums module directory and access it via the module routing logic in albums.site.php, resulting in arbitrary command execution through a GET parameter.



- [https://github.com/0xC4J/CVE-Lists](https://github.com/0xC4J/CVE-Lists) :  ![starts](https://img.shields.io/github/stars/0xC4J/CVE-Lists.svg) ![forks](https://img.shields.io/github/forks/0xC4J/CVE-Lists.svg)

## CVE-2025-46080
 HuoCMS V3.5.1 has a File Upload Vulnerability. An attacker can exploit this flaw to bypass whitelist restrictions and craft malicious files with specific suffixes, thereby gaining control of the server.



- [https://github.com/yggcwhat/CVE-2025-46080](https://github.com/yggcwhat/CVE-2025-46080) :  ![starts](https://img.shields.io/github/stars/yggcwhat/CVE-2025-46080.svg) ![forks](https://img.shields.io/github/forks/yggcwhat/CVE-2025-46080.svg)

## CVE-2025-46078
 HuoCMS V3.5.1 and before is vulnerable to file upload, which allows attackers to take control of the target server



- [https://github.com/yggcwhat/CVE-2025-46078](https://github.com/yggcwhat/CVE-2025-46078) :  ![starts](https://img.shields.io/github/stars/yggcwhat/CVE-2025-46078.svg) ![forks](https://img.shields.io/github/forks/yggcwhat/CVE-2025-46078.svg)

## CVE-2025-46047
 A User enumeration vulnerability in the /CredentialsServlet/ForgotPassword endpoint in Silverpeas 6.4.1 and 6.4.2 allows remote attackers to determine valid usernames via the Login parameter.



- [https://github.com/J0ey17/CVE-2025-46047](https://github.com/J0ey17/CVE-2025-46047) :  ![starts](https://img.shields.io/github/stars/J0ey17/CVE-2025-46047.svg) ![forks](https://img.shields.io/github/forks/J0ey17/CVE-2025-46047.svg)

## CVE-2025-46041
 A stored cross-site scripting (XSS) vulnerability in Anchor CMS v0.12.7 allows attackers to inject malicious JavaScript via the page description field in the page creation interface (/admin/pages/add).



- [https://github.com/binneko/CVE-2025-46041](https://github.com/binneko/CVE-2025-46041) :  ![starts](https://img.shields.io/github/stars/binneko/CVE-2025-46041.svg) ![forks](https://img.shields.io/github/forks/binneko/CVE-2025-46041.svg)

## CVE-2025-46018
 CSC Pay Mobile App 2.19.4 (fixed in version 2.20.0) contains a vulnerability allowing users to bypass payment authorization by disabling Bluetooth at a specific point during a transaction. This could result in unauthorized use of laundry services and potential financial loss.



- [https://github.com/niranjangaire1995/CVE-2025-46018-CSC-Pay-Mobile-App-Payment-Authentication-Bypass](https://github.com/niranjangaire1995/CVE-2025-46018-CSC-Pay-Mobile-App-Payment-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/niranjangaire1995/CVE-2025-46018-CSC-Pay-Mobile-App-Payment-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/niranjangaire1995/CVE-2025-46018-CSC-Pay-Mobile-App-Payment-Authentication-Bypass.svg)

## CVE-2025-45960
 Cross Site Scripting vulnerability in tawk.to Live Chat v.1.6.1 allows a remote attacker to execute arbitrary code via the web application stores and displays user-supplied input without proper input validation or encoding



- [https://github.com/pracharapol/CVE-2025-45960](https://github.com/pracharapol/CVE-2025-45960) :  ![starts](https://img.shields.io/github/stars/pracharapol/CVE-2025-45960.svg) ![forks](https://img.shields.io/github/forks/pracharapol/CVE-2025-45960.svg)

## CVE-2025-45805
 In phpgurukul Doctor Appointment Management System 1.0, an authenticated doctor user can inject arbitrary JavaScript code into their profile name. This payload is subsequently rendered without proper sanitization, when a user visits the website and selects the doctor to book an appointment.



- [https://github.com/mhsinj/CVE-2025-45805](https://github.com/mhsinj/CVE-2025-45805) :  ![starts](https://img.shields.io/github/stars/mhsinj/CVE-2025-45805.svg) ![forks](https://img.shields.io/github/forks/mhsinj/CVE-2025-45805.svg)

## CVE-2025-45778
 A stored cross-site scripting (XSS) vulnerability in The Language Sloth Web Application v1.0 allows attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the Description text field.



- [https://github.com/Smarttfoxx/CVE-2025-45778](https://github.com/Smarttfoxx/CVE-2025-45778) :  ![starts](https://img.shields.io/github/stars/Smarttfoxx/CVE-2025-45778.svg) ![forks](https://img.shields.io/github/forks/Smarttfoxx/CVE-2025-45778.svg)

## CVE-2025-45620
 An issue in Aver PTC310UV2 v.0.1.0000.59 allows a remote attacker to obtain sensitive information via a crafted request



- [https://github.com/weedl/CVE-2025-45620](https://github.com/weedl/CVE-2025-45620) :  ![starts](https://img.shields.io/github/stars/weedl/CVE-2025-45620.svg) ![forks](https://img.shields.io/github/forks/weedl/CVE-2025-45620.svg)

## CVE-2025-45619
 An issue in Aver PTC310UV2 firmware v.0.1.0000.59 allows a remote attacker to execute arbitrary code via the SendAction function



- [https://github.com/weedl/CVE-2025-45619](https://github.com/weedl/CVE-2025-45619) :  ![starts](https://img.shields.io/github/stars/weedl/CVE-2025-45619.svg) ![forks](https://img.shields.io/github/forks/weedl/CVE-2025-45619.svg)

## CVE-2025-45512
 A lack of signature verification in the bootloader of DENX Software Engineering Das U-Boot (U-Boot) v1.1.3 allows attackers to install crafted firmware files, leading to arbitrary code execution.



- [https://github.com/AzhariRamadhan/CVE-2025-45512](https://github.com/AzhariRamadhan/CVE-2025-45512) :  ![starts](https://img.shields.io/github/stars/AzhariRamadhan/CVE-2025-45512.svg) ![forks](https://img.shields.io/github/forks/AzhariRamadhan/CVE-2025-45512.svg)

## CVE-2025-45467
 Unitree Go1 = Go1_2022_05_11 is vulnerable to Insecure Permissions as the firmware update functionality (via Wi-Fi/Ethernet) implements an insecure verification mechanism that solely relies on MD5 checksums for firmware integrity validation.



- [https://github.com/zgsnj123/CVE-2025-45467](https://github.com/zgsnj123/CVE-2025-45467) :  ![starts](https://img.shields.io/github/stars/zgsnj123/CVE-2025-45467.svg) ![forks](https://img.shields.io/github/forks/zgsnj123/CVE-2025-45467.svg)

## CVE-2025-45466
 Unitree Go1 = Go1_2022_05_11 is vulnerale to Incorrect Access Control due to authentication credentials being hardcoded in plaintext.



- [https://github.com/zgsnj123/CVE-2025-45466](https://github.com/zgsnj123/CVE-2025-45466) :  ![starts](https://img.shields.io/github/stars/zgsnj123/CVE-2025-45466.svg) ![forks](https://img.shields.io/github/forks/zgsnj123/CVE-2025-45466.svg)

## CVE-2025-45346
 SQL Injection vulnerability in Bacula-web before v.9.7.1 allows a remote attacker to execute arbitrary code via a crafted HTTP GET request.



- [https://github.com/0xsu3ks/CVE-2025-45346](https://github.com/0xsu3ks/CVE-2025-45346) :  ![starts](https://img.shields.io/github/stars/0xsu3ks/CVE-2025-45346.svg) ![forks](https://img.shields.io/github/forks/0xsu3ks/CVE-2025-45346.svg)

## CVE-2025-45250
 MrDoc v0.95 and before is vulnerable to Server-Side Request Forgery (SSRF) in the validate_url function of the app_doc/utils.py file.



- [https://github.com/xp3s/CVE-2025-45250](https://github.com/xp3s/CVE-2025-45250) :  ![starts](https://img.shields.io/github/stars/xp3s/CVE-2025-45250.svg) ![forks](https://img.shields.io/github/forks/xp3s/CVE-2025-45250.svg)

- [https://github.com/Anike-x/CVE-2025-45250](https://github.com/Anike-x/CVE-2025-45250) :  ![starts](https://img.shields.io/github/stars/Anike-x/CVE-2025-45250.svg) ![forks](https://img.shields.io/github/forks/Anike-x/CVE-2025-45250.svg)

## CVE-2025-45157
 Insecure permissions in Splashin iOS v2.0 allow unauthorized attackers to access location data for specific users.



- [https://github.com/carterlasalle/splashin-cve-2025](https://github.com/carterlasalle/splashin-cve-2025) :  ![starts](https://img.shields.io/github/stars/carterlasalle/splashin-cve-2025.svg) ![forks](https://img.shields.io/github/forks/carterlasalle/splashin-cve-2025.svg)

## CVE-2025-45156
 Splashin iOS v2.0 fails to enforce server-side interval restrictions for location updates for free-tier users.



- [https://github.com/carterlasalle/splashin-cve-2025](https://github.com/carterlasalle/splashin-cve-2025) :  ![starts](https://img.shields.io/github/stars/carterlasalle/splashin-cve-2025.svg) ![forks](https://img.shields.io/github/forks/carterlasalle/splashin-cve-2025.svg)

## CVE-2025-44998
 A stored cross-site scripting (XSS) vulnerability in the component /tinyfilemanager.php of TinyFileManager v2.4.7 allows attackers to execute arbitrary JavaScript or HTML via injecting a crafted payload into the js-theme-3 parameter.



- [https://github.com/l8BL/CVE-2025-44998](https://github.com/l8BL/CVE-2025-44998) :  ![starts](https://img.shields.io/github/stars/l8BL/CVE-2025-44998.svg) ![forks](https://img.shields.io/github/forks/l8BL/CVE-2025-44998.svg)

## CVE-2025-44823
 Nagios Log Server before 2024R1.3.2 allows authenticated users to retrieve cleartext administrative API keys via a /nagioslogserver/index.php/api/system/get_users call. This is GL:NLS#475.



- [https://github.com/skraft9/CVE-2025-44823](https://github.com/skraft9/CVE-2025-44823) :  ![starts](https://img.shields.io/github/stars/skraft9/CVE-2025-44823.svg) ![forks](https://img.shields.io/github/forks/skraft9/CVE-2025-44823.svg)

## CVE-2025-44608
 CloudClassroom-PHP Project v1.0 was discovered to contain a SQL injection vulnerability via the viewid parameter.



- [https://github.com/mr-xmen786/CVE-2025-44608](https://github.com/mr-xmen786/CVE-2025-44608) :  ![starts](https://img.shields.io/github/stars/mr-xmen786/CVE-2025-44608.svg) ![forks](https://img.shields.io/github/forks/mr-xmen786/CVE-2025-44608.svg)

## CVE-2025-44203
 In HotelDruid 3.0.7, an unauthenticated attacker can exploit verbose SQL error messages on creadb.php before the 'create database' button is pressed. By sending malformed POST requests to this endpoint, the attacker may obtain the administrator username, password hash, and salt. In some cases, the attack results in a Denial of Service (DoS), preventing the administrator from logging in even with the correct credentials.



- [https://github.com/IvanT7D3/CVE-2025-44203](https://github.com/IvanT7D3/CVE-2025-44203) :  ![starts](https://img.shields.io/github/stars/IvanT7D3/CVE-2025-44203.svg) ![forks](https://img.shields.io/github/forks/IvanT7D3/CVE-2025-44203.svg)

## CVE-2025-44148
 Cross Site Scripting (XSS) vulnerability in MailEnable before v10 allows a remote attacker to execute arbitrary code via the failure.aspx component



- [https://github.com/barisbaydur/CVE-2025-44148](https://github.com/barisbaydur/CVE-2025-44148) :  ![starts](https://img.shields.io/github/stars/barisbaydur/CVE-2025-44148.svg) ![forks](https://img.shields.io/github/forks/barisbaydur/CVE-2025-44148.svg)

## CVE-2025-44137
 MapTiler Tileserver-php v2.0 is vulnerable to Directory Traversal. The renderTile function within tileserver.php is responsible for delivering tiles that are stored as files on the server via web request. Creating the path to a file allows the insertion of "../" and thus read any file on the web server. Affected GET parameters are "TileMatrix", "TileRow", "TileCol" and "Format"



- [https://github.com/mheranco/CVE-2025-44137](https://github.com/mheranco/CVE-2025-44137) :  ![starts](https://img.shields.io/github/stars/mheranco/CVE-2025-44137.svg) ![forks](https://img.shields.io/github/forks/mheranco/CVE-2025-44137.svg)

## CVE-2025-44136
 MapTiler Tileserver-php v2.0 is vulnerable to Cross Site Scripting (XSS). The GET parameter "layer" is reflected in an error message without html encoding. This leads to XSS and allows an unauthenticated attacker to execute arbitrary HTML or JavaScript code on a victim's browser.



- [https://github.com/mheranco/CVE-2025-44136](https://github.com/mheranco/CVE-2025-44136) :  ![starts](https://img.shields.io/github/stars/mheranco/CVE-2025-44136.svg) ![forks](https://img.shields.io/github/forks/mheranco/CVE-2025-44136.svg)

## CVE-2025-44108
 A stored Cross-Site Scripting (XSS) vulnerability exists in the administration panel of Flatpress CMS before 1.4 via the gallery captions component. An attacker with admin privileges can inject a malicious JavaScript payload into the system, which is then stored persistently.



- [https://github.com/harish0x/CVE-2025-44108-SXSS](https://github.com/harish0x/CVE-2025-44108-SXSS) :  ![starts](https://img.shields.io/github/stars/harish0x/CVE-2025-44108-SXSS.svg) ![forks](https://img.shields.io/github/forks/harish0x/CVE-2025-44108-SXSS.svg)

## CVE-2025-44039
 CP-XR-DE21-S -4G Router Firmware version 1.031.022 was discovered to contain insecure protections for its UART console. This vulnerability allows local attackers to connect to the UART port via a serial connection, read all boot sequence, and revealing internal system details and sensitive information without any authentication.



- [https://github.com/Yashodhanvivek/CP-XR-DE21-S--4G-Router-Vulnerabilities](https://github.com/Yashodhanvivek/CP-XR-DE21-S--4G-Router-Vulnerabilities) :  ![starts](https://img.shields.io/github/stars/Yashodhanvivek/CP-XR-DE21-S--4G-Router-Vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/Yashodhanvivek/CP-XR-DE21-S--4G-Router-Vulnerabilities.svg)

## CVE-2025-43960
 Adminer 4.8.1, when using Monolog for logging, allows a Denial of Service (memory consumption) via a crafted serialized payload (e.g., using s:1000000000), leading to a PHP Object Injection issue. Remote, unauthenticated attackers can trigger this by sending a malicious serialized object, which forces excessive memory usage, rendering Adminer’s interface unresponsive and causing a server-level DoS. While the server may recover after several minutes, multiple simultaneous requests can cause a complete crash requiring manual intervention.



- [https://github.com/far00t01/CVE-2025-43960](https://github.com/far00t01/CVE-2025-43960) :  ![starts](https://img.shields.io/github/stars/far00t01/CVE-2025-43960.svg) ![forks](https://img.shields.io/github/forks/far00t01/CVE-2025-43960.svg)

## CVE-2025-43929
 open_actions.py in kitty before 0.41.0 does not ask for user confirmation before running a local executable file that may have been linked from an untrusted document (e.g., a document opened in KDE ghostwriter).



- [https://github.com/0xBenCantCode/CVE-2025-43929](https://github.com/0xBenCantCode/CVE-2025-43929) :  ![starts](https://img.shields.io/github/stars/0xBenCantCode/CVE-2025-43929.svg) ![forks](https://img.shields.io/github/forks/0xBenCantCode/CVE-2025-43929.svg)

## CVE-2025-43921
 GNU Mailman 2.1.39, as bundled in cPanel (and WHM), allows unauthenticated attackers to create lists via the /mailman/create endpoint. NOTE: multiple third parties report that they are unable to reproduce this, regardless of whether cPanel or WHM is used.



- [https://github.com/0NYX-MY7H/CVE-2025-43921](https://github.com/0NYX-MY7H/CVE-2025-43921) :  ![starts](https://img.shields.io/github/stars/0NYX-MY7H/CVE-2025-43921.svg) ![forks](https://img.shields.io/github/forks/0NYX-MY7H/CVE-2025-43921.svg)

## CVE-2025-43920
 GNU Mailman 2.1.39, as bundled in cPanel (and WHM), in certain external archiver configurations, allows unauthenticated attackers to execute arbitrary OS commands via shell metacharacters in an email Subject line. NOTE: multiple third parties report that they are unable to reproduce this, regardless of whether cPanel or WHM is used.



- [https://github.com/0NYX-MY7H/CVE-2025-43920](https://github.com/0NYX-MY7H/CVE-2025-43920) :  ![starts](https://img.shields.io/github/stars/0NYX-MY7H/CVE-2025-43920.svg) ![forks](https://img.shields.io/github/forks/0NYX-MY7H/CVE-2025-43920.svg)

## CVE-2025-43919
 GNU Mailman 2.1.39, as bundled in cPanel (and WHM), allows unauthenticated attackers to read arbitrary files via ../ directory traversal at /mailman/private/mailman (aka the private archive authentication endpoint) via the username parameter. NOTE: multiple third parties report that they are unable to reproduce this, regardless of whether cPanel or WHM is used.



- [https://github.com/0NYX-MY7H/CVE-2025-43919](https://github.com/0NYX-MY7H/CVE-2025-43919) :  ![starts](https://img.shields.io/github/stars/0NYX-MY7H/CVE-2025-43919.svg) ![forks](https://img.shields.io/github/forks/0NYX-MY7H/CVE-2025-43919.svg)

- [https://github.com/cybersecplayground/CVE-2025-43919-POC](https://github.com/cybersecplayground/CVE-2025-43919-POC) :  ![starts](https://img.shields.io/github/stars/cybersecplayground/CVE-2025-43919-POC.svg) ![forks](https://img.shields.io/github/forks/cybersecplayground/CVE-2025-43919-POC.svg)

## CVE-2025-43865
 React Router is a router for React. In versions on the 7.0 branch prior to version 7.5.2, it's possible to modify pre-rendered data by adding a header to the request. This allows to completely spoof its contents and modify all the values ​​of the data object passed to the HTML. This issue has been patched in version 7.5.2.



- [https://github.com/pouriam23/Pre-render-data-spoofing-on-React-Router-framework-mode-CVE-2025-43865](https://github.com/pouriam23/Pre-render-data-spoofing-on-React-Router-framework-mode-CVE-2025-43865) :  ![starts](https://img.shields.io/github/stars/pouriam23/Pre-render-data-spoofing-on-React-Router-framework-mode-CVE-2025-43865.svg) ![forks](https://img.shields.io/github/forks/pouriam23/Pre-render-data-spoofing-on-React-Router-framework-mode-CVE-2025-43865.svg)

## CVE-2025-43864
 React Router is a router for React. Starting in version 7.2.0 and prior to version 7.5.2, it is possible to force an application to switch to SPA mode by adding a header to the request. If the application uses SSR and is forced to switch to SPA, this causes an error that completely corrupts the page. If a cache system is in place, this allows the response containing the error to be cached, resulting in a cache poisoning that strongly impacts the availability of the application. This issue has been patched in version 7.5.2.



- [https://github.com/pouriam23/DoS-via-cache-poisoning-by-forcing-SPA-mode-CVE-2025-43864-](https://github.com/pouriam23/DoS-via-cache-poisoning-by-forcing-SPA-mode-CVE-2025-43864-) :  ![starts](https://img.shields.io/github/stars/pouriam23/DoS-via-cache-poisoning-by-forcing-SPA-mode-CVE-2025-43864-.svg) ![forks](https://img.shields.io/github/forks/pouriam23/DoS-via-cache-poisoning-by-forcing-SPA-mode-CVE-2025-43864-.svg)

## CVE-2025-43300
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 15.8.5 and iPadOS 15.8.5, iOS 16.7.12 and iPadOS 16.7.12. Processing a malicious image file may result in memory corruption. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.



- [https://github.com/hunters-sec/CVE-2025-43300](https://github.com/hunters-sec/CVE-2025-43300) :  ![starts](https://img.shields.io/github/stars/hunters-sec/CVE-2025-43300.svg) ![forks](https://img.shields.io/github/forks/hunters-sec/CVE-2025-43300.svg)

- [https://github.com/h4xnz/CVE-2025-43300-Exploit](https://github.com/h4xnz/CVE-2025-43300-Exploit) :  ![starts](https://img.shields.io/github/stars/h4xnz/CVE-2025-43300-Exploit.svg) ![forks](https://img.shields.io/github/forks/h4xnz/CVE-2025-43300-Exploit.svg)

- [https://github.com/XiaomingX/CVE-2025-43300-exp](https://github.com/XiaomingX/CVE-2025-43300-exp) :  ![starts](https://img.shields.io/github/stars/XiaomingX/CVE-2025-43300-exp.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/CVE-2025-43300-exp.svg)

- [https://github.com/PwnToday/CVE-2025-43300](https://github.com/PwnToday/CVE-2025-43300) :  ![starts](https://img.shields.io/github/stars/PwnToday/CVE-2025-43300.svg) ![forks](https://img.shields.io/github/forks/PwnToday/CVE-2025-43300.svg)

- [https://github.com/ticofookfook/CVE-2025-43300](https://github.com/ticofookfook/CVE-2025-43300) :  ![starts](https://img.shields.io/github/stars/ticofookfook/CVE-2025-43300.svg) ![forks](https://img.shields.io/github/forks/ticofookfook/CVE-2025-43300.svg)

- [https://github.com/Dark-life944/CVE-2025](https://github.com/Dark-life944/CVE-2025) :  ![starts](https://img.shields.io/github/stars/Dark-life944/CVE-2025.svg) ![forks](https://img.shields.io/github/forks/Dark-life944/CVE-2025.svg)

- [https://github.com/veniversum/cve-2025-43300](https://github.com/veniversum/cve-2025-43300) :  ![starts](https://img.shields.io/github/stars/veniversum/cve-2025-43300.svg) ![forks](https://img.shields.io/github/forks/veniversum/cve-2025-43300.svg)

## CVE-2025-42999
 SAP NetWeaver Visual Composer Metadata Uploader is vulnerable when a privileged user can upload untrusted or malicious content which, when deserialized, could potentially lead to a compromise of confidentiality, integrity, and availability of the host system.



- [https://github.com/Onapsis/Onapsis-Mandiant-CVE-2025-31324-Vuln-Compromise-Assessment](https://github.com/Onapsis/Onapsis-Mandiant-CVE-2025-31324-Vuln-Compromise-Assessment) :  ![starts](https://img.shields.io/github/stars/Onapsis/Onapsis-Mandiant-CVE-2025-31324-Vuln-Compromise-Assessment.svg) ![forks](https://img.shields.io/github/forks/Onapsis/Onapsis-Mandiant-CVE-2025-31324-Vuln-Compromise-Assessment.svg)

## CVE-2025-42957
 SAP S/4HANA allows an attacker with user privileges to exploit a vulnerability in the function module exposed via RFC. This flaw enables the injection of arbitrary ABAP code into the system, bypassing essential authorization checks. This vulnerability effectively functions as a backdoor, creating the risk of full system compromise, undermining the confidentiality, integrity and availability of the system.



- [https://github.com/mrk336/CVE-2025-42957-SAP-S-4HANA-Under-Siege](https://github.com/mrk336/CVE-2025-42957-SAP-S-4HANA-Under-Siege) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2025-42957-SAP-S-4HANA-Under-Siege.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2025-42957-SAP-S-4HANA-Under-Siege.svg)

## CVE-2025-42944
 Due to a deserialization vulnerability in SAP NetWeaver, an unauthenticated attacker could exploit the system through the RMI-P4 module by submitting malicious payload to an open port. The deserialization of such untrusted Java objects could lead to arbitrary OS command execution, posing a high impact to the application's confidentiality, integrity, and availability.



- [https://github.com/rxerium/CVE-2025-42944](https://github.com/rxerium/CVE-2025-42944) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-42944.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-42944.svg)

## CVE-2025-41720
 A low privileged remote attacker can upload arbitrary data masked as a png file to the affected device using the webserver API because only the file extension is verified.



- [https://github.com/NotItsSixtyN3in/CVE-2025-4172025](https://github.com/NotItsSixtyN3in/CVE-2025-4172025) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4172025.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4172025.svg)

- [https://github.com/NotItsSixtyN3in/CVE-2025-4172026](https://github.com/NotItsSixtyN3in/CVE-2025-4172026) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4172026.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4172026.svg)

## CVE-2025-41656
 An unauthenticated remote attacker can run arbitrary commands on the affected devices with high privileges because the authentication for the Node_RED server is not configured by default.



- [https://github.com/wallyschag/CVE-2025-41656](https://github.com/wallyschag/CVE-2025-41656) :  ![starts](https://img.shields.io/github/stars/wallyschag/CVE-2025-41656.svg) ![forks](https://img.shields.io/github/forks/wallyschag/CVE-2025-41656.svg)

## CVE-2025-41646
 An unauthorized remote attacker can bypass the authentication of the affected software package by misusing an incorrect type conversion. This leads to full compromise of the device



- [https://github.com/GreenForceNetworks/CVE-2025-41646---Critical-Authentication-Bypass-](https://github.com/GreenForceNetworks/CVE-2025-41646---Critical-Authentication-Bypass-) :  ![starts](https://img.shields.io/github/stars/GreenForceNetworks/CVE-2025-41646---Critical-Authentication-Bypass-.svg) ![forks](https://img.shields.io/github/forks/GreenForceNetworks/CVE-2025-41646---Critical-Authentication-Bypass-.svg)

- [https://github.com/r0otk3r/CVE-2025-41646](https://github.com/r0otk3r/CVE-2025-41646) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2025-41646.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2025-41646.svg)

## CVE-2025-41373
 A SQL injection vulnerability has been found in Gandia Integra Total of TESI from version 2.1.2217.3 to v4.4.2236.1. The vulnerability allows an authenticated attacker to retrieve, create, update and delete databases through the 'idestudio' parameter in /encuestas/integraweb[_v4]/integra/html/view/hislistadoacciones.php.



- [https://github.com/byteReaper77/CVE-2025-41373](https://github.com/byteReaper77/CVE-2025-41373) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-41373.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-41373.svg)

## CVE-2025-41244
 VMware Aria Operations and VMware Tools contain a local privilege escalation vulnerability. A malicious local actor with non-administrative privileges having access to a VM with VMware Tools installed and managed by Aria Operations with SDMP enabled may exploit this vulnerability to escalate privileges to root on the same VM.



- [https://github.com/rxerium/CVE-2025-41244](https://github.com/rxerium/CVE-2025-41244) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-41244.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-41244.svg)

- [https://github.com/haspiranti/CVE-2025-41244-PoC](https://github.com/haspiranti/CVE-2025-41244-PoC) :  ![starts](https://img.shields.io/github/stars/haspiranti/CVE-2025-41244-PoC.svg) ![forks](https://img.shields.io/github/forks/haspiranti/CVE-2025-41244-PoC.svg)

## CVE-2025-41243
 Spring Cloud Gateway Server Webflux may be vulnerable to Spring Environment property modification.

An application should be considered vulnerable when all the following are true:

  *  The application is using Spring Cloud Gateway Server Webflux (Spring Cloud Gateway Server WebMVC is not vulnerable).
  *  Spring Boot actuator is a dependency.
  *  The Spring Cloud Gateway Server Webflux actuator web endpoint is enabled via management.endpoints.web.exposure.include=gateway.
  *  The actuator endpoints are available to attackers.
  *  The actuator endpoints are unsecured.



- [https://github.com/AabyssZG/SpringBoot-Scan](https://github.com/AabyssZG/SpringBoot-Scan) :  ![starts](https://img.shields.io/github/stars/AabyssZG/SpringBoot-Scan.svg) ![forks](https://img.shields.io/github/forks/AabyssZG/SpringBoot-Scan.svg)

## CVE-2025-41090
 microCLAUDIA in v3.2.0 and prior has an improper access control vulnerability.

This flaw allows an authenticated user to perform unauthorized actions on other organizations' systems by sending direct API requests. To do so, the attacker can use organization identifiers obtained through a compromised endpoint or deduced manually.

This vulnerability allows access between tenants, enabling an attacker to list and manage remote assets, uninstall agents, and even delete vaccines configurations.



- [https://github.com/TheMalwareGuardian/brokeCLAUDIA](https://github.com/TheMalwareGuardian/brokeCLAUDIA) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/brokeCLAUDIA.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/brokeCLAUDIA.svg)

## CVE-2025-41089
 Reflected Cross-Site Scripting (XSS) in Xibo CMS v4.1.2 from Xibo Signage, due to a lack of proper validation of user input. To exploit the vulnerability, the attacker must create a template in the 'Templates' section, then add an element that has the 'Configuration Name' field, such as the 'Clock' widget. Next, modify the 'Configuration Name' field in the left-hand section.



- [https://github.com/Marinafabregat/CVE-2025-41089](https://github.com/Marinafabregat/CVE-2025-41089) :  ![starts](https://img.shields.io/github/stars/Marinafabregat/CVE-2025-41089.svg) ![forks](https://img.shields.io/github/forks/Marinafabregat/CVE-2025-41089.svg)

## CVE-2025-41088
 Stored Cross-Site Scripting (XSS) in Xibo Signage's Xibo CMS v4.1.2, due to a lack of proper validation of user input. To exploit the vulnerability, the attacker must create a template in the 'Templates' section, then add a text element in the 'Global Elements' section, and finally modify the 'Text' field in the section with the malicious payload.



- [https://github.com/Marinafabregat/CVE-2025-41088](https://github.com/Marinafabregat/CVE-2025-41088) :  ![starts](https://img.shields.io/github/stars/Marinafabregat/CVE-2025-41088.svg) ![forks](https://img.shields.io/github/forks/Marinafabregat/CVE-2025-41088.svg)

## CVE-2025-41020
 Insecure direct object reference (IDOR) vulnerability in Sergestec's Exito v8.0. This vulnerability allows an attacker to access data belonging to other customers through the 'id' parameter in '/admin/ticket_a4.php'.



- [https://github.com/ImTheCopilotNow/CVE-2025-4102025](https://github.com/ImTheCopilotNow/CVE-2025-4102025) :  ![starts](https://img.shields.io/github/stars/ImTheCopilotNow/CVE-2025-4102025.svg) ![forks](https://img.shields.io/github/forks/ImTheCopilotNow/CVE-2025-4102025.svg)

## CVE-2025-40778
 Under certain circumstances, BIND is too lenient when accepting records from answers, allowing an attacker to inject forged data into the cache.
This issue affects BIND 9 versions 9.11.0 through 9.16.50, 9.18.0 through 9.18.39, 9.20.0 through 9.20.13, 9.21.0 through 9.21.12, 9.11.3-S1 through 9.16.50-S1, 9.18.11-S1 through 9.18.39-S1, and 9.20.9-S1 through 9.20.13-S1.



- [https://github.com/nehkark/CVE-2025-40778](https://github.com/nehkark/CVE-2025-40778) :  ![starts](https://img.shields.io/github/stars/nehkark/CVE-2025-40778.svg) ![forks](https://img.shields.io/github/forks/nehkark/CVE-2025-40778.svg)

## CVE-2025-40775
 When an incoming DNS protocol message includes a Transaction Signature (TSIG), BIND always checks it.  If the TSIG contains an invalid value in the algorithm field, BIND immediately aborts with an assertion failure.
This issue affects BIND 9 versions 9.20.0 through 9.20.8 and 9.21.0 through 9.21.7.



- [https://github.com/AlexSvobo/nhi-zero-trust-bypass](https://github.com/AlexSvobo/nhi-zero-trust-bypass) :  ![starts](https://img.shields.io/github/stars/AlexSvobo/nhi-zero-trust-bypass.svg) ![forks](https://img.shields.io/github/forks/AlexSvobo/nhi-zero-trust-bypass.svg)

## CVE-2025-40766
 A vulnerability has been identified in SINEC Traffic Analyzer (6GK8822-1BG01-0BA0) (All versions  V3.0). The affected application runs docker containers without adequate resource and security limitations. This could allow an attacker to perform a denial-of-service (DoS) attack.



- [https://github.com/FurkanKAYAPINAR/ecs_checker](https://github.com/FurkanKAYAPINAR/ecs_checker) :  ![starts](https://img.shields.io/github/stars/FurkanKAYAPINAR/ecs_checker.svg) ![forks](https://img.shields.io/github/forks/FurkanKAYAPINAR/ecs_checker.svg)

## CVE-2025-40677
 SQL injection vulnerability in Summar Software´s Portal del Empleado. This vulnerability allows an attacker to retrieve, create, update, and delete the database by sending a POST request using the parameter “ctl00$ContentPlaceHolder1$filtroNombre” in “/MemberPages/quienesquien.aspx”.



- [https://github.com/PeterGabaldon/CVE-2025-40677](https://github.com/PeterGabaldon/CVE-2025-40677) :  ![starts](https://img.shields.io/github/stars/PeterGabaldon/CVE-2025-40677.svg) ![forks](https://img.shields.io/github/forks/PeterGabaldon/CVE-2025-40677.svg)

## CVE-2025-40634
 Stack-based buffer overflow vulnerability in the 'conn-indicator' binary running as root on the TP-Link Archer AX50 router, in firmware versions prior to 1.0.15 build 241203 rel61480. This vulnerability allows an attacker to execute arbitrary code on the device over LAN and WAN networks.



- [https://github.com/hacefresko/CVE-2025-40634](https://github.com/hacefresko/CVE-2025-40634) :  ![starts](https://img.shields.io/github/stars/hacefresko/CVE-2025-40634.svg) ![forks](https://img.shields.io/github/forks/hacefresko/CVE-2025-40634.svg)

## CVE-2025-39965
 In the Linux kernel, the following vulnerability has been resolved:

xfrm: xfrm_alloc_spi shouldn't use 0 as SPI

x-id.spi == 0 means "no SPI assigned", but since commit
94f39804d891 ("xfrm: Duplicate SPI Handling"), we now create states
and add them to the byspi list with this value.

__xfrm_state_delete doesn't remove those states from the byspi list,
since they shouldn't be there, and this shows up as a UAF the next
time we go through the byspi list.



- [https://github.com/Shreyas-Penkar/CVE-2025-39965](https://github.com/Shreyas-Penkar/CVE-2025-39965) :  ![starts](https://img.shields.io/github/stars/Shreyas-Penkar/CVE-2025-39965.svg) ![forks](https://img.shields.io/github/forks/Shreyas-Penkar/CVE-2025-39965.svg)

## CVE-2025-39946
 In the Linux kernel, the following vulnerability has been resolved:

tls: make sure to abort the stream if headers are bogus

Normally we wait for the socket to buffer up the whole record
before we service it. If the socket has a tiny buffer, however,
we read out the data sooner, to prevent connection stalls.
Make sure that we abort the connection when we find out late
that the record is actually invalid. Retrying the parsing is
fine in itself but since we copy some more data each time
before we parse we can overflow the allocated skb space.

Constructing a scenario in which we're under pressure without
enough data in the socket to parse the length upfront is quite
hard. syzbot figured out a way to do this by serving us the header
in small OOB sends, and then filling in the recvbuf with a large
normal send.

Make sure that tls_rx_msg_size() aborts strp, if we reach
an invalid record there's really no way to recover.



- [https://github.com/farazsth98/exploit-CVE-2025-39946](https://github.com/farazsth98/exploit-CVE-2025-39946) :  ![starts](https://img.shields.io/github/stars/farazsth98/exploit-CVE-2025-39946.svg) ![forks](https://img.shields.io/github/forks/farazsth98/exploit-CVE-2025-39946.svg)

## CVE-2025-39913
 In the Linux kernel, the following vulnerability has been resolved:

tcp_bpf: Call sk_msg_free() when tcp_bpf_send_verdict() fails to allocate psock-cork.

syzbot reported the splat below. [0]

The repro does the following:

  1. Load a sk_msg prog that calls bpf_msg_cork_bytes(msg, cork_bytes)
  2. Attach the prog to a SOCKMAP
  3. Add a socket to the SOCKMAP
  4. Activate fault injection
  5. Send data less than cork_bytes

At 5., the data is carried over to the next sendmsg() as it is
smaller than the cork_bytes specified by bpf_msg_cork_bytes().

Then, tcp_bpf_send_verdict() tries to allocate psock-cork to hold
the data, but this fails silently due to fault injection + __GFP_NOWARN.

If the allocation fails, we need to revert the sk-sk_forward_alloc
change done by sk_msg_alloc().

Let's call sk_msg_free() when tcp_bpf_send_verdict fails to allocate
psock-cork.

The "*copied" also needs to be updated such that a proper error can
be returned to the caller, sendmsg. It fails to allocate psock-cork.
Nothing has been corked so far, so this patch simply sets "*copied"
to 0.

[0]:
WARNING: net/ipv4/af_inet.c:156 at inet_sock_destruct+0x623/0x730 net/ipv4/af_inet.c:156, CPU#1: syz-executor/5983
Modules linked in:
CPU: 1 UID: 0 PID: 5983 Comm: syz-executor Not tainted syzkaller #0 PREEMPT(full)
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 07/12/2025
RIP: 0010:inet_sock_destruct+0x623/0x730 net/ipv4/af_inet.c:156
Code: 0f 0b 90 e9 62 fe ff ff e8 7a db b5 f7 90 0f 0b 90 e9 95 fe ff ff e8 6c db b5 f7 90 0f 0b 90 e9 bb fe ff ff e8 5e db b5 f7 90 0f 0b 90 e9 e1 fe ff ff 89 f9 80 e1 07 80 c1 03 38 c1 0f 8c 9f fc
RSP: 0018:ffffc90000a08b48 EFLAGS: 00010246
RAX: ffffffff8a09d0b2 RBX: dffffc0000000000 RCX: ffff888024a23c80
RDX: 0000000000000100 RSI: 0000000000000fff RDI: 0000000000000000
RBP: 0000000000000fff R08: ffff88807e07c627 R09: 1ffff1100fc0f8c4
R10: dffffc0000000000 R11: ffffed100fc0f8c5 R12: ffff88807e07c380
R13: dffffc0000000000 R14: ffff88807e07c60c R15: 1ffff1100fc0f872
FS:  00005555604c4500(0000) GS:ffff888125af1000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00005555604df5c8 CR3: 0000000032b06000 CR4: 00000000003526f0
Call Trace:
 IRQ
 __sk_destruct+0x86/0x660 net/core/sock.c:2339
 rcu_do_batch kernel/rcu/tree.c:2605 [inline]
 rcu_core+0xca8/0x1770 kernel/rcu/tree.c:2861
 handle_softirqs+0x286/0x870 kernel/softirq.c:579
 __do_softirq kernel/softirq.c:613 [inline]
 invoke_softirq kernel/softirq.c:453 [inline]
 __irq_exit_rcu+0xca/0x1f0 kernel/softirq.c:680
 irq_exit_rcu+0x9/0x30 kernel/softirq.c:696
 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1052 [inline]
 sysvec_apic_timer_interrupt+0xa6/0xc0 arch/x86/kernel/apic/apic.c:1052
 /IRQ



- [https://github.com/byteReaper77/CVE-2025-39913](https://github.com/byteReaper77/CVE-2025-39913) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-39913.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-39913.svg)

## CVE-2025-39866
 In the Linux kernel, the following vulnerability has been resolved:

fs: writeback: fix use-after-free in __mark_inode_dirty()

An use-after-free issue occurred when __mark_inode_dirty() get the
bdi_writeback that was in the progress of switching.

CPU: 1 PID: 562 Comm: systemd-random- Not tainted 6.6.56-gb4403bd46a8e #1
......
pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : __mark_inode_dirty+0x124/0x418
lr : __mark_inode_dirty+0x118/0x418
sp : ffffffc08c9dbbc0
........
Call trace:
 __mark_inode_dirty+0x124/0x418
 generic_update_time+0x4c/0x60
 file_modified+0xcc/0xd0
 ext4_buffered_write_iter+0x58/0x124
 ext4_file_write_iter+0x54/0x704
 vfs_write+0x1c0/0x308
 ksys_write+0x74/0x10c
 __arm64_sys_write+0x1c/0x28
 invoke_syscall+0x48/0x114
 el0_svc_common.constprop.0+0xc0/0xe0
 do_el0_svc+0x1c/0x28
 el0_svc+0x40/0xe4
 el0t_64_sync_handler+0x120/0x12c
 el0t_64_sync+0x194/0x198

Root cause is:

systemd-random-seed                         kworker
----------------------------------------------------------------------
___mark_inode_dirty                     inode_switch_wbs_work_fn

  spin_lock(&inode-i_lock);
  inode_attach_wb
  locked_inode_to_wb_and_lock_list
     get inode-i_wb
     spin_unlock(&inode-i_lock);
     spin_lock(&wb-list_lock)
  spin_lock(&inode-i_lock)
  inode_io_list_move_locked
  spin_unlock(&wb-list_lock)
  spin_unlock(&inode-i_lock)
                                    spin_lock(&old_wb-list_lock)
                                      inode_do_switch_wbs
                                        spin_lock(&inode-i_lock)
                                        inode-i_wb = new_wb
                                        spin_unlock(&inode-i_lock)
                                    spin_unlock(&old_wb-list_lock)
                                    wb_put_many(old_wb, nr_switched)
                                      cgwb_release
                                      old wb released
  wb_wakeup_delayed() accesses wb,
  then trigger the use-after-free
  issue

Fix this race condition by holding inode spinlock until
wb_wakeup_delayed() finished.



- [https://github.com/byteReaper77/CVE-2025-39866](https://github.com/byteReaper77/CVE-2025-39866) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-39866.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-39866.svg)

## CVE-2025-39682
 In the Linux kernel, the following vulnerability has been resolved:

tls: fix handling of zero-length records on the rx_list

Each recvmsg() call must process either
 - only contiguous DATA records (any number of them)
 - one non-DATA record

If the next record has different type than what has already been
processed we break out of the main processing loop. If the record
has already been decrypted (which may be the case for TLS 1.3 where
we don't know type until decryption) we queue the pending record
to the rx_list. Next recvmsg() will pick it up from there.

Queuing the skb to rx_list after zero-copy decrypt is not possible,
since in that case we decrypted directly to the user space buffer,
and we don't have an skb to queue (darg.skb points to the ciphertext
skb for access to metadata like length).

Only data records are allowed zero-copy, and we break the processing
loop after each non-data record. So we should never zero-copy and
then find out that the record type has changed. The corner case
we missed is when the initial record comes from rx_list, and it's
zero length.



- [https://github.com/khoatran107/cve-2025-39682](https://github.com/khoatran107/cve-2025-39682) :  ![starts](https://img.shields.io/github/stars/khoatran107/cve-2025-39682.svg) ![forks](https://img.shields.io/github/forks/khoatran107/cve-2025-39682.svg)

## CVE-2025-39601
 Cross-Site Request Forgery (CSRF) vulnerability in WPFactory Custom CSS, JS & PHP allows Remote Code Inclusion. This issue affects Custom CSS, JS & PHP: from n/a through 2.4.1.



- [https://github.com/Nxploited/CVE-2025-39601](https://github.com/Nxploited/CVE-2025-39601) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-39601.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-39601.svg)

## CVE-2025-39596
 Weak Authentication vulnerability in Quentn.com GmbH Quentn WP allows Privilege Escalation. This issue affects Quentn WP: from n/a through 1.2.8.



- [https://github.com/Nxploited/CVE-2025-39596](https://github.com/Nxploited/CVE-2025-39596) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-39596.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-39596.svg)

## CVE-2025-39538
 Unrestricted Upload of File with Dangerous Type vulnerability in Mathieu Chartier WP-Advanced-Search allows Upload a Web Shell to a Web Server. This issue affects WP-Advanced-Search: from n/a through 3.3.9.3.



- [https://github.com/Nxploited/CVE-2025-39538](https://github.com/Nxploited/CVE-2025-39538) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-39538.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-39538.svg)

## CVE-2025-39507
 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in NasaTheme Nasa Core allows PHP Local File Inclusion. This issue affects Nasa Core: from n/a through 6.3.2.



- [https://github.com/TheCyberFairy/cve-lfi-lab](https://github.com/TheCyberFairy/cve-lfi-lab) :  ![starts](https://img.shields.io/github/stars/TheCyberFairy/cve-lfi-lab.svg) ![forks](https://img.shields.io/github/forks/TheCyberFairy/cve-lfi-lab.svg)

## CVE-2025-39436
 Unrestricted Upload of File with Dangerous Type vulnerability in aidraw I Draw allows Using Malicious Files. This issue affects I Draw: from n/a through 1.0.



- [https://github.com/Nxploited/CVE-2025-39436](https://github.com/Nxploited/CVE-2025-39436) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-39436.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-39436.svg)

## CVE-2025-38676
 In the Linux kernel, the following vulnerability has been resolved:

iommu/amd: Avoid stack buffer overflow from kernel cmdline

While the kernel command line is considered trusted in most environments,
avoid writing 1 byte past the end of "acpiid" if the "str" argument is
maximum length.



- [https://github.com/14mb1v45h/CVE-2025-38676](https://github.com/14mb1v45h/CVE-2025-38676) :  ![starts](https://img.shields.io/github/stars/14mb1v45h/CVE-2025-38676.svg) ![forks](https://img.shields.io/github/forks/14mb1v45h/CVE-2025-38676.svg)

## CVE-2025-38561
 In the Linux kernel, the following vulnerability has been resolved:

ksmbd: fix Preauh_HashValue race condition

If client send multiple session setup requests to ksmbd,
Preauh_HashValue race condition could happen.
There is no need to free sess-Preauh_HashValue at session setup phase.
It can be freed together with session at connection termination phase.



- [https://github.com/toshithh/CVE-2025-38561](https://github.com/toshithh/CVE-2025-38561) :  ![starts](https://img.shields.io/github/stars/toshithh/CVE-2025-38561.svg) ![forks](https://img.shields.io/github/forks/toshithh/CVE-2025-38561.svg)

## CVE-2025-38501
 In the Linux kernel, the following vulnerability has been resolved:

ksmbd: limit repeated connections from clients with the same IP

Repeated connections from clients with the same IP address may exhaust
the max connections and prevent other normal client connections.
This patch limit repeated connections from clients with the same IP.



- [https://github.com/keymaker-arch/KSMBDrain](https://github.com/keymaker-arch/KSMBDrain) :  ![starts](https://img.shields.io/github/stars/keymaker-arch/KSMBDrain.svg) ![forks](https://img.shields.io/github/forks/keymaker-arch/KSMBDrain.svg)

## CVE-2025-38089
 In the Linux kernel, the following vulnerability has been resolved:

sunrpc: handle SVC_GARBAGE during svc auth processing as auth error

tianshuo han reported a remotely-triggerable crash if the client sends a
kernel RPC server a specially crafted packet. If decoding the RPC reply
fails in such a way that SVC_GARBAGE is returned without setting the
rq_accept_statp pointer, then that pointer can be dereferenced and a
value stored there.

If it's the first time the thread has processed an RPC, then that
pointer will be set to NULL and the kernel will crash. In other cases,
it could create a memory scribble.

The server sunrpc code treats a SVC_GARBAGE return from svc_authenticate
or pg_authenticate as if it should send a GARBAGE_ARGS reply. RFC 5531
says that if authentication fails that the RPC should be rejected
instead with a status of AUTH_ERR.

Handle a SVC_GARBAGE return as an AUTH_ERROR, with a reason of
AUTH_BADCRED instead of returning GARBAGE_ARGS in that case. This
sidesteps the whole problem of touching the rpc_accept_statp pointer in
this situation and avoids the crash.



- [https://github.com/keymaker-arch/NFSundown](https://github.com/keymaker-arch/NFSundown) :  ![starts](https://img.shields.io/github/stars/keymaker-arch/NFSundown.svg) ![forks](https://img.shields.io/github/forks/keymaker-arch/NFSundown.svg)

## CVE-2025-38001
 In the Linux kernel, the following vulnerability has been resolved:

net_sched: hfsc: Address reentrant enqueue adding class to eltree twice

Savino says:
    "We are writing to report that this recent patch
    (141d34391abbb315d68556b7c67ad97885407547) [1]
    can be bypassed, and a UAF can still occur when HFSC is utilized with
    NETEM.

    The patch only checks the cl-cl_nactive field to determine whether
    it is the first insertion or not [2], but this field is only
    incremented by init_vf [3].

    By using HFSC_RSC (which uses init_ed) [4], it is possible to bypass the
    check and insert the class twice in the eltree.
    Under normal conditions, this would lead to an infinite loop in
    hfsc_dequeue for the reasons we already explained in this report [5].

    However, if TBF is added as root qdisc and it is configured with a
    very low rate,
    it can be utilized to prevent packets from being dequeued.
    This behavior can be exploited to perform subsequent insertions in the
    HFSC eltree and cause a UAF."

To fix both the UAF and the infinite loop, with netem as an hfsc child,
check explicitly in hfsc_enqueue whether the class is already in the eltree
whenever the HFSC_RSC flag is set.

[1] https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=141d34391abbb315d68556b7c67ad97885407547
[2] https://elixir.bootlin.com/linux/v6.15-rc5/source/net/sched/sch_hfsc.c#L1572
[3] https://elixir.bootlin.com/linux/v6.15-rc5/source/net/sched/sch_hfsc.c#L677
[4] https://elixir.bootlin.com/linux/v6.15-rc5/source/net/sched/sch_hfsc.c#L1574
[5] https://lore.kernel.org/netdev/8DuRWwfqjoRDLDmBMlIfbrsZg9Gx50DHJc1ilxsEBNe2D6NMoigR_eIRIG0LOjMc3r10nUUZtArXx4oZBIdUfZQrwjcQhdinnMis_0G7VEk=@willsroot.io/T/#u



- [https://github.com/0xdevil/CVE-2025-38001](https://github.com/0xdevil/CVE-2025-38001) :  ![starts](https://img.shields.io/github/stars/0xdevil/CVE-2025-38001.svg) ![forks](https://img.shields.io/github/forks/0xdevil/CVE-2025-38001.svg)

- [https://github.com/khoatran107/cve-2025-38001](https://github.com/khoatran107/cve-2025-38001) :  ![starts](https://img.shields.io/github/stars/khoatran107/cve-2025-38001.svg) ![forks](https://img.shields.io/github/forks/khoatran107/cve-2025-38001.svg)

- [https://github.com/ngobao2002/CVE-2025-38001-test](https://github.com/ngobao2002/CVE-2025-38001-test) :  ![starts](https://img.shields.io/github/stars/ngobao2002/CVE-2025-38001-test.svg) ![forks](https://img.shields.io/github/forks/ngobao2002/CVE-2025-38001-test.svg)

## CVE-2025-37947
 In the Linux kernel, the following vulnerability has been resolved:

ksmbd: prevent out-of-bounds stream writes by validating *pos

ksmbd_vfs_stream_write() did not validate whether the write offset
(*pos) was within the bounds of the existing stream data length (v_len).
If *pos was greater than or equal to v_len, this could lead to an
out-of-bounds memory write.

This patch adds a check to ensure *pos is less than v_len before
proceeding. If the condition fails, -EINVAL is returned.



- [https://github.com/doyensec/KSMBD-CVE-2025-37947](https://github.com/doyensec/KSMBD-CVE-2025-37947) :  ![starts](https://img.shields.io/github/stars/doyensec/KSMBD-CVE-2025-37947.svg) ![forks](https://img.shields.io/github/forks/doyensec/KSMBD-CVE-2025-37947.svg)

## CVE-2025-37899
 In the Linux kernel, the following vulnerability has been resolved:

ksmbd: fix use-after-free in session logoff

The sess-user object can currently be in use by another thread, for
example if another connection has sent a session setup request to
bind to the session being free'd. The handler for that connection could
be in the smb2_sess_setup function which makes use of sess-user.



- [https://github.com/SeanHeelan/o3_finds_cve-2025-37899](https://github.com/SeanHeelan/o3_finds_cve-2025-37899) :  ![starts](https://img.shields.io/github/stars/SeanHeelan/o3_finds_cve-2025-37899.svg) ![forks](https://img.shields.io/github/forks/SeanHeelan/o3_finds_cve-2025-37899.svg)

- [https://github.com/vett3x/SMB-LINUX-CVE-2025-37899](https://github.com/vett3x/SMB-LINUX-CVE-2025-37899) :  ![starts](https://img.shields.io/github/stars/vett3x/SMB-LINUX-CVE-2025-37899.svg) ![forks](https://img.shields.io/github/forks/vett3x/SMB-LINUX-CVE-2025-37899.svg)

## CVE-2025-36604
 Dell Unity, version(s) 5.5 and prior, contain(s) an Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability. An unauthenticated attacker with remote access could potentially exploit this vulnerability, leading to arbitrary command execution.



- [https://github.com/watchtowrlabs/watchTowr-vs-Dell-UnityVSA-PreAuth-CVE-2025-36604](https://github.com/watchtowrlabs/watchTowr-vs-Dell-UnityVSA-PreAuth-CVE-2025-36604) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Dell-UnityVSA-PreAuth-CVE-2025-36604.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Dell-UnityVSA-PreAuth-CVE-2025-36604.svg)

## CVE-2025-36041
 IBM MQ Operator LTS 2.0.0 through 2.0.29, MQ Operator CD 3.0.0, 3.0.1, 3.1.0 through 3.1.3, 3.3.0, 3.4.0, 3.4.1, 3.5.0, 3.5.1 through 3.5.3, and MQ Operator SC2 3.2.0 through 3.2.12 Native HA CRR could be configured with a private key and chain other than the intended key which could disclose sensitive information or allow the attacker to perform unauthorized actions.



- [https://github.com/byteReaper77/CVE-2025-36041](https://github.com/byteReaper77/CVE-2025-36041) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-36041.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-36041.svg)

## CVE-2025-34300
 A template injection vulnerability exists in Sawtooth Software’s Lighthouse Studio versions prior to 9.16.14 via the  ciwweb.pl http://ciwweb.pl/  Perl web application. Exploitation allows an unauthenticated attacker can execute arbitrary commands.



- [https://github.com/jisi-001/CVE-2025-34300POC](https://github.com/jisi-001/CVE-2025-34300POC) :  ![starts](https://img.shields.io/github/stars/jisi-001/CVE-2025-34300POC.svg) ![forks](https://img.shields.io/github/forks/jisi-001/CVE-2025-34300POC.svg)

## CVE-2025-34226
 OpenPLC Runtime v3 contains an input validation flaw in the /upload-program-action endpoint: the epoch_time field supplied during program uploads is not validated and can be crafted to induce corruption of the programs database. After a successful malformed upload the runtime continues to operate until a restart; on restart the runtime can fail to start because of corrupted database entries, resulting in persistent denial of service requiring complete rebase of the product to recover. This vulnerability was remediated by commit 095ee09623dd229b64ad3a1db38a901a3772f6fc.



- [https://github.com/Eyodav/CVE-2025-34226](https://github.com/Eyodav/CVE-2025-34226) :  ![starts](https://img.shields.io/github/stars/Eyodav/CVE-2025-34226.svg) ![forks](https://img.shields.io/github/forks/Eyodav/CVE-2025-34226.svg)

## CVE-2025-34161
 Coolify versions prior to v4.0.0-beta.420.7 are vulnerable to a remote code execution vulnerability in the project deployment workflow. The platform allows authenticated users, with low-level member privileges, to inject arbitrary shell commands via the Git Repository field during project creation. By submitting a crafted repository string containing command injection syntax, an attacker can execute arbitrary commands on the underlying host system, resulting in full server compromise.



- [https://github.com/Eyodav/CVE-2025-34161](https://github.com/Eyodav/CVE-2025-34161) :  ![starts](https://img.shields.io/github/stars/Eyodav/CVE-2025-34161.svg) ![forks](https://img.shields.io/github/forks/Eyodav/CVE-2025-34161.svg)

## CVE-2025-34159
 Coolify versions prior to v4.0.0-beta.420.6 are vulnerable to a remote code execution vulnerability in the application deployment workflow. The platform allows authenticated users, with low-level member privileges, to inject arbitrary Docker Compose directives during project creation. By crafting a malicious service definition that mounts the host root filesystem, an attacker can gain full root access to the underlying server.



- [https://github.com/Eyodav/CVE-2025-34159](https://github.com/Eyodav/CVE-2025-34159) :  ![starts](https://img.shields.io/github/stars/Eyodav/CVE-2025-34159.svg) ![forks](https://img.shields.io/github/forks/Eyodav/CVE-2025-34159.svg)

## CVE-2025-34157
 Coolify versions prior to v4.0.0-beta.420.6 are vulnerable to a stored cross-site scripting (XSS) attack in the project creation workflow. An authenticated user with low privileges can create a project with a maliciously crafted name containing embedded JavaScript. When an administrator attempts to delete the project or its associated resource, the payload executes in the admin’s browser context. This results in full compromise of the Coolify instance, including theft of API tokens, session cookies, and access to WebSocket-based terminal sessions on managed servers.



- [https://github.com/Eyodav/CVE-2025-34157](https://github.com/Eyodav/CVE-2025-34157) :  ![starts](https://img.shields.io/github/stars/Eyodav/CVE-2025-34157.svg) ![forks](https://img.shields.io/github/forks/Eyodav/CVE-2025-34157.svg)

## CVE-2025-34152
 An unauthenticated OS command injection vulnerability exists in the Shenzhen Aitemi M300 Wi-Fi Repeater (hardware model MT02) via the 'time' parameter of the '/protocol.csp?' endpoint. The input is processed by the internal date '-s' command without rebooting or disrupting HTTP service. Unlike other injection points, this vector allows remote compromise without triggering visible configuration changes.



- [https://github.com/Chocapikk/CVE-2025-34152](https://github.com/Chocapikk/CVE-2025-34152) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-34152.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-34152.svg)

- [https://github.com/kh4sh3i/CVE-2025-34152](https://github.com/kh4sh3i/CVE-2025-34152) :  ![starts](https://img.shields.io/github/stars/kh4sh3i/CVE-2025-34152.svg) ![forks](https://img.shields.io/github/forks/kh4sh3i/CVE-2025-34152.svg)

## CVE-2025-34100
 An unrestricted file upload vulnerability exists in BuilderEngine 3.5.0 via the integration of the elFinder 2.0 file manager and its use of the jQuery File Upload plugin. The plugin fails to properly validate or restrict file types or locations during upload operations, allowing an attacker to upload a malicious .php file and subsequently execute arbitrary PHP code on the server under the context of the web server process. While the root vulnerability lies within the jQuery File Upload component, BuilderEngine’s improper integration and lack of access controls expose this functionality to unauthenticated users, resulting in full remote code execution.



- [https://github.com/hyeonyeonglee/CVE-2025-34100](https://github.com/hyeonyeonglee/CVE-2025-34100) :  ![starts](https://img.shields.io/github/stars/hyeonyeonglee/CVE-2025-34100.svg) ![forks](https://img.shields.io/github/forks/hyeonyeonglee/CVE-2025-34100.svg)

- [https://github.com/RyanJohnJames/CVE-2025-34100-demo](https://github.com/RyanJohnJames/CVE-2025-34100-demo) :  ![starts](https://img.shields.io/github/stars/RyanJohnJames/CVE-2025-34100-demo.svg) ![forks](https://img.shields.io/github/forks/RyanJohnJames/CVE-2025-34100-demo.svg)

## CVE-2025-34085
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority as it is a duplicate of CVE-2020-36847.



- [https://github.com/ill-deed/CVE-2025-34085-Multi-target](https://github.com/ill-deed/CVE-2025-34085-Multi-target) :  ![starts](https://img.shields.io/github/stars/ill-deed/CVE-2025-34085-Multi-target.svg) ![forks](https://img.shields.io/github/forks/ill-deed/CVE-2025-34085-Multi-target.svg)

- [https://github.com/yukinime/CVE-2025-34085](https://github.com/yukinime/CVE-2025-34085) :  ![starts](https://img.shields.io/github/stars/yukinime/CVE-2025-34085.svg) ![forks](https://img.shields.io/github/forks/yukinime/CVE-2025-34085.svg)

- [https://github.com/MrjHaxcore/CVE-2025-34085](https://github.com/MrjHaxcore/CVE-2025-34085) :  ![starts](https://img.shields.io/github/stars/MrjHaxcore/CVE-2025-34085.svg) ![forks](https://img.shields.io/github/forks/MrjHaxcore/CVE-2025-34085.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-34085](https://github.com/B1ack4sh/Blackash-CVE-2025-34085) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-34085.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-34085.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-34085](https://github.com/0xgh057r3c0n/CVE-2025-34085) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-34085.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-34085.svg)

## CVE-2025-34077
 An authentication bypass vulnerability exists in the WordPress Pie Register plugin ≤ 3.7.1.4 that allows unauthenticated attackers to impersonate arbitrary users by submitting a crafted POST request to the login endpoint. By setting social_site=true and manipulating the user_id_social_site parameter, an attacker can generate a valid WordPress session cookie for any user ID, including administrators. Once authenticated, the attacker may exploit plugin upload functionality to install a malicious plugin containing arbitrary PHP code, resulting in remote code execution on the underlying server.



- [https://github.com/MrjHaxcore/CVE-2025-34077](https://github.com/MrjHaxcore/CVE-2025-34077) :  ![starts](https://img.shields.io/github/stars/MrjHaxcore/CVE-2025-34077.svg) ![forks](https://img.shields.io/github/forks/MrjHaxcore/CVE-2025-34077.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-34077](https://github.com/0xgh057r3c0n/CVE-2025-34077) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-34077.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-34077.svg)

## CVE-2025-34040
 An arbitrary file upload vulnerability exists in the Zhiyuan OA platform via the wpsAssistServlet interface. The realFileType and fileId parameters are improperly validated during multipart file uploads, allowing unauthenticated attackers to upload crafted JSP files outside of intended directories using path traversal. Successful exploitation enables remote code execution as the uploaded file can be accessed and executed through the web server.



- [https://github.com/jisi-001/CVE-2025-34040Exp](https://github.com/jisi-001/CVE-2025-34040Exp) :  ![starts](https://img.shields.io/github/stars/jisi-001/CVE-2025-34040Exp.svg) ![forks](https://img.shields.io/github/forks/jisi-001/CVE-2025-34040Exp.svg)

## CVE-2025-34036
 An OS command injection vulnerability exists in white-labeled DVRs manufactured by TVT, affecting a custom HTTP service called "Cross Web Server" that listens on TCP ports 81 and 82. The web interface fails to sanitize input in the URI path passed to the language extraction functionality. When the server processes a request to /language/[lang]/index.html, it uses the [lang] input unsafely in a tar extraction command without proper escaping. This allows an unauthenticated remote attacker to inject shell commands and achieve arbitrary command execution as root.



- [https://github.com/Prabhukiran161/cve-2025-34036](https://github.com/Prabhukiran161/cve-2025-34036) :  ![starts](https://img.shields.io/github/stars/Prabhukiran161/cve-2025-34036.svg) ![forks](https://img.shields.io/github/forks/Prabhukiran161/cve-2025-34036.svg)

## CVE-2025-34030
 An OS command injection vulnerability exists in sar2html version 3.2.2 and prior via the plot parameter in index.php. The application fails to sanitize user-supplied input before using it in a system-level context. Remote, unauthenticated attackers can inject shell commands by appending them to the plot parameter (e.g., ?plot=;id) in a crafted GET request. The output of the command is displayed in the application's interface after interacting with the host selection UI. Successful exploitation leads to arbitrary command execution on the underlying system.



- [https://github.com/HackerTyperAbuser/CVE-2025-34030-PoC](https://github.com/HackerTyperAbuser/CVE-2025-34030-PoC) :  ![starts](https://img.shields.io/github/stars/HackerTyperAbuser/CVE-2025-34030-PoC.svg) ![forks](https://img.shields.io/github/forks/HackerTyperAbuser/CVE-2025-34030-PoC.svg)

## CVE-2025-34028
 The Commvault Command Center Innovation Release allows an unauthenticated actor to upload ZIP files that represent install packages that, when expanded by the target server, are vulnerable to path traversal vulnerability that can result in Remote Code Execution via malicious JSP.





This issue affects Command Center Innovation Release: 11.38.0 to 11.38.20. The vulnerability is fixed in 11.38.20 with SP38-CU20-433 and SP38-CU20-436 and also fixed in 11.38.25 with SP38-CU25-434 and SP38-CU25-438.



- [https://github.com/watchtowrlabs/watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028](https://github.com/watchtowrlabs/watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028.svg)

- [https://github.com/Mattb709/CVE-2025-34028-PoC-Commvault-RCE](https://github.com/Mattb709/CVE-2025-34028-PoC-Commvault-RCE) :  ![starts](https://img.shields.io/github/stars/Mattb709/CVE-2025-34028-PoC-Commvault-RCE.svg) ![forks](https://img.shields.io/github/forks/Mattb709/CVE-2025-34028-PoC-Commvault-RCE.svg)

- [https://github.com/becrevex/Commvault-CVE-2025-34028](https://github.com/becrevex/Commvault-CVE-2025-34028) :  ![starts](https://img.shields.io/github/stars/becrevex/Commvault-CVE-2025-34028.svg) ![forks](https://img.shields.io/github/forks/becrevex/Commvault-CVE-2025-34028.svg)

- [https://github.com/tinkerlev/commvault-cve2025-34028-check](https://github.com/tinkerlev/commvault-cve2025-34028-check) :  ![starts](https://img.shields.io/github/stars/tinkerlev/commvault-cve2025-34028-check.svg) ![forks](https://img.shields.io/github/forks/tinkerlev/commvault-cve2025-34028-check.svg)

## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.



- [https://github.com/mverschu/CVE-2025-33073](https://github.com/mverschu/CVE-2025-33073) :  ![starts](https://img.shields.io/github/stars/mverschu/CVE-2025-33073.svg) ![forks](https://img.shields.io/github/forks/mverschu/CVE-2025-33073.svg)

- [https://github.com/SellMeFish/windows-smb-vulnerability-framework-cve-2025-33073](https://github.com/SellMeFish/windows-smb-vulnerability-framework-cve-2025-33073) :  ![starts](https://img.shields.io/github/stars/SellMeFish/windows-smb-vulnerability-framework-cve-2025-33073.svg) ![forks](https://img.shields.io/github/forks/SellMeFish/windows-smb-vulnerability-framework-cve-2025-33073.svg)

- [https://github.com/obscura-cert/CVE-2025-33073](https://github.com/obscura-cert/CVE-2025-33073) :  ![starts](https://img.shields.io/github/stars/obscura-cert/CVE-2025-33073.svg) ![forks](https://img.shields.io/github/forks/obscura-cert/CVE-2025-33073.svg)

- [https://github.com/cve-2025-33073/cve-2025-33073](https://github.com/cve-2025-33073/cve-2025-33073) :  ![starts](https://img.shields.io/github/stars/cve-2025-33073/cve-2025-33073.svg) ![forks](https://img.shields.io/github/forks/cve-2025-33073/cve-2025-33073.svg)

- [https://github.com/sleepasleepzzz/CVE-2025-33073](https://github.com/sleepasleepzzz/CVE-2025-33073) :  ![starts](https://img.shields.io/github/stars/sleepasleepzzz/CVE-2025-33073.svg) ![forks](https://img.shields.io/github/forks/sleepasleepzzz/CVE-2025-33073.svg)

- [https://github.com/matejsmycka/CVE-2025-33073-checker](https://github.com/matejsmycka/CVE-2025-33073-checker) :  ![starts](https://img.shields.io/github/stars/matejsmycka/CVE-2025-33073-checker.svg) ![forks](https://img.shields.io/github/forks/matejsmycka/CVE-2025-33073-checker.svg)

## CVE-2025-33053
 External control of file name or path in Internet Shortcut Files allows an unauthorized attacker to execute code over a network.



- [https://github.com/DevBuiHieu/CVE-2025-33053-Proof-Of-Concept](https://github.com/DevBuiHieu/CVE-2025-33053-Proof-Of-Concept) :  ![starts](https://img.shields.io/github/stars/DevBuiHieu/CVE-2025-33053-Proof-Of-Concept.svg) ![forks](https://img.shields.io/github/forks/DevBuiHieu/CVE-2025-33053-Proof-Of-Concept.svg)

- [https://github.com/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept](https://github.com/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept) :  ![starts](https://img.shields.io/github/stars/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept.svg) ![forks](https://img.shields.io/github/forks/kra1t0/CVE-2025-33053-WebDAV-RCE-PoC-and-C2-Concept.svg)

- [https://github.com/TheTorjanCaptain/CVE-2025-33053-Checker-PoC](https://github.com/TheTorjanCaptain/CVE-2025-33053-Checker-PoC) :  ![starts](https://img.shields.io/github/stars/TheTorjanCaptain/CVE-2025-33053-Checker-PoC.svg) ![forks](https://img.shields.io/github/forks/TheTorjanCaptain/CVE-2025-33053-Checker-PoC.svg)

- [https://github.com/4n4s4zi/CVE-2025-33053_PoC](https://github.com/4n4s4zi/CVE-2025-33053_PoC) :  ![starts](https://img.shields.io/github/stars/4n4s4zi/CVE-2025-33053_PoC.svg) ![forks](https://img.shields.io/github/forks/4n4s4zi/CVE-2025-33053_PoC.svg)

## CVE-2025-32965
 xrpl.js is a JavaScript/TypeScript API for interacting with the XRP Ledger in Node.js and the browser. Versions 4.2.1, 4.2.2, 4.2.3, and 4.2.4 of xrpl.js were compromised and contained malicious code designed to exfiltrate private keys. Version 2.14.2 is also malicious, though it is less likely to lead to exploitation as it is not compatible with other 2.x versions. Anyone who used one of these versions should stop immediately and rotate any private keys or secrets used with affected systems. Users of xrpl.js should pgrade to version 4.2.5 or 2.14.3 to receive a patch. To secure funds, think carefully about whether any keys may have been compromised by this supply chain attack, and mitigate by sending funds to secure wallets, and/or rotating keys. If any account's master key is potentially compromised, disable the key.



- [https://github.com/yusufdalbudak/CVE-2025-32965-xrpl-js-poc](https://github.com/yusufdalbudak/CVE-2025-32965-xrpl-js-poc) :  ![starts](https://img.shields.io/github/stars/yusufdalbudak/CVE-2025-32965-xrpl-js-poc.svg) ![forks](https://img.shields.io/github/forks/yusufdalbudak/CVE-2025-32965-xrpl-js-poc.svg)

## CVE-2025-32942
 SSH Tectia Server before 6.6.6 sometimes allows attackers to read and alter a user's session traffic.



- [https://github.com/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts](https://github.com/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts) :  ![starts](https://img.shields.io/github/stars/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts.svg) ![forks](https://img.shields.io/github/forks/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts.svg)

## CVE-2025-32873
 An issue was discovered in Django 4.2 before 4.2.21, 5.1 before 5.1.9, and 5.2 before 5.2.1. The django.utils.html.strip_tags() function is vulnerable to a potential denial-of-service (slow performance) when processing inputs containing large sequences of incomplete HTML tags. The template filter striptags is also vulnerable, because it is built on top of strip_tags().



- [https://github.com/Apollo-R3bot/django-vulnerability-CVE-2025-32873](https://github.com/Apollo-R3bot/django-vulnerability-CVE-2025-32873) :  ![starts](https://img.shields.io/github/stars/Apollo-R3bot/django-vulnerability-CVE-2025-32873.svg) ![forks](https://img.shields.io/github/forks/Apollo-R3bot/django-vulnerability-CVE-2025-32873.svg)

## CVE-2025-32778
 Web-Check is an all-in-one OSINT tool for analyzing any website. A command injection vulnerability exists in the screenshot API of the Web Check project (Lissy93/web-check). The issue stems from user-controlled input (url) being passed unsanitized into a shell command using exec(), allowing attackers to execute arbitrary system commands on the underlying host. This could be exploited by sending crafted url parameters to extract files or even establish remote access. The vulnerability has been patched by replacing exec() with execFile(), which avoids using a shell and properly isolates arguments.



- [https://github.com/00xCanelo/CVE-2025-32778](https://github.com/00xCanelo/CVE-2025-32778) :  ![starts](https://img.shields.io/github/stars/00xCanelo/CVE-2025-32778.svg) ![forks](https://img.shields.io/github/forks/00xCanelo/CVE-2025-32778.svg)

## CVE-2025-32756
 A stack-based buffer overflow vulnerability [CWE-121] in Fortinet FortiVoice versions 7.2.0, 7.0.0 through 7.0.6, 6.4.0 through 6.4.10, FortiRecorder versions 7.2.0 through 7.2.3, 7.0.0 through 7.0.5, 6.4.0 through 6.4.5, FortiMail versions 7.6.0 through 7.6.2, 7.4.0 through 7.4.4, 7.2.0 through 7.2.7, 7.0.0 through 7.0.8, FortiNDR versions 7.6.0, 7.4.0 through 7.4.7, 7.2.0 through 7.2.4, 7.0.0 through 7.0.6, FortiCamera versions 2.1.0 through 2.1.3, 2.0 all versions, 1.1 all versions, allows a remote unauthenticated attacker to execute arbitrary code or commands via sending HTTP requests with specially crafted hash cookie.



- [https://github.com/kn0x0x/CVE-2025-32756-POC](https://github.com/kn0x0x/CVE-2025-32756-POC) :  ![starts](https://img.shields.io/github/stars/kn0x0x/CVE-2025-32756-POC.svg) ![forks](https://img.shields.io/github/forks/kn0x0x/CVE-2025-32756-POC.svg)

- [https://github.com/exfil0/CVE-2025-32756-POC](https://github.com/exfil0/CVE-2025-32756-POC) :  ![starts](https://img.shields.io/github/stars/exfil0/CVE-2025-32756-POC.svg) ![forks](https://img.shields.io/github/forks/exfil0/CVE-2025-32756-POC.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-32756](https://github.com/B1ack4sh/Blackash-CVE-2025-32756) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-32756.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-32756.svg)

- [https://github.com/becrevex/CVE-2025-32756](https://github.com/becrevex/CVE-2025-32756) :  ![starts](https://img.shields.io/github/stars/becrevex/CVE-2025-32756.svg) ![forks](https://img.shields.io/github/forks/becrevex/CVE-2025-32756.svg)

- [https://github.com/shan0ar/cve-2025-32756](https://github.com/shan0ar/cve-2025-32756) :  ![starts](https://img.shields.io/github/stars/shan0ar/cve-2025-32756.svg) ![forks](https://img.shields.io/github/forks/shan0ar/cve-2025-32756.svg)

- [https://github.com/alm6no5/CVE-2025-32756-POC](https://github.com/alm6no5/CVE-2025-32756-POC) :  ![starts](https://img.shields.io/github/stars/alm6no5/CVE-2025-32756-POC.svg) ![forks](https://img.shields.io/github/forks/alm6no5/CVE-2025-32756-POC.svg)

## CVE-2025-32711
 Ai command injection in M365 Copilot allows an unauthorized attacker to disclose information over a network.



- [https://github.com/daryllundy/cve-2025-32711](https://github.com/daryllundy/cve-2025-32711) :  ![starts](https://img.shields.io/github/stars/daryllundy/cve-2025-32711.svg) ![forks](https://img.shields.io/github/forks/daryllundy/cve-2025-32711.svg)

## CVE-2025-32710
 Use after free in Windows Remote Desktop Services allows an unauthorized attacker to execute code over a network.



- [https://github.com/Sincan2/RCE-CVE-2025-32710](https://github.com/Sincan2/RCE-CVE-2025-32710) :  ![starts](https://img.shields.io/github/stars/Sincan2/RCE-CVE-2025-32710.svg) ![forks](https://img.shields.io/github/forks/Sincan2/RCE-CVE-2025-32710.svg)

## CVE-2025-32709
 Use after free in Windows Ancillary Function Driver for WinSock allows an authorized attacker to elevate privileges locally.



- [https://github.com/AdnanSiyat/How-to-Patch-CVE-2025-32709](https://github.com/AdnanSiyat/How-to-Patch-CVE-2025-32709) :  ![starts](https://img.shields.io/github/stars/AdnanSiyat/How-to-Patch-CVE-2025-32709.svg) ![forks](https://img.shields.io/github/forks/AdnanSiyat/How-to-Patch-CVE-2025-32709.svg)

## CVE-2025-32682
 Unrestricted Upload of File with Dangerous Type vulnerability in RomanCode MapSVG Lite allows Upload a Web Shell to a Web Server. This issue affects MapSVG Lite: from n/a through 8.5.34.



- [https://github.com/Nxploited/CVE-2025-32682](https://github.com/Nxploited/CVE-2025-32682) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-32682.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-32682.svg)

## CVE-2025-32641
 Cross-Site Request Forgery (CSRF) vulnerability in anantaddons Anant Addons for Elementor allows Cross Site Request Forgery. This issue affects Anant Addons for Elementor: from n/a through 1.1.5.



- [https://github.com/Nxploited/CVE-2025-32641](https://github.com/Nxploited/CVE-2025-32641) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-32641.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-32641.svg)

## CVE-2025-32583
 Improper Control of Generation of Code ('Code Injection') vulnerability in termel PDF 2 Post allows Remote Code Inclusion. This issue affects PDF 2 Post: from n/a through 2.4.0.



- [https://github.com/Nxploited/CVE-2025-32583](https://github.com/Nxploited/CVE-2025-32583) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-32583.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-32583.svg)

- [https://github.com/GadaLuBau1337/CVE-2025-32583](https://github.com/GadaLuBau1337/CVE-2025-32583) :  ![starts](https://img.shields.io/github/stars/GadaLuBau1337/CVE-2025-32583.svg) ![forks](https://img.shields.io/github/forks/GadaLuBau1337/CVE-2025-32583.svg)

## CVE-2025-32579
 Unrestricted Upload of File with Dangerous Type vulnerability in SoftClever Limited Sync Posts allows Upload a Web Shell to a Web Server. This issue affects Sync Posts: from n/a through 1.0.



- [https://github.com/Nxploited/CVE-2025-32579](https://github.com/Nxploited/CVE-2025-32579) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-32579.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-32579.svg)

## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.



- [https://github.com/pr0v3rbs/CVE-2025-32463_chwoot](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) :  ![starts](https://img.shields.io/github/stars/pr0v3rbs/CVE-2025-32463_chwoot.svg) ![forks](https://img.shields.io/github/forks/pr0v3rbs/CVE-2025-32463_chwoot.svg)

- [https://github.com/kh4sh3i/CVE-2025-32463](https://github.com/kh4sh3i/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/kh4sh3i/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/kh4sh3i/CVE-2025-32463.svg)

- [https://github.com/MohamedKarrab/CVE-2025-32463](https://github.com/MohamedKarrab/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/MohamedKarrab/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/MohamedKarrab/CVE-2025-32463.svg)

- [https://github.com/K1tt3h/CVE-2025-32463-POC](https://github.com/K1tt3h/CVE-2025-32463-POC) :  ![starts](https://img.shields.io/github/stars/K1tt3h/CVE-2025-32463-POC.svg) ![forks](https://img.shields.io/github/forks/K1tt3h/CVE-2025-32463-POC.svg)

- [https://github.com/mirchr/CVE-2025-32463-sudo-chwoot](https://github.com/mirchr/CVE-2025-32463-sudo-chwoot) :  ![starts](https://img.shields.io/github/stars/mirchr/CVE-2025-32463-sudo-chwoot.svg) ![forks](https://img.shields.io/github/forks/mirchr/CVE-2025-32463-sudo-chwoot.svg)

- [https://github.com/Nowafen/CVE-2025-32463](https://github.com/Nowafen/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/Nowafen/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/Nowafen/CVE-2025-32463.svg)

- [https://github.com/junxian428/CVE-2025-32463](https://github.com/junxian428/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/junxian428/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/junxian428/CVE-2025-32463.svg)

- [https://github.com/IC3-512/linux-root-kit](https://github.com/IC3-512/linux-root-kit) :  ![starts](https://img.shields.io/github/stars/IC3-512/linux-root-kit.svg) ![forks](https://img.shields.io/github/forks/IC3-512/linux-root-kit.svg)

- [https://github.com/zinzloun/CVE-2025-32463](https://github.com/zinzloun/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/zinzloun/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/zinzloun/CVE-2025-32463.svg)

- [https://github.com/FreeDurok/CVE-2025-32463-PoC](https://github.com/FreeDurok/CVE-2025-32463-PoC) :  ![starts](https://img.shields.io/github/stars/FreeDurok/CVE-2025-32463-PoC.svg) ![forks](https://img.shields.io/github/forks/FreeDurok/CVE-2025-32463-PoC.svg)

- [https://github.com/MAAYTHM/CVE-2025-32462_32463-Lab](https://github.com/MAAYTHM/CVE-2025-32462_32463-Lab) :  ![starts](https://img.shields.io/github/stars/MAAYTHM/CVE-2025-32462_32463-Lab.svg) ![forks](https://img.shields.io/github/forks/MAAYTHM/CVE-2025-32462_32463-Lab.svg)

- [https://github.com/behnamvanda/CVE-2025-32463](https://github.com/behnamvanda/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/behnamvanda/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/behnamvanda/CVE-2025-32463.svg)

- [https://github.com/SysMancer/CVE-2025-32463](https://github.com/SysMancer/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/SysMancer/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/SysMancer/CVE-2025-32463.svg)

- [https://github.com/K3ysTr0K3R/CVE-2025-32463-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2025-32463-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2025-32463-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2025-32463-EXPLOIT.svg)

- [https://github.com/y4ney/CVE-2025-32463-lab](https://github.com/y4ney/CVE-2025-32463-lab) :  ![starts](https://img.shields.io/github/stars/y4ney/CVE-2025-32463-lab.svg) ![forks](https://img.shields.io/github/forks/y4ney/CVE-2025-32463-lab.svg)

- [https://github.com/Maalfer/Sudo-CVE-2021-3156](https://github.com/Maalfer/Sudo-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Maalfer/Sudo-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Maalfer/Sudo-CVE-2021-3156.svg)

- [https://github.com/AdityaBhatt3010/Sudo-Privilege-Escalation-Linux-CVE-2025-32463-and-CVE-2025-32462](https://github.com/AdityaBhatt3010/Sudo-Privilege-Escalation-Linux-CVE-2025-32463-and-CVE-2025-32462) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/Sudo-Privilege-Escalation-Linux-CVE-2025-32463-and-CVE-2025-32462.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/Sudo-Privilege-Escalation-Linux-CVE-2025-32463-and-CVE-2025-32462.svg)

- [https://github.com/nflatrea/CVE-2025-32463](https://github.com/nflatrea/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/nflatrea/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/nflatrea/CVE-2025-32463.svg)

- [https://github.com/pevinkumar10/CVE-2025-32463](https://github.com/pevinkumar10/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/pevinkumar10/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/pevinkumar10/CVE-2025-32463.svg)

- [https://github.com/KaiHT-Ladiant/CVE-2025-32463](https://github.com/KaiHT-Ladiant/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/KaiHT-Ladiant/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/KaiHT-Ladiant/CVE-2025-32463.svg)

- [https://github.com/Yuy0ung/CVE-2025-32463_chwoot](https://github.com/Yuy0ung/CVE-2025-32463_chwoot) :  ![starts](https://img.shields.io/github/stars/Yuy0ung/CVE-2025-32463_chwoot.svg) ![forks](https://img.shields.io/github/forks/Yuy0ung/CVE-2025-32463_chwoot.svg)

- [https://github.com/4f-kira/CVE-2025-32463](https://github.com/4f-kira/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/4f-kira/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/4f-kira/CVE-2025-32463.svg)

- [https://github.com/abrewer251/CVE-2025-32463_Sudo_PoC](https://github.com/abrewer251/CVE-2025-32463_Sudo_PoC) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-32463_Sudo_PoC.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-32463_Sudo_PoC.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-32463](https://github.com/B1ack4sh/Blackash-CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-32463.svg)

- [https://github.com/SpongeBob-369/cve-2025-32463](https://github.com/SpongeBob-369/cve-2025-32463) :  ![starts](https://img.shields.io/github/stars/SpongeBob-369/cve-2025-32463.svg) ![forks](https://img.shields.io/github/forks/SpongeBob-369/cve-2025-32463.svg)

- [https://github.com/7r00t/cve-2025-32463-lab](https://github.com/7r00t/cve-2025-32463-lab) :  ![starts](https://img.shields.io/github/stars/7r00t/cve-2025-32463-lab.svg) ![forks](https://img.shields.io/github/forks/7r00t/cve-2025-32463-lab.svg)

- [https://github.com/0xb0rn3/CVE-2025-32463-EXPLOIT](https://github.com/0xb0rn3/CVE-2025-32463-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/0xb0rn3/CVE-2025-32463-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/0xb0rn3/CVE-2025-32463-EXPLOIT.svg)

- [https://github.com/cybershaolin47/CVE-2025-32463_POC](https://github.com/cybershaolin47/CVE-2025-32463_POC) :  ![starts](https://img.shields.io/github/stars/cybershaolin47/CVE-2025-32463_POC.svg) ![forks](https://img.shields.io/github/forks/cybershaolin47/CVE-2025-32463_POC.svg)

- [https://github.com/dr4x-c0d3r/sudo-chroot](https://github.com/dr4x-c0d3r/sudo-chroot) :  ![starts](https://img.shields.io/github/stars/dr4x-c0d3r/sudo-chroot.svg) ![forks](https://img.shields.io/github/forks/dr4x-c0d3r/sudo-chroot.svg)

- [https://github.com/dr4xp/sudo-chroot](https://github.com/dr4xp/sudo-chroot) :  ![starts](https://img.shields.io/github/stars/dr4xp/sudo-chroot.svg) ![forks](https://img.shields.io/github/forks/dr4xp/sudo-chroot.svg)

- [https://github.com/Mikivirus0/sudoinjection](https://github.com/Mikivirus0/sudoinjection) :  ![starts](https://img.shields.io/github/stars/Mikivirus0/sudoinjection.svg) ![forks](https://img.shields.io/github/forks/Mikivirus0/sudoinjection.svg)

- [https://github.com/DensuLabs/CVE-2025-32463](https://github.com/DensuLabs/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/DensuLabs/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/DensuLabs/CVE-2025-32463.svg)

- [https://github.com/ChetanKomal/sudo_exploit](https://github.com/ChetanKomal/sudo_exploit) :  ![starts](https://img.shields.io/github/stars/ChetanKomal/sudo_exploit.svg) ![forks](https://img.shields.io/github/forks/ChetanKomal/sudo_exploit.svg)

- [https://github.com/0xAkarii/CVE-2025-32463](https://github.com/0xAkarii/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/0xAkarii/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/0xAkarii/CVE-2025-32463.svg)

- [https://github.com/r3dBust3r/CVE-2025-32463](https://github.com/r3dBust3r/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/r3dBust3r/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/r3dBust3r/CVE-2025-32463.svg)

- [https://github.com/Floodnut/CVE-2025-32463](https://github.com/Floodnut/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/Floodnut/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/Floodnut/CVE-2025-32463.svg)

- [https://github.com/Rajneeshkarya/CVE-2025-32463](https://github.com/Rajneeshkarya/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/Rajneeshkarya/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/Rajneeshkarya/CVE-2025-32463.svg)

- [https://github.com/san8383/CVE-2025-32463](https://github.com/san8383/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/san8383/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/san8383/CVE-2025-32463.svg)

- [https://github.com/shazed-x/CVE-2025-32463](https://github.com/shazed-x/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/shazed-x/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/shazed-x/CVE-2025-32463.svg)

- [https://github.com/MGunturG/CVE-2025-32463](https://github.com/MGunturG/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/MGunturG/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/MGunturG/CVE-2025-32463.svg)

- [https://github.com/aldoClau98/CVE-2025-32463](https://github.com/aldoClau98/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/aldoClau98/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/aldoClau98/CVE-2025-32463.svg)

- [https://github.com/hacieda/CVE-2025-32463](https://github.com/hacieda/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/hacieda/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/hacieda/CVE-2025-32463.svg)

- [https://github.com/muhammedkayag/CVE-2025-32463](https://github.com/muhammedkayag/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/muhammedkayag/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/muhammedkayag/CVE-2025-32463.svg)

- [https://github.com/khoazero123/CVE-2025-32463](https://github.com/khoazero123/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/khoazero123/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/khoazero123/CVE-2025-32463.svg)

- [https://github.com/painoob/CVE-2025-32463](https://github.com/painoob/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/painoob/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/painoob/CVE-2025-32463.svg)

- [https://github.com/0x3c4dfa1/CVE-2025-32463](https://github.com/0x3c4dfa1/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/0x3c4dfa1/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/0x3c4dfa1/CVE-2025-32463.svg)

- [https://github.com/cyberajju/CVE-2025-32463](https://github.com/cyberajju/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/cyberajju/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/cyberajju/CVE-2025-32463.svg)

- [https://github.com/ricardomaia/CVE-2025-32463](https://github.com/ricardomaia/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/ricardomaia/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/ricardomaia/CVE-2025-32463.svg)

- [https://github.com/daryllundy/CVE-2025-32463](https://github.com/daryllundy/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/daryllundy/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/daryllundy/CVE-2025-32463.svg)

- [https://github.com/onniio/CVE-2025-32463](https://github.com/onniio/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/onniio/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/onniio/CVE-2025-32463.svg)

- [https://github.com/robbin0919/CVE-2025-32463](https://github.com/robbin0919/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/robbin0919/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/robbin0919/CVE-2025-32463.svg)

- [https://github.com/cyberpoul/CVE-2025-32463-POC](https://github.com/cyberpoul/CVE-2025-32463-POC) :  ![starts](https://img.shields.io/github/stars/cyberpoul/CVE-2025-32463-POC.svg) ![forks](https://img.shields.io/github/forks/cyberpoul/CVE-2025-32463-POC.svg)

- [https://github.com/AC8999/CVE-2025-32463](https://github.com/AC8999/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/AC8999/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/AC8999/CVE-2025-32463.svg)

- [https://github.com/mihnasdsad/CVE-2025-32463](https://github.com/mihnasdsad/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/mihnasdsad/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/mihnasdsad/CVE-2025-32463.svg)

- [https://github.com/dbarquero/cve-2025-32463-lab](https://github.com/dbarquero/cve-2025-32463-lab) :  ![starts](https://img.shields.io/github/stars/dbarquero/cve-2025-32463-lab.svg) ![forks](https://img.shields.io/github/forks/dbarquero/cve-2025-32463-lab.svg)

- [https://github.com/neko205-mx/CVE-2025-32463_Exploit](https://github.com/neko205-mx/CVE-2025-32463_Exploit) :  ![starts](https://img.shields.io/github/stars/neko205-mx/CVE-2025-32463_Exploit.svg) ![forks](https://img.shields.io/github/forks/neko205-mx/CVE-2025-32463_Exploit.svg)

- [https://github.com/harsh1verma/CVE-Analysis](https://github.com/harsh1verma/CVE-Analysis) :  ![starts](https://img.shields.io/github/stars/harsh1verma/CVE-Analysis.svg) ![forks](https://img.shields.io/github/forks/harsh1verma/CVE-Analysis.svg)

- [https://github.com/Chocapikk/CVE-2025-32463-lab](https://github.com/Chocapikk/CVE-2025-32463-lab) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-32463-lab.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-32463-lab.svg)

- [https://github.com/zhaduchanhzz/CVE-2025-32463_POC](https://github.com/zhaduchanhzz/CVE-2025-32463_POC) :  ![starts](https://img.shields.io/github/stars/zhaduchanhzz/CVE-2025-32463_POC.svg) ![forks](https://img.shields.io/github/forks/zhaduchanhzz/CVE-2025-32463_POC.svg)

- [https://github.com/robbert1978/CVE-2025-32463_POC](https://github.com/robbert1978/CVE-2025-32463_POC) :  ![starts](https://img.shields.io/github/stars/robbert1978/CVE-2025-32463_POC.svg) ![forks](https://img.shields.io/github/forks/robbert1978/CVE-2025-32463_POC.svg)

- [https://github.com/ashardev002/CVE-2025-32463_chwoot](https://github.com/ashardev002/CVE-2025-32463_chwoot) :  ![starts](https://img.shields.io/github/stars/ashardev002/CVE-2025-32463_chwoot.svg) ![forks](https://img.shields.io/github/forks/ashardev002/CVE-2025-32463_chwoot.svg)

- [https://github.com/ill-deed/CVE-2025-32463_illdeed](https://github.com/ill-deed/CVE-2025-32463_illdeed) :  ![starts](https://img.shields.io/github/stars/ill-deed/CVE-2025-32463_illdeed.svg) ![forks](https://img.shields.io/github/forks/ill-deed/CVE-2025-32463_illdeed.svg)

- [https://github.com/yeremeu/CVE-2025-32463_chwoot](https://github.com/yeremeu/CVE-2025-32463_chwoot) :  ![starts](https://img.shields.io/github/stars/yeremeu/CVE-2025-32463_chwoot.svg) ![forks](https://img.shields.io/github/forks/yeremeu/CVE-2025-32463_chwoot.svg)

- [https://github.com/lowercasenumbers/CVE-2025-32463_sudo_chroot](https://github.com/lowercasenumbers/CVE-2025-32463_sudo_chroot) :  ![starts](https://img.shields.io/github/stars/lowercasenumbers/CVE-2025-32463_sudo_chroot.svg) ![forks](https://img.shields.io/github/forks/lowercasenumbers/CVE-2025-32463_sudo_chroot.svg)

- [https://github.com/krypton-0x00/CVE-2025-32463-Chwoot-POC](https://github.com/krypton-0x00/CVE-2025-32463-Chwoot-POC) :  ![starts](https://img.shields.io/github/stars/krypton-0x00/CVE-2025-32463-Chwoot-POC.svg) ![forks](https://img.shields.io/github/forks/krypton-0x00/CVE-2025-32463-Chwoot-POC.svg)

- [https://github.com/CIA911/sudo_patch_CVE-2025-32463](https://github.com/CIA911/sudo_patch_CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/CIA911/sudo_patch_CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/CIA911/sudo_patch_CVE-2025-32463.svg)

- [https://github.com/morgenm/sudo-chroot-CVE-2025-32463](https://github.com/morgenm/sudo-chroot-CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/morgenm/sudo-chroot-CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/morgenm/sudo-chroot-CVE-2025-32463.svg)

- [https://github.com/blackcat4347/CVE-2025-32463_PoC](https://github.com/blackcat4347/CVE-2025-32463_PoC) :  ![starts](https://img.shields.io/github/stars/blackcat4347/CVE-2025-32463_PoC.svg) ![forks](https://img.shields.io/github/forks/blackcat4347/CVE-2025-32463_PoC.svg)

- [https://github.com/D3ltaFormation/CVE-2025-32463-Sudo-Chroot-Escape](https://github.com/D3ltaFormation/CVE-2025-32463-Sudo-Chroot-Escape) :  ![starts](https://img.shields.io/github/stars/D3ltaFormation/CVE-2025-32463-Sudo-Chroot-Escape.svg) ![forks](https://img.shields.io/github/forks/D3ltaFormation/CVE-2025-32463-Sudo-Chroot-Escape.svg)

- [https://github.com/0x00315732/musical-engine](https://github.com/0x00315732/musical-engine) :  ![starts](https://img.shields.io/github/stars/0x00315732/musical-engine.svg) ![forks](https://img.shields.io/github/forks/0x00315732/musical-engine.svg)

## CVE-2025-32462
 Sudo before 1.9.17p1, when used with a sudoers file that specifies a host that is neither the current host nor ALL, allows listed users to execute commands on unintended machines.



- [https://github.com/CryingN/CVE-2025-32462](https://github.com/CryingN/CVE-2025-32462) :  ![starts](https://img.shields.io/github/stars/CryingN/CVE-2025-32462.svg) ![forks](https://img.shields.io/github/forks/CryingN/CVE-2025-32462.svg)

- [https://github.com/cyberpoul/CVE-2025-32462-POC](https://github.com/cyberpoul/CVE-2025-32462-POC) :  ![starts](https://img.shields.io/github/stars/cyberpoul/CVE-2025-32462-POC.svg) ![forks](https://img.shields.io/github/forks/cyberpoul/CVE-2025-32462-POC.svg)

- [https://github.com/MAAYTHM/CVE-2025-32462_32463-Lab](https://github.com/MAAYTHM/CVE-2025-32462_32463-Lab) :  ![starts](https://img.shields.io/github/stars/MAAYTHM/CVE-2025-32462_32463-Lab.svg) ![forks](https://img.shields.io/github/forks/MAAYTHM/CVE-2025-32462_32463-Lab.svg)

- [https://github.com/AdityaBhatt3010/Sudo-Privilege-Escalation-Linux-CVE-2025-32463-and-CVE-2025-32462](https://github.com/AdityaBhatt3010/Sudo-Privilege-Escalation-Linux-CVE-2025-32463-and-CVE-2025-32462) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/Sudo-Privilege-Escalation-Linux-CVE-2025-32463-and-CVE-2025-32462.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/Sudo-Privilege-Escalation-Linux-CVE-2025-32463-and-CVE-2025-32462.svg)

- [https://github.com/SpongeBob-369/cve-2025-32462](https://github.com/SpongeBob-369/cve-2025-32462) :  ![starts](https://img.shields.io/github/stars/SpongeBob-369/cve-2025-32462.svg) ![forks](https://img.shields.io/github/forks/SpongeBob-369/cve-2025-32462.svg)

- [https://github.com/cybersentinelx1/CVE-2025-32462-Exploit](https://github.com/cybersentinelx1/CVE-2025-32462-Exploit) :  ![starts](https://img.shields.io/github/stars/cybersentinelx1/CVE-2025-32462-Exploit.svg) ![forks](https://img.shields.io/github/forks/cybersentinelx1/CVE-2025-32462-Exploit.svg)

- [https://github.com/j3r1ch0123/CVE-2025-32462](https://github.com/j3r1ch0123/CVE-2025-32462) :  ![starts](https://img.shields.io/github/stars/j3r1ch0123/CVE-2025-32462.svg) ![forks](https://img.shields.io/github/forks/j3r1ch0123/CVE-2025-32462.svg)

- [https://github.com/mylovem313/CVE-2025-32462](https://github.com/mylovem313/CVE-2025-32462) :  ![starts](https://img.shields.io/github/stars/mylovem313/CVE-2025-32462.svg) ![forks](https://img.shields.io/github/forks/mylovem313/CVE-2025-32462.svg)

- [https://github.com/harsh1verma/CVE-Analysis](https://github.com/harsh1verma/CVE-Analysis) :  ![starts](https://img.shields.io/github/stars/harsh1verma/CVE-Analysis.svg) ![forks](https://img.shields.io/github/forks/harsh1verma/CVE-Analysis.svg)

- [https://github.com/Hacksparo/CVE-2025-32462](https://github.com/Hacksparo/CVE-2025-32462) :  ![starts](https://img.shields.io/github/stars/Hacksparo/CVE-2025-32462.svg) ![forks](https://img.shields.io/github/forks/Hacksparo/CVE-2025-32462.svg)

- [https://github.com/toohau/CVE-2025-32462-32463-Detection-Script-](https://github.com/toohau/CVE-2025-32462-32463-Detection-Script-) :  ![starts](https://img.shields.io/github/stars/toohau/CVE-2025-32462-32463-Detection-Script-.svg) ![forks](https://img.shields.io/github/forks/toohau/CVE-2025-32462-32463-Detection-Script-.svg)

## CVE-2025-32444
 vLLM is a high-throughput and memory-efficient inference and serving engine for LLMs. Versions starting from 0.6.5 and prior to 0.8.5, having vLLM integration with mooncake, are vulnerable to remote code execution due to using pickle based serialization over unsecured ZeroMQ sockets. The vulnerable sockets were set to listen on all network interfaces, increasing the likelihood that an attacker is able to reach the vulnerable ZeroMQ sockets to carry out an attack. vLLM instances that do not make use of the mooncake integration are not vulnerable. This issue has been patched in version 0.8.5.



- [https://github.com/stuxbench/vllm-cve-2025-32444](https://github.com/stuxbench/vllm-cve-2025-32444) :  ![starts](https://img.shields.io/github/stars/stuxbench/vllm-cve-2025-32444.svg) ![forks](https://img.shields.io/github/forks/stuxbench/vllm-cve-2025-32444.svg)

## CVE-2025-32434
 PyTorch is a Python package that provides tensor computation with strong GPU acceleration and deep neural networks built on a tape-based autograd system. In version 2.5.1 and prior, a Remote Command Execution (RCE) vulnerability exists in PyTorch when loading a model using torch.load with weights_only=True. This issue has been patched in version 2.6.0.



- [https://github.com/Camier/VOIXCODER](https://github.com/Camier/VOIXCODER) :  ![starts](https://img.shields.io/github/stars/Camier/VOIXCODER.svg) ![forks](https://img.shields.io/github/forks/Camier/VOIXCODER.svg)

## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.



- [https://github.com/platsecurity/CVE-2025-32433](https://github.com/platsecurity/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/platsecurity/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/platsecurity/CVE-2025-32433.svg)

- [https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC](https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC.svg)

- [https://github.com/TeneBrae93/CVE-2025-3243](https://github.com/TeneBrae93/CVE-2025-3243) :  ![starts](https://img.shields.io/github/stars/TeneBrae93/CVE-2025-3243.svg) ![forks](https://img.shields.io/github/forks/TeneBrae93/CVE-2025-3243.svg)

- [https://github.com/0xPThree/cve-2025-32433](https://github.com/0xPThree/cve-2025-32433) :  ![starts](https://img.shields.io/github/stars/0xPThree/cve-2025-32433.svg) ![forks](https://img.shields.io/github/forks/0xPThree/cve-2025-32433.svg)

- [https://github.com/m0usem0use/erl_mouse](https://github.com/m0usem0use/erl_mouse) :  ![starts](https://img.shields.io/github/stars/m0usem0use/erl_mouse.svg) ![forks](https://img.shields.io/github/forks/m0usem0use/erl_mouse.svg)

- [https://github.com/NiteeshPujari/CVE-2025-32433-PoC](https://github.com/NiteeshPujari/CVE-2025-32433-PoC) :  ![starts](https://img.shields.io/github/stars/NiteeshPujari/CVE-2025-32433-PoC.svg) ![forks](https://img.shields.io/github/forks/NiteeshPujari/CVE-2025-32433-PoC.svg)

- [https://github.com/LemieOne/CVE-2025-32433](https://github.com/LemieOne/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/LemieOne/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/LemieOne/CVE-2025-32433.svg)

- [https://github.com/darses/CVE-2025-32433](https://github.com/darses/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/darses/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/darses/CVE-2025-32433.svg)

- [https://github.com/ekomsSavior/POC_CVE-2025-32433](https://github.com/ekomsSavior/POC_CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/ekomsSavior/POC_CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/ekomsSavior/POC_CVE-2025-32433.svg)

- [https://github.com/exa-offsec/ssh_erlangotp_rce](https://github.com/exa-offsec/ssh_erlangotp_rce) :  ![starts](https://img.shields.io/github/stars/exa-offsec/ssh_erlangotp_rce.svg) ![forks](https://img.shields.io/github/forks/exa-offsec/ssh_erlangotp_rce.svg)

- [https://github.com/dollarboysushil/CVE-2025-32433-Erlang-OTP-SSH-Unauthenticated-RCE](https://github.com/dollarboysushil/CVE-2025-32433-Erlang-OTP-SSH-Unauthenticated-RCE) :  ![starts](https://img.shields.io/github/stars/dollarboysushil/CVE-2025-32433-Erlang-OTP-SSH-Unauthenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/dollarboysushil/CVE-2025-32433-Erlang-OTP-SSH-Unauthenticated-RCE.svg)

- [https://github.com/mirmeweu/cve-2025-32433](https://github.com/mirmeweu/cve-2025-32433) :  ![starts](https://img.shields.io/github/stars/mirmeweu/cve-2025-32433.svg) ![forks](https://img.shields.io/github/forks/mirmeweu/cve-2025-32433.svg)

- [https://github.com/0x7556/CVE-2025-32433](https://github.com/0x7556/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/0x7556/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/0x7556/CVE-2025-32433.svg)

- [https://github.com/Yuri08loveElaina/CVE_2025_32433_exploit](https://github.com/Yuri08loveElaina/CVE_2025_32433_exploit) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_32433_exploit.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_32433_exploit.svg)

- [https://github.com/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit](https://github.com/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit.svg)

- [https://github.com/teamtopkarl/CVE-2025-32433](https://github.com/teamtopkarl/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/teamtopkarl/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/teamtopkarl/CVE-2025-32433.svg)

- [https://github.com/becrevex/CVE-2025-32433](https://github.com/becrevex/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/becrevex/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/becrevex/CVE-2025-32433.svg)

- [https://github.com/Know56/CVE-2025-32433](https://github.com/Know56/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/Know56/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/Know56/CVE-2025-32433.svg)

- [https://github.com/iteride/CVE-2025-32433](https://github.com/iteride/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/iteride/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/iteride/CVE-2025-32433.svg)

- [https://github.com/MrDreamReal/CVE-2025-32433](https://github.com/MrDreamReal/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/MrDreamReal/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/MrDreamReal/CVE-2025-32433.svg)

- [https://github.com/abrewer251/CVE-2025-32433_Erlang-OTP_PoC](https://github.com/abrewer251/CVE-2025-32433_Erlang-OTP_PoC) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-32433_Erlang-OTP_PoC.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-32433_Erlang-OTP_PoC.svg)

- [https://github.com/Mdusmandasthaheer/CVE-2025-32433](https://github.com/Mdusmandasthaheer/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/Mdusmandasthaheer/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/Mdusmandasthaheer/CVE-2025-32433.svg)

- [https://github.com/vigilante-1337/CVE-2025-32433](https://github.com/vigilante-1337/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/vigilante-1337/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/vigilante-1337/CVE-2025-32433.svg)

- [https://github.com/toshithh/CVE-2025-32433](https://github.com/toshithh/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/toshithh/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/toshithh/CVE-2025-32433.svg)

- [https://github.com/te0rwx/CVE-2025-32433-Detection](https://github.com/te0rwx/CVE-2025-32433-Detection) :  ![starts](https://img.shields.io/github/stars/te0rwx/CVE-2025-32433-Detection.svg) ![forks](https://img.shields.io/github/forks/te0rwx/CVE-2025-32433-Detection.svg)

- [https://github.com/Epivalent/CVE-2025-32433-detection](https://github.com/Epivalent/CVE-2025-32433-detection) :  ![starts](https://img.shields.io/github/stars/Epivalent/CVE-2025-32433-detection.svg) ![forks](https://img.shields.io/github/forks/Epivalent/CVE-2025-32433-detection.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-32433](https://github.com/B1ack4sh/Blackash-CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-32433.svg)

- [https://github.com/ps-interactive/lab_CVE-2025-32433](https://github.com/ps-interactive/lab_CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/ps-interactive/lab_CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/ps-interactive/lab_CVE-2025-32433.svg)

- [https://github.com/meloppeitreet/CVE-2025-32433-Remote-Shell](https://github.com/meloppeitreet/CVE-2025-32433-Remote-Shell) :  ![starts](https://img.shields.io/github/stars/meloppeitreet/CVE-2025-32433-Remote-Shell.svg) ![forks](https://img.shields.io/github/forks/meloppeitreet/CVE-2025-32433-Remote-Shell.svg)

- [https://github.com/Batman529/PoC-CVE-2025-32433](https://github.com/Batman529/PoC-CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/Batman529/PoC-CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/Batman529/PoC-CVE-2025-32433.svg)

- [https://github.com/C9b3rD3vi1/Erlang-OTP-SSH-CVE-2025-32433](https://github.com/C9b3rD3vi1/Erlang-OTP-SSH-CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/C9b3rD3vi1/Erlang-OTP-SSH-CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/C9b3rD3vi1/Erlang-OTP-SSH-CVE-2025-32433.svg)

- [https://github.com/bilalz5-github/Erlang-OTP-SSH-CVE-2025-32433](https://github.com/bilalz5-github/Erlang-OTP-SSH-CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/bilalz5-github/Erlang-OTP-SSH-CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/bilalz5-github/Erlang-OTP-SSH-CVE-2025-32433.svg)

- [https://github.com/ODST-Forge/CVE-2025-32433_PoC](https://github.com/ODST-Forge/CVE-2025-32433_PoC) :  ![starts](https://img.shields.io/github/stars/ODST-Forge/CVE-2025-32433_PoC.svg) ![forks](https://img.shields.io/github/forks/ODST-Forge/CVE-2025-32433_PoC.svg)

- [https://github.com/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts](https://github.com/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts) :  ![starts](https://img.shields.io/github/stars/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts.svg) ![forks](https://img.shields.io/github/forks/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts.svg)

## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.



- [https://github.com/Sachinart/CVE-2025-32432](https://github.com/Sachinart/CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2025-32432.svg)

- [https://github.com/Chocapikk/CVE-2025-32432](https://github.com/Chocapikk/CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-32432.svg)

- [https://github.com/bambooqj/CVE-2025-32432](https://github.com/bambooqj/CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/bambooqj/CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/bambooqj/CVE-2025-32432.svg)

- [https://github.com/CTY-Research-1/CVE-2025-32432-PoC](https://github.com/CTY-Research-1/CVE-2025-32432-PoC) :  ![starts](https://img.shields.io/github/stars/CTY-Research-1/CVE-2025-32432-PoC.svg) ![forks](https://img.shields.io/github/forks/CTY-Research-1/CVE-2025-32432-PoC.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-32432](https://github.com/B1ack4sh/Blackash-CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-32432.svg)

## CVE-2025-32429
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. In versions 9.4-rc-1 through 16.10.5 and 17.0.0-rc-1 through 17.2.2, it's possible for anyone to inject SQL using the parameter sort of the getdeleteddocuments.vm. It's injected as is as an ORDER BY value. This is fixed in versions 16.10.6 and 17.3.0-rc-1.



- [https://github.com/byteReaper77/CVE-2025-32429](https://github.com/byteReaper77/CVE-2025-32429) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-32429.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-32429.svg)

- [https://github.com/amir-othman/CVE-2025-32429](https://github.com/amir-othman/CVE-2025-32429) :  ![starts](https://img.shields.io/github/stars/amir-othman/CVE-2025-32429.svg) ![forks](https://img.shields.io/github/forks/amir-othman/CVE-2025-32429.svg)

- [https://github.com/imbas007/CVE-2025-32429-Checker](https://github.com/imbas007/CVE-2025-32429-Checker) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-32429-Checker.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-32429-Checker.svg)

## CVE-2025-32421
 Next.js is a React framework for building full-stack web applications. Versions prior to 14.2.24 and 15.1.6 have a race-condition vulnerability. This issue only affects the Pages Router under certain misconfigurations, causing normal endpoints to serve `pageProps` data instead of standard HTML. This issue was patched in versions 15.1.6 and 14.2.24 by stripping the `x-now-route-matches` header from incoming requests. Applications hosted on Vercel's platform are not affected by this issue, as the platform does not cache responses based solely on `200 OK` status without explicit `cache-control` headers. Those who self-host Next.js deployments and are unable to upgrade immediately can mitigate this vulnerability by stripping the `x-now-route-matches` header from all incoming requests at the content development network and setting `cache-control: no-store` for all responses under risk. The maintainers of Next.js strongly recommend only caching responses with explicit cache-control headers.



- [https://github.com/hidesec/CVE-2025-32421](https://github.com/hidesec/CVE-2025-32421) :  ![starts](https://img.shields.io/github/stars/hidesec/CVE-2025-32421.svg) ![forks](https://img.shields.io/github/forks/hidesec/CVE-2025-32421.svg)

- [https://github.com/zeroc00I/CVE-2025-32421](https://github.com/zeroc00I/CVE-2025-32421) :  ![starts](https://img.shields.io/github/stars/zeroc00I/CVE-2025-32421.svg) ![forks](https://img.shields.io/github/forks/zeroc00I/CVE-2025-32421.svg)

## CVE-2025-32407
 Samsung Internet for Galaxy Watch version 5.0.9, available up until Samsung Galaxy Watch 3, does not properly validate TLS certificates, allowing for an attacker to impersonate any and all websites visited by the user. This is a critical misconfiguration in the way the browser validates the identity of the server. It negates the use of HTTPS as a secure channel, allowing for Man-in-the-Middle attacks, stealing sensitive information or modifying incoming and outgoing traffic. NOTE: This vulnerability is in an end-of-life product that is no longer maintained by the vendor.



- [https://github.com/diegovargasj/CVE-2025-32407](https://github.com/diegovargasj/CVE-2025-32407) :  ![starts](https://img.shields.io/github/stars/diegovargasj/CVE-2025-32407.svg) ![forks](https://img.shields.io/github/forks/diegovargasj/CVE-2025-32407.svg)

## CVE-2025-32395
 Vite is a frontend tooling framework for javascript. Prior to 6.2.6, 6.1.5, 6.0.15, 5.4.18, and 4.5.13, the contents of arbitrary files can be returned to the browser if the dev server is running on Node or Bun. HTTP 1.1 spec (RFC 9112) does not allow # in request-target. Although an attacker can send such a request. For those requests with an invalid request-line (it includes request-target), the spec recommends to reject them with 400 or 301. The same can be said for HTTP 2. On Node and Bun, those requests are not rejected internally and is passed to the user land. For those requests, the value of http.IncomingMessage.url contains #. Vite assumed req.url won't contain # when checking server.fs.deny, allowing those kinds of requests to bypass the check. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) and running the Vite dev server on runtimes that are not Deno (e.g. Node, Bun) are affected. This vulnerability is fixed in 6.2.6, 6.1.5, 6.0.15, 5.4.18, and 4.5.13.



- [https://github.com/xuemian168/CVE-2025-30208](https://github.com/xuemian168/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/xuemian168/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/xuemian168/CVE-2025-30208.svg)

- [https://github.com/ruiwenya/CVE-2025-32395](https://github.com/ruiwenya/CVE-2025-32395) :  ![starts](https://img.shields.io/github/stars/ruiwenya/CVE-2025-32395.svg) ![forks](https://img.shields.io/github/forks/ruiwenya/CVE-2025-32395.svg)

## CVE-2025-32375
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. Prior to 1.4.8, there was an insecure deserialization in BentoML's runner server. By setting specific headers and parameters in the POST request, it is possible to execute any unauthorized arbitrary code on the server, which will grant the attackers to have the initial access and information disclosure on the server. This vulnerability is fixed in 1.4.8.



- [https://github.com/theGEBIRGE/CVE-2025-32375](https://github.com/theGEBIRGE/CVE-2025-32375) :  ![starts](https://img.shields.io/github/stars/theGEBIRGE/CVE-2025-32375.svg) ![forks](https://img.shields.io/github/forks/theGEBIRGE/CVE-2025-32375.svg)

## CVE-2025-32367
 The Oz Forensics face recognition application before 4.0.8 late 2023 allows PII retrieval via /statistic/list Insecure Direct Object Reference. NOTE: the number 4.0.8 was used for both the unpatched and patched versions.



- [https://github.com/Brakerciti/OZForensics_exploit](https://github.com/Brakerciti/OZForensics_exploit) :  ![starts](https://img.shields.io/github/stars/Brakerciti/OZForensics_exploit.svg) ![forks](https://img.shields.io/github/forks/Brakerciti/OZForensics_exploit.svg)

## CVE-2025-32324
 In onCommand of ActivityManagerShellCommand.java, there is a possible arbitrary activity launch due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.



- [https://github.com/rifting/UnrestrictedUserCreator](https://github.com/rifting/UnrestrictedUserCreator) :  ![starts](https://img.shields.io/github/stars/rifting/UnrestrictedUserCreator.svg) ![forks](https://img.shields.io/github/forks/rifting/UnrestrictedUserCreator.svg)

## CVE-2025-32259
 Missing Authorization vulnerability in Alimir WP ULike. This issue affects WP ULike: from n/a through 4.7.9.1.



- [https://github.com/HossamEAhmed/wp-ulike-cve-2025-32259-poc](https://github.com/HossamEAhmed/wp-ulike-cve-2025-32259-poc) :  ![starts](https://img.shields.io/github/stars/HossamEAhmed/wp-ulike-cve-2025-32259-poc.svg) ![forks](https://img.shields.io/github/forks/HossamEAhmed/wp-ulike-cve-2025-32259-poc.svg)

## CVE-2025-32206
 Unrestricted Upload of File with Dangerous Type vulnerability in LABCAT Processing Projects allows Upload a Web Shell to a Web Server. This issue affects Processing Projects: from n/a through 1.0.2.



- [https://github.com/Nxploited/CVE-2025-32206](https://github.com/Nxploited/CVE-2025-32206) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-32206.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-32206.svg)

## CVE-2025-32140
 Unrestricted Upload of File with Dangerous Type vulnerability in Nirmal Kumar Ram WP Remote Thumbnail allows Upload a Web Shell to a Web Server. This issue affects WP Remote Thumbnail: from n/a through 1.3.1.



- [https://github.com/Nxploited/CVE-2025-32140](https://github.com/Nxploited/CVE-2025-32140) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-32140.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-32140.svg)

## CVE-2025-32118
 Unrestricted Upload of File with Dangerous Type vulnerability in NiteoThemes CMP – Coming Soon & Maintenance allows Using Malicious Files. This issue affects CMP – Coming Soon & Maintenance: from n/a through 4.1.13.



- [https://github.com/Nxploited/CVE-2025-32118](https://github.com/Nxploited/CVE-2025-32118) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-32118.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-32118.svg)

## CVE-2025-32094
 An issue was discovered in Akamai Ghost, as used for the Akamai CDN platform before 2025-03-26. Under certain circumstances, a client making an HTTP/1.x OPTIONS request with an "Expect: 100-continue" header, and using obsolete line folding, can lead to a discrepancy in how two in-path Akamai servers interpret the request, allowing an attacker to smuggle a second request in the original request body.



- [https://github.com/perplext/echteeteepee](https://github.com/perplext/echteeteepee) :  ![starts](https://img.shields.io/github/stars/perplext/echteeteepee.svg) ![forks](https://img.shields.io/github/forks/perplext/echteeteepee.svg)

## CVE-2025-32023
 Redis is an open source, in-memory database that persists on disk. From 2.8 to before 8.0.3, 7.4.5, 7.2.10, and 6.2.19, an authenticated user may use a specially crafted string to trigger a stack/heap out of bounds write on hyperloglog operations, potentially leading to remote code execution. The bug likely affects all Redis versions with hyperloglog operations implemented. This vulnerability is fixed in 8.0.3, 7.4.5, 7.2.10, and 6.2.19. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing hyperloglog operations. This can be done using ACL to restrict HLL commands.



- [https://github.com/leesh3288/CVE-2025-32023](https://github.com/leesh3288/CVE-2025-32023) :  ![starts](https://img.shields.io/github/stars/leesh3288/CVE-2025-32023.svg) ![forks](https://img.shields.io/github/forks/leesh3288/CVE-2025-32023.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-32023](https://github.com/B1ack4sh/Blackash-CVE-2025-32023) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-32023.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-32023.svg)

- [https://github.com/LordBheem/CVE-2025-32023](https://github.com/LordBheem/CVE-2025-32023) :  ![starts](https://img.shields.io/github/stars/LordBheem/CVE-2025-32023.svg) ![forks](https://img.shields.io/github/forks/LordBheem/CVE-2025-32023.svg)

## CVE-2025-32013
 LNbits is a Lightning wallet and accounts system. A Server-Side Request Forgery (SSRF) vulnerability has been discovered in LNbits' LNURL authentication handling functionality. When processing LNURL authentication requests, the application accepts a callback URL parameter and makes an HTTP request to that URL using the httpx library with redirect following enabled. The application doesn't properly validate the callback URL, allowing attackers to specify internal network addresses and access internal resources.



- [https://github.com/Mohith-T/CVE-2025-32013](https://github.com/Mohith-T/CVE-2025-32013) :  ![starts](https://img.shields.io/github/stars/Mohith-T/CVE-2025-32013.svg) ![forks](https://img.shields.io/github/forks/Mohith-T/CVE-2025-32013.svg)

## CVE-2025-31864
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Out the Box Beam me up Scotty – Back to Top Button allows Stored XSS. This issue affects Beam me up Scotty – Back to Top Button: from n/a through 1.0.23.



- [https://github.com/DoTTak/CVE-2025-31864](https://github.com/DoTTak/CVE-2025-31864) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-31864.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-31864.svg)

## CVE-2025-31722
 In Jenkins Templating Engine Plugin 2.5.3 and earlier, libraries defined in folders are not subject to sandbox protection, allowing attackers with Item/Configure permission to execute arbitrary code in the context of the Jenkins controller JVM.



- [https://github.com/Nick6371/CVE-2025-31722](https://github.com/Nick6371/CVE-2025-31722) :  ![starts](https://img.shields.io/github/stars/Nick6371/CVE-2025-31722.svg) ![forks](https://img.shields.io/github/forks/Nick6371/CVE-2025-31722.svg)

## CVE-2025-31710
 In engineermode service, there is a possible command injection due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed.



- [https://github.com/Skorpion96/unisoc-su](https://github.com/Skorpion96/unisoc-su) :  ![starts](https://img.shields.io/github/stars/Skorpion96/unisoc-su.svg) ![forks](https://img.shields.io/github/forks/Skorpion96/unisoc-su.svg)

## CVE-2025-31702
 A vulnerability exists in certain Dahua embedded products. Third-party malicious attacker with obtained normal user credentials could exploit the vulnerability to access certain data which are restricted to admin privileges, such as system-sensitive files through specific HTTP request. This may cause tampering with admin password, leading to privilege escalation. Systems with only admin account are not affected.



- [https://github.com/purpleghosts/CVE-2025-31702](https://github.com/purpleghosts/CVE-2025-31702) :  ![starts](https://img.shields.io/github/stars/purpleghosts/CVE-2025-31702.svg) ![forks](https://img.shields.io/github/forks/purpleghosts/CVE-2025-31702.svg)

## CVE-2025-31651
 Improper Neutralization of Escape, Meta, or Control Sequences vulnerability in Apache Tomcat. For a subset of unlikely rewrite rule configurations, it was possible 
for a specially crafted request to bypass some rewrite rules. If those 
rewrite rules effectively enforced security constraints, those 
constraints could be bypassed.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.5, from 10.1.0-M1 through 10.1.39, from 9.0.0.M1 through 9.0.102.
The following versions were EOL at the time the CVE was created but are 
known to be affected: 8.5.0 though 8.5.100. Other, older, EOL versions 
may also be affected.


Users are recommended to upgrade to version [FIXED_VERSION], which fixes the issue.



- [https://github.com/gregk4sec/CVE-2025-31651](https://github.com/gregk4sec/CVE-2025-31651) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-31651.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-31651.svg)

## CVE-2025-31650
 Improper Input Validation vulnerability in Apache Tomcat. Incorrect error handling for some invalid HTTP priority headers resulted in incomplete clean-up of the failed request which created a memory leak. A large number of such requests could trigger an OutOfMemoryException resulting in a denial of service.

This issue affects Apache Tomcat: from 9.0.76 through 9.0.102, from 10.1.10 through 10.1.39, from 11.0.0-M2 through 11.0.5.
The following versions were EOL at the time the CVE was created but are 
known to be affected: 8.5.90 though 8.5.100.


Users are recommended to upgrade to version 9.0.104, 10.1.40 or 11.0.6 which fix the issue.



- [https://github.com/absholi7ly/TomcatKiller-CVE-2025-31650](https://github.com/absholi7ly/TomcatKiller-CVE-2025-31650) :  ![starts](https://img.shields.io/github/stars/absholi7ly/TomcatKiller-CVE-2025-31650.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/TomcatKiller-CVE-2025-31650.svg)

- [https://github.com/tunahantekeoglu/CVE-2025-31650](https://github.com/tunahantekeoglu/CVE-2025-31650) :  ![starts](https://img.shields.io/github/stars/tunahantekeoglu/CVE-2025-31650.svg) ![forks](https://img.shields.io/github/forks/tunahantekeoglu/CVE-2025-31650.svg)

- [https://github.com/assad12341/Dos-exploit-](https://github.com/assad12341/Dos-exploit-) :  ![starts](https://img.shields.io/github/stars/assad12341/Dos-exploit-.svg) ![forks](https://img.shields.io/github/forks/assad12341/Dos-exploit-.svg)

- [https://github.com/assad12341/DOS-exploit](https://github.com/assad12341/DOS-exploit) :  ![starts](https://img.shields.io/github/stars/assad12341/DOS-exploit.svg) ![forks](https://img.shields.io/github/forks/assad12341/DOS-exploit.svg)

- [https://github.com/obscura-cert/CVE-2025-31650](https://github.com/obscura-cert/CVE-2025-31650) :  ![starts](https://img.shields.io/github/stars/obscura-cert/CVE-2025-31650.svg) ![forks](https://img.shields.io/github/forks/obscura-cert/CVE-2025-31650.svg)

- [https://github.com/B1gN0Se/Tomcat-CVE-2025-31650](https://github.com/B1gN0Se/Tomcat-CVE-2025-31650) :  ![starts](https://img.shields.io/github/stars/B1gN0Se/Tomcat-CVE-2025-31650.svg) ![forks](https://img.shields.io/github/forks/B1gN0Se/Tomcat-CVE-2025-31650.svg)

- [https://github.com/sattarbug/Analysis-of-TomcatKiller---CVE-2025-31650-Exploit-Tool](https://github.com/sattarbug/Analysis-of-TomcatKiller---CVE-2025-31650-Exploit-Tool) :  ![starts](https://img.shields.io/github/stars/sattarbug/Analysis-of-TomcatKiller---CVE-2025-31650-Exploit-Tool.svg) ![forks](https://img.shields.io/github/forks/sattarbug/Analysis-of-TomcatKiller---CVE-2025-31650-Exploit-Tool.svg)

## CVE-2025-31644
 When running in Appliance mode, a command injection vulnerability exists in an undisclosed iControl REST and BIG-IP TMOS Shell (tmsh) command which may allow an authenticated attacker with administrator role privileges to execute arbitrary system commands. A successful exploit can allow the attacker to cross a security boundary.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/mbadanoiu/CVE-2025-31644](https://github.com/mbadanoiu/CVE-2025-31644) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2025-31644.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2025-31644.svg)

## CVE-2025-31486
 Vite is a frontend tooling framework for javascript. The contents of arbitrary files can be returned to the browser. By adding ?.svg with ?.wasm?init or with sec-fetch-dest: script header, the server.fs.deny restriction was able to bypass. This bypass is only possible if the file is smaller than build.assetsInlineLimit (default: 4kB) and when using Vite 6.0+. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. This vulnerability is fixed in 4.5.12, 5.4.17, 6.0.14, 6.1.4, and 6.2.5.



- [https://github.com/iSee857/CVE-2025-31486-PoC](https://github.com/iSee857/CVE-2025-31486-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-31486-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-31486-PoC.svg)

- [https://github.com/Ly4j/CVE-2025-31486](https://github.com/Ly4j/CVE-2025-31486) :  ![starts](https://img.shields.io/github/stars/Ly4j/CVE-2025-31486.svg) ![forks](https://img.shields.io/github/forks/Ly4j/CVE-2025-31486.svg)

- [https://github.com/hackmelocal/CVE-2025-31486-Simulation](https://github.com/hackmelocal/CVE-2025-31486-Simulation) :  ![starts](https://img.shields.io/github/stars/hackmelocal/CVE-2025-31486-Simulation.svg) ![forks](https://img.shields.io/github/forks/hackmelocal/CVE-2025-31486-Simulation.svg)

## CVE-2025-31324
 SAP NetWeaver Visual Composer Metadata Uploader is not protected with a proper authorization, allowing unauthenticated agent to upload potentially malicious executable binaries that could severely harm the host system. This could significantly affect the confidentiality, integrity, and availability of the targeted system.



- [https://github.com/redrays-io/CVE-2025-31324](https://github.com/redrays-io/CVE-2025-31324) :  ![starts](https://img.shields.io/github/stars/redrays-io/CVE-2025-31324.svg) ![forks](https://img.shields.io/github/forks/redrays-io/CVE-2025-31324.svg)

- [https://github.com/antichainalysis/sap-netweaver-0day-CVE-2025-31324](https://github.com/antichainalysis/sap-netweaver-0day-CVE-2025-31324) :  ![starts](https://img.shields.io/github/stars/antichainalysis/sap-netweaver-0day-CVE-2025-31324.svg) ![forks](https://img.shields.io/github/forks/antichainalysis/sap-netweaver-0day-CVE-2025-31324.svg)

- [https://github.com/Onapsis/Onapsis_CVE-2025-31324_Scanner_Tools](https://github.com/Onapsis/Onapsis_CVE-2025-31324_Scanner_Tools) :  ![starts](https://img.shields.io/github/stars/Onapsis/Onapsis_CVE-2025-31324_Scanner_Tools.svg) ![forks](https://img.shields.io/github/forks/Onapsis/Onapsis_CVE-2025-31324_Scanner_Tools.svg)

- [https://github.com/NULLTRACE0X/CVE-2025-31324](https://github.com/NULLTRACE0X/CVE-2025-31324) :  ![starts](https://img.shields.io/github/stars/NULLTRACE0X/CVE-2025-31324.svg) ![forks](https://img.shields.io/github/forks/NULLTRACE0X/CVE-2025-31324.svg)

- [https://github.com/Onapsis/Onapsis-Mandiant-CVE-2025-31324-Vuln-Compromise-Assessment](https://github.com/Onapsis/Onapsis-Mandiant-CVE-2025-31324-Vuln-Compromise-Assessment) :  ![starts](https://img.shields.io/github/stars/Onapsis/Onapsis-Mandiant-CVE-2025-31324-Vuln-Compromise-Assessment.svg) ![forks](https://img.shields.io/github/forks/Onapsis/Onapsis-Mandiant-CVE-2025-31324-Vuln-Compromise-Assessment.svg)

- [https://github.com/ODST-Forge/CVE-2025-31324_PoC](https://github.com/ODST-Forge/CVE-2025-31324_PoC) :  ![starts](https://img.shields.io/github/stars/ODST-Forge/CVE-2025-31324_PoC.svg) ![forks](https://img.shields.io/github/forks/ODST-Forge/CVE-2025-31324_PoC.svg)

- [https://github.com/rxerium/CVE-2025-31324](https://github.com/rxerium/CVE-2025-31324) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-31324.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-31324.svg)

- [https://github.com/rf-peixoto/sap_netweaver_cve-2025-31324-](https://github.com/rf-peixoto/sap_netweaver_cve-2025-31324-) :  ![starts](https://img.shields.io/github/stars/rf-peixoto/sap_netweaver_cve-2025-31324-.svg) ![forks](https://img.shields.io/github/forks/rf-peixoto/sap_netweaver_cve-2025-31324-.svg)

- [https://github.com/JonathanStross/CVE-2025-31324](https://github.com/JonathanStross/CVE-2025-31324) :  ![starts](https://img.shields.io/github/stars/JonathanStross/CVE-2025-31324.svg) ![forks](https://img.shields.io/github/forks/JonathanStross/CVE-2025-31324.svg)

- [https://github.com/nairuzabulhul/nuclei-template-cve-2025-31324-check](https://github.com/nairuzabulhul/nuclei-template-cve-2025-31324-check) :  ![starts](https://img.shields.io/github/stars/nairuzabulhul/nuclei-template-cve-2025-31324-check.svg) ![forks](https://img.shields.io/github/forks/nairuzabulhul/nuclei-template-cve-2025-31324-check.svg)

- [https://github.com/moften/CVE-2025-31324-NUCLEI](https://github.com/moften/CVE-2025-31324-NUCLEI) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2025-31324-NUCLEI.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2025-31324-NUCLEI.svg)

- [https://github.com/nullcult/CVE-2025-31324-File-Upload](https://github.com/nullcult/CVE-2025-31324-File-Upload) :  ![starts](https://img.shields.io/github/stars/nullcult/CVE-2025-31324-File-Upload.svg) ![forks](https://img.shields.io/github/forks/nullcult/CVE-2025-31324-File-Upload.svg)

- [https://github.com/abrewer251/CVE-2025-31324_PoC_SAP](https://github.com/abrewer251/CVE-2025-31324_PoC_SAP) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-31324_PoC_SAP.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-31324_PoC_SAP.svg)

- [https://github.com/moften/CVE-2025-31324](https://github.com/moften/CVE-2025-31324) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2025-31324.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2025-31324.svg)

- [https://github.com/sug4r-wr41th/CVE-2025-31324](https://github.com/sug4r-wr41th/CVE-2025-31324) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2025-31324.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2025-31324.svg)

- [https://github.com/BlueOWL-overlord/Burp_CVE-2025-31324](https://github.com/BlueOWL-overlord/Burp_CVE-2025-31324) :  ![starts](https://img.shields.io/github/stars/BlueOWL-overlord/Burp_CVE-2025-31324.svg) ![forks](https://img.shields.io/github/forks/BlueOWL-overlord/Burp_CVE-2025-31324.svg)

- [https://github.com/harshitvarma05/CVE-2025-31324-Exploits](https://github.com/harshitvarma05/CVE-2025-31324-Exploits) :  ![starts](https://img.shields.io/github/stars/harshitvarma05/CVE-2025-31324-Exploits.svg) ![forks](https://img.shields.io/github/forks/harshitvarma05/CVE-2025-31324-Exploits.svg)

- [https://github.com/Alizngnc/SAP-CVE-2025-31324](https://github.com/Alizngnc/SAP-CVE-2025-31324) :  ![starts](https://img.shields.io/github/stars/Alizngnc/SAP-CVE-2025-31324.svg) ![forks](https://img.shields.io/github/forks/Alizngnc/SAP-CVE-2025-31324.svg)

- [https://github.com/respondiq/jsp-webshell-scanner](https://github.com/respondiq/jsp-webshell-scanner) :  ![starts](https://img.shields.io/github/stars/respondiq/jsp-webshell-scanner.svg) ![forks](https://img.shields.io/github/forks/respondiq/jsp-webshell-scanner.svg)

## CVE-2025-31258
 This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sequoia 15.5. An app may be able to break out of its sandbox.



- [https://github.com/wh1te4ever/CVE-2025-31258-PoC](https://github.com/wh1te4ever/CVE-2025-31258-PoC) :  ![starts](https://img.shields.io/github/stars/wh1te4ever/CVE-2025-31258-PoC.svg) ![forks](https://img.shields.io/github/forks/wh1te4ever/CVE-2025-31258-PoC.svg)

- [https://github.com/sureshkumarsat/CVE-2025-31258-PoC](https://github.com/sureshkumarsat/CVE-2025-31258-PoC) :  ![starts](https://img.shields.io/github/stars/sureshkumarsat/CVE-2025-31258-PoC.svg) ![forks](https://img.shields.io/github/forks/sureshkumarsat/CVE-2025-31258-PoC.svg)

## CVE-2025-31201
 This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. An attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.



- [https://github.com/JGoyd/iOS-Attack-Chain-CVE-2025-31200-CVE-2025-31201](https://github.com/JGoyd/iOS-Attack-Chain-CVE-2025-31200-CVE-2025-31201) :  ![starts](https://img.shields.io/github/stars/JGoyd/iOS-Attack-Chain-CVE-2025-31200-CVE-2025-31201.svg) ![forks](https://img.shields.io/github/forks/JGoyd/iOS-Attack-Chain-CVE-2025-31200-CVE-2025-31201.svg)

## CVE-2025-31200
 A memory corruption issue was addressed with improved bounds checking. This issue is fixed in tvOS 18.4.1, visionOS 2.4.1, iOS iOS 18.4.1 and iPadOS 18.4.1, macOS Sequoia 15.4.1. Processing an audio stream in a maliciously crafted media file may result in code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on iOS.



- [https://github.com/zhuowei/apple-positional-audio-codec-invalid-header](https://github.com/zhuowei/apple-positional-audio-codec-invalid-header) :  ![starts](https://img.shields.io/github/stars/zhuowei/apple-positional-audio-codec-invalid-header.svg) ![forks](https://img.shields.io/github/forks/zhuowei/apple-positional-audio-codec-invalid-header.svg)

- [https://github.com/JGoyd/iOS-Attack-Chain-CVE-2025-31200-CVE-2025-31201](https://github.com/JGoyd/iOS-Attack-Chain-CVE-2025-31200-CVE-2025-31201) :  ![starts](https://img.shields.io/github/stars/JGoyd/iOS-Attack-Chain-CVE-2025-31200-CVE-2025-31201.svg) ![forks](https://img.shields.io/github/forks/JGoyd/iOS-Attack-Chain-CVE-2025-31200-CVE-2025-31201.svg)

- [https://github.com/hunters-sec/CVE-2025-31200](https://github.com/hunters-sec/CVE-2025-31200) :  ![starts](https://img.shields.io/github/stars/hunters-sec/CVE-2025-31200.svg) ![forks](https://img.shields.io/github/forks/hunters-sec/CVE-2025-31200.svg)

- [https://github.com/serundengsapi/CVE-2025-31200-iOS-AudioConverter-RCE](https://github.com/serundengsapi/CVE-2025-31200-iOS-AudioConverter-RCE) :  ![starts](https://img.shields.io/github/stars/serundengsapi/CVE-2025-31200-iOS-AudioConverter-RCE.svg) ![forks](https://img.shields.io/github/forks/serundengsapi/CVE-2025-31200-iOS-AudioConverter-RCE.svg)

## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.



- [https://github.com/Immersive-Labs-Sec/CVE-2025-31161](https://github.com/Immersive-Labs-Sec/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/CVE-2025-31161.svg)

- [https://github.com/ghostsec420/ShatteredFTP](https://github.com/ghostsec420/ShatteredFTP) :  ![starts](https://img.shields.io/github/stars/ghostsec420/ShatteredFTP.svg) ![forks](https://img.shields.io/github/forks/ghostsec420/ShatteredFTP.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-31161](https://github.com/0xgh057r3c0n/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-31161.svg)

- [https://github.com/ibrahmsql/CVE-2025-31161](https://github.com/ibrahmsql/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2025-31161.svg)

- [https://github.com/TX-One/CVE-2025-31161](https://github.com/TX-One/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/TX-One/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/TX-One/CVE-2025-31161.svg)

- [https://github.com/f4dee-backup/CVE-2025-31161](https://github.com/f4dee-backup/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/f4dee-backup/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/f4dee-backup/CVE-2025-31161.svg)

- [https://github.com/cesarbtakeda/CVE-2025-31161](https://github.com/cesarbtakeda/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/cesarbtakeda/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/cesarbtakeda/CVE-2025-31161.svg)

- [https://github.com/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825](https://github.com/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-31161](https://github.com/B1ack4sh/Blackash-CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-31161.svg)

- [https://github.com/acan0007/CVE-2025-31161](https://github.com/acan0007/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/acan0007/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/acan0007/CVE-2025-31161.svg)

- [https://github.com/Teexo/CVE-2025-31161](https://github.com/Teexo/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/Teexo/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/Teexo/CVE-2025-31161.svg)

- [https://github.com/r0otk3r/CVE-2025-31161](https://github.com/r0otk3r/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2025-31161.svg)

- [https://github.com/SUPRAAA-1337/CVE-2025-31161_exploit](https://github.com/SUPRAAA-1337/CVE-2025-31161_exploit) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/CVE-2025-31161_exploit.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/CVE-2025-31161_exploit.svg)

- [https://github.com/0xDTC/CrushFTP-auth-bypass-CVE-2025-31161](https://github.com/0xDTC/CrushFTP-auth-bypass-CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/0xDTC/CrushFTP-auth-bypass-CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/0xDTC/CrushFTP-auth-bypass-CVE-2025-31161.svg)

## CVE-2025-31137
 React Router is a multi-strategy router for React bridging the gap from React 18 to React 19. There is a vulnerability in Remix/React Router that affects all Remix 2 and React Router 7 consumers using the Express adapter. Basically, this vulnerability allows anyone to spoof the URL used in an incoming Request by putting a URL pathname in the port section of a URL that is part of a Host or X-Forwarded-Host header sent to a Remix/React Router request handler. This issue has been patched and released in Remix 2.16.3 and React Router 7.4.1.



- [https://github.com/pouriam23/vulnerability-in-Remix-React-Router-CVE-2025-31137-](https://github.com/pouriam23/vulnerability-in-Remix-React-Router-CVE-2025-31137-) :  ![starts](https://img.shields.io/github/stars/pouriam23/vulnerability-in-Remix-React-Router-CVE-2025-31137-.svg) ![forks](https://img.shields.io/github/forks/pouriam23/vulnerability-in-Remix-React-Router-CVE-2025-31137-.svg)

## CVE-2025-31131
 YesWiki is a wiki system written in PHP. The squelette parameter is vulnerable to path traversal attacks, enabling read access to arbitrary files on the server. This vulnerability is fixed in 4.5.2.



- [https://github.com/MuhammadWaseem29/CVE-2025-31131](https://github.com/MuhammadWaseem29/CVE-2025-31131) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-31131.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-31131.svg)

- [https://github.com/nak000/CVE-2025-31131-RCE](https://github.com/nak000/CVE-2025-31131-RCE) :  ![starts](https://img.shields.io/github/stars/nak000/CVE-2025-31131-RCE.svg) ![forks](https://img.shields.io/github/forks/nak000/CVE-2025-31131-RCE.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-31131](https://github.com/B1ack4sh/Blackash-CVE-2025-31131) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-31131.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-31131.svg)

## CVE-2025-31129
 Jooby is a web framework for Java and Kotlin. The pac4j io.jooby.internal.pac4j.SessionStoreImpl#get module deserializes untrusted data. This vulnerability is fixed in 2.17.0 (2.x) and 3.7.0 (3.x).



- [https://github.com/cwm1123/CVE-2025-31129](https://github.com/cwm1123/CVE-2025-31129) :  ![starts](https://img.shields.io/github/stars/cwm1123/CVE-2025-31129.svg) ![forks](https://img.shields.io/github/forks/cwm1123/CVE-2025-31129.svg)

## CVE-2025-31125
 Vite is a frontend tooling framework for javascript. Vite exposes content of non-allowed files using ?inline&import or ?raw?import. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. This vulnerability is fixed in 6.2.4, 6.1.3, 6.0.13, 5.4.16, and 4.5.11.



- [https://github.com/xuemian168/CVE-2025-30208](https://github.com/xuemian168/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/xuemian168/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/xuemian168/CVE-2025-30208.svg)

- [https://github.com/jackieya/ViteVulScan](https://github.com/jackieya/ViteVulScan) :  ![starts](https://img.shields.io/github/stars/jackieya/ViteVulScan.svg) ![forks](https://img.shields.io/github/forks/jackieya/ViteVulScan.svg)

- [https://github.com/sunhuiHi666/CVE-2025-31125](https://github.com/sunhuiHi666/CVE-2025-31125) :  ![starts](https://img.shields.io/github/stars/sunhuiHi666/CVE-2025-31125.svg) ![forks](https://img.shields.io/github/forks/sunhuiHi666/CVE-2025-31125.svg)

- [https://github.com/nak000/Vitejs-exploit-CVE-2025-31125-rce](https://github.com/nak000/Vitejs-exploit-CVE-2025-31125-rce) :  ![starts](https://img.shields.io/github/stars/nak000/Vitejs-exploit-CVE-2025-31125-rce.svg) ![forks](https://img.shields.io/github/forks/nak000/Vitejs-exploit-CVE-2025-31125-rce.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-31125](https://github.com/0xgh057r3c0n/CVE-2025-31125) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-31125.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-31125.svg)

- [https://github.com/harshgupptaa/Path-Transversal-CVE-2025-31125-](https://github.com/harshgupptaa/Path-Transversal-CVE-2025-31125-) :  ![starts](https://img.shields.io/github/stars/harshgupptaa/Path-Transversal-CVE-2025-31125-.svg) ![forks](https://img.shields.io/github/forks/harshgupptaa/Path-Transversal-CVE-2025-31125-.svg)

- [https://github.com/MuhammadWaseem29/Vitejs-exploit](https://github.com/MuhammadWaseem29/Vitejs-exploit) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/Vitejs-exploit.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/Vitejs-exploit.svg)

## CVE-2025-31033
 Cross-Site Request Forgery (CSRF) vulnerability in Adam Nowak Buddypress Humanity allows Cross Site Request Forgery. This issue affects Buddypress Humanity: from n/a through 1.2.



- [https://github.com/Nxploited/CVE-2025-31033](https://github.com/Nxploited/CVE-2025-31033) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-31033.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-31033.svg)

## CVE-2025-30967
 Cross-Site Request Forgery (CSRF) vulnerability in NotFound WPJobBoard allows Upload a Web Shell to a Web Server. This issue affects WPJobBoard: from n/a through n/a.



- [https://github.com/Anton-ai111/CVE-2025-30967](https://github.com/Anton-ai111/CVE-2025-30967) :  ![starts](https://img.shields.io/github/stars/Anton-ai111/CVE-2025-30967.svg) ![forks](https://img.shields.io/github/forks/Anton-ai111/CVE-2025-30967.svg)

## CVE-2025-30921
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Tribulant Software Newsletters allows SQL Injection. This issue affects Newsletters: from n/a through 4.9.9.7.



- [https://github.com/DoTTak/CVE-2025-30921](https://github.com/DoTTak/CVE-2025-30921) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-30921.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-30921.svg)

## CVE-2025-30911
 Improper Control of Generation of Code ('Code Injection') vulnerability in Rometheme RomethemeKit For Elementor allows Command Injection. This issue affects RomethemeKit For Elementor: from n/a through 1.5.4.



- [https://github.com/Nxploited/CVE-2025-30911](https://github.com/Nxploited/CVE-2025-30911) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-30911.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-30911.svg)

## CVE-2025-30772
 Missing Authorization vulnerability in WPClever WPC Smart Upsell Funnel for WooCommerce allows Privilege Escalation. This issue affects WPC Smart Upsell Funnel for WooCommerce: from n/a through 3.0.4.



- [https://github.com/Nxploited/CVE-2025-30772](https://github.com/Nxploited/CVE-2025-30772) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-30772.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-30772.svg)

## CVE-2025-30712
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core).   The supported version that is affected is 7.1.6. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox.  While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle VM VirtualBox accessible data as well as  unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle VM VirtualBox. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L).



- [https://github.com/jamesb5959/CVE-2025-30712-_PoC](https://github.com/jamesb5959/CVE-2025-30712-_PoC) :  ![starts](https://img.shields.io/github/stars/jamesb5959/CVE-2025-30712-_PoC.svg) ![forks](https://img.shields.io/github/forks/jamesb5959/CVE-2025-30712-_PoC.svg)

## CVE-2025-30567
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in wp01ru WP01 allows Path Traversal. This issue affects WP01: from n/a through 2.6.2.



- [https://github.com/Oyst3r1ng/CVE-2025-30567](https://github.com/Oyst3r1ng/CVE-2025-30567) :  ![starts](https://img.shields.io/github/stars/Oyst3r1ng/CVE-2025-30567.svg) ![forks](https://img.shields.io/github/forks/Oyst3r1ng/CVE-2025-30567.svg)

## CVE-2025-30468
 This issue was addressed through improved state management. This issue is fixed in iOS 26 and iPadOS 26. Private Browsing tabs may be accessed without authentication.



- [https://github.com/richeeta/DEFCON33-Siriously-Leaky](https://github.com/richeeta/DEFCON33-Siriously-Leaky) :  ![starts](https://img.shields.io/github/stars/richeeta/DEFCON33-Siriously-Leaky.svg) ![forks](https://img.shields.io/github/forks/richeeta/DEFCON33-Siriously-Leaky.svg)

## CVE-2025-30406
 Gladinet CentreStack through 16.1.10296.56315 (fixed in 16.4.10315.56368) has a deserialization vulnerability due to the CentreStack portal's hardcoded machineKey use, as exploited in the wild in March 2025. This enables threat actors (who know the machineKey) to serialize a payload for server-side deserialization to achieve remote code execution. NOTE: a CentreStack admin can manually delete the machineKey defined in portal\web.config.



- [https://github.com/mchklt/CVE-2025-30406](https://github.com/mchklt/CVE-2025-30406) :  ![starts](https://img.shields.io/github/stars/mchklt/CVE-2025-30406.svg) ![forks](https://img.shields.io/github/forks/mchklt/CVE-2025-30406.svg)

- [https://github.com/W01fh4cker/CVE-2025-30406](https://github.com/W01fh4cker/CVE-2025-30406) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/CVE-2025-30406.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/CVE-2025-30406.svg)

- [https://github.com/threadpoolx/CVE-2025-30406-CentreStack-Triofox-Deserialization-RCE](https://github.com/threadpoolx/CVE-2025-30406-CentreStack-Triofox-Deserialization-RCE) :  ![starts](https://img.shields.io/github/stars/threadpoolx/CVE-2025-30406-CentreStack-Triofox-Deserialization-RCE.svg) ![forks](https://img.shields.io/github/forks/threadpoolx/CVE-2025-30406-CentreStack-Triofox-Deserialization-RCE.svg)

## CVE-2025-30400
 Use after free in Windows DWM allows an authorized attacker to elevate privileges locally.



- [https://github.com/encrypter15/CVE-2025-30400](https://github.com/encrypter15/CVE-2025-30400) :  ![starts](https://img.shields.io/github/stars/encrypter15/CVE-2025-30400.svg) ![forks](https://img.shields.io/github/forks/encrypter15/CVE-2025-30400.svg)

## CVE-2025-30397
 Access of resource using incompatible type ('type confusion') in Microsoft Scripting Engine allows an unauthorized attacker to execute code over a network.



- [https://github.com/mbanyamer/CVE-2025-30397---Windows-Server-2025-JScript-RCE-Use-After-Free-](https://github.com/mbanyamer/CVE-2025-30397---Windows-Server-2025-JScript-RCE-Use-After-Free-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2025-30397---Windows-Server-2025-JScript-RCE-Use-After-Free-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2025-30397---Windows-Server-2025-JScript-RCE-Use-After-Free-.svg)

- [https://github.com/Leviticus-Triage/ChromSploit-Framework](https://github.com/Leviticus-Triage/ChromSploit-Framework) :  ![starts](https://img.shields.io/github/stars/Leviticus-Triage/ChromSploit-Framework.svg) ![forks](https://img.shields.io/github/forks/Leviticus-Triage/ChromSploit-Framework.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-30397](https://github.com/B1ack4sh/Blackash-CVE-2025-30397) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-30397.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-30397.svg)

## CVE-2025-30349
 Horde IMP through 6.2.27, as used with Horde Application Framework through 5.2.23, allows XSS that leads to account takeover via a crafted text/html e-mail message with an onerror attribute (that may use base64-encoded JavaScript code), as exploited in the wild in March 2025.



- [https://github.com/natasaka/CVE-2025-30349](https://github.com/natasaka/CVE-2025-30349) :  ![starts](https://img.shields.io/github/stars/natasaka/CVE-2025-30349.svg) ![forks](https://img.shields.io/github/forks/natasaka/CVE-2025-30349.svg)

## CVE-2025-30216
 CryptoLib provides a software-only solution using the CCSDS Space Data Link Security Protocol - Extended Procedures (SDLS-EP) to secure communications between a spacecraft running the core Flight System (cFS) and a ground station. In versions 1.3.3 and prior, a Heap Overflow vulnerability occurs in the `Crypto_TM_ProcessSecurity` function (`crypto_tm.c:1735:8`). When processing the Secondary Header Length of a TM protocol packet, if the Secondary Header Length exceeds the packet's total length, a heap overflow is triggered during the memcpy operation that copies packet data into the dynamically allocated buffer `p_new_dec_frame`. This allows an attacker to overwrite adjacent heap memory, potentially leading to arbitrary code execution or system instability. A patch is available at commit 810fd66d592c883125272fef123c3240db2f170f.



- [https://github.com/oliviaisntcringe/CVE-2025-30216-PoC](https://github.com/oliviaisntcringe/CVE-2025-30216-PoC) :  ![starts](https://img.shields.io/github/stars/oliviaisntcringe/CVE-2025-30216-PoC.svg) ![forks](https://img.shields.io/github/forks/oliviaisntcringe/CVE-2025-30216-PoC.svg)

## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.



- [https://github.com/ThumpBo/CVE-2025-30208-EXP](https://github.com/ThumpBo/CVE-2025-30208-EXP) :  ![starts](https://img.shields.io/github/stars/ThumpBo/CVE-2025-30208-EXP.svg) ![forks](https://img.shields.io/github/forks/ThumpBo/CVE-2025-30208-EXP.svg)

- [https://github.com/xuemian168/CVE-2025-30208](https://github.com/xuemian168/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/xuemian168/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/xuemian168/CVE-2025-30208.svg)

- [https://github.com/marino-admin/Vite-CVE-2025-30208-Scanner](https://github.com/marino-admin/Vite-CVE-2025-30208-Scanner) :  ![starts](https://img.shields.io/github/stars/marino-admin/Vite-CVE-2025-30208-Scanner.svg) ![forks](https://img.shields.io/github/forks/marino-admin/Vite-CVE-2025-30208-Scanner.svg)

- [https://github.com/4xura/CVE-2025-30208](https://github.com/4xura/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/4xura/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/4xura/CVE-2025-30208.svg)

- [https://github.com/jackieya/ViteVulScan](https://github.com/jackieya/ViteVulScan) :  ![starts](https://img.shields.io/github/stars/jackieya/ViteVulScan.svg) ![forks](https://img.shields.io/github/forks/jackieya/ViteVulScan.svg)

- [https://github.com/ThemeHackers/CVE-2025-30208](https://github.com/ThemeHackers/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-30208.svg)

- [https://github.com/nkuty/CVE-2025-30208-31125-31486-32395](https://github.com/nkuty/CVE-2025-30208-31125-31486-32395) :  ![starts](https://img.shields.io/github/stars/nkuty/CVE-2025-30208-31125-31486-32395.svg) ![forks](https://img.shields.io/github/forks/nkuty/CVE-2025-30208-31125-31486-32395.svg)

- [https://github.com/On1onss/CVE-2025-30208-LFI](https://github.com/On1onss/CVE-2025-30208-LFI) :  ![starts](https://img.shields.io/github/stars/On1onss/CVE-2025-30208-LFI.svg) ![forks](https://img.shields.io/github/forks/On1onss/CVE-2025-30208-LFI.svg)

- [https://github.com/4m3rr0r/CVE-2025-30208-PoC](https://github.com/4m3rr0r/CVE-2025-30208-PoC) :  ![starts](https://img.shields.io/github/stars/4m3rr0r/CVE-2025-30208-PoC.svg) ![forks](https://img.shields.io/github/forks/4m3rr0r/CVE-2025-30208-PoC.svg)

- [https://github.com/kk12-30/CVE-2025-30208](https://github.com/kk12-30/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/kk12-30/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/kk12-30/CVE-2025-30208.svg)

- [https://github.com/r0ngy40/CVE-2025-30208-Series](https://github.com/r0ngy40/CVE-2025-30208-Series) :  ![starts](https://img.shields.io/github/stars/r0ngy40/CVE-2025-30208-Series.svg) ![forks](https://img.shields.io/github/forks/r0ngy40/CVE-2025-30208-Series.svg)

- [https://github.com/keklick1337/CVE-2025-30208-ViteVulnScanner](https://github.com/keklick1337/CVE-2025-30208-ViteVulnScanner) :  ![starts](https://img.shields.io/github/stars/keklick1337/CVE-2025-30208-ViteVulnScanner.svg) ![forks](https://img.shields.io/github/forks/keklick1337/CVE-2025-30208-ViteVulnScanner.svg)

- [https://github.com/sumeet-darekar/CVE-2025-30208](https://github.com/sumeet-darekar/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/sumeet-darekar/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/sumeet-darekar/CVE-2025-30208.svg)

- [https://github.com/TH-SecForge/CVE-2025-30208](https://github.com/TH-SecForge/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/TH-SecForge/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/TH-SecForge/CVE-2025-30208.svg)

- [https://github.com/imbas007/CVE-2025-30208-template](https://github.com/imbas007/CVE-2025-30208-template) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-30208-template.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-30208-template.svg)

- [https://github.com/lilil3333/Vite-CVE-2025-30208-EXP](https://github.com/lilil3333/Vite-CVE-2025-30208-EXP) :  ![starts](https://img.shields.io/github/stars/lilil3333/Vite-CVE-2025-30208-EXP.svg) ![forks](https://img.shields.io/github/forks/lilil3333/Vite-CVE-2025-30208-EXP.svg)

- [https://github.com/qodo-dev/CVE-2025-30208](https://github.com/qodo-dev/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/qodo-dev/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/qodo-dev/CVE-2025-30208.svg)

- [https://github.com/bugdotexe/CVE-2025-30208](https://github.com/bugdotexe/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/bugdotexe/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/bugdotexe/CVE-2025-30208.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-30208](https://github.com/B1ack4sh/Blackash-CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-30208.svg)

- [https://github.com/HaGsec/CVE-2025-30208](https://github.com/HaGsec/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/HaGsec/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/HaGsec/CVE-2025-30208.svg)

- [https://github.com/0xshaheen/CVE-2025-30208](https://github.com/0xshaheen/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/0xshaheen/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/0xshaheen/CVE-2025-30208.svg)

- [https://github.com/Lusensec/CVE-2025-30208](https://github.com/Lusensec/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/Lusensec/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/Lusensec/CVE-2025-30208.svg)

- [https://github.com/sadhfdw129/CVE-2025-30208-Vite](https://github.com/sadhfdw129/CVE-2025-30208-Vite) :  ![starts](https://img.shields.io/github/stars/sadhfdw129/CVE-2025-30208-Vite.svg) ![forks](https://img.shields.io/github/forks/sadhfdw129/CVE-2025-30208-Vite.svg)

- [https://github.com/MiclelsonCN/CVE-2025-30208_POC](https://github.com/MiclelsonCN/CVE-2025-30208_POC) :  ![starts](https://img.shields.io/github/stars/MiclelsonCN/CVE-2025-30208_POC.svg) ![forks](https://img.shields.io/github/forks/MiclelsonCN/CVE-2025-30208_POC.svg)

- [https://github.com/iSee857/CVE-2025-30208-PoC](https://github.com/iSee857/CVE-2025-30208-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-30208-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-30208-PoC.svg)

## CVE-2025-30144
 fast-jwt provides fast JSON Web Token (JWT) implementation. Prior to 5.0.6, the fast-jwt library does not properly validate the iss claim based on the RFC 7519. The iss (issuer) claim validation within the fast-jwt library permits an array of strings as a valid iss value. This design flaw enables a potential attack where a malicious actor crafts a JWT with an iss claim structured as ['https://attacker-domain/', 'https://valid-iss']. Due to the permissive validation, the JWT will be deemed valid. Furthermore, if the application relies on external libraries like get-jwks that do not independently validate the iss claim, the attacker can leverage this vulnerability to forge a JWT that will be accepted by the victim application. Essentially, the attacker can insert their own domain into the iss array, alongside the legitimate issuer, and bypass the intended security checks. This issue is fixed in 5.0.6.



- [https://github.com/tibrn/CVE-2025-30144](https://github.com/tibrn/CVE-2025-30144) :  ![starts](https://img.shields.io/github/stars/tibrn/CVE-2025-30144.svg) ![forks](https://img.shields.io/github/forks/tibrn/CVE-2025-30144.svg)

## CVE-2025-30066
 tj-actions changed-files before 46 allows remote attackers to discover secrets by reading actions logs. (The tags v1 through v45.0.7 were affected on 2025-03-14 and 2025-03-15 because they were modified by a threat actor to point at commit 0e58ed8, which contained malicious updateFeatures code.)



- [https://github.com/Checkmarx/Checkmarx-CVE-2025-30066-Detection-Tool](https://github.com/Checkmarx/Checkmarx-CVE-2025-30066-Detection-Tool) :  ![starts](https://img.shields.io/github/stars/Checkmarx/Checkmarx-CVE-2025-30066-Detection-Tool.svg) ![forks](https://img.shields.io/github/forks/Checkmarx/Checkmarx-CVE-2025-30066-Detection-Tool.svg)

- [https://github.com/OS-pedrogustavobilro/test-changed-files](https://github.com/OS-pedrogustavobilro/test-changed-files) :  ![starts](https://img.shields.io/github/stars/OS-pedrogustavobilro/test-changed-files.svg) ![forks](https://img.shields.io/github/forks/OS-pedrogustavobilro/test-changed-files.svg)

## CVE-2025-30065
 Schema parsing in the parquet-avro module of Apache Parquet 1.15.0 and previous versions allows bad actors to execute arbitrary code


Users are recommended to upgrade to version 1.15.1, which fixes the issue.



- [https://github.com/bjornhels/CVE-2025-30065](https://github.com/bjornhels/CVE-2025-30065) :  ![starts](https://img.shields.io/github/stars/bjornhels/CVE-2025-30065.svg) ![forks](https://img.shields.io/github/forks/bjornhels/CVE-2025-30065.svg)

- [https://github.com/F5-Labs/parquet-canary-exploit-rce-poc-CVE-2025-30065](https://github.com/F5-Labs/parquet-canary-exploit-rce-poc-CVE-2025-30065) :  ![starts](https://img.shields.io/github/stars/F5-Labs/parquet-canary-exploit-rce-poc-CVE-2025-30065.svg) ![forks](https://img.shields.io/github/forks/F5-Labs/parquet-canary-exploit-rce-poc-CVE-2025-30065.svg)

- [https://github.com/h3st4k3r/CVE-2025-30065](https://github.com/h3st4k3r/CVE-2025-30065) :  ![starts](https://img.shields.io/github/stars/h3st4k3r/CVE-2025-30065.svg) ![forks](https://img.shields.io/github/forks/h3st4k3r/CVE-2025-30065.svg)

- [https://github.com/mouadk/parquet-rce-poc-CVE-2025-30065](https://github.com/mouadk/parquet-rce-poc-CVE-2025-30065) :  ![starts](https://img.shields.io/github/stars/mouadk/parquet-rce-poc-CVE-2025-30065.svg) ![forks](https://img.shields.io/github/forks/mouadk/parquet-rce-poc-CVE-2025-30065.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-30065](https://github.com/B1ack4sh/Blackash-CVE-2025-30065) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-30065.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-30065.svg)

- [https://github.com/ThreatRadarAI/TRAI-001-Critical-RCE-Vulnerability-in-Apache-Parquet-CVE-2025-30065-Simulation](https://github.com/ThreatRadarAI/TRAI-001-Critical-RCE-Vulnerability-in-Apache-Parquet-CVE-2025-30065-Simulation) :  ![starts](https://img.shields.io/github/stars/ThreatRadarAI/TRAI-001-Critical-RCE-Vulnerability-in-Apache-Parquet-CVE-2025-30065-Simulation.svg) ![forks](https://img.shields.io/github/forks/ThreatRadarAI/TRAI-001-Critical-RCE-Vulnerability-in-Apache-Parquet-CVE-2025-30065-Simulation.svg)

- [https://github.com/ron-imperva/CVE-2025-30065-PoC](https://github.com/ron-imperva/CVE-2025-30065-PoC) :  ![starts](https://img.shields.io/github/stars/ron-imperva/CVE-2025-30065-PoC.svg) ![forks](https://img.shields.io/github/forks/ron-imperva/CVE-2025-30065-PoC.svg)

## CVE-2025-29972
 Server-Side Request Forgery (SSRF) in Azure allows an authorized attacker to perform spoofing over a network.



- [https://github.com/ThemeHackers/CVE-2025-29972](https://github.com/ThemeHackers/CVE-2025-29972) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-29972.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-29972.svg)

- [https://github.com/TH-SecForge/CVE-2025-29972](https://github.com/TH-SecForge/CVE-2025-29972) :  ![starts](https://img.shields.io/github/stars/TH-SecForge/CVE-2025-29972.svg) ![forks](https://img.shields.io/github/forks/TH-SecForge/CVE-2025-29972.svg)

## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.



- [https://github.com/aydinnyunus/CVE-2025-29927](https://github.com/aydinnyunus/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/aydinnyunus/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/aydinnyunus/CVE-2025-29927.svg)

- [https://github.com/AnonKryptiQuz/NextSploit](https://github.com/AnonKryptiQuz/NextSploit) :  ![starts](https://img.shields.io/github/stars/AnonKryptiQuz/NextSploit.svg) ![forks](https://img.shields.io/github/forks/AnonKryptiQuz/NextSploit.svg)

- [https://github.com/websecnl/CVE-2025-29927-PoC-Exploit](https://github.com/websecnl/CVE-2025-29927-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/websecnl/CVE-2025-29927-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/websecnl/CVE-2025-29927-PoC-Exploit.svg)

- [https://github.com/6mile/nextjs-CVE-2025-29927](https://github.com/6mile/nextjs-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/6mile/nextjs-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/6mile/nextjs-CVE-2025-29927.svg)

- [https://github.com/azu/nextjs-cve-2025-29927-poc](https://github.com/azu/nextjs-cve-2025-29927-poc) :  ![starts](https://img.shields.io/github/stars/azu/nextjs-cve-2025-29927-poc.svg) ![forks](https://img.shields.io/github/forks/azu/nextjs-cve-2025-29927-poc.svg)

- [https://github.com/lirantal/vulnerable-nextjs-14-CVE-2025-29927](https://github.com/lirantal/vulnerable-nextjs-14-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/lirantal/vulnerable-nextjs-14-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/lirantal/vulnerable-nextjs-14-CVE-2025-29927.svg)

- [https://github.com/takumade/ghost-route](https://github.com/takumade/ghost-route) :  ![starts](https://img.shields.io/github/stars/takumade/ghost-route.svg) ![forks](https://img.shields.io/github/forks/takumade/ghost-route.svg)

- [https://github.com/KaztoRay/CVE-2025-29927-Research](https://github.com/KaztoRay/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2025-29927-Research.svg)

- [https://github.com/gotr00t0day/CVE-2025-29927](https://github.com/gotr00t0day/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/gotr00t0day/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/gotr00t0day/CVE-2025-29927.svg)

- [https://github.com/UNICORDev/exploit-CVE-2025-29927](https://github.com/UNICORDev/exploit-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/UNICORDev/exploit-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/UNICORDev/exploit-CVE-2025-29927.svg)

- [https://github.com/MuhammadWaseem29/CVE-2025-29927-POC](https://github.com/MuhammadWaseem29/CVE-2025-29927-POC) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-29927-POC.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-29927-POC.svg)

- [https://github.com/HoumanPashaei/CVE-2025-29927](https://github.com/HoumanPashaei/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/HoumanPashaei/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/HoumanPashaei/CVE-2025-29927.svg)

- [https://github.com/fourcube/nextjs-middleware-bypass-demo](https://github.com/fourcube/nextjs-middleware-bypass-demo) :  ![starts](https://img.shields.io/github/stars/fourcube/nextjs-middleware-bypass-demo.svg) ![forks](https://img.shields.io/github/forks/fourcube/nextjs-middleware-bypass-demo.svg)

- [https://github.com/RoyCampos/CVE-2025-29927](https://github.com/RoyCampos/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/RoyCampos/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/RoyCampos/CVE-2025-29927.svg)

- [https://github.com/Ademking/CVE-2025-29927](https://github.com/Ademking/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Ademking/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Ademking/CVE-2025-29927.svg)

- [https://github.com/t3tra-dev/cve-2025-29927-demo](https://github.com/t3tra-dev/cve-2025-29927-demo) :  ![starts](https://img.shields.io/github/stars/t3tra-dev/cve-2025-29927-demo.svg) ![forks](https://img.shields.io/github/forks/t3tra-dev/cve-2025-29927-demo.svg)

- [https://github.com/0xWhoknows/CVE-2025-29927](https://github.com/0xWhoknows/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xWhoknows/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xWhoknows/CVE-2025-29927.svg)

- [https://github.com/c0dejump/CVE-2025-29927-check](https://github.com/c0dejump/CVE-2025-29927-check) :  ![starts](https://img.shields.io/github/stars/c0dejump/CVE-2025-29927-check.svg) ![forks](https://img.shields.io/github/forks/c0dejump/CVE-2025-29927-check.svg)

- [https://github.com/yugo-eliatrope/test-cve-2025-29927](https://github.com/yugo-eliatrope/test-cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/yugo-eliatrope/test-cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/yugo-eliatrope/test-cve-2025-29927.svg)

- [https://github.com/Eve-SatOrU/POC-CVE-2025-29927](https://github.com/Eve-SatOrU/POC-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Eve-SatOrU/POC-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Eve-SatOrU/POC-CVE-2025-29927.svg)

- [https://github.com/alihussainzada/CVE-2025-29927-PoC](https://github.com/alihussainzada/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/alihussainzada/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/alihussainzada/CVE-2025-29927-PoC.svg)

- [https://github.com/luq0x/0xMiddleware](https://github.com/luq0x/0xMiddleware) :  ![starts](https://img.shields.io/github/stars/luq0x/0xMiddleware.svg) ![forks](https://img.shields.io/github/forks/luq0x/0xMiddleware.svg)

- [https://github.com/Neoxs/nextjs-middleware-vuln-poc](https://github.com/Neoxs/nextjs-middleware-vuln-poc) :  ![starts](https://img.shields.io/github/stars/Neoxs/nextjs-middleware-vuln-poc.svg) ![forks](https://img.shields.io/github/forks/Neoxs/nextjs-middleware-vuln-poc.svg)

- [https://github.com/strobes-security/nextjs-vulnerable-app](https://github.com/strobes-security/nextjs-vulnerable-app) :  ![starts](https://img.shields.io/github/stars/strobes-security/nextjs-vulnerable-app.svg) ![forks](https://img.shields.io/github/forks/strobes-security/nextjs-vulnerable-app.svg)

- [https://github.com/TheresAFewConors/CVE-2025-29927-Testing](https://github.com/TheresAFewConors/CVE-2025-29927-Testing) :  ![starts](https://img.shields.io/github/stars/TheresAFewConors/CVE-2025-29927-Testing.svg) ![forks](https://img.shields.io/github/forks/TheresAFewConors/CVE-2025-29927-Testing.svg)

- [https://github.com/kOaDT/poc-cve-2025-29927](https://github.com/kOaDT/poc-cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/kOaDT/poc-cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/kOaDT/poc-cve-2025-29927.svg)

- [https://github.com/Oyst3r1ng/CVE-2025-29927](https://github.com/Oyst3r1ng/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Oyst3r1ng/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Oyst3r1ng/CVE-2025-29927.svg)

- [https://github.com/lem0n817/CVE-2025-29927](https://github.com/lem0n817/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/lem0n817/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/lem0n817/CVE-2025-29927.svg)

- [https://github.com/emadshanab/CVE-2025-29927](https://github.com/emadshanab/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/emadshanab/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/emadshanab/CVE-2025-29927.svg)

- [https://github.com/arvion-agent/next-CVE-2025-29927](https://github.com/arvion-agent/next-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/arvion-agent/next-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/arvion-agent/next-CVE-2025-29927.svg)

- [https://github.com/Nekicj/CVE-2025-29927-exploit](https://github.com/Nekicj/CVE-2025-29927-exploit) :  ![starts](https://img.shields.io/github/stars/Nekicj/CVE-2025-29927-exploit.svg) ![forks](https://img.shields.io/github/forks/Nekicj/CVE-2025-29927-exploit.svg)

- [https://github.com/pouriam23/Next.js-Middleware-Bypass-CVE-2025-29927-](https://github.com/pouriam23/Next.js-Middleware-Bypass-CVE-2025-29927-) :  ![starts](https://img.shields.io/github/stars/pouriam23/Next.js-Middleware-Bypass-CVE-2025-29927-.svg) ![forks](https://img.shields.io/github/forks/pouriam23/Next.js-Middleware-Bypass-CVE-2025-29927-.svg)

- [https://github.com/Jull3Hax0r/next.js-exploit](https://github.com/Jull3Hax0r/next.js-exploit) :  ![starts](https://img.shields.io/github/stars/Jull3Hax0r/next.js-exploit.svg) ![forks](https://img.shields.io/github/forks/Jull3Hax0r/next.js-exploit.svg)

- [https://github.com/ferpalma21/Automated-Next.js-Security-Scanner-for-CVE-2025-29927](https://github.com/ferpalma21/Automated-Next.js-Security-Scanner-for-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ferpalma21/Automated-Next.js-Security-Scanner-for-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ferpalma21/Automated-Next.js-Security-Scanner-for-CVE-2025-29927.svg)

- [https://github.com/ThemeHackers/CVE-2025-29972](https://github.com/ThemeHackers/CVE-2025-29972) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-29972.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-29972.svg)

- [https://github.com/pixilated730/NextJS-Exploit-](https://github.com/pixilated730/NextJS-Exploit-) :  ![starts](https://img.shields.io/github/stars/pixilated730/NextJS-Exploit-.svg) ![forks](https://img.shields.io/github/forks/pixilated730/NextJS-Exploit-.svg)

- [https://github.com/0xnxt1me/CVE-2025-29927](https://github.com/0xnxt1me/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xnxt1me/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xnxt1me/CVE-2025-29927.svg)

- [https://github.com/alastair66/CVE-2025-29927](https://github.com/alastair66/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/alastair66/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/alastair66/CVE-2025-29927.svg)

- [https://github.com/EQSTLab/CVE-2025-29927](https://github.com/EQSTLab/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2025-29927.svg)

- [https://github.com/rubbxalc/CVE-2025-29927](https://github.com/rubbxalc/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rubbxalc/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rubbxalc/CVE-2025-29927.svg)

- [https://github.com/ricsirigu/CVE-2025-29927](https://github.com/ricsirigu/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ricsirigu/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ricsirigu/CVE-2025-29927.svg)

- [https://github.com/iteride/CVE-2025-29927](https://github.com/iteride/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/iteride/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/iteride/CVE-2025-29927.svg)

- [https://github.com/Bongni/CVE-2025-29927](https://github.com/Bongni/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Bongni/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Bongni/CVE-2025-29927.svg)

- [https://github.com/kuzushiki/CVE-2025-29927-test](https://github.com/kuzushiki/CVE-2025-29927-test) :  ![starts](https://img.shields.io/github/stars/kuzushiki/CVE-2025-29927-test.svg) ![forks](https://img.shields.io/github/forks/kuzushiki/CVE-2025-29927-test.svg)

- [https://github.com/nocomp/CVE-2025-29927-scanner](https://github.com/nocomp/CVE-2025-29927-scanner) :  ![starts](https://img.shields.io/github/stars/nocomp/CVE-2025-29927-scanner.svg) ![forks](https://img.shields.io/github/forks/nocomp/CVE-2025-29927-scanner.svg)

- [https://github.com/olimpiofreitas/CVE-2025-29927-scanner](https://github.com/olimpiofreitas/CVE-2025-29927-scanner) :  ![starts](https://img.shields.io/github/stars/olimpiofreitas/CVE-2025-29927-scanner.svg) ![forks](https://img.shields.io/github/forks/olimpiofreitas/CVE-2025-29927-scanner.svg)

- [https://github.com/w2hcorp/CVE-2025-29927-PoC](https://github.com/w2hcorp/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/w2hcorp/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/w2hcorp/CVE-2025-29927-PoC.svg)

- [https://github.com/Kamal-418/Vulnerable-Lab-NextJS-CVE-2025-29927](https://github.com/Kamal-418/Vulnerable-Lab-NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Kamal-418/Vulnerable-Lab-NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Kamal-418/Vulnerable-Lab-NextJS-CVE-2025-29927.svg)

- [https://github.com/TH-SecForge/CVE-2025-29972](https://github.com/TH-SecForge/CVE-2025-29972) :  ![starts](https://img.shields.io/github/stars/TH-SecForge/CVE-2025-29972.svg) ![forks](https://img.shields.io/github/forks/TH-SecForge/CVE-2025-29972.svg)

- [https://github.com/0xh3g4z1/CVE-2025-29927-Next.js-Middleware-Authorization-Bypass](https://github.com/0xh3g4z1/CVE-2025-29927-Next.js-Middleware-Authorization-Bypass) :  ![starts](https://img.shields.io/github/stars/0xh3g4z1/CVE-2025-29927-Next.js-Middleware-Authorization-Bypass.svg) ![forks](https://img.shields.io/github/forks/0xh3g4z1/CVE-2025-29927-Next.js-Middleware-Authorization-Bypass.svg)

- [https://github.com/nicknisi/next-attack](https://github.com/nicknisi/next-attack) :  ![starts](https://img.shields.io/github/stars/nicknisi/next-attack.svg) ![forks](https://img.shields.io/github/forks/nicknisi/next-attack.svg)

- [https://github.com/diogolourencodev/middleforce](https://github.com/diogolourencodev/middleforce) :  ![starts](https://img.shields.io/github/stars/diogolourencodev/middleforce.svg) ![forks](https://img.shields.io/github/forks/diogolourencodev/middleforce.svg)

- [https://github.com/m2hcz/PoC-for-Next.js-Middleware](https://github.com/m2hcz/PoC-for-Next.js-Middleware) :  ![starts](https://img.shields.io/github/stars/m2hcz/PoC-for-Next.js-Middleware.svg) ![forks](https://img.shields.io/github/forks/m2hcz/PoC-for-Next.js-Middleware.svg)

- [https://github.com/narasimhauppala/nextjs-middleware-bypass](https://github.com/narasimhauppala/nextjs-middleware-bypass) :  ![starts](https://img.shields.io/github/stars/narasimhauppala/nextjs-middleware-bypass.svg) ![forks](https://img.shields.io/github/forks/narasimhauppala/nextjs-middleware-bypass.svg)

- [https://github.com/dedibagus/cve-2025-29927-poc](https://github.com/dedibagus/cve-2025-29927-poc) :  ![starts](https://img.shields.io/github/stars/dedibagus/cve-2025-29927-poc.svg) ![forks](https://img.shields.io/github/forks/dedibagus/cve-2025-29927-poc.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-29927](https://github.com/B1ack4sh/Blackash-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-29927.svg)

- [https://github.com/sermikr0/nextjs-middleware-auth-bypass](https://github.com/sermikr0/nextjs-middleware-auth-bypass) :  ![starts](https://img.shields.io/github/stars/sermikr0/nextjs-middleware-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/sermikr0/nextjs-middleware-auth-bypass.svg)

- [https://github.com/hed1ad/CVE-2025-29927](https://github.com/hed1ad/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/hed1ad/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/hed1ad/CVE-2025-29927.svg)

- [https://github.com/ethanol1310/POC-CVE-2025-29927-](https://github.com/ethanol1310/POC-CVE-2025-29927-) :  ![starts](https://img.shields.io/github/stars/ethanol1310/POC-CVE-2025-29927-.svg) ![forks](https://img.shields.io/github/forks/ethanol1310/POC-CVE-2025-29927-.svg)

- [https://github.com/aleongx/CVE-2025-29927](https://github.com/aleongx/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/aleongx/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/aleongx/CVE-2025-29927.svg)

- [https://github.com/mhamzakhattak/CVE-2025-29927](https://github.com/mhamzakhattak/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/mhamzakhattak/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/mhamzakhattak/CVE-2025-29927.svg)

- [https://github.com/zs1n/CVE-2025-29927](https://github.com/zs1n/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/zs1n/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/zs1n/CVE-2025-29927.svg)

- [https://github.com/0xcucumbersalad/cve-2025-29927](https://github.com/0xcucumbersalad/cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xcucumbersalad/cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xcucumbersalad/cve-2025-29927.svg)

- [https://github.com/Hirainsingadia/CVE-2025-29927](https://github.com/Hirainsingadia/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Hirainsingadia/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Hirainsingadia/CVE-2025-29927.svg)

- [https://github.com/BilalGns/CVE-2025-29927](https://github.com/BilalGns/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/BilalGns/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/BilalGns/CVE-2025-29927.svg)

- [https://github.com/newweshi/CVE-2025-29927](https://github.com/newweshi/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/newweshi/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/newweshi/CVE-2025-29927.svg)

- [https://github.com/JOOJIII/CVE-2025-29927](https://github.com/JOOJIII/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/JOOJIII/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/JOOJIII/CVE-2025-29927.svg)

- [https://github.com/iSee857/CVE-2025-29927](https://github.com/iSee857/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-29927.svg)

- [https://github.com/Balajih4kr/cve-2025-29927](https://github.com/Balajih4kr/cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/Balajih4kr/cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Balajih4kr/cve-2025-29927.svg)

- [https://github.com/kh4sh3i/CVE-2025-29927](https://github.com/kh4sh3i/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/kh4sh3i/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/kh4sh3i/CVE-2025-29927.svg)

- [https://github.com/sdrtba/CVE-2025-29927](https://github.com/sdrtba/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sdrtba/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sdrtba/CVE-2025-29927.svg)

- [https://github.com/sagsooz/CVE-2025-29927](https://github.com/sagsooz/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sagsooz/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sagsooz/CVE-2025-29927.svg)

- [https://github.com/jeymo092/cve-2025-29927](https://github.com/jeymo092/cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/jeymo092/cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/jeymo092/cve-2025-29927.svg)

- [https://github.com/b4sh0xf/PoC-CVE-2025-29927](https://github.com/b4sh0xf/PoC-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/b4sh0xf/PoC-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/b4sh0xf/PoC-CVE-2025-29927.svg)

- [https://github.com/dante01yoon/CVE-2025-29927](https://github.com/dante01yoon/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/dante01yoon/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/dante01yoon/CVE-2025-29927.svg)

- [https://github.com/sahbaazansari/CVE-2025-29927](https://github.com/sahbaazansari/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sahbaazansari/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sahbaazansari/CVE-2025-29927.svg)

- [https://github.com/Gokul-Krishnan-V-R/cve-2025-29927](https://github.com/Gokul-Krishnan-V-R/cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/Gokul-Krishnan-V-R/cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Gokul-Krishnan-V-R/cve-2025-29927.svg)

- [https://github.com/furmak331/CVE-2025-29927](https://github.com/furmak331/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/furmak331/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/furmak331/CVE-2025-29927.svg)

- [https://github.com/kuyrathdaro/cve-2025-29927](https://github.com/kuyrathdaro/cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/kuyrathdaro/cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/kuyrathdaro/cve-2025-29927.svg)

- [https://github.com/YEONDG/nextjs-cve-2025-29927](https://github.com/YEONDG/nextjs-cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/YEONDG/nextjs-cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/YEONDG/nextjs-cve-2025-29927.svg)

- [https://github.com/serhalp/test-cve-2025-29927](https://github.com/serhalp/test-cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/serhalp/test-cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/serhalp/test-cve-2025-29927.svg)

- [https://github.com/yuzu-juice/CVE-2025-29927_demo](https://github.com/yuzu-juice/CVE-2025-29927_demo) :  ![starts](https://img.shields.io/github/stars/yuzu-juice/CVE-2025-29927_demo.svg) ![forks](https://img.shields.io/github/forks/yuzu-juice/CVE-2025-29927_demo.svg)

- [https://github.com/SugiB3o/vulnerable-nextjs-14-CVE-2025-29927](https://github.com/SugiB3o/vulnerable-nextjs-14-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/SugiB3o/vulnerable-nextjs-14-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/SugiB3o/vulnerable-nextjs-14-CVE-2025-29927.svg)

- [https://github.com/aleongx/CVE-2025-29927_Scanner](https://github.com/aleongx/CVE-2025-29927_Scanner) :  ![starts](https://img.shields.io/github/stars/aleongx/CVE-2025-29927_Scanner.svg) ![forks](https://img.shields.io/github/forks/aleongx/CVE-2025-29927_Scanner.svg)

- [https://github.com/amitlttwo/Next.JS-CVE-2025-29927](https://github.com/amitlttwo/Next.JS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/amitlttwo/Next.JS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/amitlttwo/Next.JS-CVE-2025-29927.svg)

- [https://github.com/ticofookfook/poc-nextjs-CVE-2025-29927](https://github.com/ticofookfook/poc-nextjs-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ticofookfook/poc-nextjs-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ticofookfook/poc-nextjs-CVE-2025-29927.svg)

- [https://github.com/ayato-shitomi/WebLab_CVE-2025-29927](https://github.com/ayato-shitomi/WebLab_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ayato-shitomi/WebLab_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ayato-shitomi/WebLab_CVE-2025-29927.svg)

- [https://github.com/darklotuskdb/nextjs-CVE-2025-29927-hunter](https://github.com/darklotuskdb/nextjs-CVE-2025-29927-hunter) :  ![starts](https://img.shields.io/github/stars/darklotuskdb/nextjs-CVE-2025-29927-hunter.svg) ![forks](https://img.shields.io/github/forks/darklotuskdb/nextjs-CVE-2025-29927-hunter.svg)

- [https://github.com/elshaheedy/CVE-2025-29927-Sigma-Rule](https://github.com/elshaheedy/CVE-2025-29927-Sigma-Rule) :  ![starts](https://img.shields.io/github/stars/elshaheedy/CVE-2025-29927-Sigma-Rule.svg) ![forks](https://img.shields.io/github/forks/elshaheedy/CVE-2025-29927-Sigma-Rule.svg)

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)

- [https://github.com/MKIRAHMET/CVE-2025-29927-PoC](https://github.com/MKIRAHMET/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/MKIRAHMET/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/MKIRAHMET/CVE-2025-29927-PoC.svg)

- [https://github.com/0xPb1/Next.js-CVE-2025-29927](https://github.com/0xPb1/Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPb1/Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPb1/Next.js-CVE-2025-29927.svg)

- [https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927](https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sn1p3rt3s7/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sn1p3rt3s7/NextJS_CVE-2025-29927.svg)

- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)

- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)

- [https://github.com/maronnjapan/claude-create-CVE-2025-29927](https://github.com/maronnjapan/claude-create-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/maronnjapan/claude-create-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/maronnjapan/claude-create-CVE-2025-29927.svg)

- [https://github.com/0xPThree/next.js_cve-2025-29927](https://github.com/0xPThree/next.js_cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPThree/next.js_cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPThree/next.js_cve-2025-29927.svg)

- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)

- [https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg)

- [https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927](https://github.com/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/R3verseIN/Nextjs-middleware-vulnerable-appdemo-CVE-2025-29927.svg)

## CVE-2025-29824
 Use after free in Windows Common Log File System Driver allows an authorized attacker to elevate privileges locally.



- [https://github.com/encrypter15/CVE-2025-29824](https://github.com/encrypter15/CVE-2025-29824) :  ![starts](https://img.shields.io/github/stars/encrypter15/CVE-2025-29824.svg) ![forks](https://img.shields.io/github/forks/encrypter15/CVE-2025-29824.svg)

- [https://github.com/AfanPan/CVE-2025-29824-Exploit](https://github.com/AfanPan/CVE-2025-29824-Exploit) :  ![starts](https://img.shields.io/github/stars/AfanPan/CVE-2025-29824-Exploit.svg) ![forks](https://img.shields.io/github/forks/AfanPan/CVE-2025-29824-Exploit.svg)

- [https://github.com/zmkeh/CVE-2025-29824-CLFS-Local-privilege-escalation](https://github.com/zmkeh/CVE-2025-29824-CLFS-Local-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/zmkeh/CVE-2025-29824-CLFS-Local-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/zmkeh/CVE-2025-29824-CLFS-Local-privilege-escalation.svg)

## CVE-2025-29810
 Improper access control in Active Directory Domain Services allows an authorized attacker to elevate privileges over a network.



- [https://github.com/aleongx/CVE-2025-29810-check](https://github.com/aleongx/CVE-2025-29810-check) :  ![starts](https://img.shields.io/github/stars/aleongx/CVE-2025-29810-check.svg) ![forks](https://img.shields.io/github/forks/aleongx/CVE-2025-29810-check.svg)

## CVE-2025-29775
 xml-crypto is an XML digital signature and encryption library for Node.js. An attacker may be able to exploit a vulnerability in versions prior to 6.0.1, 3.2.1, and 2.1.6 to bypass authentication or authorization mechanisms in systems that rely on xml-crypto for verifying signed XML documents. The vulnerability allows an attacker to modify a valid signed XML message in a way that still passes signature verification checks. For example, it could be used to alter critical identity or access control attributes, enabling an attacker to escalate privileges or impersonate another user. Users of versions 6.0.0 and prior should upgrade to version 6.0.1 to receive a fix. Those who are still using v2.x or v3.x should upgrade to patched versions 2.1.6 or 3.2.1, respectively.



- [https://github.com/ethicalPap/CVE-2025-29775](https://github.com/ethicalPap/CVE-2025-29775) :  ![starts](https://img.shields.io/github/stars/ethicalPap/CVE-2025-29775.svg) ![forks](https://img.shields.io/github/forks/ethicalPap/CVE-2025-29775.svg)

## CVE-2025-29774
 xml-crypto is an XML digital signature and encryption library for Node.js. An attacker may be able to exploit a vulnerability in versions prior to 6.0.1, 3.2.1, and 2.1.6 to bypass authentication or authorization mechanisms in systems that rely on xml-crypto for verifying signed XML documents. The vulnerability allows an attacker to modify a valid signed XML message in a way that still passes signature verification checks. For example, it could be used to alter critical identity or access control attributes, enabling an attacker with a valid account to escalate privileges or impersonate another user. Users of versions 6.0.0 and prior should upgrade to version 6.0.1 to receive a fix. Those who are still using v2.x or v3.x should upgrade to patched versions 2.1.6 or 3.2.1, respectively.



- [https://github.com/demining/Digital-Signature-Forgery-Attack](https://github.com/demining/Digital-Signature-Forgery-Attack) :  ![starts](https://img.shields.io/github/stars/demining/Digital-Signature-Forgery-Attack.svg) ![forks](https://img.shields.io/github/forks/demining/Digital-Signature-Forgery-Attack.svg)

## CVE-2025-29722
 A CSRF vulnerability in Commercify v1.0 allows remote attackers to perform unauthorized actions on behalf of authenticated users. The issue exists due to missing CSRF protection on sensitive endpoints.



- [https://github.com/cypherdavy/CVE-2025-29722](https://github.com/cypherdavy/CVE-2025-29722) :  ![starts](https://img.shields.io/github/stars/cypherdavy/CVE-2025-29722.svg) ![forks](https://img.shields.io/github/forks/cypherdavy/CVE-2025-29722.svg)

## CVE-2025-29705
 code-gen =2.0.6 is vulnerable to Incorrect Access Control. The project does not have permission control allowing anyone to access such projects.



- [https://github.com/yxzrw/CVE-2025-29705](https://github.com/yxzrw/CVE-2025-29705) :  ![starts](https://img.shields.io/github/stars/yxzrw/CVE-2025-29705.svg) ![forks](https://img.shields.io/github/forks/yxzrw/CVE-2025-29705.svg)

## CVE-2025-29632
 Buffer Overflow vulnerability in Free5gc v.4.0.0 allows a remote attacker to cause a denial of service via the AMF, NGAP, security.go, handler_generated.go, handleInitialUEMessageMain, DecodePlainNasNoIntegrityCheck, GetSecurityHeaderType components



- [https://github.com/OHnogood/CVE-2025-29632](https://github.com/OHnogood/CVE-2025-29632) :  ![starts](https://img.shields.io/github/stars/OHnogood/CVE-2025-29632.svg) ![forks](https://img.shields.io/github/forks/OHnogood/CVE-2025-29632.svg)

## CVE-2025-29631
 An issue in Gardyn 4 allows a remote attacker execute arbitrary code



- [https://github.com/mselbrede/gardyn](https://github.com/mselbrede/gardyn) :  ![starts](https://img.shields.io/github/stars/mselbrede/gardyn.svg) ![forks](https://img.shields.io/github/forks/mselbrede/gardyn.svg)

## CVE-2025-29630
 An issue in Gardyn 4 allows a remote attacker with the corresponding ssh private key can gain remote root access to affected devices



- [https://github.com/mselbrede/gardyn](https://github.com/mselbrede/gardyn) :  ![starts](https://img.shields.io/github/stars/mselbrede/gardyn.svg) ![forks](https://img.shields.io/github/forks/mselbrede/gardyn.svg)

## CVE-2025-29629
 An issue in Gardyn 4 allows a remote attacker to obtain sensitive information and execute arbitrary code via the Gardyn Home component



- [https://github.com/mselbrede/gardyn](https://github.com/mselbrede/gardyn) :  ![starts](https://img.shields.io/github/stars/mselbrede/gardyn.svg) ![forks](https://img.shields.io/github/forks/mselbrede/gardyn.svg)

## CVE-2025-29628
 An issue in Gardyn 4 allows a remote attacker to obtain sensitive information and execute arbitrary code via a request



- [https://github.com/mselbrede/gardyn](https://github.com/mselbrede/gardyn) :  ![starts](https://img.shields.io/github/stars/mselbrede/gardyn.svg) ![forks](https://img.shields.io/github/forks/mselbrede/gardyn.svg)

## CVE-2025-29602
 flatpress 1.3.1 is vulnerable to Cross Site Scripting (XSS) in Administration area via Manage categories.



- [https://github.com/harish0x/CVE-2025-29602](https://github.com/harish0x/CVE-2025-29602) :  ![starts](https://img.shields.io/github/stars/harish0x/CVE-2025-29602.svg) ![forks](https://img.shields.io/github/forks/harish0x/CVE-2025-29602.svg)

## CVE-2025-29557
 ExaGrid EX10 6.3 - 7.0.1.P08 is vulnerable to Incorrect Access Control in the MailConfiguration API endpoint, where users with operator-level privileges can issue an HTTP request to retrieve SMTP credentials, including plaintext passwords.



- [https://github.com/0xsu3ks/CVE-2025-29557](https://github.com/0xsu3ks/CVE-2025-29557) :  ![starts](https://img.shields.io/github/stars/0xsu3ks/CVE-2025-29557.svg) ![forks](https://img.shields.io/github/forks/0xsu3ks/CVE-2025-29557.svg)

## CVE-2025-29556
 ExaGrid EX10 6.3 - 7.0.1.P08 is vulnerable to Incorrect Access Control. Since version 6.3, ExaGrid enforces restrictions preventing users with the Admin role from creating or modifying users with the Security Officer role without approval. However, a flaw in the account creation process allows an attacker to bypass these restrictions via API request manipulation. An attacker with an Admin access can intercept and modify the API request during user creation, altering the parameters to assign the new account to the ExaGrid Security Officers group without the required approval.



- [https://github.com/0xsu3ks/CVE-2025-29556](https://github.com/0xsu3ks/CVE-2025-29556) :  ![starts](https://img.shields.io/github/stars/0xsu3ks/CVE-2025-29556.svg) ![forks](https://img.shields.io/github/forks/0xsu3ks/CVE-2025-29556.svg)

## CVE-2025-29529
 ITC Systems Multiplan/Matrix OneCard platform v3.7.4.1002 was discovered to contain a SQL injection vulnerability via the component Forgotpassword.aspx.



- [https://github.com/Yoshik0xF6/CVE-2025-29529](https://github.com/Yoshik0xF6/CVE-2025-29529) :  ![starts](https://img.shields.io/github/stars/Yoshik0xF6/CVE-2025-29529.svg) ![forks](https://img.shields.io/github/forks/Yoshik0xF6/CVE-2025-29529.svg)

## CVE-2025-29471
 Cross Site Scripting vulnerability in Nagios Log Server v.2024R1.3.1 allows a remote attacker to execute arbitrary code via a payload into the Email field.



- [https://github.com/skraft9/CVE-2025-29471](https://github.com/skraft9/CVE-2025-29471) :  ![starts](https://img.shields.io/github/stars/skraft9/CVE-2025-29471.svg) ![forks](https://img.shields.io/github/forks/skraft9/CVE-2025-29471.svg)

## CVE-2025-29448
 Booking logic flaw in Easy!Appointments v1.5.1 allows unauthenticated attackers to create appointments with excessively long durations, causing a denial of service by blocking all future booking availability.



- [https://github.com/Abdullah4eb/CVE-2025-29448](https://github.com/Abdullah4eb/CVE-2025-29448) :  ![starts](https://img.shields.io/github/stars/Abdullah4eb/CVE-2025-29448.svg) ![forks](https://img.shields.io/github/forks/Abdullah4eb/CVE-2025-29448.svg)

## CVE-2025-29384
 In Tenda AC9 v1.0 V15.03.05.14_multi, the wanMTU parameter of /goform/AdvSetMacMtuWan has a stack overflow vulnerability, which can lead to remote arbitrary code execution.



- [https://github.com/Otsmane-Ahmed/cve-2025-29384-poc](https://github.com/Otsmane-Ahmed/cve-2025-29384-poc) :  ![starts](https://img.shields.io/github/stars/Otsmane-Ahmed/cve-2025-29384-poc.svg) ![forks](https://img.shields.io/github/forks/Otsmane-Ahmed/cve-2025-29384-poc.svg)

## CVE-2025-29306
 An issue in FoxCMS v.1.2.5 allows a remote attacker to execute arbitrary code via the case display page in the index.html component.



- [https://github.com/Mattb709/CVE-2025-29306-PoC-FoxCMS-RCE](https://github.com/Mattb709/CVE-2025-29306-PoC-FoxCMS-RCE) :  ![starts](https://img.shields.io/github/stars/Mattb709/CVE-2025-29306-PoC-FoxCMS-RCE.svg) ![forks](https://img.shields.io/github/forks/Mattb709/CVE-2025-29306-PoC-FoxCMS-RCE.svg)

- [https://github.com/verylazytech/CVE-2025-29306](https://github.com/verylazytech/CVE-2025-29306) :  ![starts](https://img.shields.io/github/stars/verylazytech/CVE-2025-29306.svg) ![forks](https://img.shields.io/github/forks/verylazytech/CVE-2025-29306.svg)

- [https://github.com/somatrasss/CVE-2025-29306](https://github.com/somatrasss/CVE-2025-29306) :  ![starts](https://img.shields.io/github/stars/somatrasss/CVE-2025-29306.svg) ![forks](https://img.shields.io/github/forks/somatrasss/CVE-2025-29306.svg)

- [https://github.com/congdong007/CVE-2025-29306_poc](https://github.com/congdong007/CVE-2025-29306_poc) :  ![starts](https://img.shields.io/github/stars/congdong007/CVE-2025-29306_poc.svg) ![forks](https://img.shields.io/github/forks/congdong007/CVE-2025-29306_poc.svg)

- [https://github.com/inok009/FOXCMS-CVE-2025-29306-POC](https://github.com/inok009/FOXCMS-CVE-2025-29306-POC) :  ![starts](https://img.shields.io/github/stars/inok009/FOXCMS-CVE-2025-29306-POC.svg) ![forks](https://img.shields.io/github/forks/inok009/FOXCMS-CVE-2025-29306-POC.svg)

- [https://github.com/amalpvatayam67/day06-foxcms-rce](https://github.com/amalpvatayam67/day06-foxcms-rce) :  ![starts](https://img.shields.io/github/stars/amalpvatayam67/day06-foxcms-rce.svg) ![forks](https://img.shields.io/github/forks/amalpvatayam67/day06-foxcms-rce.svg)

## CVE-2025-29094
 Cross Site Scripting vulnerability in Motivian Content Mangment System v.41.0.0 allows a remote attacker to execute arbitrary code via the Marketing/Forms, Marketing/Offers and Content/Pages components.



- [https://github.com/FraMarcuccio/CVE-2025-29094-Multiple-Stored-Cross-Site-Scripting-XSS](https://github.com/FraMarcuccio/CVE-2025-29094-Multiple-Stored-Cross-Site-Scripting-XSS) :  ![starts](https://img.shields.io/github/stars/FraMarcuccio/CVE-2025-29094-Multiple-Stored-Cross-Site-Scripting-XSS.svg) ![forks](https://img.shields.io/github/forks/FraMarcuccio/CVE-2025-29094-Multiple-Stored-Cross-Site-Scripting-XSS.svg)

## CVE-2025-29093
 File Upload vulnerability in Motivian Content Mangment System v.41.0.0 allows a remote attacker to execute arbitrary code via the Content/Gallery/Images component.



- [https://github.com/FraMarcuccio/CVE-2025-29093-Arbitrary-File-Upload](https://github.com/FraMarcuccio/CVE-2025-29093-Arbitrary-File-Upload) :  ![starts](https://img.shields.io/github/stars/FraMarcuccio/CVE-2025-29093-Arbitrary-File-Upload.svg) ![forks](https://img.shields.io/github/forks/FraMarcuccio/CVE-2025-29093-Arbitrary-File-Upload.svg)

## CVE-2025-29018
 A Stored Cross-Site Scripting (XSS) vulnerability exists in the name parameter of pages_add_acc_type.php in Code Astro Internet Banking System 2.0.0.



- [https://github.com/b1tm4r/CVE-2025-29018](https://github.com/b1tm4r/CVE-2025-29018) :  ![starts](https://img.shields.io/github/stars/b1tm4r/CVE-2025-29018.svg) ![forks](https://img.shields.io/github/forks/b1tm4r/CVE-2025-29018.svg)

## CVE-2025-29017
 A Remote Code Execution (RCE) vulnerability exists in Code Astro Internet Banking System 2.0.0 due to improper file upload validation in the profile_pic parameter within pages_view_client.php.



- [https://github.com/b1tm4r/CVE-2025-29017](https://github.com/b1tm4r/CVE-2025-29017) :  ![starts](https://img.shields.io/github/stars/b1tm4r/CVE-2025-29017.svg) ![forks](https://img.shields.io/github/forks/b1tm4r/CVE-2025-29017.svg)

## CVE-2025-29015
 Code Astro Internet Banking System 2.0.0 is vulnerable to Cross Site Scripting (XSS) via the name parameter in /admin/pages_account.php.



- [https://github.com/b1tm4r/CVE-2025-29015](https://github.com/b1tm4r/CVE-2025-29015) :  ![starts](https://img.shields.io/github/stars/b1tm4r/CVE-2025-29015.svg) ![forks](https://img.shields.io/github/forks/b1tm4r/CVE-2025-29015.svg)

## CVE-2025-28915
 Unrestricted Upload of File with Dangerous Type vulnerability in Theme Egg ThemeEgg ToolKit allows Upload a Web Shell to a Web Server. This issue affects ThemeEgg ToolKit: from n/a through 1.2.9.



- [https://github.com/Nxploited/CVE-2025-28915](https://github.com/Nxploited/CVE-2025-28915) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-28915.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-28915.svg)

- [https://github.com/Pei4AN/CVE-2025-28915](https://github.com/Pei4AN/CVE-2025-28915) :  ![starts](https://img.shields.io/github/stars/Pei4AN/CVE-2025-28915.svg) ![forks](https://img.shields.io/github/forks/Pei4AN/CVE-2025-28915.svg)

## CVE-2025-28355
 Volmarg Personal Management System 1.4.65 is vulnerable to Cross Site Request Forgery (CSRF) allowing attackers to execute arbitrary code and obtain sensitive information via the SameSite cookie attribute defaults value set to none



- [https://github.com/abbisQQ/CVE-2025-28355](https://github.com/abbisQQ/CVE-2025-28355) :  ![starts](https://img.shields.io/github/stars/abbisQQ/CVE-2025-28355.svg) ![forks](https://img.shields.io/github/forks/abbisQQ/CVE-2025-28355.svg)

## CVE-2025-28121
 code-projects Online Exam Mastering System 1.0 is vulnerable to Cross Site Scripting (XSS) in feedback.php via the "q" parameter allowing remote attackers to execute arbitrary code.



- [https://github.com/pruthuraut/CVE-2025-28121](https://github.com/pruthuraut/CVE-2025-28121) :  ![starts](https://img.shields.io/github/stars/pruthuraut/CVE-2025-28121.svg) ![forks](https://img.shields.io/github/forks/pruthuraut/CVE-2025-28121.svg)

## CVE-2025-28074
 phpList before 3.6.15 is vulnerable to Cross-Site Scripting (XSS) due to improper input sanitization in lt.php. The vulnerability is exploitable when the application dynamically references internal paths and processes untrusted input without escaping, allowing an attacker to inject malicious JavaScript.



- [https://github.com/mLniumm/CVE-2025-28074](https://github.com/mLniumm/CVE-2025-28074) :  ![starts](https://img.shields.io/github/stars/mLniumm/CVE-2025-28074.svg) ![forks](https://img.shields.io/github/forks/mLniumm/CVE-2025-28074.svg)

## CVE-2025-28073
 phpList before 3.6.15 is vulnerable to Reflected Cross-Site Scripting (XSS) via the /lists/dl.php endpoint. An attacker can inject arbitrary JavaScript code by manipulating the id parameter, which is improperly sanitized.



- [https://github.com/mLniumm/CVE-2025-28073](https://github.com/mLniumm/CVE-2025-28073) :  ![starts](https://img.shields.io/github/stars/mLniumm/CVE-2025-28073.svg) ![forks](https://img.shields.io/github/forks/mLniumm/CVE-2025-28073.svg)

## CVE-2025-28062
 A Cross-Site Request Forgery (CSRF) vulnerability was discovered in ERPNEXT 14.82.1 and 14.74.3. The vulnerability allows an attacker to perform unauthorized actions such as user deletion, password resets, and privilege escalation due to missing CSRF protections.



- [https://github.com/Thvt0ne/CVE-2025-28062](https://github.com/Thvt0ne/CVE-2025-28062) :  ![starts](https://img.shields.io/github/stars/Thvt0ne/CVE-2025-28062.svg) ![forks](https://img.shields.io/github/forks/Thvt0ne/CVE-2025-28062.svg)

## CVE-2025-28009
 A SQL Injection vulnerability exists in the `u` parameter of the progress-body-weight.php endpoint of Dietiqa App v1.0.20.



- [https://github.com/0xs4h4/CVE-2025-28009](https://github.com/0xs4h4/CVE-2025-28009) :  ![starts](https://img.shields.io/github/stars/0xs4h4/CVE-2025-28009.svg) ![forks](https://img.shields.io/github/forks/0xs4h4/CVE-2025-28009.svg)

## CVE-2025-27893
 In Archer Platform 6 through 6.14.00202.10024, an authenticated user with record creation privileges can manipulate immutable fields, such as the creation date, by intercepting and modifying a Copy request via a GenericContent/Record.aspx?id= URI. NOTE: the Supplier analyzed the reported exploitation steps and found that, although the user can modify the immutable field, upon switching to View mode the field is reverted to its original value, without anything being saved to the database (and consequently there is no impact).



- [https://github.com/NastyCrow/CVE-2025-27893](https://github.com/NastyCrow/CVE-2025-27893) :  ![starts](https://img.shields.io/github/stars/NastyCrow/CVE-2025-27893.svg) ![forks](https://img.shields.io/github/forks/NastyCrow/CVE-2025-27893.svg)

## CVE-2025-27840
 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).



- [https://github.com/demining/Bluetooth-Attacks-CVE-2025-27840](https://github.com/demining/Bluetooth-Attacks-CVE-2025-27840) :  ![starts](https://img.shields.io/github/stars/demining/Bluetooth-Attacks-CVE-2025-27840.svg) ![forks](https://img.shields.io/github/forks/demining/Bluetooth-Attacks-CVE-2025-27840.svg)

- [https://github.com/em0gi/CVE-2025-27840](https://github.com/em0gi/CVE-2025-27840) :  ![starts](https://img.shields.io/github/stars/em0gi/CVE-2025-27840.svg) ![forks](https://img.shields.io/github/forks/em0gi/CVE-2025-27840.svg)

- [https://github.com/ladyg00se/CVE-2025-27840-WIP](https://github.com/ladyg00se/CVE-2025-27840-WIP) :  ![starts](https://img.shields.io/github/stars/ladyg00se/CVE-2025-27840-WIP.svg) ![forks](https://img.shields.io/github/forks/ladyg00se/CVE-2025-27840-WIP.svg)

## CVE-2025-27817
 A possible arbitrary file read and SSRF vulnerability has been identified in Apache Kafka Client. Apache Kafka Clients accept configuration data for setting the SASL/OAUTHBEARER connection with the brokers, including "sasl.oauthbearer.token.endpoint.url" and "sasl.oauthbearer.jwks.endpoint.url". Apache Kafka allows clients to read an arbitrary file and return the content in the error log, or sending requests to an unintended location. In applications where Apache Kafka Clients configurations can be specified by an untrusted party, attackers may use the "sasl.oauthbearer.token.endpoint.url" and "sasl.oauthbearer.jwks.endpoint.url" configuratin to read arbitrary contents of the disk and environment variables or make requests to an unintended location. In particular, this flaw may be used in Apache Kafka Connect to escalate from REST API access to filesystem/environment/URL access, which may be undesirable in certain environments, including SaaS products. 

Since Apache Kafka 3.9.1/4.0.0, we have added a system property ("-Dorg.apache.kafka.sasl.oauthbearer.allowed.urls") to set the allowed urls in SASL JAAS configuration. In 3.9.1, it accepts all urls by default for backward compatibility. However in 4.0.0 and newer, the default value is empty list and users have to set the allowed urls explicitly.



- [https://github.com/kk12-30/CVE-2025-27817](https://github.com/kk12-30/CVE-2025-27817) :  ![starts](https://img.shields.io/github/stars/kk12-30/CVE-2025-27817.svg) ![forks](https://img.shields.io/github/forks/kk12-30/CVE-2025-27817.svg)

- [https://github.com/iSee857/CVE-2025-27817](https://github.com/iSee857/CVE-2025-27817) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-27817.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-27817.svg)

- [https://github.com/oriolrius/kafka-keycloak-oauth](https://github.com/oriolrius/kafka-keycloak-oauth) :  ![starts](https://img.shields.io/github/stars/oriolrius/kafka-keycloak-oauth.svg) ![forks](https://img.shields.io/github/forks/oriolrius/kafka-keycloak-oauth.svg)

## CVE-2025-27636
 Bypass/Injection vulnerability in Apache Camel components under particular conditions.

This issue affects Apache Camel: from 4.10.0 through = 4.10.1, from 4.8.0 through = 4.8.4, from 3.10.0 through = 3.22.3.

Users are recommended to upgrade to version 4.10.2 for 4.10.x LTS, 4.8.5 for 4.8.x LTS and 3.22.4 for 3.x releases.



This vulnerability is present in Camel's default incoming header filter, that allows an attacker to include Camel specific

headers that for some Camel components can alter the behaviours such as the camel-bean component, to call another method

on the bean, than was coded in the application. In the camel-jms component, then a malicious header can be used to send

the message to another queue (on the same broker) than was coded in the application. This could also be seen by using the camel-exec component




The attacker would need to inject custom headers, such as HTTP protocols. So if you have Camel applications that are

directly connected to the internet via HTTP, then an attacker could include malicious HTTP headers in the HTTP requests

that are send to the Camel application.




All the known Camel HTTP component such as camel-servlet, camel-jetty, camel-undertow, camel-platform-http, and camel-netty-http would be vulnerable out of the box.

In these conditions an attacker could be able to forge a Camel header name and make the bean component invoking other methods in the same bean.

In terms of usage of the default header filter strategy the list of components using that is: 


  *  camel-activemq
  *  camel-activemq6
  *  camel-amqp
  *  camel-aws2-sqs
  *  camel-azure-servicebus
  *  camel-cxf-rest
  *  camel-cxf-soap
  *  camel-http
  *  camel-jetty
  *  camel-jms
  *  camel-kafka
  *  camel-knative
  *  camel-mail
  *  camel-nats
  *  camel-netty-http
  *  camel-platform-http
  *  camel-rest
  *  camel-sjms
  *  camel-spring-rabbitmq
  *  camel-stomp
  *  camel-tahu
  *  camel-undertow
  *  camel-xmpp






The vulnerability arises due to a bug in the default filtering mechanism that only blocks headers starting with "Camel", "camel", or "org.apache.camel.". 


Mitigation: You can easily work around this in your Camel applications by removing the headers in your Camel routes. There are many ways of doing this, also globally or per route. This means you could use the removeHeaders EIP, to filter out anything like "cAmel, cAMEL" etc, or in general everything not starting with "Camel", "camel" or "org.apache.camel.".



- [https://github.com/akamai/CVE-2025-27636-Apache-Camel-PoC](https://github.com/akamai/CVE-2025-27636-Apache-Camel-PoC) :  ![starts](https://img.shields.io/github/stars/akamai/CVE-2025-27636-Apache-Camel-PoC.svg) ![forks](https://img.shields.io/github/forks/akamai/CVE-2025-27636-Apache-Camel-PoC.svg)

- [https://github.com/Crystallen1/CVE-2025-27636-demo](https://github.com/Crystallen1/CVE-2025-27636-demo) :  ![starts](https://img.shields.io/github/stars/Crystallen1/CVE-2025-27636-demo.svg) ![forks](https://img.shields.io/github/forks/Crystallen1/CVE-2025-27636-demo.svg)

- [https://github.com/enochgitgamefied/CVE-2025-27636-Practical-Lab](https://github.com/enochgitgamefied/CVE-2025-27636-Practical-Lab) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/CVE-2025-27636-Practical-Lab.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/CVE-2025-27636-Practical-Lab.svg)

## CVE-2025-27607
 Python JSON Logger is a JSON Formatter for Python Logging. Between 30 December 2024 and 4 March 2025 Python JSON Logger was vulnerable to RCE through a missing dependency. This occurred because msgspec-python313-pre was deleted by the owner leaving the name open to being claimed by a third party. If the package was claimed, it would allow them RCE on any Python JSON Logger user who installed the development dependencies on Python 3.13 (e.g. pip install python-json-logger[dev]). This issue has been resolved with 3.3.0.



- [https://github.com/Barsug/msgspec-python313-pre](https://github.com/Barsug/msgspec-python313-pre) :  ![starts](https://img.shields.io/github/stars/Barsug/msgspec-python313-pre.svg) ![forks](https://img.shields.io/github/forks/Barsug/msgspec-python313-pre.svg)

## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.



- [https://github.com/BridgerAlderson/CVE-2025-27591-PoC](https://github.com/BridgerAlderson/CVE-2025-27591-PoC) :  ![starts](https://img.shields.io/github/stars/BridgerAlderson/CVE-2025-27591-PoC.svg) ![forks](https://img.shields.io/github/forks/BridgerAlderson/CVE-2025-27591-PoC.svg)

- [https://github.com/obamalaolu/CVE-2025-27591](https://github.com/obamalaolu/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/obamalaolu/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/obamalaolu/CVE-2025-27591.svg)

- [https://github.com/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591](https://github.com/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591.svg)

- [https://github.com/Cythonic1/CVE-2025-27591](https://github.com/Cythonic1/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/Cythonic1/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/Cythonic1/CVE-2025-27591.svg)

- [https://github.com/rvizx/CVE-2025-27591](https://github.com/rvizx/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2025-27591.svg)

- [https://github.com/HOEUN-Visai/CVE-2025-27591-below-](https://github.com/HOEUN-Visai/CVE-2025-27591-below-) :  ![starts](https://img.shields.io/github/stars/HOEUN-Visai/CVE-2025-27591-below-.svg) ![forks](https://img.shields.io/github/forks/HOEUN-Visai/CVE-2025-27591-below-.svg)

- [https://github.com/umutcamliyurt/CVE-2025-27591](https://github.com/umutcamliyurt/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/umutcamliyurt/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/umutcamliyurt/CVE-2025-27591.svg)

- [https://github.com/00xCanelo/CVE-2025-27591](https://github.com/00xCanelo/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/00xCanelo/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/00xCanelo/CVE-2025-27591.svg)

- [https://github.com/incommatose/CVE-2025-27591-PoC](https://github.com/incommatose/CVE-2025-27591-PoC) :  ![starts](https://img.shields.io/github/stars/incommatose/CVE-2025-27591-PoC.svg) ![forks](https://img.shields.io/github/forks/incommatose/CVE-2025-27591-PoC.svg)

- [https://github.com/Diabl0xE/CVE-2025-27519](https://github.com/Diabl0xE/CVE-2025-27519) :  ![starts](https://img.shields.io/github/stars/Diabl0xE/CVE-2025-27519.svg) ![forks](https://img.shields.io/github/forks/Diabl0xE/CVE-2025-27519.svg)

- [https://github.com/danil-koltsov/below-log-race-poc](https://github.com/danil-koltsov/below-log-race-poc) :  ![starts](https://img.shields.io/github/stars/danil-koltsov/below-log-race-poc.svg) ![forks](https://img.shields.io/github/forks/danil-koltsov/below-log-race-poc.svg)

- [https://github.com/krn966/CVE-2025-27591](https://github.com/krn966/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/krn966/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/krn966/CVE-2025-27591.svg)

- [https://github.com/DarksBlackSk/CVE-2025-27591](https://github.com/DarksBlackSk/CVE-2025-27591) :  ![starts](https://img.shields.io/github/stars/DarksBlackSk/CVE-2025-27591.svg) ![forks](https://img.shields.io/github/forks/DarksBlackSk/CVE-2025-27591.svg)

- [https://github.com/Thekin-ctrl/CVE-2025-27591-Below](https://github.com/Thekin-ctrl/CVE-2025-27591-Below) :  ![starts](https://img.shields.io/github/stars/Thekin-ctrl/CVE-2025-27591-Below.svg) ![forks](https://img.shields.io/github/forks/Thekin-ctrl/CVE-2025-27591-Below.svg)

- [https://github.com/alialucas7/CVE-2025-27591_PoC](https://github.com/alialucas7/CVE-2025-27591_PoC) :  ![starts](https://img.shields.io/github/stars/alialucas7/CVE-2025-27591_PoC.svg) ![forks](https://img.shields.io/github/forks/alialucas7/CVE-2025-27591_PoC.svg)

## CVE-2025-27590
 In oxidized-web (aka Oxidized Web) before 0.15.0, the RANCID migration page allows an unauthenticated user to gain control over the Linux user account that is running oxidized-web.



- [https://github.com/fatkz/CVE-2025-27590](https://github.com/fatkz/CVE-2025-27590) :  ![starts](https://img.shields.io/github/stars/fatkz/CVE-2025-27590.svg) ![forks](https://img.shields.io/github/forks/fatkz/CVE-2025-27590.svg)

## CVE-2025-27581
 NIH BRICS (aka Biomedical Research Informatics Computing System) through 14.0.0-67 allows users who lack the InET role to access the InET module via direct requests to known endpoints.



- [https://github.com/Henryisnotavailable/CVE-2025-27581](https://github.com/Henryisnotavailable/CVE-2025-27581) :  ![starts](https://img.shields.io/github/stars/Henryisnotavailable/CVE-2025-27581.svg) ![forks](https://img.shields.io/github/forks/Henryisnotavailable/CVE-2025-27581.svg)

## CVE-2025-27580
 NIH BRICS (aka Biomedical Research Informatics Computing System) through 14.0.0-67 generates predictable tokens (that depend on username, time, and the fixed 7Dl9#dj- string) and thus allows unauthenticated users with a Common Access Card (CAC) to escalate privileges and compromise any account, including administrators.



- [https://github.com/TrustStackSecurity/CVE-2025-27580](https://github.com/TrustStackSecurity/CVE-2025-27580) :  ![starts](https://img.shields.io/github/stars/TrustStackSecurity/CVE-2025-27580.svg) ![forks](https://img.shields.io/github/forks/TrustStackSecurity/CVE-2025-27580.svg)

## CVE-2025-27558
 IEEE P802.11-REVme D1.1 through D7.0 allows FragAttacks against mesh networks. In mesh networks using Wi-Fi Protected Access (WPA, WPA2, or WPA3) or Wired Equivalent Privacy (WEP), an adversary can exploit this vulnerability to inject arbitrary frames towards devices that support receiving non-SSP A-MSDU frames. NOTE: this issue exists because of an incorrect fix for CVE-2020-24588. P802.11-REVme, as of early 2025, is a planned release of the 802.11 standard.



- [https://github.com/Atlas-ghostshell/CVE-2025-27558_Patching](https://github.com/Atlas-ghostshell/CVE-2025-27558_Patching) :  ![starts](https://img.shields.io/github/stars/Atlas-ghostshell/CVE-2025-27558_Patching.svg) ![forks](https://img.shields.io/github/forks/Atlas-ghostshell/CVE-2025-27558_Patching.svg)

## CVE-2025-27533
 Memory Allocation with Excessive Size Value vulnerability in Apache ActiveMQ.

During unmarshalling of OpenWire commands the size value of buffers was not properly validated which could lead to excessive memory allocation and be exploited to cause a denial of service (DoS) by depleting process memory, thereby affecting applications and services that rely on the availability of the ActiveMQ broker when not using mutual TLS connections.
This issue affects Apache ActiveMQ: from 6.0.0 before 6.1.6, from 5.18.0 before 5.18.7, from 5.17.0 before 5.17.7, before 5.16.8. ActiveMQ 5.19.0 is not affected.

Users are recommended to upgrade to version 6.1.6+, 5.19.0+,  5.18.7+, 5.17.7, or 5.16.8 or which fixes the issue.

Existing users may implement mutual TLS to mitigate the risk on affected brokers.



- [https://github.com/absholi7ly/CVE-2025-27533-Exploit-for-Apache-ActiveMQ](https://github.com/absholi7ly/CVE-2025-27533-Exploit-for-Apache-ActiveMQ) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2025-27533-Exploit-for-Apache-ActiveMQ.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2025-27533-Exploit-for-Apache-ActiveMQ.svg)

## CVE-2025-27520
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. A Remote Code Execution (RCE) vulnerability caused by insecure deserialization has been identified in the latest version (v1.4.2) of BentoML. It allows any unauthenticated user to execute arbitrary code on the server. It exists an unsafe code segment in serde.py. This vulnerability is fixed in 1.4.3.



- [https://github.com/amalpvatayam67/day09-bentoml-deser-lab](https://github.com/amalpvatayam67/day09-bentoml-deser-lab) :  ![starts](https://img.shields.io/github/stars/amalpvatayam67/day09-bentoml-deser-lab.svg) ![forks](https://img.shields.io/github/forks/amalpvatayam67/day09-bentoml-deser-lab.svg)

## CVE-2025-27519
 Cognita is a RAG (Retrieval Augmented Generation) Framework for building modular, open source applications for production by TrueFoundry. A path traversal issue exists at /v1/internal/upload-to-local-directory which is enabled when the Local env variable is set to true, such as when Cognita is setup using Docker. Because the docker environment sets up the backend uvicorn server with auto reload enabled, when an attacker overwrites the /app/backend/__init__.py file, the file will automatically be reloaded and executed. This allows an attacker to get remote code execution in the context of the Docker container. This vulnerability is fixed in commit a78bd065e05a1b30a53a3386cc02e08c317d2243.



- [https://github.com/Diabl0xE/CVE-2025-27519](https://github.com/Diabl0xE/CVE-2025-27519) :  ![starts](https://img.shields.io/github/stars/Diabl0xE/CVE-2025-27519.svg) ![forks](https://img.shields.io/github/forks/Diabl0xE/CVE-2025-27519.svg)

## CVE-2025-27480
 Use after free in Remote Desktop Gateway Service allows an unauthorized attacker to execute code over a network.



- [https://github.com/mrk336/CVE-2025-27480](https://github.com/mrk336/CVE-2025-27480) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2025-27480.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2025-27480.svg)

- [https://github.com/mrk336/CVE-2025-27480-The-Silent-Gateway-Risk](https://github.com/mrk336/CVE-2025-27480-The-Silent-Gateway-Risk) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2025-27480-The-Silent-Gateway-Risk.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2025-27480-The-Silent-Gateway-Risk.svg)

## CVE-2025-27415
 Nuxt is an open-source web development framework for Vue.js. Prior to 3.16.0, by sending a crafted HTTP request to a server behind an CDN, it is possible in some circumstances to poison the CDN cache and highly impacts the availability of a site. It is possible to craft a request, such as https://mysite.com/?/_payload.json which will be rendered as JSON. If the CDN in front of a Nuxt site ignores the query string when determining whether to cache a route, then this JSON response could be served to future visitors to the site. An attacker can perform this attack to a vulnerable site in order to make a site unavailable indefinitely. It is also possible in the case where the cache will be reset to make a small script to send a request each X seconds (=caching duration) so that the cache is permanently poisoned making the site completely unavailable. This vulnerability is fixed in 3.16.0.



- [https://github.com/jiseoung/CVE-2025-27415-PoC](https://github.com/jiseoung/CVE-2025-27415-PoC) :  ![starts](https://img.shields.io/github/stars/jiseoung/CVE-2025-27415-PoC.svg) ![forks](https://img.shields.io/github/forks/jiseoung/CVE-2025-27415-PoC.svg)

## CVE-2025-27410
 PwnDoc is a penetration test reporting application. Prior to version 1.2.0, the backup restore functionality is vulnerable to path traversal in the TAR entry's name, allowing an attacker to overwrite any file on the system with their content. By overwriting an included `.js` file and restarting the container, this allows for Remote Code Execution as an administrator. The remote code execution occurs because any user with the `backups:create` and `backups:update` (only administrators by default) is able to overwrite any file on the system. Version 1.2.0 fixes the issue.



- [https://github.com/shreyas-malhotra/CVE-2025-27410](https://github.com/shreyas-malhotra/CVE-2025-27410) :  ![starts](https://img.shields.io/github/stars/shreyas-malhotra/CVE-2025-27410.svg) ![forks](https://img.shields.io/github/forks/shreyas-malhotra/CVE-2025-27410.svg)

## CVE-2025-27363
 An out of bounds write exists in FreeType versions 2.13.0 and below (newer versions of FreeType are not vulnerable) when attempting to parse font subglyph structures related to TrueType GX and variable font files. The vulnerable code assigns a signed short value to an unsigned long and then adds a static value causing it to wrap around and allocate too small of a heap buffer. The code then writes up to 6 signed long integers out of bounds relative to this buffer. This may result in arbitrary code execution. This vulnerability may have been exploited in the wild.



- [https://github.com/zhuowei/CVE-2025-27363-proof-of-concept](https://github.com/zhuowei/CVE-2025-27363-proof-of-concept) :  ![starts](https://img.shields.io/github/stars/zhuowei/CVE-2025-27363-proof-of-concept.svg) ![forks](https://img.shields.io/github/forks/zhuowei/CVE-2025-27363-proof-of-concept.svg)

- [https://github.com/tin-z/CVE-2025-27363](https://github.com/tin-z/CVE-2025-27363) :  ![starts](https://img.shields.io/github/stars/tin-z/CVE-2025-27363.svg) ![forks](https://img.shields.io/github/forks/tin-z/CVE-2025-27363.svg)

- [https://github.com/ov3rf1ow/CVE-2025-27363](https://github.com/ov3rf1ow/CVE-2025-27363) :  ![starts](https://img.shields.io/github/stars/ov3rf1ow/CVE-2025-27363.svg) ![forks](https://img.shields.io/github/forks/ov3rf1ow/CVE-2025-27363.svg)

## CVE-2025-27210
 An incomplete fix has been identified for CVE-2025-23084 in Node.js, specifically affecting Windows device names like CON, PRN, and AUX. 

This vulnerability affects Windows users of `path.join` API.



- [https://github.com/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit](https://github.com/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-27210](https://github.com/B1ack4sh/Blackash-CVE-2025-27210) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-27210.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-27210.svg)

- [https://github.com/mindeddu/Vulnerable-CVE-2025-27210](https://github.com/mindeddu/Vulnerable-CVE-2025-27210) :  ![starts](https://img.shields.io/github/stars/mindeddu/Vulnerable-CVE-2025-27210.svg) ![forks](https://img.shields.io/github/forks/mindeddu/Vulnerable-CVE-2025-27210.svg)

## CVE-2025-27152
 axios is a promise based HTTP client for the browser and node.js. The issue occurs when passing absolute URLs rather than protocol-relative URLs to axios. Even if ⁠baseURL is set, axios sends the request to the specified absolute URL, potentially causing SSRF and credential leakage. This issue impacts both server-side and client-side usage of axios. This issue is fixed in 1.8.2.



- [https://github.com/andreglock/axios-ssrf](https://github.com/andreglock/axios-ssrf) :  ![starts](https://img.shields.io/github/stars/andreglock/axios-ssrf.svg) ![forks](https://img.shields.io/github/forks/andreglock/axios-ssrf.svg)

- [https://github.com/davidblakecoe/axios-CVE-2025-27152-PoC](https://github.com/davidblakecoe/axios-CVE-2025-27152-PoC) :  ![starts](https://img.shields.io/github/stars/davidblakecoe/axios-CVE-2025-27152-PoC.svg) ![forks](https://img.shields.io/github/forks/davidblakecoe/axios-CVE-2025-27152-PoC.svg)

## CVE-2025-27007
 Incorrect Privilege Assignment vulnerability in Brainstorm Force SureTriggers allows Privilege Escalation.This issue affects SureTriggers: from n/a through 1.0.82.



- [https://github.com/absholi7ly/CVE-2025-27007-OttoKit-exploit](https://github.com/absholi7ly/CVE-2025-27007-OttoKit-exploit) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2025-27007-OttoKit-exploit.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2025-27007-OttoKit-exploit.svg)

## CVE-2025-26909
 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') vulnerability in John Darrel Hide My WP Ghost allows PHP Local File Inclusion.This issue affects Hide My WP Ghost: from n/a through 5.4.01.



- [https://github.com/issamjr/CVE-2025-26909-Scanner](https://github.com/issamjr/CVE-2025-26909-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-26909-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-26909-Scanner.svg)

## CVE-2025-26892
 Unrestricted Upload of File with Dangerous Type vulnerability in dkszone Celestial Aura allows Using Malicious Files.This issue affects Celestial Aura: from n/a through 2.2.



- [https://github.com/Nxploited/CVE-2025-26892](https://github.com/Nxploited/CVE-2025-26892) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-26892.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-26892.svg)

## CVE-2025-26865
 Improper Neutralization of Special Elements Used in a Template Engine vulnerability in Apache OFBiz.

This issue affects Apache OFBiz: from 18.12.17 before 18.12.18.  

It's a regression between 18.12.17 and 18.12.18.
In case you use something like that, which is not recommended!
For security, only official releases should be used.

In other words, if you use 18.12.17 you are still safe.
The version 18.12.17 is not a affected.
But something between 18.12.17 and 18.12.18 is.

In that case, users are recommended to upgrade to version 18.12.18, which fixes the issue.



- [https://github.com/mbadanoiu/CVE-2025-26865](https://github.com/mbadanoiu/CVE-2025-26865) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2025-26865.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2025-26865.svg)

## CVE-2025-26794
 Exim 4.98 before 4.98.1, when SQLite hints and ETRN serialization are used, allows remote SQL injection.



- [https://github.com/OscarBataille/CVE-2025-26794](https://github.com/OscarBataille/CVE-2025-26794) :  ![starts](https://img.shields.io/github/stars/OscarBataille/CVE-2025-26794.svg) ![forks](https://img.shields.io/github/forks/OscarBataille/CVE-2025-26794.svg)

- [https://github.com/XploitGh0st/CVE-2025-26794-exploit](https://github.com/XploitGh0st/CVE-2025-26794-exploit) :  ![starts](https://img.shields.io/github/stars/XploitGh0st/CVE-2025-26794-exploit.svg) ![forks](https://img.shields.io/github/forks/XploitGh0st/CVE-2025-26794-exploit.svg)

- [https://github.com/ishwardeepp/CVE-2025-26794-Exim-Mail-SQLi](https://github.com/ishwardeepp/CVE-2025-26794-Exim-Mail-SQLi) :  ![starts](https://img.shields.io/github/stars/ishwardeepp/CVE-2025-26794-Exim-Mail-SQLi.svg) ![forks](https://img.shields.io/github/forks/ishwardeepp/CVE-2025-26794-Exim-Mail-SQLi.svg)

## CVE-2025-26788
 StrongKey FIDO Server before 4.15.1 treats a non-discoverable (namedcredential) flow as a discoverable transaction.



- [https://github.com/EQSTLab/CVE-2025-26788](https://github.com/EQSTLab/CVE-2025-26788) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2025-26788.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2025-26788.svg)

## CVE-2025-26686
 Sensitive data storage in improperly locked memory in Windows TCP/IP allows an unauthorized attacker to execute code over a network.



- [https://github.com/mrk336/CVE-2025-26686-The-TCP-IP-Flaw-That-Opens-the-Gates](https://github.com/mrk336/CVE-2025-26686-The-TCP-IP-Flaw-That-Opens-the-Gates) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2025-26686-The-TCP-IP-Flaw-That-Opens-the-Gates.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2025-26686-The-TCP-IP-Flaw-That-Opens-the-Gates.svg)

## CVE-2025-26633
 Improper neutralization in Microsoft Management Console allows an unauthorized attacker to bypass a security feature locally.



- [https://github.com/sandsoncosta/CVE-2025-26633](https://github.com/sandsoncosta/CVE-2025-26633) :  ![starts](https://img.shields.io/github/stars/sandsoncosta/CVE-2025-26633.svg) ![forks](https://img.shields.io/github/forks/sandsoncosta/CVE-2025-26633.svg)

## CVE-2025-26625
 Git LFS is a Git extension for versioning large files. In Git LFS versions 0.5.2 through 3.7.0, when populating a Git repository's working tree with the contents of Git LFS objects, certain Git LFS commands may write to files visible outside the current Git working tree if symbolic or hard links exist which collide with the paths of files tracked by Git LFS. The git lfs checkout and git lfs pull commands do not check for symbolic links before writing to files in the working tree, allowing an attacker to craft a repository containing symbolic or hard links that cause Git LFS to write to arbitrary file system locations accessible to the user running these commands. As well, when the git lfs checkout and git lfs pull commands are run in a bare repository, they could write to files visible outside the repository. The vulnerability is fixed in version 3.7.1. As a workaround, support for symlinks in Git may be disabled by setting the core.symlinks configuration option to false, after which further clones and fetches will not create symbolic links. However, any symbolic or hard links in existing repositories will still provide the opportunity for Git LFS to write to their targets.



- [https://github.com/Mitchellzhou1/CVE_2025_26625_PoC](https://github.com/Mitchellzhou1/CVE_2025_26625_PoC) :  ![starts](https://img.shields.io/github/stars/Mitchellzhou1/CVE_2025_26625_PoC.svg) ![forks](https://img.shields.io/github/forks/Mitchellzhou1/CVE_2025_26625_PoC.svg)

## CVE-2025-26529
 Description information displayed in the site administration live log 
required additional sanitizing to prevent a stored XSS risk.



- [https://github.com/NightBloodz/moodleTestingEnv](https://github.com/NightBloodz/moodleTestingEnv) :  ![starts](https://img.shields.io/github/stars/NightBloodz/moodleTestingEnv.svg) ![forks](https://img.shields.io/github/forks/NightBloodz/moodleTestingEnv.svg)

- [https://github.com/Astroo18/PoC-CVE-2025-26529](https://github.com/Astroo18/PoC-CVE-2025-26529) :  ![starts](https://img.shields.io/github/stars/Astroo18/PoC-CVE-2025-26529.svg) ![forks](https://img.shields.io/github/forks/Astroo18/PoC-CVE-2025-26529.svg)

## CVE-2025-26466
 A flaw was found in the OpenSSH package. For each ping packet the SSH server receives, a pong packet is allocated in a memory buffer and stored in a queue of packages. It is only freed when the server/client key exchange has finished. A malicious client may keep sending such packages, leading to an uncontrolled increase in memory consumption on the server side. Consequently, the server may become unavailable, resulting in a denial of service attack.



- [https://github.com/rxerium/CVE-2025-26466](https://github.com/rxerium/CVE-2025-26466) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-26466.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-26466.svg)

- [https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466](https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466) :  ![starts](https://img.shields.io/github/stars/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg) ![forks](https://img.shields.io/github/forks/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg)

- [https://github.com/mrowkoob/CVE-2025-26466-msf](https://github.com/mrowkoob/CVE-2025-26466-msf) :  ![starts](https://img.shields.io/github/stars/mrowkoob/CVE-2025-26466-msf.svg) ![forks](https://img.shields.io/github/forks/mrowkoob/CVE-2025-26466-msf.svg)

## CVE-2025-26465
 A vulnerability was found in OpenSSH when the VerifyHostKeyDNS option is enabled. A machine-in-the-middle attack can be performed by a malicious machine impersonating a legit server. This issue occurs due to how OpenSSH mishandles error codes in specific conditions when verifying the host key. For an attack to be considered successful, the attacker needs to manage to exhaust the client's memory resource first, turning the attack complexity high.



- [https://github.com/rxerium/CVE-2025-26465](https://github.com/rxerium/CVE-2025-26465) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-26465.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-26465.svg)

- [https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466](https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466) :  ![starts](https://img.shields.io/github/stars/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg) ![forks](https://img.shields.io/github/forks/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg)

## CVE-2025-26443
 In parseHtml of HtmlToSpannedParser.java, there is a possible way to install apps without allowing installation from unknown sources due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.



- [https://github.com/Pazhanivelmani/ManagedProvisioning-A10_r33_CVE-2025-26443](https://github.com/Pazhanivelmani/ManagedProvisioning-A10_r33_CVE-2025-26443) :  ![starts](https://img.shields.io/github/stars/Pazhanivelmani/ManagedProvisioning-A10_r33_CVE-2025-26443.svg) ![forks](https://img.shields.io/github/forks/Pazhanivelmani/ManagedProvisioning-A10_r33_CVE-2025-26443.svg)

## CVE-2025-26417
 In checkWhetherCallingAppHasAccess of DownloadProvider.java, there is a possible bypass of user consent when opening files in shared storage due to a confused deputy. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.



- [https://github.com/uthrasri/CVE-2025-26417](https://github.com/uthrasri/CVE-2025-26417) :  ![starts](https://img.shields.io/github/stars/uthrasri/CVE-2025-26417.svg) ![forks](https://img.shields.io/github/forks/uthrasri/CVE-2025-26417.svg)

## CVE-2025-26399
 SolarWinds Web Help Desk was found to be susceptible to an unauthenticated AjaxProxy deserialization remote code execution vulnerability that, if exploited, would allow an attacker to run commands on the host machine. This vulnerability is a patch bypass of CVE-2024-28988, which in turn is a patch bypass of CVE-2024-28986.



- [https://github.com/rxerium/CVE-2025-26399](https://github.com/rxerium/CVE-2025-26399) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-26399.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-26399.svg)

## CVE-2025-26326
 A vulnerability was identified in the NVDA Remote (version 2.6.4) and Tele NVDA Remote (version 2025.3.3) remote connection add-ons, which allows an attacker to obtain total control of the remote system by guessing a weak password. The problem occurs because these add-ons accept any password entered by the user and do not have an additional authentication or computer verification mechanism. Tests indicate that more than 1,000 systems use easy-to-guess passwords, many with less than 4 to 6 characters, including common sequences. This allows brute force attacks or trial-and-error attempts by malicious invaders. The vulnerability can be exploited by a remote attacker who knows or can guess the password used in the connection. As a result, the attacker gains complete access to the affected system and can execute commands, modify files, and compromise user security.



- [https://github.com/azurejoga/CVE-2025-26326](https://github.com/azurejoga/CVE-2025-26326) :  ![starts](https://img.shields.io/github/stars/azurejoga/CVE-2025-26326.svg) ![forks](https://img.shields.io/github/forks/azurejoga/CVE-2025-26326.svg)

## CVE-2025-26319
 FlowiseAI Flowise v2.2.6 was discovered to contain an arbitrary file upload vulnerability in /api/v1/attachments.



- [https://github.com/dorattias/CVE-2025-26319](https://github.com/dorattias/CVE-2025-26319) :  ![starts](https://img.shields.io/github/stars/dorattias/CVE-2025-26319.svg) ![forks](https://img.shields.io/github/forks/dorattias/CVE-2025-26319.svg)

- [https://github.com/redpack-kr/CVE-2025-26319](https://github.com/redpack-kr/CVE-2025-26319) :  ![starts](https://img.shields.io/github/stars/redpack-kr/CVE-2025-26319.svg) ![forks](https://img.shields.io/github/forks/redpack-kr/CVE-2025-26319.svg)

## CVE-2025-26318
 hb.exe in TSplus Remote Access before 17.30 2024-10-30 allows remote attackers to retrieve a list of all domain accounts currently connected to the application.



- [https://github.com/Frozenka/CVE-2025-26318](https://github.com/Frozenka/CVE-2025-26318) :  ![starts](https://img.shields.io/github/stars/Frozenka/CVE-2025-26318.svg) ![forks](https://img.shields.io/github/forks/Frozenka/CVE-2025-26318.svg)

## CVE-2025-26264
 GeoVision GV-ASWeb with the version 6.1.2.0 or less (fixed in 6.2.0), contains a Remote Code Execution (RCE) vulnerability within its Notification Settings feature. An authenticated attacker with "System Settings" privileges in ASWeb can exploit this flaw to execute arbitrary commands on the server, leading to a full system compromise.



- [https://github.com/DRAGOWN/CVE-2025-26264](https://github.com/DRAGOWN/CVE-2025-26264) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/CVE-2025-26264.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/CVE-2025-26264.svg)

## CVE-2025-26263
 GeoVision ASManager Windows desktop application with the version 6.1.2.0 or less (fixed in 6.2.0), is vulnerable to credentials disclosure due to improper memory handling in the ASManagerService.exe process.



- [https://github.com/DRAGOWN/CVE-2025-26263](https://github.com/DRAGOWN/CVE-2025-26263) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/CVE-2025-26263.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/CVE-2025-26263.svg)

## CVE-2025-26206
 Cross Site Request Forgery vulnerability in sell done storefront v.1.0 allows a remote attacker to escalate privileges via the index.html component



- [https://github.com/xibhi/CVE-2025-26206](https://github.com/xibhi/CVE-2025-26206) :  ![starts](https://img.shields.io/github/stars/xibhi/CVE-2025-26206.svg) ![forks](https://img.shields.io/github/forks/xibhi/CVE-2025-26206.svg)

## CVE-2025-26202
 Cross-Site Scripting (XSS) vulnerability exists in the WPA/WAPI Passphrase field of the Wireless Security settings (2.4GHz & 5GHz bands) in DZS Router Web Interface. An authenticated attacker can inject malicious JavaScript into the passphrase field, which is stored and later executed when an administrator views the passphrase via the "Click here to display" option on the Status page



- [https://github.com/A17-ba/CVE-2025-26202-Details](https://github.com/A17-ba/CVE-2025-26202-Details) :  ![starts](https://img.shields.io/github/stars/A17-ba/CVE-2025-26202-Details.svg) ![forks](https://img.shields.io/github/forks/A17-ba/CVE-2025-26202-Details.svg)

## CVE-2025-26199
 CloudClassroom-PHP-Project v1.0 is affected by an insecure credential transmission vulnerability. The application transmits passwords over unencrypted HTTP during the login process, exposing sensitive credentials to potential interception by network-based attackers. A remote attacker with access to the same network (e.g., public Wi-Fi or compromised router) can capture login credentials via Man-in-the-Middle (MitM) techniques. If the attacker subsequently uses the credentials to log in and exploit administrative functions (e.g., file upload), this may lead to remote code execution depending on the environment.



- [https://github.com/tansique-17/CVE-2025-26199](https://github.com/tansique-17/CVE-2025-26199) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-26199.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-26199.svg)

## CVE-2025-26198
 CloudClassroom-PHP-Project v1.0 contains a critical SQL Injection vulnerability in the loginlinkadmin.php component. The application fails to sanitize user-supplied input in the admin login form before directly including it in SQL queries. This allows unauthenticated attackers to inject arbitrary SQL payloads and bypass authentication, gaining unauthorized administrative access. The vulnerability is triggered when an attacker supplies specially crafted input in the username field, such as ' OR '1'='1, leading to complete compromise of the login mechanism and potential exposure of sensitive backend data.



- [https://github.com/tansique-17/CVE-2025-26198](https://github.com/tansique-17/CVE-2025-26198) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-26198.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-26198.svg)

## CVE-2025-26159
 Laravel Starter 11.11.0 is vulnerable to Cross Site Scripting (XSS) in the tags feature. Any user with the ability of create or modify tags can inject malicious JavaScript code in the name field.



- [https://github.com/godBADTRY/CVE-2025-26159](https://github.com/godBADTRY/CVE-2025-26159) :  ![starts](https://img.shields.io/github/stars/godBADTRY/CVE-2025-26159.svg) ![forks](https://img.shields.io/github/forks/godBADTRY/CVE-2025-26159.svg)

## CVE-2025-26125
 An exposed ioctl in the IMFForceDelete driver of IObit Malware Fighter v12.1.0 allows attackers to arbitrarily delete files and escalate privileges.



- [https://github.com/ZeroMemoryEx/CVE-2025-26125](https://github.com/ZeroMemoryEx/CVE-2025-26125) :  ![starts](https://img.shields.io/github/stars/ZeroMemoryEx/CVE-2025-26125.svg) ![forks](https://img.shields.io/github/forks/ZeroMemoryEx/CVE-2025-26125.svg)

## CVE-2025-26056
 A command injection vulnerability exists in the Infinxt iEdge 100 2.1.32 in the Troubleshoot module "MTR" functionality. The vulnerability is due to improper validation of user-supplied input in the mtrIp parameter. An attacker can exploit this flaw to execute arbitrary operating system commands on the underlying system with the same privileges as the web application process.



- [https://github.com/rohan-pt/CVE-2025-26056](https://github.com/rohan-pt/CVE-2025-26056) :  ![starts](https://img.shields.io/github/stars/rohan-pt/CVE-2025-26056.svg) ![forks](https://img.shields.io/github/forks/rohan-pt/CVE-2025-26056.svg)

## CVE-2025-26055
 An OS Command Injection vulnerability exists in the Infinxt iEdge 100 2.1.32 Troubleshoot module, specifically in the tracertVal parameter of the Tracert function.



- [https://github.com/rohan-pt/CVE-2025-26055](https://github.com/rohan-pt/CVE-2025-26055) :  ![starts](https://img.shields.io/github/stars/rohan-pt/CVE-2025-26055.svg) ![forks](https://img.shields.io/github/forks/rohan-pt/CVE-2025-26055.svg)

## CVE-2025-26054
 Infinxt iEdge 100 2.1.32 is vulnerable to Cross Site Scripting (XSS) via the "Description" field during LAN configuration.



- [https://github.com/rohan-pt/CVE-2025-26054](https://github.com/rohan-pt/CVE-2025-26054) :  ![starts](https://img.shields.io/github/stars/rohan-pt/CVE-2025-26054.svg) ![forks](https://img.shields.io/github/forks/rohan-pt/CVE-2025-26054.svg)

## CVE-2025-26014
 A Remote Code Execution (RCE) vulnerability in Loggrove v.1.0 allows a remote attacker to execute arbitrary code via the path parameter.



- [https://github.com/vigilante-1337/CVE-2025-26014](https://github.com/vigilante-1337/CVE-2025-26014) :  ![starts](https://img.shields.io/github/stars/vigilante-1337/CVE-2025-26014.svg) ![forks](https://img.shields.io/github/forks/vigilante-1337/CVE-2025-26014.svg)

## CVE-2025-25968
 DDSN Interactive cm3 Acora CMS version 10.1.1 contains an improper access control vulnerability. An editor-privileged user can access sensitive information, such as system administrator credentials, by force browsing the endpoint and exploiting the 'file' parameter. By referencing specific files (e.g., cm3.xml), attackers can bypass access controls, leading to account takeover and potential privilege escalation.



- [https://github.com/padayali-JD/CVE-2025-25968](https://github.com/padayali-JD/CVE-2025-25968) :  ![starts](https://img.shields.io/github/stars/padayali-JD/CVE-2025-25968.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/CVE-2025-25968.svg)

## CVE-2025-25967
 Acora CMS version 10.1.1 is vulnerable to Cross-Site Request Forgery (CSRF). This flaw enables attackers to trick authenticated users into performing unauthorized actions, such as account deletion or user creation, by embedding malicious requests in external content. The lack of CSRF protections allows exploitation via crafted requests.



- [https://github.com/padayali-JD/CVE-2025-25967](https://github.com/padayali-JD/CVE-2025-25967) :  ![starts](https://img.shields.io/github/stars/padayali-JD/CVE-2025-25967.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/CVE-2025-25967.svg)

## CVE-2025-25763
 crmeb CRMEB-KY v5.4.0 and before has a SQL Injection vulnerability at getRead() in /system/SystemDatabackupServices.php



- [https://github.com/Oyst3r1ng/CVE-2025-25763](https://github.com/Oyst3r1ng/CVE-2025-25763) :  ![starts](https://img.shields.io/github/stars/Oyst3r1ng/CVE-2025-25763.svg) ![forks](https://img.shields.io/github/forks/Oyst3r1ng/CVE-2025-25763.svg)

## CVE-2025-25749
 An issue in HotelDruid version 3.0.7 and earlier allows users to set weak passwords due to the lack of enforcement of password strength policies.



- [https://github.com/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7](https://github.com/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7) :  ![starts](https://img.shields.io/github/stars/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7.svg) ![forks](https://img.shields.io/github/forks/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7.svg)

## CVE-2025-25748
 A CSRF vulnerability in the gestione_utenti.php endpoint of HotelDruid 3.0.7 allows attackers to perform unauthorized actions (e.g., modifying user passwords) on behalf of authenticated users by exploiting the lack of origin or referrer validation and the absence of CSRF tokens. NOTE: this is disputed because there is an id_sessione CSRF token.



- [https://github.com/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7](https://github.com/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7) :  ![starts](https://img.shields.io/github/stars/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7.svg) ![forks](https://img.shields.io/github/forks/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7.svg)

## CVE-2025-25747
 Cross Site Scripting vulnerability in DigitalDruid HotelDruid v.3.0.7 allows an attacker to execute arbitrary code and obtain sensitive information via the ripristina_backup parameter in the crea_backup.php endpoint



- [https://github.com/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS](https://github.com/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS) :  ![starts](https://img.shields.io/github/stars/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS.svg) ![forks](https://img.shields.io/github/forks/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS.svg)

## CVE-2025-25650
 An issue in the storage of NFC card data in Dorset DG 201 Digital Lock H5_433WBSK_v2.2_220605 allows attackers to produce cloned NFC cards to bypass authentication.



- [https://github.com/AbhijithAJ/Dorset_SmartLock_Vulnerability](https://github.com/AbhijithAJ/Dorset_SmartLock_Vulnerability) :  ![starts](https://img.shields.io/github/stars/AbhijithAJ/Dorset_SmartLock_Vulnerability.svg) ![forks](https://img.shields.io/github/forks/AbhijithAJ/Dorset_SmartLock_Vulnerability.svg)

## CVE-2025-25621
 Unifiedtransform 2.0 is vulnerable to Incorrect Access Control, which allows teachers to take attendance of fellow teachers. This affected endpoint is /courses/teacher/index?teacher_id=2&semester_id=1.



- [https://github.com/armaansidana2003/CVE-2025-25621](https://github.com/armaansidana2003/CVE-2025-25621) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25621.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25621.svg)

## CVE-2025-25620
 Unifiedtransform 2.0 is vulnerable to Cross Site Scripting (XSS) in the Create assignment function.



- [https://github.com/armaansidana2003/CVE-2025-25620](https://github.com/armaansidana2003/CVE-2025-25620) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25620.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25620.svg)

## CVE-2025-25618
 Incorrect Access Control in Unifiedtransform 2.0 leads to Privilege Escalation allowing the change of Section Name and Room Number by Teachers.



- [https://github.com/armaansidana2003/CVE-2025-25618](https://github.com/armaansidana2003/CVE-2025-25618) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25618.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25618.svg)

## CVE-2025-25617
 Incorrect Access Control in Unifiedtransform 2.X leads to Privilege Escalation allowing teachers to create syllabus.



- [https://github.com/armaansidana2003/CVE-2025-25617](https://github.com/armaansidana2003/CVE-2025-25617) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25617.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25617.svg)

## CVE-2025-25616
 Unifiedtransform 2.0 is vulnerable to Incorrect Access Control, which allows students to modify rules for exams. The affected endpoint is /exams/edit-rule?exam_rule_id=1.



- [https://github.com/armaansidana2003/CVE-2025-25616](https://github.com/armaansidana2003/CVE-2025-25616) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25616.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25616.svg)

## CVE-2025-25615
 Unifiedtransform 2.0 is vulnerable to Incorrect Access Control which allows viewing attendance list for all class sections.



- [https://github.com/armaansidana2003/CVE-2025-25615](https://github.com/armaansidana2003/CVE-2025-25615) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25615.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25615.svg)

## CVE-2025-25614
 Incorrect Access Control in Unifiedtransform 2.0 leads to Privilege Escalation, which allows teachers to update the personal data of fellow teachers.



- [https://github.com/armaansidana2003/CVE-2025-25614](https://github.com/armaansidana2003/CVE-2025-25614) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25614.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25614.svg)

## CVE-2025-25612
 FS Inc S3150-8T2F prior to version S3150-8T2F_2.2.0D_135103 is vulnerable to Cross Site Scripting (XSS) in the Time Range Configuration functionality of the administration interface. An attacker can inject malicious JavaScript into the "Time Range Name" field, which is improperly sanitized. When this input is saved, it is later executed in the browser of any user accessing the affected page, including administrators, resulting in arbitrary script execution in the user's browser.



- [https://github.com/secmuzz/CVE-2025-25612](https://github.com/secmuzz/CVE-2025-25612) :  ![starts](https://img.shields.io/github/stars/secmuzz/CVE-2025-25612.svg) ![forks](https://img.shields.io/github/forks/secmuzz/CVE-2025-25612.svg)

## CVE-2025-25461
 A Stored Cross-Site Scripting (XSS) vulnerability exists in SeedDMS 6.0.29. A user or rogue admin with the "Add Category" permission can inject a malicious XSS payload into the category name field. When a document is subsequently associated with this category, the payload is stored on the server and rendered without proper sanitization or output encoding. This results in the XSS payload executing in the browser of any user who views the document.



- [https://github.com/RoNiXxCybSeC0101/CVE-2025-25461](https://github.com/RoNiXxCybSeC0101/CVE-2025-25461) :  ![starts](https://img.shields.io/github/stars/RoNiXxCybSeC0101/CVE-2025-25461.svg) ![forks](https://img.shields.io/github/forks/RoNiXxCybSeC0101/CVE-2025-25461.svg)

## CVE-2025-25460
 A stored Cross-Site Scripting (XSS) vulnerability was identified in FlatPress 1.3.1 within the "Add Entry" feature. This vulnerability allows authenticated attackers to inject malicious JavaScript payloads into blog posts, which are executed when other users view the posts. The issue arises due to improper input sanitization of the "TextArea" field in the blog entry submission form.



- [https://github.com/RoNiXxCybSeC0101/CVE-2025-25460](https://github.com/RoNiXxCybSeC0101/CVE-2025-25460) :  ![starts](https://img.shields.io/github/stars/RoNiXxCybSeC0101/CVE-2025-25460.svg) ![forks](https://img.shields.io/github/forks/RoNiXxCybSeC0101/CVE-2025-25460.svg)

## CVE-2025-25427
 A stored cross-site scripting (XSS) vulnerability in the upnp.htm page of the web Interface in TP-Link WR841N v14/v14.6/v14.8 = Build 241230 Rel. 50788n allows remote attackers to inject arbitrary JavaScript code via the port mapping description. This leads to an execution of the JavaScript payload when the upnp page is loaded.



- [https://github.com/slin99/2025-25427](https://github.com/slin99/2025-25427) :  ![starts](https://img.shields.io/github/stars/slin99/2025-25427.svg) ![forks](https://img.shields.io/github/forks/slin99/2025-25427.svg)

## CVE-2025-25296
 Label Studio is an open source data labeling tool. Prior to version 1.16.0, Label Studio's `/projects/upload-example` endpoint allows injection of arbitrary HTML through a `GET` request with an appropriately crafted `label_config` query parameter. By crafting a specially formatted XML label config with inline task data containing malicious HTML/JavaScript, an attacker can achieve Cross-Site Scripting (XSS). While the application has a Content Security Policy (CSP), it is only set in report-only mode, making it ineffective at preventing script execution. The vulnerability exists because the upload-example endpoint renders user-provided HTML content without proper sanitization on a GET request. This allows attackers to inject and execute arbitrary JavaScript in victims' browsers by getting them to visit a maliciously crafted URL. This is considered vulnerable because it enables attackers to execute JavaScript in victims' contexts, potentially allowing theft of sensitive data, session hijacking, or other malicious actions. Version 1.16.0 contains a patch for the issue.



- [https://github.com/math-x-io/CVE-2025-25296-POC](https://github.com/math-x-io/CVE-2025-25296-POC) :  ![starts](https://img.shields.io/github/stars/math-x-io/CVE-2025-25296-POC.svg) ![forks](https://img.shields.io/github/forks/math-x-io/CVE-2025-25296-POC.svg)

## CVE-2025-25279
 Mattermost versions 10.4.x = 10.4.1, 9.11.x = 9.11.7, 10.3.x = 10.3.2, 10.2.x = 10.2.2 fail to properly validate board blocks when importing boards which allows an attacker could read any arbitrary file on the system via importing and exporting a specially crafted import archive in Boards.



- [https://github.com/numanturle/CVE-2025-25279](https://github.com/numanturle/CVE-2025-25279) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2025-25279.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2025-25279.svg)

## CVE-2025-25257
 An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89] in Fortinet FortiWeb version 7.6.0 through 7.6.3, 7.4.0 through 7.4.7, 7.2.0 through 7.2.10 and below 7.0.10 allows an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPs requests.



- [https://github.com/watchtowrlabs/watchTowr-vs-FortiWeb-CVE-2025-25257](https://github.com/watchtowrlabs/watchTowr-vs-FortiWeb-CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-FortiWeb-CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-FortiWeb-CVE-2025-25257.svg)

- [https://github.com/0xbigshaq/CVE-2025-25257](https://github.com/0xbigshaq/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/0xbigshaq/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/0xbigshaq/CVE-2025-25257.svg)

- [https://github.com/mrmtwoj/CVE-2025-25257](https://github.com/mrmtwoj/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/mrmtwoj/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/mrmtwoj/CVE-2025-25257.svg)

- [https://github.com/silentexploitexe/CVE-2025-25257](https://github.com/silentexploitexe/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/silentexploitexe/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/silentexploitexe/CVE-2025-25257.svg)

- [https://github.com/TheStingR/CVE-2025-25257](https://github.com/TheStingR/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/TheStingR/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/TheStingR/CVE-2025-25257.svg)

- [https://github.com/imbas007/CVE-2025-25257](https://github.com/imbas007/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-25257.svg)

- [https://github.com/aitorfirm/CVE-2025-25257](https://github.com/aitorfirm/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/aitorfirm/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/aitorfirm/CVE-2025-25257.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-25257](https://github.com/B1ack4sh/Blackash-CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-25257.svg)

- [https://github.com/segfault-it/CVE-2025-25257](https://github.com/segfault-it/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/segfault-it/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/segfault-it/CVE-2025-25257.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-25257](https://github.com/0xgh057r3c0n/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-25257.svg)

- [https://github.com/adilburaksen/CVE-2025-25257-Exploit-Tool](https://github.com/adilburaksen/CVE-2025-25257-Exploit-Tool) :  ![starts](https://img.shields.io/github/stars/adilburaksen/CVE-2025-25257-Exploit-Tool.svg) ![forks](https://img.shields.io/github/forks/adilburaksen/CVE-2025-25257-Exploit-Tool.svg)

- [https://github.com/secwatch92/fortiweb_rce_toolkit](https://github.com/secwatch92/fortiweb_rce_toolkit) :  ![starts](https://img.shields.io/github/stars/secwatch92/fortiweb_rce_toolkit.svg) ![forks](https://img.shields.io/github/forks/secwatch92/fortiweb_rce_toolkit.svg)

## CVE-2025-25256
 An improper neutralization of special elements used in an OS command ('OS Command Injection') vulnerability [CWE-78] in Fortinet FortiSIEM version 7.3.0 through 7.3.1, 7.2.0 through 7.2.5, 7.1.0 through 7.1.7, 7.0.0 through 7.0.3 and before 6.7.9 allows an unauthenticated attacker to execute unauthorized code or commands via crafted CLI requests.



- [https://github.com/watchtowrlabs/watchTowr-vs-FortiSIEM-CVE-2025-25256](https://github.com/watchtowrlabs/watchTowr-vs-FortiSIEM-CVE-2025-25256) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-FortiSIEM-CVE-2025-25256.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-FortiSIEM-CVE-2025-25256.svg)

## CVE-2025-25231
 Omnissa Workspace ONE UEM contains a Secondary Context Path Traversal Vulnerability. A malicious actor may be able to gain access to sensitive information by sending crafted GET requests (read-only) to restricted API endpoints.



- [https://github.com/ashkan-pu/CVE-CVE-2025-25231](https://github.com/ashkan-pu/CVE-CVE-2025-25231) :  ![starts](https://img.shields.io/github/stars/ashkan-pu/CVE-CVE-2025-25231.svg) ![forks](https://img.shields.io/github/forks/ashkan-pu/CVE-CVE-2025-25231.svg)

## CVE-2025-25198
 mailcow: dockerized is an open source groupware/email suite based on docker. Prior to version 2025-01a, a vulnerability in mailcow's password reset functionality allows an attacker to manipulate the `Host HTTP` header to generate a password reset link pointing to an attacker-controlled domain. This can lead to account takeover if a user clicks the poisoned link. Version 2025-01a contains a patch. As a workaround, deactivate the password reset functionality by clearing `Notification email sender` and `Notification email subject` under System - Configuration - Options - Password Settings.



- [https://github.com/Groppoxx/CVE-2025-25198-PoC](https://github.com/Groppoxx/CVE-2025-25198-PoC) :  ![starts](https://img.shields.io/github/stars/Groppoxx/CVE-2025-25198-PoC.svg) ![forks](https://img.shields.io/github/forks/Groppoxx/CVE-2025-25198-PoC.svg)

- [https://github.com/enzocipher/CVE-2025-25198](https://github.com/enzocipher/CVE-2025-25198) :  ![starts](https://img.shields.io/github/stars/enzocipher/CVE-2025-25198.svg) ![forks](https://img.shields.io/github/forks/enzocipher/CVE-2025-25198.svg)

## CVE-2025-25163
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Zach Swetz Plugin A/B Image Optimizer allows Path Traversal. This issue affects Plugin A/B Image Optimizer: from n/a through 3.3.



- [https://github.com/RootHarpy/CVE-2025-25163-Nuclei-Template](https://github.com/RootHarpy/CVE-2025-25163-Nuclei-Template) :  ![starts](https://img.shields.io/github/stars/RootHarpy/CVE-2025-25163-Nuclei-Template.svg) ![forks](https://img.shields.io/github/forks/RootHarpy/CVE-2025-25163-Nuclei-Template.svg)

- [https://github.com/RandomRobbieBF/CVE-2025-25163](https://github.com/RandomRobbieBF/CVE-2025-25163) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-25163.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-25163.svg)

## CVE-2025-25101
 Cross-Site Request Forgery (CSRF) vulnerability in MetricThemes Munk Sites allows Cross Site Request Forgery. This issue affects Munk Sites: from n/a through 1.0.7.



- [https://github.com/Nxploited/CVE-2025-25101](https://github.com/Nxploited/CVE-2025-25101) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-25101.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-25101.svg)

## CVE-2025-25064
 SQL injection vulnerability in the ZimbraSync Service SOAP endpoint in Zimbra Collaboration 10.0.x before 10.0.12 and 10.1.x before 10.1.4 due to insufficient sanitization of a user-supplied parameter. Authenticated attackers can exploit this vulnerability by manipulating a specific parameter in the request, allowing them to inject arbitrary SQL queries that could retrieve email metadata.



- [https://github.com/yelang123/Zimbra10_SQL_Injection](https://github.com/yelang123/Zimbra10_SQL_Injection) :  ![starts](https://img.shields.io/github/stars/yelang123/Zimbra10_SQL_Injection.svg) ![forks](https://img.shields.io/github/forks/yelang123/Zimbra10_SQL_Injection.svg)

## CVE-2025-25063
 An XSS issue was discovered in Backdrop CMS 1.28.x before 1.28.5 and 1.29.x before 1.29.3. It does not sufficiently validate uploaded SVG images to ensure they do not contain potentially dangerous SVG tags. SVG images can contain clickable links and executable scripting, and using a crafted SVG, it is possible to execute scripting in the browser when an SVG image is viewed. This issue is mitigated by the attacker needing to be able to upload SVG images, and that Backdrop embeds all uploaded SVG images within &lt;img&gt; tags, which prevents scripting from executing. The SVG must be viewed directly by its URL in order to run any embedded scripting.



- [https://github.com/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS](https://github.com/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS.svg)

## CVE-2025-25062
 An XSS issue was discovered in Backdrop CMS 1.28.x before 1.28.5 and 1.29.x before 1.29.3. It doesn't sufficiently isolate long text content when the CKEditor 5 rich text editor is used. This allows a potential attacker to craft specialized HTML and JavaScript that may be executed when an administrator attempts to edit a piece of content. This vulnerability is mitigated by the fact that an attacker must have the ability to create long text content (such as through the node or comment forms) and an administrator must edit (not view) the content that contains the malicious content. This problem only exists when using the CKEditor 5 module.



- [https://github.com/rhburt/CVE-2025-25062](https://github.com/rhburt/CVE-2025-25062) :  ![starts](https://img.shields.io/github/stars/rhburt/CVE-2025-25062.svg) ![forks](https://img.shields.io/github/forks/rhburt/CVE-2025-25062.svg)

## CVE-2025-25014
 A Prototype pollution vulnerability in Kibana leads to arbitrary code execution via crafted HTTP requests to machine learning and reporting endpoints.



- [https://github.com/davidxbors/CVE-2025-25014](https://github.com/davidxbors/CVE-2025-25014) :  ![starts](https://img.shields.io/github/stars/davidxbors/CVE-2025-25014.svg) ![forks](https://img.shields.io/github/forks/davidxbors/CVE-2025-25014.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-25014](https://github.com/B1ack4sh/Blackash-CVE-2025-25014) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-25014.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-25014.svg)

## CVE-2025-24990
 Microsoft is aware of vulnerabilities in the third party Agere Modem driver that ships natively with supported Windows operating systems.  This is an announcement of the upcoming removal of ltmdm64.sys driver.  The driver has been removed in the October cumulative update.
Fax modem hardware dependent on this specific driver will no longer work on Windows.
Microsoft recommends removing any existing dependencies on this hardware.



- [https://github.com/moiz-2x/CVE-2025-24990_POC](https://github.com/moiz-2x/CVE-2025-24990_POC) :  ![starts](https://img.shields.io/github/stars/moiz-2x/CVE-2025-24990_POC.svg) ![forks](https://img.shields.io/github/forks/moiz-2x/CVE-2025-24990_POC.svg)

## CVE-2025-24985
 Integer overflow or wraparound in Windows Fast FAT Driver allows an unauthorized attacker to execute code locally.



- [https://github.com/airbus-cert/cve-2025-24985](https://github.com/airbus-cert/cve-2025-24985) :  ![starts](https://img.shields.io/github/stars/airbus-cert/cve-2025-24985.svg) ![forks](https://img.shields.io/github/forks/airbus-cert/cve-2025-24985.svg)

## CVE-2025-24971
 DumpDrop is a stupid simple file upload application that provides an interface for dragging and dropping files. An OS Command Injection vulnerability was discovered in the DumbDrop application, `/upload/init` endpoint. This vulnerability could allow an attacker to execute arbitrary code remotely when the **Apprise Notification** enabled. This issue has been addressed in commit `4ff8469d` and all users are advised to patch. There are no known workarounds for this vulnerability.



- [https://github.com/be4zad/CVE-2025-24971](https://github.com/be4zad/CVE-2025-24971) :  ![starts](https://img.shields.io/github/stars/be4zad/CVE-2025-24971.svg) ![forks](https://img.shields.io/github/forks/be4zad/CVE-2025-24971.svg)

## CVE-2025-24963
 Vitest is a testing framework powered by Vite. The `__screenshot-error` handler on the browser mode HTTP server that responds any file on the file system. Especially if the server is exposed on the network by `browser.api.host: true`, an attacker can send a request to that handler from remote to get the content of arbitrary files.This `__screenshot-error` handler on the browser mode HTTP server responds any file on the file system. This code was added by commit `2d62051`. Users explicitly exposing the browser mode server to the network by `browser.api.host: true` may get any files exposed. This issue has been addressed in versions 2.1.9 and 3.0.4. Users are advised to upgrade. There are no known workarounds for this vulnerability.



- [https://github.com/0xdeviner/CVE-2025-24963](https://github.com/0xdeviner/CVE-2025-24963) :  ![starts](https://img.shields.io/github/stars/0xdeviner/CVE-2025-24963.svg) ![forks](https://img.shields.io/github/forks/0xdeviner/CVE-2025-24963.svg)

## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.



- [https://github.com/gunzf0x/CVE-2025-24893](https://github.com/gunzf0x/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2025-24893.svg)

- [https://github.com/b0ySie7e/CVE-2025-24893](https://github.com/b0ySie7e/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/b0ySie7e/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/b0ySie7e/CVE-2025-24893.svg)

- [https://github.com/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC](https://github.com/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC) :  ![starts](https://img.shields.io/github/stars/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC.svg) ![forks](https://img.shields.io/github/forks/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC.svg)

- [https://github.com/iSee857/CVE-2025-24893-PoC](https://github.com/iSee857/CVE-2025-24893-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-24893-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-24893-PoC.svg)

- [https://github.com/AliElKhatteb/CVE-2024-32019-POC](https://github.com/AliElKhatteb/CVE-2024-32019-POC) :  ![starts](https://img.shields.io/github/stars/AliElKhatteb/CVE-2024-32019-POC.svg) ![forks](https://img.shields.io/github/forks/AliElKhatteb/CVE-2024-32019-POC.svg)

- [https://github.com/Infinit3i/CVE-2025-24893](https://github.com/Infinit3i/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/Infinit3i/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/Infinit3i/CVE-2025-24893.svg)

- [https://github.com/Hex00-0x4/CVE-2025-24893-XWiki-RCE](https://github.com/Hex00-0x4/CVE-2025-24893-XWiki-RCE) :  ![starts](https://img.shields.io/github/stars/Hex00-0x4/CVE-2025-24893-XWiki-RCE.svg) ![forks](https://img.shields.io/github/forks/Hex00-0x4/CVE-2025-24893-XWiki-RCE.svg)

- [https://github.com/hackersonsteroids/cve-2025-24893](https://github.com/hackersonsteroids/cve-2025-24893) :  ![starts](https://img.shields.io/github/stars/hackersonsteroids/cve-2025-24893.svg) ![forks](https://img.shields.io/github/forks/hackersonsteroids/cve-2025-24893.svg)

- [https://github.com/gotr00t0day/CVE-2025-24893](https://github.com/gotr00t0day/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/gotr00t0day/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/gotr00t0day/CVE-2025-24893.svg)

- [https://github.com/nopgadget/CVE-2025-24893](https://github.com/nopgadget/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/nopgadget/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/nopgadget/CVE-2025-24893.svg)

- [https://github.com/D3Ext/CVE-2025-24893](https://github.com/D3Ext/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/D3Ext/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/D3Ext/CVE-2025-24893.svg)

- [https://github.com/570RMBR3AK3R/xwiki-cve-2025-24893-poc](https://github.com/570RMBR3AK3R/xwiki-cve-2025-24893-poc) :  ![starts](https://img.shields.io/github/stars/570RMBR3AK3R/xwiki-cve-2025-24893-poc.svg) ![forks](https://img.shields.io/github/forks/570RMBR3AK3R/xwiki-cve-2025-24893-poc.svg)

- [https://github.com/Artemir7/CVE-2025-24893-EXP](https://github.com/Artemir7/CVE-2025-24893-EXP) :  ![starts](https://img.shields.io/github/stars/Artemir7/CVE-2025-24893-EXP.svg) ![forks](https://img.shields.io/github/forks/Artemir7/CVE-2025-24893-EXP.svg)

- [https://github.com/Yukik4z3/CVE-2025-24893](https://github.com/Yukik4z3/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/Yukik4z3/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/Yukik4z3/CVE-2025-24893.svg)

- [https://github.com/Th3Gl0w/CVE-2025-24893-POC](https://github.com/Th3Gl0w/CVE-2025-24893-POC) :  ![starts](https://img.shields.io/github/stars/Th3Gl0w/CVE-2025-24893-POC.svg) ![forks](https://img.shields.io/github/forks/Th3Gl0w/CVE-2025-24893-POC.svg)

- [https://github.com/x0da6h/POC-for-CVE-2025-24893](https://github.com/x0da6h/POC-for-CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/x0da6h/POC-for-CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/x0da6h/POC-for-CVE-2025-24893.svg)

- [https://github.com/Kai7788/CVE-2025-24893-RCE-PoC](https://github.com/Kai7788/CVE-2025-24893-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/Kai7788/CVE-2025-24893-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/Kai7788/CVE-2025-24893-RCE-PoC.svg)

- [https://github.com/IIIeJlyXaKapToIIIKu/CVE-2025-24893-XWiki-unauthenticated-RCE-via-SolrSearch](https://github.com/IIIeJlyXaKapToIIIKu/CVE-2025-24893-XWiki-unauthenticated-RCE-via-SolrSearch) :  ![starts](https://img.shields.io/github/stars/IIIeJlyXaKapToIIIKu/CVE-2025-24893-XWiki-unauthenticated-RCE-via-SolrSearch.svg) ![forks](https://img.shields.io/github/forks/IIIeJlyXaKapToIIIKu/CVE-2025-24893-XWiki-unauthenticated-RCE-via-SolrSearch.svg)

- [https://github.com/torjan0/xwiki_solrsearch-rce-exploit](https://github.com/torjan0/xwiki_solrsearch-rce-exploit) :  ![starts](https://img.shields.io/github/stars/torjan0/xwiki_solrsearch-rce-exploit.svg) ![forks](https://img.shields.io/github/forks/torjan0/xwiki_solrsearch-rce-exploit.svg)

- [https://github.com/AliAmouz/CVE2025-24893](https://github.com/AliAmouz/CVE2025-24893) :  ![starts](https://img.shields.io/github/stars/AliAmouz/CVE2025-24893.svg) ![forks](https://img.shields.io/github/forks/AliAmouz/CVE2025-24893.svg)

- [https://github.com/ibrahmsql/CVE-2025-24893](https://github.com/ibrahmsql/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2025-24893.svg)

- [https://github.com/andwati/CVE-2025-24893](https://github.com/andwati/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/andwati/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/andwati/CVE-2025-24893.svg)

- [https://github.com/mah4nzfr/CVE-2025-24893](https://github.com/mah4nzfr/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/mah4nzfr/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/mah4nzfr/CVE-2025-24893.svg)

- [https://github.com/The-Red-Serpent/CVE-2025-24893](https://github.com/The-Red-Serpent/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/The-Red-Serpent/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/The-Red-Serpent/CVE-2025-24893.svg)

- [https://github.com/CMassa/CVE-2025-24893](https://github.com/CMassa/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/CMassa/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/CMassa/CVE-2025-24893.svg)

- [https://github.com/rvizx/CVE-2025-24893](https://github.com/rvizx/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2025-24893.svg)

- [https://github.com/zs1n/CVE-2025-24893](https://github.com/zs1n/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/zs1n/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/zs1n/CVE-2025-24893.svg)

- [https://github.com/Y2F05p2w/CVE-2025-24893](https://github.com/Y2F05p2w/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/Y2F05p2w/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/Y2F05p2w/CVE-2025-24893.svg)

- [https://github.com/alaxar/CVE-2025-24893](https://github.com/alaxar/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/alaxar/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/alaxar/CVE-2025-24893.svg)

- [https://github.com/investigato/cve-2025-24893-poc](https://github.com/investigato/cve-2025-24893-poc) :  ![starts](https://img.shields.io/github/stars/investigato/cve-2025-24893-poc.svg) ![forks](https://img.shields.io/github/forks/investigato/cve-2025-24893-poc.svg)

- [https://github.com/Retro023/CVE-2025-24893-POC](https://github.com/Retro023/CVE-2025-24893-POC) :  ![starts](https://img.shields.io/github/stars/Retro023/CVE-2025-24893-POC.svg) ![forks](https://img.shields.io/github/forks/Retro023/CVE-2025-24893-POC.svg)

- [https://github.com/dhiaZnaidi/CVE-2025-24893-PoC](https://github.com/dhiaZnaidi/CVE-2025-24893-PoC) :  ![starts](https://img.shields.io/github/stars/dhiaZnaidi/CVE-2025-24893-PoC.svg) ![forks](https://img.shields.io/github/forks/dhiaZnaidi/CVE-2025-24893-PoC.svg)

- [https://github.com/AzureADTrent/CVE-2025-24893-Reverse-Shell](https://github.com/AzureADTrent/CVE-2025-24893-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/AzureADTrent/CVE-2025-24893-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/AzureADTrent/CVE-2025-24893-Reverse-Shell.svg)

- [https://github.com/ibadovulfat/CVE-2025-24893_HackTheBox-Editor-Writeup](https://github.com/ibadovulfat/CVE-2025-24893_HackTheBox-Editor-Writeup) :  ![starts](https://img.shields.io/github/stars/ibadovulfat/CVE-2025-24893_HackTheBox-Editor-Writeup.svg) ![forks](https://img.shields.io/github/forks/ibadovulfat/CVE-2025-24893_HackTheBox-Editor-Writeup.svg)

- [https://github.com/Bishben/xwiki-15.10.8-reverse-shell-cve-2025-24893](https://github.com/Bishben/xwiki-15.10.8-reverse-shell-cve-2025-24893) :  ![starts](https://img.shields.io/github/stars/Bishben/xwiki-15.10.8-reverse-shell-cve-2025-24893.svg) ![forks](https://img.shields.io/github/forks/Bishben/xwiki-15.10.8-reverse-shell-cve-2025-24893.svg)

- [https://github.com/achnouri/Editor-CTF-writre-up](https://github.com/achnouri/Editor-CTF-writre-up) :  ![starts](https://img.shields.io/github/stars/achnouri/Editor-CTF-writre-up.svg) ![forks](https://img.shields.io/github/forks/achnouri/Editor-CTF-writre-up.svg)

## CVE-2025-24813
 Path Equivalence: 'file.Name' (Internal Dot) leading to Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet in Apache Tomcat.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.2, from 10.1.0-M1 through 10.1.34, from 9.0.0.M1 through 9.0.98.
The following versions were EOL at the time the CVE was created but are 
known to be affected: 8.5.0 though 8.5.100. Other, older, EOL versions 
may also be affected.


If all of the following were true, a malicious user was able to view       security sensitive files and/or inject content into those files:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- a target URL for security sensitive uploads that was a sub-directory of a target URL for public uploads
- attacker knowledge of the names of security sensitive files being uploaded
- the security sensitive files also being uploaded via partial PUT

If all of the following were true, a malicious user was able to       perform remote code execution:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- application was using Tomcat's file based session persistence with the default storage location
- application included a library that may be leveraged in a deserialization attack

Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.



- [https://github.com/absholi7ly/POC-CVE-2025-24813](https://github.com/absholi7ly/POC-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/absholi7ly/POC-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/POC-CVE-2025-24813.svg)

- [https://github.com/iSee857/CVE-2025-24813-PoC](https://github.com/iSee857/CVE-2025-24813-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-24813-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-24813-PoC.svg)

- [https://github.com/drcrypterdotru/Apache-GOExploiter](https://github.com/drcrypterdotru/Apache-GOExploiter) :  ![starts](https://img.shields.io/github/stars/drcrypterdotru/Apache-GOExploiter.svg) ![forks](https://img.shields.io/github/forks/drcrypterdotru/Apache-GOExploiter.svg)

- [https://github.com/charis3306/CVE-2025-24813](https://github.com/charis3306/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/charis3306/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/charis3306/CVE-2025-24813.svg)

- [https://github.com/mbanyamer/Apache-Tomcat---Remote-Code-Execution-via-Session-Deserialization-CVE-2025-24813-](https://github.com/mbanyamer/Apache-Tomcat---Remote-Code-Execution-via-Session-Deserialization-CVE-2025-24813-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/Apache-Tomcat---Remote-Code-Execution-via-Session-Deserialization-CVE-2025-24813-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/Apache-Tomcat---Remote-Code-Execution-via-Session-Deserialization-CVE-2025-24813-.svg)

- [https://github.com/qzy0x/cve-2025-24813_poc](https://github.com/qzy0x/cve-2025-24813_poc) :  ![starts](https://img.shields.io/github/stars/qzy0x/cve-2025-24813_poc.svg) ![forks](https://img.shields.io/github/forks/qzy0x/cve-2025-24813_poc.svg)

- [https://github.com/Franconyu/Poc_for_CVE-2025-24813](https://github.com/Franconyu/Poc_for_CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/Franconyu/Poc_for_CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/Franconyu/Poc_for_CVE-2025-24813.svg)

- [https://github.com/Erosion2020/CVE-2025-24813-vulhub](https://github.com/Erosion2020/CVE-2025-24813-vulhub) :  ![starts](https://img.shields.io/github/stars/Erosion2020/CVE-2025-24813-vulhub.svg) ![forks](https://img.shields.io/github/forks/Erosion2020/CVE-2025-24813-vulhub.svg)

- [https://github.com/u238/Tomcat-CVE_2025_24813](https://github.com/u238/Tomcat-CVE_2025_24813) :  ![starts](https://img.shields.io/github/stars/u238/Tomcat-CVE_2025_24813.svg) ![forks](https://img.shields.io/github/forks/u238/Tomcat-CVE_2025_24813.svg)

- [https://github.com/Mattb709/CVE-2025-24813-Scanner](https://github.com/Mattb709/CVE-2025-24813-Scanner) :  ![starts](https://img.shields.io/github/stars/Mattb709/CVE-2025-24813-Scanner.svg) ![forks](https://img.shields.io/github/forks/Mattb709/CVE-2025-24813-Scanner.svg)

- [https://github.com/msadeghkarimi/CVE-2025-24813-Exploit](https://github.com/msadeghkarimi/CVE-2025-24813-Exploit) :  ![starts](https://img.shields.io/github/stars/msadeghkarimi/CVE-2025-24813-Exploit.svg) ![forks](https://img.shields.io/github/forks/msadeghkarimi/CVE-2025-24813-Exploit.svg)

- [https://github.com/x00byte/PutScanner](https://github.com/x00byte/PutScanner) :  ![starts](https://img.shields.io/github/stars/x00byte/PutScanner.svg) ![forks](https://img.shields.io/github/forks/x00byte/PutScanner.svg)

- [https://github.com/AsaL1n/CVE-2025-24813](https://github.com/AsaL1n/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/AsaL1n/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/AsaL1n/CVE-2025-24813.svg)

- [https://github.com/Shivshantp/CVE-2025-24813](https://github.com/Shivshantp/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/Shivshantp/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/Shivshantp/CVE-2025-24813.svg)

- [https://github.com/N0c1or/CVE-2025-24813_POC](https://github.com/N0c1or/CVE-2025-24813_POC) :  ![starts](https://img.shields.io/github/stars/N0c1or/CVE-2025-24813_POC.svg) ![forks](https://img.shields.io/github/forks/N0c1or/CVE-2025-24813_POC.svg)

- [https://github.com/AlperenY-cs/CVE-2025-24813](https://github.com/AlperenY-cs/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/AlperenY-cs/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/AlperenY-cs/CVE-2025-24813.svg)

- [https://github.com/imbas007/CVE-2025-24813-apache-tomcat](https://github.com/imbas007/CVE-2025-24813-apache-tomcat) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-24813-apache-tomcat.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-24813-apache-tomcat.svg)

- [https://github.com/Alaatk/CVE-2025-24813-POC](https://github.com/Alaatk/CVE-2025-24813-POC) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2025-24813-POC.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2025-24813-POC.svg)

- [https://github.com/Mattb709/CVE-2025-24813-PoC-Apache-Tomcat-RCE](https://github.com/Mattb709/CVE-2025-24813-PoC-Apache-Tomcat-RCE) :  ![starts](https://img.shields.io/github/stars/Mattb709/CVE-2025-24813-PoC-Apache-Tomcat-RCE.svg) ![forks](https://img.shields.io/github/forks/Mattb709/CVE-2025-24813-PoC-Apache-Tomcat-RCE.svg)

- [https://github.com/beyond-devsecops/CVE-2025-24813](https://github.com/beyond-devsecops/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/beyond-devsecops/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/beyond-devsecops/CVE-2025-24813.svg)

- [https://github.com/issamjr/CVE-2025-24813-Scanner](https://github.com/issamjr/CVE-2025-24813-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-24813-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-24813-Scanner.svg)

- [https://github.com/pirenga/CVE-2025-24813](https://github.com/pirenga/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/pirenga/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/pirenga/CVE-2025-24813.svg)

- [https://github.com/fatkz/CVE-2025-24813](https://github.com/fatkz/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/fatkz/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/fatkz/CVE-2025-24813.svg)

- [https://github.com/MuhammadWaseem29/CVE-2025-24813](https://github.com/MuhammadWaseem29/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-24813.svg)

- [https://github.com/gregk4sec/CVE-2025-24813](https://github.com/gregk4sec/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-24813.svg)

- [https://github.com/cyglegit/CVE-2025-24813](https://github.com/cyglegit/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/cyglegit/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/cyglegit/CVE-2025-24813.svg)

- [https://github.com/GadaLuBau1337/CVE-2025-24813](https://github.com/GadaLuBau1337/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/GadaLuBau1337/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/GadaLuBau1337/CVE-2025-24813.svg)

- [https://github.com/tonyarris/CVE-2025-24813-PoC](https://github.com/tonyarris/CVE-2025-24813-PoC) :  ![starts](https://img.shields.io/github/stars/tonyarris/CVE-2025-24813-PoC.svg) ![forks](https://img.shields.io/github/forks/tonyarris/CVE-2025-24813-PoC.svg)

- [https://github.com/thebringerofdeath789/CVE-2025-24813](https://github.com/thebringerofdeath789/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/thebringerofdeath789/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/thebringerofdeath789/CVE-2025-24813.svg)

- [https://github.com/GongWook/CVE-2025-24813](https://github.com/GongWook/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/GongWook/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/GongWook/CVE-2025-24813.svg)

- [https://github.com/manjula-aw/CVE-2025-24813](https://github.com/manjula-aw/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/manjula-aw/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/manjula-aw/CVE-2025-24813.svg)

- [https://github.com/horsehacks/CVE-2025-24813-checker](https://github.com/horsehacks/CVE-2025-24813-checker) :  ![starts](https://img.shields.io/github/stars/horsehacks/CVE-2025-24813-checker.svg) ![forks](https://img.shields.io/github/forks/horsehacks/CVE-2025-24813-checker.svg)

- [https://github.com/ThHardvester/CVE-2025-24813](https://github.com/ThHardvester/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/ThHardvester/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/ThHardvester/CVE-2025-24813.svg)

- [https://github.com/hakankarabacak/CVE-2025-24813](https://github.com/hakankarabacak/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/hakankarabacak/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/hakankarabacak/CVE-2025-24813.svg)

- [https://github.com/x1ongsec/CVE-2025-24813](https://github.com/x1ongsec/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/x1ongsec/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/x1ongsec/CVE-2025-24813.svg)

- [https://github.com/yaleman/cve-2025-24813-poc](https://github.com/yaleman/cve-2025-24813-poc) :  ![starts](https://img.shields.io/github/stars/yaleman/cve-2025-24813-poc.svg) ![forks](https://img.shields.io/github/forks/yaleman/cve-2025-24813-poc.svg)

- [https://github.com/B1gN0Se/Tomcat-CVE-2025-24813](https://github.com/B1gN0Se/Tomcat-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/B1gN0Se/Tomcat-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/B1gN0Se/Tomcat-CVE-2025-24813.svg)

- [https://github.com/ps-interactive/lab-cve-2025-24813](https://github.com/ps-interactive/lab-cve-2025-24813) :  ![starts](https://img.shields.io/github/stars/ps-interactive/lab-cve-2025-24813.svg) ![forks](https://img.shields.io/github/forks/ps-interactive/lab-cve-2025-24813.svg)

- [https://github.com/f8l124/CVE-2025-24813-POC](https://github.com/f8l124/CVE-2025-24813-POC) :  ![starts](https://img.shields.io/github/stars/f8l124/CVE-2025-24813-POC.svg) ![forks](https://img.shields.io/github/forks/f8l124/CVE-2025-24813-POC.svg)

- [https://github.com/La3B0z/CVE-2025-24813-POC](https://github.com/La3B0z/CVE-2025-24813-POC) :  ![starts](https://img.shields.io/github/stars/La3B0z/CVE-2025-24813-POC.svg) ![forks](https://img.shields.io/github/forks/La3B0z/CVE-2025-24813-POC.svg)

- [https://github.com/137f/PoC-CVE-2025-24813](https://github.com/137f/PoC-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/137f/PoC-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/137f/PoC-CVE-2025-24813.svg)

- [https://github.com/CEAlbez/CVE-2025-24813-PoC](https://github.com/CEAlbez/CVE-2025-24813-PoC) :  ![starts](https://img.shields.io/github/stars/CEAlbez/CVE-2025-24813-PoC.svg) ![forks](https://img.shields.io/github/forks/CEAlbez/CVE-2025-24813-PoC.svg)

- [https://github.com/Heimd411/CVE-2025-24813-noPoC](https://github.com/Heimd411/CVE-2025-24813-noPoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-24813-noPoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-24813-noPoC.svg)

- [https://github.com/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813](https://github.com/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813.svg)

- [https://github.com/michael-david-fry/Apache-Tomcat-Vulnerability-POC-CVE-2025-24813](https://github.com/michael-david-fry/Apache-Tomcat-Vulnerability-POC-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/michael-david-fry/Apache-Tomcat-Vulnerability-POC-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/michael-david-fry/Apache-Tomcat-Vulnerability-POC-CVE-2025-24813.svg)

- [https://github.com/sentilaso1/CVE-2025-24813-Apache-Tomcat-RCE-PoC](https://github.com/sentilaso1/CVE-2025-24813-Apache-Tomcat-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/sentilaso1/CVE-2025-24813-Apache-Tomcat-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/sentilaso1/CVE-2025-24813-Apache-Tomcat-RCE-PoC.svg)

- [https://github.com/Makavellik/POC-CVE-2025-24813-Apache-Tomcat-Remote-Code-Execution](https://github.com/Makavellik/POC-CVE-2025-24813-Apache-Tomcat-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/Makavellik/POC-CVE-2025-24813-Apache-Tomcat-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/Makavellik/POC-CVE-2025-24813-Apache-Tomcat-Remote-Code-Execution.svg)

- [https://github.com/threadpoolx/CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat](https://github.com/threadpoolx/CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat) :  ![starts](https://img.shields.io/github/stars/threadpoolx/CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat.svg) ![forks](https://img.shields.io/github/forks/threadpoolx/CVE-2025-24813-Remote-Code-Execution-in-Apache-Tomcat.svg)

## CVE-2025-24801
 GLPI is a free asset and IT management software package. An authenticated user can upload and force the execution of *.php files located on the GLPI server. This vulnerability is fixed in 10.0.18.



- [https://github.com/fatkz/CVE-2025-24801](https://github.com/fatkz/CVE-2025-24801) :  ![starts](https://img.shields.io/github/stars/fatkz/CVE-2025-24801.svg) ![forks](https://img.shields.io/github/forks/fatkz/CVE-2025-24801.svg)

- [https://github.com/r1beirin/CVE-2025-24801](https://github.com/r1beirin/CVE-2025-24801) :  ![starts](https://img.shields.io/github/stars/r1beirin/CVE-2025-24801.svg) ![forks](https://img.shields.io/github/forks/r1beirin/CVE-2025-24801.svg)

## CVE-2025-24799
 GLPI is a free asset and IT management software package. An unauthenticated user can perform a SQL injection through the inventory endpoint. This vulnerability is fixed in 10.0.18.



- [https://github.com/MatheuZSecurity/Exploit-CVE-2025-24799](https://github.com/MatheuZSecurity/Exploit-CVE-2025-24799) :  ![starts](https://img.shields.io/github/stars/MatheuZSecurity/Exploit-CVE-2025-24799.svg) ![forks](https://img.shields.io/github/forks/MatheuZSecurity/Exploit-CVE-2025-24799.svg)

- [https://github.com/MuhammadWaseem29/CVE-2025-24799](https://github.com/MuhammadWaseem29/CVE-2025-24799) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-24799.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-24799.svg)

- [https://github.com/nak000/CVE-2025-24799-sqli](https://github.com/nak000/CVE-2025-24799-sqli) :  ![starts](https://img.shields.io/github/stars/nak000/CVE-2025-24799-sqli.svg) ![forks](https://img.shields.io/github/forks/nak000/CVE-2025-24799-sqli.svg)

- [https://github.com/Rosemary1337/CVE-2025-24799](https://github.com/Rosemary1337/CVE-2025-24799) :  ![starts](https://img.shields.io/github/stars/Rosemary1337/CVE-2025-24799.svg) ![forks](https://img.shields.io/github/forks/Rosemary1337/CVE-2025-24799.svg)

- [https://github.com/airbus-cert/CVE-2025-24799-scanner](https://github.com/airbus-cert/CVE-2025-24799-scanner) :  ![starts](https://img.shields.io/github/stars/airbus-cert/CVE-2025-24799-scanner.svg) ![forks](https://img.shields.io/github/forks/airbus-cert/CVE-2025-24799-scanner.svg)

## CVE-2025-24797
 Meshtastic is an open source mesh networking solution. A fault in the handling of mesh packets containing invalid protobuf data can result in an attacker-controlled buffer overflow, allowing an attacker to hijack execution flow, potentially resulting in remote code execution. This attack does not require authentication or user interaction, as long as the target device rebroadcasts packets on the default channel. This vulnerability fixed in 2.6.2.



- [https://github.com/Alainx277/CVE-2025-24797](https://github.com/Alainx277/CVE-2025-24797) :  ![starts](https://img.shields.io/github/stars/Alainx277/CVE-2025-24797.svg) ![forks](https://img.shields.io/github/forks/Alainx277/CVE-2025-24797.svg)

## CVE-2025-24752
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in WPDeveloper Essential Addons for Elementor allows Reflected XSS. This issue affects Essential Addons for Elementor: from n/a through 6.0.14.



- [https://github.com/Sachinart/essential-addons-for-elementor-xss-poc](https://github.com/Sachinart/essential-addons-for-elementor-xss-poc) :  ![starts](https://img.shields.io/github/stars/Sachinart/essential-addons-for-elementor-xss-poc.svg) ![forks](https://img.shields.io/github/forks/Sachinart/essential-addons-for-elementor-xss-poc.svg)

- [https://github.com/bartfroklage/CVE-2025-24752-POC](https://github.com/bartfroklage/CVE-2025-24752-POC) :  ![starts](https://img.shields.io/github/stars/bartfroklage/CVE-2025-24752-POC.svg) ![forks](https://img.shields.io/github/forks/bartfroklage/CVE-2025-24752-POC.svg)

## CVE-2025-24659
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in WordPress Download Manager Premium Packages allows Blind SQL Injection. This issue affects Premium Packages: from n/a through 5.9.6.



- [https://github.com/DoTTak/CVE-2025-24659](https://github.com/DoTTak/CVE-2025-24659) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-24659.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-24659.svg)

## CVE-2025-24587
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in I Thirteen Web Solution Email Subscription Popup allows Blind SQL Injection. This issue affects Email Subscription Popup: from n/a through 1.2.23.



- [https://github.com/DoTTak/CVE-2025-24587](https://github.com/DoTTak/CVE-2025-24587) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-24587.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-24587.svg)

## CVE-2025-24514
 A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `auth-url` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)



- [https://github.com/hakaioffsec/IngressNightmare-PoC](https://github.com/hakaioffsec/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/IngressNightmare-PoC.svg)

- [https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps](https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps) :  ![starts](https://img.shields.io/github/stars/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg) ![forks](https://img.shields.io/github/forks/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg)

- [https://github.com/lufeirider/IngressNightmare-PoC](https://github.com/lufeirider/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/lufeirider/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/lufeirider/IngressNightmare-PoC.svg)

- [https://github.com/KimJuhyeong95/cve-2025-24514](https://github.com/KimJuhyeong95/cve-2025-24514) :  ![starts](https://img.shields.io/github/stars/KimJuhyeong95/cve-2025-24514.svg) ![forks](https://img.shields.io/github/forks/KimJuhyeong95/cve-2025-24514.svg)

## CVE-2025-24367
 Cacti is an open source performance and fault management framework. An authenticated Cacti user can abuse graph creation and graph template functionality to create arbitrary PHP scripts in the web root of the application, leading to remote code execution on the server. This vulnerability is fixed in 1.2.29.



- [https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC) :  ![starts](https://img.shields.io/github/stars/TheCyberGeek/CVE-2025-24367-Cacti-PoC.svg) ![forks](https://img.shields.io/github/forks/TheCyberGeek/CVE-2025-24367-Cacti-PoC.svg)

## CVE-2025-24354
 imgproxy is server for resizing, processing, and converting images. Imgproxy does not block the 0.0.0.0 address, even with IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES set to false. This can expose services on the local host. This vulnerability is fixed in 3.27.2.



- [https://github.com/Admin9961/CVE-2025-24354-PoC](https://github.com/Admin9961/CVE-2025-24354-PoC) :  ![starts](https://img.shields.io/github/stars/Admin9961/CVE-2025-24354-PoC.svg) ![forks](https://img.shields.io/github/forks/Admin9961/CVE-2025-24354-PoC.svg)

## CVE-2025-24271
 An access issue was addressed with improved access restrictions. This issue is fixed in macOS Sequoia 15.4, tvOS 18.4, macOS Ventura 13.7.5, iPadOS 17.7.6, macOS Sonoma 14.7.5, iOS 18.4 and iPadOS 18.4, visionOS 2.4. An unauthenticated user on the same network as a signed-in Mac could send it AirPlay commands without pairing.



- [https://github.com/moften/CVE-2025-24271](https://github.com/moften/CVE-2025-24271) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2025-24271.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2025-24271.svg)

## CVE-2025-24252
 A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS Sequoia 15.4, tvOS 18.4, macOS Ventura 13.7.5, iPadOS 17.7.6, macOS Sonoma 14.7.5, iOS 18.4 and iPadOS 18.4, visionOS 2.4. An attacker on the local network may be able to corrupt process memory.



- [https://github.com/ekomsSavior/AirBorne-PoC](https://github.com/ekomsSavior/AirBorne-PoC) :  ![starts](https://img.shields.io/github/stars/ekomsSavior/AirBorne-PoC.svg) ![forks](https://img.shields.io/github/forks/ekomsSavior/AirBorne-PoC.svg)

- [https://github.com/cakescats/airborn-IOS-CVE-2025-24252](https://github.com/cakescats/airborn-IOS-CVE-2025-24252) :  ![starts](https://img.shields.io/github/stars/cakescats/airborn-IOS-CVE-2025-24252.svg) ![forks](https://img.shields.io/github/forks/cakescats/airborn-IOS-CVE-2025-24252.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-24252](https://github.com/B1ack4sh/Blackash-CVE-2025-24252) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-24252.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-24252.svg)

## CVE-2025-24225
 An injection issue was addressed with improved input validation. This issue is fixed in iPadOS 17.7.7, iOS 18.5 and iPadOS 18.5. Processing an email may lead to user interface spoofing.



- [https://github.com/richeeta/DEFCON33-Siriously-Leaky](https://github.com/richeeta/DEFCON33-Siriously-Leaky) :  ![starts](https://img.shields.io/github/stars/richeeta/DEFCON33-Siriously-Leaky.svg) ![forks](https://img.shields.io/github/forks/richeeta/DEFCON33-Siriously-Leaky.svg)

## CVE-2025-24204
 The issue was addressed with improved checks. This issue is fixed in macOS Sequoia 15.4. An app may be able to access protected user data.



- [https://github.com/34306/decrypted](https://github.com/34306/decrypted) :  ![starts](https://img.shields.io/github/stars/34306/decrypted.svg) ![forks](https://img.shields.io/github/forks/34306/decrypted.svg)

- [https://github.com/FFRI/CVE-2025-24204](https://github.com/FFRI/CVE-2025-24204) :  ![starts](https://img.shields.io/github/stars/FFRI/CVE-2025-24204.svg) ![forks](https://img.shields.io/github/forks/FFRI/CVE-2025-24204.svg)

## CVE-2025-24203
 The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.7.5, iPadOS 17.7.6, macOS Sequoia 15.4, macOS Sonoma 14.7.5. An app may be able to modify protected parts of the file system.



- [https://github.com/jailbreakdotparty/dirtyZero](https://github.com/jailbreakdotparty/dirtyZero) :  ![starts](https://img.shields.io/github/stars/jailbreakdotparty/dirtyZero.svg) ![forks](https://img.shields.io/github/forks/jailbreakdotparty/dirtyZero.svg)

- [https://github.com/GeoSn0w/iDevice-Toolkit](https://github.com/GeoSn0w/iDevice-Toolkit) :  ![starts](https://img.shields.io/github/stars/GeoSn0w/iDevice-Toolkit.svg) ![forks](https://img.shields.io/github/forks/GeoSn0w/iDevice-Toolkit.svg)

- [https://github.com/GeoSn0w/CVE-2025-24203-iOS-Exploit-With-Error-Logging](https://github.com/GeoSn0w/CVE-2025-24203-iOS-Exploit-With-Error-Logging) :  ![starts](https://img.shields.io/github/stars/GeoSn0w/CVE-2025-24203-iOS-Exploit-With-Error-Logging.svg) ![forks](https://img.shields.io/github/forks/GeoSn0w/CVE-2025-24203-iOS-Exploit-With-Error-Logging.svg)

- [https://github.com/pxx917144686/iDevice_ZH](https://github.com/pxx917144686/iDevice_ZH) :  ![starts](https://img.shields.io/github/stars/pxx917144686/iDevice_ZH.svg) ![forks](https://img.shields.io/github/forks/pxx917144686/iDevice_ZH.svg)

## CVE-2025-24201
 An out-of-bounds write issue was addressed with improved checks to prevent unauthorized actions. This issue is fixed in visionOS 2.3.2, iOS 18.3.2 and iPadOS 18.3.2, macOS Sequoia 15.3.2, Safari 18.3.1, watchOS 11.4, iPadOS 17.7.6, iOS 16.7.11 and iPadOS 16.7.11, iOS 15.8.4 and iPadOS 15.8.4. Maliciously crafted web content may be able to break out of Web Content sandbox. This is a supplementary fix for an attack that was blocked in iOS 17.2. (Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 17.2.).



- [https://github.com/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201](https://github.com/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201) :  ![starts](https://img.shields.io/github/stars/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201.svg) ![forks](https://img.shields.io/github/forks/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201.svg)

- [https://github.com/The-Maxu/CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-](https://github.com/The-Maxu/CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-) :  ![starts](https://img.shields.io/github/stars/The-Maxu/CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-.svg) ![forks](https://img.shields.io/github/forks/The-Maxu/CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-.svg)

- [https://github.com/5ky9uy/glass-cage-i18-2025-24085-and-cve-2025-24201](https://github.com/5ky9uy/glass-cage-i18-2025-24085-and-cve-2025-24201) :  ![starts](https://img.shields.io/github/stars/5ky9uy/glass-cage-i18-2025-24085-and-cve-2025-24201.svg) ![forks](https://img.shields.io/github/forks/5ky9uy/glass-cage-i18-2025-24085-and-cve-2025-24201.svg)

## CVE-2025-24198
 This issue was addressed by restricting options offered on a locked device. This issue is fixed in macOS Ventura 13.7.5, iOS 18.4 and iPadOS 18.4, iPadOS 17.7.6, macOS Sequoia 15.4, macOS Sonoma 14.7.5. An attacker with physical access may be able to use Siri to access sensitive user data.



- [https://github.com/richeeta/DEFCON33-Siriously-Leaky](https://github.com/richeeta/DEFCON33-Siriously-Leaky) :  ![starts](https://img.shields.io/github/stars/richeeta/DEFCON33-Siriously-Leaky.svg) ![forks](https://img.shields.io/github/forks/richeeta/DEFCON33-Siriously-Leaky.svg)

## CVE-2025-24132
 The issue was addressed with improved memory handling. This issue is fixed in AirPlay audio SDK 2.7.1, AirPlay video SDK 3.6.0.126, CarPlay Communication Plug-in R18.1. An attacker on the local network may cause an unexpected app termination.



- [https://github.com/ekomsSavior/AirBorne-PoC](https://github.com/ekomsSavior/AirBorne-PoC) :  ![starts](https://img.shields.io/github/stars/ekomsSavior/AirBorne-PoC.svg) ![forks](https://img.shields.io/github/forks/ekomsSavior/AirBorne-PoC.svg)

- [https://github.com/Feralthedogg/CVE-2025-24132-Scanner](https://github.com/Feralthedogg/CVE-2025-24132-Scanner) :  ![starts](https://img.shields.io/github/stars/Feralthedogg/CVE-2025-24132-Scanner.svg) ![forks](https://img.shields.io/github/forks/Feralthedogg/CVE-2025-24132-Scanner.svg)

## CVE-2025-24118
 The issue was addressed with improved memory handling. This issue is fixed in iPadOS 17.7.4, macOS Sequoia 15.3, macOS Sonoma 14.7.3. An app may be able to cause unexpected system termination or write kernel memory.



- [https://github.com/jprx/CVE-2025-24118](https://github.com/jprx/CVE-2025-24118) :  ![starts](https://img.shields.io/github/stars/jprx/CVE-2025-24118.svg) ![forks](https://img.shields.io/github/forks/jprx/CVE-2025-24118.svg)

- [https://github.com/rawtips/-CVE-2025-24118](https://github.com/rawtips/-CVE-2025-24118) :  ![starts](https://img.shields.io/github/stars/rawtips/-CVE-2025-24118.svg) ![forks](https://img.shields.io/github/forks/rawtips/-CVE-2025-24118.svg)

## CVE-2025-24104
 This issue was addressed with improved handling of symlinks. This issue is fixed in iPadOS 17.7.4, iOS 18.3 and iPadOS 18.3. Restoring a maliciously crafted backup file may lead to modification of protected system files.



- [https://github.com/ifpdz/CVE-2025-24104](https://github.com/ifpdz/CVE-2025-24104) :  ![starts](https://img.shields.io/github/stars/ifpdz/CVE-2025-24104.svg) ![forks](https://img.shields.io/github/forks/ifpdz/CVE-2025-24104.svg)

- [https://github.com/missaels235/POC-CVE-2025-24104-Py](https://github.com/missaels235/POC-CVE-2025-24104-Py) :  ![starts](https://img.shields.io/github/stars/missaels235/POC-CVE-2025-24104-Py.svg) ![forks](https://img.shields.io/github/forks/missaels235/POC-CVE-2025-24104-Py.svg)

## CVE-2025-24085
 A use after free issue was addressed with improved memory management. This issue is fixed in visionOS 2.3, iOS 18.3 and iPadOS 18.3, macOS Sequoia 15.3, watchOS 11.3, tvOS 18.3. A malicious application may be able to elevate privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 17.2.



- [https://github.com/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201](https://github.com/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201) :  ![starts](https://img.shields.io/github/stars/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201.svg) ![forks](https://img.shields.io/github/forks/JGoyd/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201.svg)

- [https://github.com/5ky9uy/glass-cage-i18-2025-24085-and-cve-2025-24201](https://github.com/5ky9uy/glass-cage-i18-2025-24085-and-cve-2025-24201) :  ![starts](https://img.shields.io/github/stars/5ky9uy/glass-cage-i18-2025-24085-and-cve-2025-24201.svg) ![forks](https://img.shields.io/github/forks/5ky9uy/glass-cage-i18-2025-24085-and-cve-2025-24201.svg)

## CVE-2025-24076
 Improper access control in Windows Cross Device Service allows an authorized attacker to elevate privileges locally.



- [https://github.com/mbanyamer/CVE-2025-24076](https://github.com/mbanyamer/CVE-2025-24076) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2025-24076.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2025-24076.svg)

## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.



- [https://github.com/0x6rss/CVE-2025-24071_PoC](https://github.com/0x6rss/CVE-2025-24071_PoC) :  ![starts](https://img.shields.io/github/stars/0x6rss/CVE-2025-24071_PoC.svg) ![forks](https://img.shields.io/github/forks/0x6rss/CVE-2025-24071_PoC.svg)

- [https://github.com/FOLKS-iwd/CVE-2025-24071-msfvenom](https://github.com/FOLKS-iwd/CVE-2025-24071-msfvenom) :  ![starts](https://img.shields.io/github/stars/FOLKS-iwd/CVE-2025-24071-msfvenom.svg) ![forks](https://img.shields.io/github/forks/FOLKS-iwd/CVE-2025-24071-msfvenom.svg)

- [https://github.com/ThemeHackers/CVE-2025-24071](https://github.com/ThemeHackers/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-24071.svg)

- [https://github.com/Marcejr117/CVE-2025-24071_PoC](https://github.com/Marcejr117/CVE-2025-24071_PoC) :  ![starts](https://img.shields.io/github/stars/Marcejr117/CVE-2025-24071_PoC.svg) ![forks](https://img.shields.io/github/forks/Marcejr117/CVE-2025-24071_PoC.svg)

- [https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC](https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC) :  ![starts](https://img.shields.io/github/stars/helidem/CVE-2025-24054_CVE-2025-24071-PoC.svg) ![forks](https://img.shields.io/github/forks/helidem/CVE-2025-24054_CVE-2025-24071-PoC.svg)

- [https://github.com/TH-SecForge/CVE-2025-24071](https://github.com/TH-SecForge/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/TH-SecForge/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/TH-SecForge/CVE-2025-24071.svg)

- [https://github.com/basekilll/CVE-2025-24054_PoC](https://github.com/basekilll/CVE-2025-24054_PoC) :  ![starts](https://img.shields.io/github/stars/basekilll/CVE-2025-24054_PoC.svg) ![forks](https://img.shields.io/github/forks/basekilll/CVE-2025-24054_PoC.svg)

- [https://github.com/shacojx/CVE-2025-24071-Exploit](https://github.com/shacojx/CVE-2025-24071-Exploit) :  ![starts](https://img.shields.io/github/stars/shacojx/CVE-2025-24071-Exploit.svg) ![forks](https://img.shields.io/github/forks/shacojx/CVE-2025-24071-Exploit.svg)

- [https://github.com/ctabango/CVE-2025-24071_PoCExtra](https://github.com/ctabango/CVE-2025-24071_PoCExtra) :  ![starts](https://img.shields.io/github/stars/ctabango/CVE-2025-24071_PoCExtra.svg) ![forks](https://img.shields.io/github/forks/ctabango/CVE-2025-24071_PoCExtra.svg)

- [https://github.com/LOOKY243/CVE-2025-24071-PoC](https://github.com/LOOKY243/CVE-2025-24071-PoC) :  ![starts](https://img.shields.io/github/stars/LOOKY243/CVE-2025-24071-PoC.svg) ![forks](https://img.shields.io/github/forks/LOOKY243/CVE-2025-24071-PoC.svg)

- [https://github.com/ex-cal1bur/SMB_CVE-2025-24071](https://github.com/ex-cal1bur/SMB_CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/ex-cal1bur/SMB_CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/ex-cal1bur/SMB_CVE-2025-24071.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-24071](https://github.com/B1ack4sh/Blackash-CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-24071.svg)

- [https://github.com/rubbxalc/CVE-2025-24071](https://github.com/rubbxalc/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/rubbxalc/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/rubbxalc/CVE-2025-24071.svg)

- [https://github.com/cesarbtakeda/Windows-Explorer-CVE-2025-24071](https://github.com/cesarbtakeda/Windows-Explorer-CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/cesarbtakeda/Windows-Explorer-CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/cesarbtakeda/Windows-Explorer-CVE-2025-24071.svg)

- [https://github.com/pswalia2u/CVE-2025-24071_POC](https://github.com/pswalia2u/CVE-2025-24071_POC) :  ![starts](https://img.shields.io/github/stars/pswalia2u/CVE-2025-24071_POC.svg) ![forks](https://img.shields.io/github/forks/pswalia2u/CVE-2025-24071_POC.svg)

- [https://github.com/f4dee-backup/CVE-2025-24071](https://github.com/f4dee-backup/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/f4dee-backup/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/f4dee-backup/CVE-2025-24071.svg)

- [https://github.com/AC8999/CVE-2025-24071](https://github.com/AC8999/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/AC8999/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/AC8999/CVE-2025-24071.svg)

- [https://github.com/Royall-Researchers/CVE-2025-24071](https://github.com/Royall-Researchers/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/Royall-Researchers/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/Royall-Researchers/CVE-2025-24071.svg)

- [https://github.com/aleongx/CVE-2025-24071](https://github.com/aleongx/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/aleongx/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/aleongx/CVE-2025-24071.svg)

- [https://github.com/DeshanFer94/CVE-2025-24071-POC-NTLMHashDisclosure-](https://github.com/DeshanFer94/CVE-2025-24071-POC-NTLMHashDisclosure-) :  ![starts](https://img.shields.io/github/stars/DeshanFer94/CVE-2025-24071-POC-NTLMHashDisclosure-.svg) ![forks](https://img.shields.io/github/forks/DeshanFer94/CVE-2025-24071-POC-NTLMHashDisclosure-.svg)

## CVE-2025-24054
 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.



- [https://github.com/rubenformation/CVE-2025-50154](https://github.com/rubenformation/CVE-2025-50154) :  ![starts](https://img.shields.io/github/stars/rubenformation/CVE-2025-50154.svg) ![forks](https://img.shields.io/github/forks/rubenformation/CVE-2025-50154.svg)

- [https://github.com/Marcejr117/CVE-2025-24071_PoC](https://github.com/Marcejr117/CVE-2025-24071_PoC) :  ![starts](https://img.shields.io/github/stars/Marcejr117/CVE-2025-24071_PoC.svg) ![forks](https://img.shields.io/github/forks/Marcejr117/CVE-2025-24071_PoC.svg)

- [https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC](https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC) :  ![starts](https://img.shields.io/github/stars/helidem/CVE-2025-24054_CVE-2025-24071-PoC.svg) ![forks](https://img.shields.io/github/forks/helidem/CVE-2025-24054_CVE-2025-24071-PoC.svg)

- [https://github.com/basekilll/CVE-2025-24054_PoC](https://github.com/basekilll/CVE-2025-24054_PoC) :  ![starts](https://img.shields.io/github/stars/basekilll/CVE-2025-24054_PoC.svg) ![forks](https://img.shields.io/github/forks/basekilll/CVE-2025-24054_PoC.svg)

- [https://github.com/Yuri08loveElaina/CVE-2025-24054_POC](https://github.com/Yuri08loveElaina/CVE-2025-24054_POC) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-24054_POC.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-24054_POC.svg)

- [https://github.com/moften/CVE-2025-24054](https://github.com/moften/CVE-2025-24054) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2025-24054.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2025-24054.svg)

- [https://github.com/S4mma3l/CVE-2025-24054](https://github.com/S4mma3l/CVE-2025-24054) :  ![starts](https://img.shields.io/github/stars/S4mma3l/CVE-2025-24054.svg) ![forks](https://img.shields.io/github/forks/S4mma3l/CVE-2025-24054.svg)

## CVE-2025-24035
 Sensitive data storage in improperly locked memory in Windows Remote Desktop Services allows an unauthorized attacker to execute code over a network.



- [https://github.com/MSeymenD/cve-2025-24035-rds-websocket-dos-test](https://github.com/MSeymenD/cve-2025-24035-rds-websocket-dos-test) :  ![starts](https://img.shields.io/github/stars/MSeymenD/cve-2025-24035-rds-websocket-dos-test.svg) ![forks](https://img.shields.io/github/forks/MSeymenD/cve-2025-24035-rds-websocket-dos-test.svg)

## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.



- [https://github.com/0xjessie21/CVE-2025-24016](https://github.com/0xjessie21/CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/0xjessie21/CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/0xjessie21/CVE-2025-24016.svg)

- [https://github.com/guinea-offensive-security/Wazuh-RCE](https://github.com/guinea-offensive-security/Wazuh-RCE) :  ![starts](https://img.shields.io/github/stars/guinea-offensive-security/Wazuh-RCE.svg) ![forks](https://img.shields.io/github/forks/guinea-offensive-security/Wazuh-RCE.svg)

- [https://github.com/MuhammadWaseem29/CVE-2025-24016](https://github.com/MuhammadWaseem29/CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-24016.svg)

- [https://github.com/rxerium/CVE-2025-24016](https://github.com/rxerium/CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-24016.svg)

- [https://github.com/huseyinstif/CVE-2025-24016-Nuclei-Template](https://github.com/huseyinstif/CVE-2025-24016-Nuclei-Template) :  ![starts](https://img.shields.io/github/stars/huseyinstif/CVE-2025-24016-Nuclei-Template.svg) ![forks](https://img.shields.io/github/forks/huseyinstif/CVE-2025-24016-Nuclei-Template.svg)

- [https://github.com/cybersecplayground/CVE-2025-24016-Wazuh-Remote-Code-Execution-RCE-PoC](https://github.com/cybersecplayground/CVE-2025-24016-Wazuh-Remote-Code-Execution-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/cybersecplayground/CVE-2025-24016-Wazuh-Remote-Code-Execution-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/cybersecplayground/CVE-2025-24016-Wazuh-Remote-Code-Execution-RCE-PoC.svg)

- [https://github.com/GloStarRx1/CVE-2025-24016](https://github.com/GloStarRx1/CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/GloStarRx1/CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/GloStarRx1/CVE-2025-24016.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-24016](https://github.com/B1ack4sh/Blackash-CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-24016.svg)

- [https://github.com/celsius026/poc_CVE-2025-24016](https://github.com/celsius026/poc_CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/celsius026/poc_CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/celsius026/poc_CVE-2025-24016.svg)

## CVE-2025-24011
 Umbraco is a free and open source .NET content management system. Starting in version 14.0.0 and prior to versions 14.3.2 and 15.1.2, it's possible to determine whether an account exists based on an analysis of response codes and timing of Umbraco management API responses. Versions 14.3.2 and 15.1.2 contain a patch. No known workarounds are available.



- [https://github.com/Puben/CVE-2025-24011-PoC](https://github.com/Puben/CVE-2025-24011-PoC) :  ![starts](https://img.shields.io/github/stars/Puben/CVE-2025-24011-PoC.svg) ![forks](https://img.shields.io/github/forks/Puben/CVE-2025-24011-PoC.svg)

## CVE-2025-23968
 Unrestricted Upload of File with Dangerous Type vulnerability in WPCenter AiBud WP allows Upload a Web Shell to a Web Server.This issue affects AiBud WP: from n/a through 1.8.5.



- [https://github.com/d0n601/CVE-2025-23968](https://github.com/d0n601/CVE-2025-23968) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-23968.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-23968.svg)

## CVE-2025-23942
 Unrestricted Upload of File with Dangerous Type vulnerability in NgocCode WP Load Gallery allows Upload a Web Shell to a Web Server. This issue affects WP Load Gallery: from n/a through 2.1.6.



- [https://github.com/Nxploited/CVE-2025-23942-poc](https://github.com/Nxploited/CVE-2025-23942-poc) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-23942-poc.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-23942-poc.svg)

## CVE-2025-23922
 Cross-Site Request Forgery (CSRF) vulnerability in Harsh iSpring Embedder allows Upload a Web Shell to a Web Server.This issue affects iSpring Embedder: from n/a through 1.0.



- [https://github.com/Nxploited/CVE-2025-23922](https://github.com/Nxploited/CVE-2025-23922) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-23922.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-23922.svg)

## CVE-2025-23369
 An improper verification of cryptographic signature vulnerability was identified in GitHub Enterprise Server that allowed signature spoofing for unauthorized internal users.  Instances not utilizing SAML single sign-on or where the attacker is not already an existing user were not impacted. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.12.14, 3.13.10, 3.14.7, 3.15.2, and 3.16.0. This vulnerability was reported via the GitHub Bug Bounty program.



- [https://github.com/hakivvi/CVE-2025-23369](https://github.com/hakivvi/CVE-2025-23369) :  ![starts](https://img.shields.io/github/stars/hakivvi/CVE-2025-23369.svg) ![forks](https://img.shields.io/github/forks/hakivvi/CVE-2025-23369.svg)

- [https://github.com/Arian91/CVE-2025-23369_SAML_bypass](https://github.com/Arian91/CVE-2025-23369_SAML_bypass) :  ![starts](https://img.shields.io/github/stars/Arian91/CVE-2025-23369_SAML_bypass.svg) ![forks](https://img.shields.io/github/forks/Arian91/CVE-2025-23369_SAML_bypass.svg)

## CVE-2025-23320
 NVIDIA Triton Inference Server for Windows and Linux contains a vulnerability in the Python backend, where an attacker could cause the shared memory limit to be exceeded by sending a very large request. A successful exploit of this vulnerability might lead to information disclosure.



- [https://github.com/There-was-a-bird/triton-cve-2025-23320](https://github.com/There-was-a-bird/triton-cve-2025-23320) :  ![starts](https://img.shields.io/github/stars/There-was-a-bird/triton-cve-2025-23320.svg) ![forks](https://img.shields.io/github/forks/There-was-a-bird/triton-cve-2025-23320.svg)

## CVE-2025-23266
 NVIDIA Container Toolkit for all platforms contains a vulnerability in some hooks used to initialize the container, where an attacker could execute arbitrary code with elevated permissions. A successful exploit of this vulnerability might lead to escalation of privileges, data tampering, information disclosure, and denial of service.



- [https://github.com/jpts/cve-2025-23266-poc](https://github.com/jpts/cve-2025-23266-poc) :  ![starts](https://img.shields.io/github/stars/jpts/cve-2025-23266-poc.svg) ![forks](https://img.shields.io/github/forks/jpts/cve-2025-23266-poc.svg)

- [https://github.com/Mindasy/cve-2025-23266-migration-bypass](https://github.com/Mindasy/cve-2025-23266-migration-bypass) :  ![starts](https://img.shields.io/github/stars/Mindasy/cve-2025-23266-migration-bypass.svg) ![forks](https://img.shields.io/github/forks/Mindasy/cve-2025-23266-migration-bypass.svg)

- [https://github.com/mrk336/CVE-2025-23266](https://github.com/mrk336/CVE-2025-23266) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2025-23266.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2025-23266.svg)

- [https://github.com/r0binak/CVE-2025-23266](https://github.com/r0binak/CVE-2025-23266) :  ![starts](https://img.shields.io/github/stars/r0binak/CVE-2025-23266.svg) ![forks](https://img.shields.io/github/forks/r0binak/CVE-2025-23266.svg)

## CVE-2025-23245
 NVIDIA vGPU software for Windows and Linux contains a vulnerability in the Virtual GPU Manager (vGPU plugin), where it allows a guest to access global resources. A successful exploit of this vulnerability might lead to denial of service.



- [https://github.com/cydragLINUX/CVE-2025-23245655](https://github.com/cydragLINUX/CVE-2025-23245655) :  ![starts](https://img.shields.io/github/stars/cydragLINUX/CVE-2025-23245655.svg) ![forks](https://img.shields.io/github/forks/cydragLINUX/CVE-2025-23245655.svg)

## CVE-2025-23167
 A flaw in Node.js 20's HTTP parser allows improper termination of HTTP/1 headers using `\r\n\rX` instead of the required `\r\n\r\n`.
This inconsistency enables request smuggling, allowing attackers to bypass proxy-based access controls and submit unauthorized requests.

The issue was resolved by upgrading `llhttp` to version 9, which enforces correct header termination.

Impact:
* This vulnerability affects only Node.js 20.x users prior to the `llhttp` v9 upgrade.



- [https://github.com/abhisek3122/CVE-2025-23167](https://github.com/abhisek3122/CVE-2025-23167) :  ![starts](https://img.shields.io/github/stars/abhisek3122/CVE-2025-23167.svg) ![forks](https://img.shields.io/github/forks/abhisek3122/CVE-2025-23167.svg)

## CVE-2025-23165
 In Node.js, the `ReadFileUtf8` internal binding leaks memory due to a corrupted pointer in `uv_fs_s.file`: a UTF-16 path buffer is allocated but subsequently overwritten when the file descriptor is set. This results in an unrecoverable memory leak on every call. Repeated use can cause unbounded memory growth, leading to a denial of service.

Impact:
* This vulnerability affects APIs relying on `ReadFileUtf8` on Node.js release lines: v20 and v22.



- [https://github.com/mrk336/ElkStack-Secured-From-Logs-to-CVEs](https://github.com/mrk336/ElkStack-Secured-From-Logs-to-CVEs) :  ![starts](https://img.shields.io/github/stars/mrk336/ElkStack-Secured-From-Logs-to-CVEs.svg) ![forks](https://img.shields.io/github/forks/mrk336/ElkStack-Secured-From-Logs-to-CVEs.svg)

## CVE-2025-23048
 In some mod_ssl configurations on Apache HTTP Server 2.4.35 through to 2.4.63, an access control bypass by trusted clients is possible using TLS 1.3 session resumption.

Configurations are affected when mod_ssl is configured for multiple virtual hosts, with each restricted to a different set of trusted client certificates (for example with a different SSLCACertificateFile/Path setting). In such a case, a client trusted to access one virtual host may be able to access another virtual host, if SSLStrictSNIVHostCheck is not enabled in either virtual host.



- [https://github.com/absholi7ly/CVE-2025-23048-POC](https://github.com/absholi7ly/CVE-2025-23048-POC) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2025-23048-POC.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2025-23048-POC.svg)

## CVE-2025-23040
 GitHub Desktop is an open-source Electron-based GitHub app designed for git development. An attacker convincing a user to clone a repository directly or through a submodule can allow the attacker access to the user's credentials through the use of maliciously crafted remote URL. GitHub Desktop relies on Git to perform all network related operations (such as cloning, fetching, and pushing). When a user attempts to clone a repository GitHub Desktop will invoke `git clone` and when Git encounters a remote which requires authentication it will request the credentials for that remote host from GitHub Desktop using the git-credential protocol. Using a maliciously crafted URL it's possible to cause the credential request coming from Git to be misinterpreted by Github Desktop such that it will send credentials for a different host than the host that Git is currently communicating with thereby allowing for secret exfiltration. GitHub username and OAuth token, or credentials for other Git remote hosts stored in GitHub Desktop could be improperly transmitted to an unrelated host. Users should update to GitHub Desktop 3.4.12 or greater which fixes this vulnerability. Users who suspect they may be affected should revoke any relevant credentials.



- [https://github.com/GabrieleDattile/CVE-2025-23040](https://github.com/GabrieleDattile/CVE-2025-23040) :  ![starts](https://img.shields.io/github/stars/GabrieleDattile/CVE-2025-23040.svg) ![forks](https://img.shields.io/github/forks/GabrieleDattile/CVE-2025-23040.svg)

## CVE-2025-22968
 An issue in D-Link DWR-M972V 1.05SSG allows a remote attacker to execute arbitrary code via SSH using root account without restrictions



- [https://github.com/CRUNZEX/CVE-2025-22968](https://github.com/CRUNZEX/CVE-2025-22968) :  ![starts](https://img.shields.io/github/stars/CRUNZEX/CVE-2025-22968.svg) ![forks](https://img.shields.io/github/forks/CRUNZEX/CVE-2025-22968.svg)

## CVE-2025-22964
 DDSN Interactive cm3 Acora CMS version 10.1.1 has an unauthenticated time-based blind SQL Injection vulnerability caused by insufficient input sanitization and validation in the "table" parameter. This flaw allows attackers to inject malicious SQL queries by directly incorporating user-supplied input into database queries without proper escaping or validation. Exploiting this issue enables unauthorized access, manipulation of data, or exposure of sensitive information, posing significant risks to the integrity and confidentiality of the application.



- [https://github.com/padayali-JD/CVE-2025-22964](https://github.com/padayali-JD/CVE-2025-22964) :  ![starts](https://img.shields.io/github/stars/padayali-JD/CVE-2025-22964.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/CVE-2025-22964.svg)

## CVE-2025-22963
 Teedy through 1.11 allows CSRF for account takeover via POST /api/user/admin.



- [https://github.com/samplev45/CVE-2025-22963](https://github.com/samplev45/CVE-2025-22963) :  ![starts](https://img.shields.io/github/stars/samplev45/CVE-2025-22963.svg) ![forks](https://img.shields.io/github/forks/samplev45/CVE-2025-22963.svg)

- [https://github.com/gmh5225/CVE-2025-22963](https://github.com/gmh5225/CVE-2025-22963) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2025-22963.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2025-22963.svg)

## CVE-2025-22954
 GetLateOrMissingIssues in C4/Serials.pm in Koha before 24.11.02 allows SQL Injection in /serials/lateissues-export.pl via the supplierid or serialid parameter.



- [https://github.com/RandomRobbieBF/CVE-2025-22954](https://github.com/RandomRobbieBF/CVE-2025-22954) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-22954.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-22954.svg)

## CVE-2025-22953
 A SQL injection vulnerability exists in Epicor HCM 2021 1.9, with patches available: 5.16.0.1033/HCM2022, 5.17.0.1146/HCM2023, and 5.18.0.573/HCM2024. The injection is specifically in the filter parameter of the JsonFetcher.svc endpoint. An attacker can exploit this vulnerability by injecting malicious SQL payloads into the filter parameter, enabling the unauthorized execution of arbitrary SQL commands on the backend database. If certain features (like xp_cmdshell) are enabled, this may lead to remote code execution.



- [https://github.com/maliktawfiq/CVE-2025-22953](https://github.com/maliktawfiq/CVE-2025-22953) :  ![starts](https://img.shields.io/github/stars/maliktawfiq/CVE-2025-22953.svg) ![forks](https://img.shields.io/github/forks/maliktawfiq/CVE-2025-22953.svg)

## CVE-2025-22912
 RE11S v1.11 was discovered to contain a command injection vulnerability via the component /goform/formAccept.



- [https://github.com/passwa11/RE11S_1.11-formAccept-CommandInjection](https://github.com/passwa11/RE11S_1.11-formAccept-CommandInjection) :  ![starts](https://img.shields.io/github/stars/passwa11/RE11S_1.11-formAccept-CommandInjection.svg) ![forks](https://img.shields.io/github/forks/passwa11/RE11S_1.11-formAccept-CommandInjection.svg)

## CVE-2025-22870
 Matching of hosts against proxy patterns can improperly treat an IPv6 zone ID as a hostname component. For example, when the NO_PROXY environment variable is set to "*.example.com", a request to "[::1%25.example.com]:80` will incorrectly match and not be proxied.



- [https://github.com/JoshuaProvoste/CVE-2025-22870](https://github.com/JoshuaProvoste/CVE-2025-22870) :  ![starts](https://img.shields.io/github/stars/JoshuaProvoste/CVE-2025-22870.svg) ![forks](https://img.shields.io/github/forks/JoshuaProvoste/CVE-2025-22870.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-22870](https://github.com/B1ack4sh/Blackash-CVE-2025-22870) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-22870.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-22870.svg)

## CVE-2025-22828
 CloudStack users can add and read comments (annotations) on resources they are authorised to access. 

Due to an access validation issue that affects Apache CloudStack versions from 4.16.0, users who have access, prior access or knowledge of resource UUIDs can list and add comments (annotations) to such resources. 

An attacker with a user-account and access or prior knowledge of resource UUIDs may exploit this issue to read contents of the comments (annotations) or add malicious comments (annotations) to such resources. 

This may cause potential loss of confidentiality of CloudStack environments and resources if the comments (annotations) contain any privileged information. However, guessing or brute-forcing resource UUIDs are generally hard to impossible and access to listing or adding comments isn't same as access to CloudStack resources, making this issue of very low severity and general low impact.


CloudStack admins may also disallow listAnnotations and addAnnotation API access to non-admin roles in their environment as an interim measure.



- [https://github.com/Stolichnayer/CVE-2025-22828](https://github.com/Stolichnayer/CVE-2025-22828) :  ![starts](https://img.shields.io/github/stars/Stolichnayer/CVE-2025-22828.svg) ![forks](https://img.shields.io/github/forks/Stolichnayer/CVE-2025-22828.svg)

## CVE-2025-22785
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ComMotion Course Booking System allows SQL Injection.This issue affects Course Booking System: from n/a through 6.0.5.



- [https://github.com/RandomRobbieBF/CVE-2025-22785](https://github.com/RandomRobbieBF/CVE-2025-22785) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-22785.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-22785.svg)

## CVE-2025-22783
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in SEO Squirrly SEO Plugin by Squirrly SEO allows SQL Injection.This issue affects SEO Plugin by Squirrly SEO: from n/a through 12.4.03.



- [https://github.com/DoTTak/CVE-2025-22783](https://github.com/DoTTak/CVE-2025-22783) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22783.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22783.svg)

## CVE-2025-22777
 Deserialization of Untrusted Data vulnerability in GiveWP GiveWP allows Object Injection.This issue affects GiveWP: from n/a through 3.19.3.



- [https://github.com/RandomRobbieBF/CVE-2025-22777](https://github.com/RandomRobbieBF/CVE-2025-22777) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-22777.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-22777.svg)

## CVE-2025-22710
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in StoreApps Smart Manager allows Blind SQL Injection. This issue affects Smart Manager: from n/a through 8.52.0.



- [https://github.com/DoTTak/CVE-2025-22710](https://github.com/DoTTak/CVE-2025-22710) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22710.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22710.svg)

## CVE-2025-22652
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in kendysond Payment Forms for Paystack allows SQL Injection.This issue affects Payment Forms for Paystack: from n/a through 4.0.1.



- [https://github.com/DoTTak/CVE-2025-22652](https://github.com/DoTTak/CVE-2025-22652) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22652.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22652.svg)

## CVE-2025-22620
 gitoxide is an implementation of git written in Rust. Prior to 0.17.0, gix-worktree-state specifies 0777 permissions when checking out executable files, intending that the umask will restrict them appropriately. But one of the strategies it uses to set permissions is not subject to the umask. This causes files in a repository to be world-writable in some situations. This vulnerability is fixed in 0.17.0.



- [https://github.com/EliahKagan/checkout-index](https://github.com/EliahKagan/checkout-index) :  ![starts](https://img.shields.io/github/stars/EliahKagan/checkout-index.svg) ![forks](https://img.shields.io/github/forks/EliahKagan/checkout-index.svg)

## CVE-2025-22604
 Cacti is an open source performance and fault management framework. Due to a flaw in multi-line SNMP result parser, authenticated users can inject malformed OIDs in the response. When processed by ss_net_snmp_disk_io() or ss_net_snmp_disk_bytes(), a part of each OID will be used as a key in an array that is used as part of a system command, causing a command execution vulnerability. This vulnerability is fixed in 1.2.29.



- [https://github.com/ishwardeepp/CVE-2025-22604-Cacti-RCE](https://github.com/ishwardeepp/CVE-2025-22604-Cacti-RCE) :  ![starts](https://img.shields.io/github/stars/ishwardeepp/CVE-2025-22604-Cacti-RCE.svg) ![forks](https://img.shields.io/github/forks/ishwardeepp/CVE-2025-22604-Cacti-RCE.svg)

## CVE-2025-22510
 Deserialization of Untrusted Data vulnerability in Konrad Karpieszuk WC Price History for Omnibus allows Object Injection.This issue affects WC Price History for Omnibus: from n/a through 2.1.4.



- [https://github.com/DoTTak/CVE-2025-22510](https://github.com/DoTTak/CVE-2025-22510) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22510.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22510.svg)

## CVE-2025-22457
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.6, Ivanti Policy Secure before version 22.7R1.4, and Ivanti ZTA Gateways before version 22.8R2.2 allows a remote unauthenticated attacker to achieve remote code execution.



- [https://github.com/sfewer-r7/CVE-2025-22457](https://github.com/sfewer-r7/CVE-2025-22457) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2025-22457.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2025-22457.svg)

- [https://github.com/securekomodo/CVE-2025-22457](https://github.com/securekomodo/CVE-2025-22457) :  ![starts](https://img.shields.io/github/stars/securekomodo/CVE-2025-22457.svg) ![forks](https://img.shields.io/github/forks/securekomodo/CVE-2025-22457.svg)

- [https://github.com/Vinylrider/ivantiunlocker](https://github.com/Vinylrider/ivantiunlocker) :  ![starts](https://img.shields.io/github/stars/Vinylrider/ivantiunlocker.svg) ![forks](https://img.shields.io/github/forks/Vinylrider/ivantiunlocker.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-22457](https://github.com/B1ack4sh/Blackash-CVE-2025-22457) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-22457.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-22457.svg)

- [https://github.com/TRone-ux/CVE-2025-22457](https://github.com/TRone-ux/CVE-2025-22457) :  ![starts](https://img.shields.io/github/stars/TRone-ux/CVE-2025-22457.svg) ![forks](https://img.shields.io/github/forks/TRone-ux/CVE-2025-22457.svg)

## CVE-2025-22441
 In getContextForResourcesEnsuringCorrectCachedApkPaths of RemoteViews.java, there is a possible way to load arbitrary java code in a privileged context due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.



- [https://github.com/michalbednarski/ResourcePoison](https://github.com/michalbednarski/ResourcePoison) :  ![starts](https://img.shields.io/github/stars/michalbednarski/ResourcePoison.svg) ![forks](https://img.shields.io/github/forks/michalbednarski/ResourcePoison.svg)

## CVE-2025-22352
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ELEXtensions ELEX WooCommerce Advanced Bulk Edit Products, Prices & Attributes allows Blind SQL Injection.This issue affects ELEX WooCommerce Advanced Bulk Edit Products, Prices & Attributes: from n/a through 1.4.8.



- [https://github.com/DoTTak/CVE-2025-22352](https://github.com/DoTTak/CVE-2025-22352) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22352.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22352.svg)

## CVE-2025-22294
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Gravity Master Custom Field For WP Job Manager allows Reflected XSS.This issue affects Custom Field For WP Job Manager: from n/a through 1.3.



- [https://github.com/mirmeweu/cve-2025-22294](https://github.com/mirmeweu/cve-2025-22294) :  ![starts](https://img.shields.io/github/stars/mirmeweu/cve-2025-22294.svg) ![forks](https://img.shields.io/github/forks/mirmeweu/cve-2025-22294.svg)

## CVE-2025-22235
 EndpointRequest.to() creates a matcher for null/** if the actuator endpoint, for which the EndpointRequest has been created, is disabled or not exposed.

Your application may be affected by this if all the following conditions are met:

  *  You use Spring Security
  *  EndpointRequest.to() has been used in a Spring Security chain configuration
  *  The endpoint which EndpointRequest references is disabled or not exposed via web
  *  Your application handles requests to /null and this path needs protection


You are not affected if any of the following is true:

  *  You don't use Spring Security
  *  You don't use EndpointRequest.to()
  *  The endpoint which EndpointRequest.to() refers to is enabled and is exposed
  *  Your application does not handle requests to /null or this path does not need protection



- [https://github.com/idealzh/cve-2025-22235-demo](https://github.com/idealzh/cve-2025-22235-demo) :  ![starts](https://img.shields.io/github/stars/idealzh/cve-2025-22235-demo.svg) ![forks](https://img.shields.io/github/forks/idealzh/cve-2025-22235-demo.svg)

## CVE-2025-22223
 Spring Security 6.4.0 - 6.4.3 may not correctly locate method security annotations on parameterized types or methods. This may cause an authorization bypass. 

You are not affected if you are not using @EnableMethodSecurity, or
you do not have method security annotations on parameterized types or methods, or all method security annotations are attached to target methods



- [https://github.com/1ucky7/cve-2025-22223-demo-1.0.0](https://github.com/1ucky7/cve-2025-22223-demo-1.0.0) :  ![starts](https://img.shields.io/github/stars/1ucky7/cve-2025-22223-demo-1.0.0.svg) ![forks](https://img.shields.io/github/forks/1ucky7/cve-2025-22223-demo-1.0.0.svg)

## CVE-2025-22167
 This High severity Path Traversal (Arbitrary Write) vulnerability was introduced in versions: 9.12.0, 10.3.0 and remain present in 11.0.0 of Jira Software Data Center and Server. This Path Traversal (Arbitrary Write) vulnerability, with a CVSS Score of 8.7, allows an attacker to modify any filesystem path writable by the Jira JVM process. Atlassian recommends that Jira Software Data Center and Server customers upgrade to the latest version; if you are unable to do so, upgrade your instance to one of the specified supported fixed versions:
 Jira Software Data Center and Server 9.12: Upgrade to a release greater than or equal to 9.12.28
 Jira Software Data Center and Server 10.3: Upgrade to a release greater than or equal to 10.3.12
 Jira Software Data Center and Server 11.0: Upgrade to a release greater than or equal to 11.1.0

See the release notes. You can download the latest version of Jira Software Data Center and Server from the download center. This vulnerability was reported via our Atlassian (Internal) program.



- [https://github.com/issamjr/CVE-2025-22167](https://github.com/issamjr/CVE-2025-22167) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-22167.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-22167.svg)

## CVE-2025-22131
 PhpSpreadsheet is a PHP library for reading and writing spreadsheet files. Cross-Site Scripting (XSS) vulnerability in the code which translates the XLSX file into a HTML representation and displays it in the response.



- [https://github.com/s0ck37/CVE-2025-22131-POC](https://github.com/s0ck37/CVE-2025-22131-POC) :  ![starts](https://img.shields.io/github/stars/s0ck37/CVE-2025-22131-POC.svg) ![forks](https://img.shields.io/github/forks/s0ck37/CVE-2025-22131-POC.svg)

- [https://github.com/ZzN1NJ4/CVE-2025-22131-PoC](https://github.com/ZzN1NJ4/CVE-2025-22131-PoC) :  ![starts](https://img.shields.io/github/stars/ZzN1NJ4/CVE-2025-22131-PoC.svg) ![forks](https://img.shields.io/github/forks/ZzN1NJ4/CVE-2025-22131-PoC.svg)

## CVE-2025-21756
 In the Linux kernel, the following vulnerability has been resolved:

vsock: Keep the binding until socket destruction

Preserve sockets bindings; this includes both resulting from an explicit
bind() and those implicitly bound through autobind during connect().

Prevents socket unbinding during a transport reassignment, which fixes a
use-after-free:

    1. vsock_create() (refcnt=1) calls vsock_insert_unbound() (refcnt=2)
    2. transport-release() calls vsock_remove_bound() without checking if
       sk was bound and moved to bound list (refcnt=1)
    3. vsock_bind() assumes sk is in unbound list and before
       __vsock_insert_bound(vsock_bound_sockets()) calls
       __vsock_remove_bound() which does:
           list_del_init(&vsk-bound_table); // nop
           sock_put(&vsk-sk);               // refcnt=0

BUG: KASAN: slab-use-after-free in __vsock_bind+0x62e/0x730
Read of size 4 at addr ffff88816b46a74c by task a.out/2057
 dump_stack_lvl+0x68/0x90
 print_report+0x174/0x4f6
 kasan_report+0xb9/0x190
 __vsock_bind+0x62e/0x730
 vsock_bind+0x97/0xe0
 __sys_bind+0x154/0x1f0
 __x64_sys_bind+0x6e/0xb0
 do_syscall_64+0x93/0x1b0
 entry_SYSCALL_64_after_hwframe+0x76/0x7e

Allocated by task 2057:
 kasan_save_stack+0x1e/0x40
 kasan_save_track+0x10/0x30
 __kasan_slab_alloc+0x85/0x90
 kmem_cache_alloc_noprof+0x131/0x450
 sk_prot_alloc+0x5b/0x220
 sk_alloc+0x2c/0x870
 __vsock_create.constprop.0+0x2e/0xb60
 vsock_create+0xe4/0x420
 __sock_create+0x241/0x650
 __sys_socket+0xf2/0x1a0
 __x64_sys_socket+0x6e/0xb0
 do_syscall_64+0x93/0x1b0
 entry_SYSCALL_64_after_hwframe+0x76/0x7e

Freed by task 2057:
 kasan_save_stack+0x1e/0x40
 kasan_save_track+0x10/0x30
 kasan_save_free_info+0x37/0x60
 __kasan_slab_free+0x4b/0x70
 kmem_cache_free+0x1a1/0x590
 __sk_destruct+0x388/0x5a0
 __vsock_bind+0x5e1/0x730
 vsock_bind+0x97/0xe0
 __sys_bind+0x154/0x1f0
 __x64_sys_bind+0x6e/0xb0
 do_syscall_64+0x93/0x1b0
 entry_SYSCALL_64_after_hwframe+0x76/0x7e

refcount_t: addition on 0; use-after-free.
WARNING: CPU: 7 PID: 2057 at lib/refcount.c:25 refcount_warn_saturate+0xce/0x150
RIP: 0010:refcount_warn_saturate+0xce/0x150
 __vsock_bind+0x66d/0x730
 vsock_bind+0x97/0xe0
 __sys_bind+0x154/0x1f0
 __x64_sys_bind+0x6e/0xb0
 do_syscall_64+0x93/0x1b0
 entry_SYSCALL_64_after_hwframe+0x76/0x7e

refcount_t: underflow; use-after-free.
WARNING: CPU: 7 PID: 2057 at lib/refcount.c:28 refcount_warn_saturate+0xee/0x150
RIP: 0010:refcount_warn_saturate+0xee/0x150
 vsock_remove_bound+0x187/0x1e0
 __vsock_release+0x383/0x4a0
 vsock_release+0x90/0x120
 __sock_release+0xa3/0x250
 sock_close+0x14/0x20
 __fput+0x359/0xa80
 task_work_run+0x107/0x1d0
 do_exit+0x847/0x2560
 do_group_exit+0xb8/0x250
 __x64_sys_exit_group+0x3a/0x50
 x64_sys_call+0xfec/0x14f0
 do_syscall_64+0x93/0x1b0
 entry_SYSCALL_64_after_hwframe+0x76/0x7e



- [https://github.com/hoefler02/CVE-2025-21756](https://github.com/hoefler02/CVE-2025-21756) :  ![starts](https://img.shields.io/github/stars/hoefler02/CVE-2025-21756.svg) ![forks](https://img.shields.io/github/forks/hoefler02/CVE-2025-21756.svg)

- [https://github.com/khoatran107/cve-2025-21756](https://github.com/khoatran107/cve-2025-21756) :  ![starts](https://img.shields.io/github/stars/khoatran107/cve-2025-21756.svg) ![forks](https://img.shields.io/github/forks/khoatran107/cve-2025-21756.svg)

- [https://github.com/KuanKuanQAQ/cve-testing](https://github.com/KuanKuanQAQ/cve-testing) :  ![starts](https://img.shields.io/github/stars/KuanKuanQAQ/cve-testing.svg) ![forks](https://img.shields.io/github/forks/KuanKuanQAQ/cve-testing.svg)

## CVE-2025-21692
 In the Linux kernel, the following vulnerability has been resolved:

net: sched: fix ets qdisc OOB Indexing

Haowei Yan g1042620637@gmail.com found that ets_class_from_arg() can
index an Out-Of-Bound class in ets_class_from_arg() when passed clid of
0. The overflow may cause local privilege escalation.

 [   18.852298] ------------[ cut here ]------------
 [   18.853271] UBSAN: array-index-out-of-bounds in net/sched/sch_ets.c:93:20
 [   18.853743] index 18446744073709551615 is out of range for type 'ets_class [16]'
 [   18.854254] CPU: 0 UID: 0 PID: 1275 Comm: poc Not tainted 6.12.6-dirty #17
 [   18.854821] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
 [   18.856532] Call Trace:
 [   18.857441]  TASK
 [   18.858227]  dump_stack_lvl+0xc2/0xf0
 [   18.859607]  dump_stack+0x10/0x20
 [   18.860908]  __ubsan_handle_out_of_bounds+0xa7/0xf0
 [   18.864022]  ets_class_change+0x3d6/0x3f0
 [   18.864322]  tc_ctl_tclass+0x251/0x910
 [   18.864587]  ? lock_acquire+0x5e/0x140
 [   18.865113]  ? __mutex_lock+0x9c/0xe70
 [   18.866009]  ? __mutex_lock+0xa34/0xe70
 [   18.866401]  rtnetlink_rcv_msg+0x170/0x6f0
 [   18.866806]  ? __lock_acquire+0x578/0xc10
 [   18.867184]  ? __pfx_rtnetlink_rcv_msg+0x10/0x10
 [   18.867503]  netlink_rcv_skb+0x59/0x110
 [   18.867776]  rtnetlink_rcv+0x15/0x30
 [   18.868159]  netlink_unicast+0x1c3/0x2b0
 [   18.868440]  netlink_sendmsg+0x239/0x4b0
 [   18.868721]  ____sys_sendmsg+0x3e2/0x410
 [   18.869012]  ___sys_sendmsg+0x88/0xe0
 [   18.869276]  ? rseq_ip_fixup+0x198/0x260
 [   18.869563]  ? rseq_update_cpu_node_id+0x10a/0x190
 [   18.869900]  ? trace_hardirqs_off+0x5a/0xd0
 [   18.870196]  ? syscall_exit_to_user_mode+0xcc/0x220
 [   18.870547]  ? do_syscall_64+0x93/0x150
 [   18.870821]  ? __memcg_slab_free_hook+0x69/0x290
 [   18.871157]  __sys_sendmsg+0x69/0xd0
 [   18.871416]  __x64_sys_sendmsg+0x1d/0x30
 [   18.871699]  x64_sys_call+0x9e2/0x2670
 [   18.871979]  do_syscall_64+0x87/0x150
 [   18.873280]  ? do_syscall_64+0x93/0x150
 [   18.874742]  ? lock_release+0x7b/0x160
 [   18.876157]  ? do_user_addr_fault+0x5ce/0x8f0
 [   18.877833]  ? irqentry_exit_to_user_mode+0xc2/0x210
 [   18.879608]  ? irqentry_exit+0x77/0xb0
 [   18.879808]  ? clear_bhb_loop+0x15/0x70
 [   18.880023]  ? clear_bhb_loop+0x15/0x70
 [   18.880223]  ? clear_bhb_loop+0x15/0x70
 [   18.880426]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
 [   18.880683] RIP: 0033:0x44a957
 [   18.880851] Code: ff ff e8 fc 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 66 90 f3 0f 1e fa 64 8b 04 25 18 00 00 00 85 c0 75 10 b8 2e 00 00 00 0f 05 48 3d 00 f0 ff ff 77 51 c3 48 83 ec 28 89 54 24 1c 48 8974 24 10
 [   18.881766] RSP: 002b:00007ffcdd00fad8 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
 [   18.882149] RAX: ffffffffffffffda RBX: 00007ffcdd010db8 RCX: 000000000044a957
 [   18.882507] RDX: 0000000000000000 RSI: 00007ffcdd00fb70 RDI: 0000000000000003
 [   18.885037] RBP: 00007ffcdd010bc0 R08: 000000000703c770 R09: 000000000703c7c0
 [   18.887203] R10: 0000000000000080 R11: 0000000000000246 R12: 0000000000000001
 [   18.888026] R13: 00007ffcdd010da8 R14: 00000000004ca7d0 R15: 0000000000000001
 [   18.888395]  /TASK
 [   18.888610] ---[ end trace ]---



- [https://github.com/volticks/CVE-2025-21692-poc](https://github.com/volticks/CVE-2025-21692-poc) :  ![starts](https://img.shields.io/github/stars/volticks/CVE-2025-21692-poc.svg) ![forks](https://img.shields.io/github/forks/volticks/CVE-2025-21692-poc.svg)

## CVE-2025-21574
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Parser).  Supported versions that are affected are 8.0.0-8.0.41, 8.4.0-8.4.4 and  9.0.0-9.2.0. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/mdriaz009/CVE-2025-21574-Exploit](https://github.com/mdriaz009/CVE-2025-21574-Exploit) :  ![starts](https://img.shields.io/github/stars/mdriaz009/CVE-2025-21574-Exploit.svg) ![forks](https://img.shields.io/github/forks/mdriaz009/CVE-2025-21574-Exploit.svg)

## CVE-2025-21497
 Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB).  Supported versions that are affected are 8.0.40 and prior, 8.4.3 and prior and  9.1.0 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server as well as  unauthorized update, insert or delete access to some of MySQL Server accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H).



- [https://github.com/Urbank-61/cve-2025-21497-lab](https://github.com/Urbank-61/cve-2025-21497-lab) :  ![starts](https://img.shields.io/github/stars/Urbank-61/cve-2025-21497-lab.svg) ![forks](https://img.shields.io/github/forks/Urbank-61/cve-2025-21497-lab.svg)

## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.



- [https://github.com/zhuowei/cheese](https://github.com/zhuowei/cheese) :  ![starts](https://img.shields.io/github/stars/zhuowei/cheese.svg) ![forks](https://img.shields.io/github/forks/zhuowei/cheese.svg)

## CVE-2025-21420
 Windows Disk Cleanup Tool Elevation of Privilege Vulnerability



- [https://github.com/Network-Sec/CVE-2025-21420-PoC](https://github.com/Network-Sec/CVE-2025-21420-PoC) :  ![starts](https://img.shields.io/github/stars/Network-Sec/CVE-2025-21420-PoC.svg) ![forks](https://img.shields.io/github/forks/Network-Sec/CVE-2025-21420-PoC.svg)

- [https://github.com/moiz-2x/CVE-2025-21420_POC](https://github.com/moiz-2x/CVE-2025-21420_POC) :  ![starts](https://img.shields.io/github/stars/moiz-2x/CVE-2025-21420_POC.svg) ![forks](https://img.shields.io/github/forks/moiz-2x/CVE-2025-21420_POC.svg)

- [https://github.com/toxy4ny/edge-maradeur](https://github.com/toxy4ny/edge-maradeur) :  ![starts](https://img.shields.io/github/stars/toxy4ny/edge-maradeur.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/edge-maradeur.svg)

## CVE-2025-21401
 Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability



- [https://github.com/toxy4ny/edge-maradeur](https://github.com/toxy4ny/edge-maradeur) :  ![starts](https://img.shields.io/github/stars/toxy4ny/edge-maradeur.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/edge-maradeur.svg)

## CVE-2025-21385
 A Server-Side Request Forgery (SSRF) vulnerability in Microsoft Purview allows an authorized attacker to disclose information over a network.



- [https://github.com/Pauloxc6/CVE-2025-21385](https://github.com/Pauloxc6/CVE-2025-21385) :  ![starts](https://img.shields.io/github/stars/Pauloxc6/CVE-2025-21385.svg) ![forks](https://img.shields.io/github/forks/Pauloxc6/CVE-2025-21385.svg)

## CVE-2025-21333
 Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability



- [https://github.com/MrAle98/CVE-2025-21333-POC](https://github.com/MrAle98/CVE-2025-21333-POC) :  ![starts](https://img.shields.io/github/stars/MrAle98/CVE-2025-21333-POC.svg) ![forks](https://img.shields.io/github/forks/MrAle98/CVE-2025-21333-POC.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-21333](https://github.com/B1ack4sh/Blackash-CVE-2025-21333) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-21333.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-21333.svg)

- [https://github.com/aleongx/KQL_sentinel_CVE-2025-21333](https://github.com/aleongx/KQL_sentinel_CVE-2025-21333) :  ![starts](https://img.shields.io/github/stars/aleongx/KQL_sentinel_CVE-2025-21333.svg) ![forks](https://img.shields.io/github/forks/aleongx/KQL_sentinel_CVE-2025-21333.svg)

## CVE-2025-21298
 Windows OLE Remote Code Execution Vulnerability



- [https://github.com/ynwarcs/CVE-2025-21298](https://github.com/ynwarcs/CVE-2025-21298) :  ![starts](https://img.shields.io/github/stars/ynwarcs/CVE-2025-21298.svg) ![forks](https://img.shields.io/github/forks/ynwarcs/CVE-2025-21298.svg)

- [https://github.com/Dit-Developers/CVE-2025-21298](https://github.com/Dit-Developers/CVE-2025-21298) :  ![starts](https://img.shields.io/github/stars/Dit-Developers/CVE-2025-21298.svg) ![forks](https://img.shields.io/github/forks/Dit-Developers/CVE-2025-21298.svg)

- [https://github.com/Denyningbow/rtf-ctf-cve-2025-21298](https://github.com/Denyningbow/rtf-ctf-cve-2025-21298) :  ![starts](https://img.shields.io/github/stars/Denyningbow/rtf-ctf-cve-2025-21298.svg) ![forks](https://img.shields.io/github/forks/Denyningbow/rtf-ctf-cve-2025-21298.svg)

- [https://github.com/fy-poc/full-poc-CVE-2025_21298](https://github.com/fy-poc/full-poc-CVE-2025_21298) :  ![starts](https://img.shields.io/github/stars/fy-poc/full-poc-CVE-2025_21298.svg) ![forks](https://img.shields.io/github/forks/fy-poc/full-poc-CVE-2025_21298.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-21298](https://github.com/B1ack4sh/Blackash-CVE-2025-21298) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-21298.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-21298.svg)

- [https://github.com/Arkha-Corvus/LetsDefend-SOC336-Windows-OLE-Zero-Click-RCE-Exploitation-Detected-CVE-2025-21298-](https://github.com/Arkha-Corvus/LetsDefend-SOC336-Windows-OLE-Zero-Click-RCE-Exploitation-Detected-CVE-2025-21298-) :  ![starts](https://img.shields.io/github/stars/Arkha-Corvus/LetsDefend-SOC336-Windows-OLE-Zero-Click-RCE-Exploitation-Detected-CVE-2025-21298-.svg) ![forks](https://img.shields.io/github/forks/Arkha-Corvus/LetsDefend-SOC336-Windows-OLE-Zero-Click-RCE-Exploitation-Detected-CVE-2025-21298-.svg)

## CVE-2025-21293
 Active Directory Domain Services Elevation of Privilege Vulnerability



- [https://github.com/ahmedumarehman/CVE-2025-21293](https://github.com/ahmedumarehman/CVE-2025-21293) :  ![starts](https://img.shields.io/github/stars/ahmedumarehman/CVE-2025-21293.svg) ![forks](https://img.shields.io/github/forks/ahmedumarehman/CVE-2025-21293.svg)

## CVE-2025-21204
 Improper link resolution before file access ('link following') in Windows Update Stack allows an authorized attacker to elevate privileges locally.



- [https://github.com/mmotti/Reset-inetpub](https://github.com/mmotti/Reset-inetpub) :  ![starts](https://img.shields.io/github/stars/mmotti/Reset-inetpub.svg) ![forks](https://img.shields.io/github/forks/mmotti/Reset-inetpub.svg)

## CVE-2025-20352
 A vulnerability in the Simple Network Management Protocol (SNMP) subsystem of Cisco IOS Software and Cisco IOS XE Software could allow the following:
  An authenticated, remote attacker with low privileges could cause a denial of service (DoS) condition on an affected device that is running Cisco IOS Software or Cisco IOS XE Software. To cause the DoS, the attacker must have the SNMPv2c or earlier read-only community string or valid SNMPv3 user credentials.  An authenticated, remote attacker with high privileges could execute code as the root user on an affected device that is running Cisco IOS XE Software. To execute code as the root user, the attacker must have the SNMPv1 or v2c read-only community string or valid SNMPv3 user credentials and administrative or privilege 15 credentials on the affected device.   An attacker could exploit this vulnerability by sending a crafted SNMP packet to an affected device over IPv4 or IPv6 networks. 
 This vulnerability is due to a stack overflow condition in the SNMP subsystem of the affected software. A successful exploit could allow a low-privileged attacker to cause the affected system to reload, resulting in a DoS condition, or allow a high-privileged attacker to execute arbitrary code as the root user and obtain full control of the affected system.
 Note: This vulnerability affects all versions of SNMP.



- [https://github.com/scadastrangelove/CVE-2025-20352](https://github.com/scadastrangelove/CVE-2025-20352) :  ![starts](https://img.shields.io/github/stars/scadastrangelove/CVE-2025-20352.svg) ![forks](https://img.shields.io/github/forks/scadastrangelove/CVE-2025-20352.svg)

## CVE-2025-20282
 A vulnerability in an internal API of Cisco ISE and Cisco ISE-PIC could allow an unauthenticated, remote attacker to upload arbitrary files to an affected device and then execute those files on the underlying operating system as root.

This vulnerability is due a lack of file validation checks that would prevent uploaded files from being placed in privileged directories on an affected system. An attacker could exploit this vulnerability by uploading a crafted file to the affected device. A successful exploit could allow the attacker to store malicious files on the affected system and then execute arbitrary code or obtain root privileges on the system.



- [https://github.com/skadevare/CiscoISE-CVE-2025-20282-POC](https://github.com/skadevare/CiscoISE-CVE-2025-20282-POC) :  ![starts](https://img.shields.io/github/stars/skadevare/CiscoISE-CVE-2025-20282-POC.svg) ![forks](https://img.shields.io/github/forks/skadevare/CiscoISE-CVE-2025-20282-POC.svg)

## CVE-2025-20281
 A vulnerability in a specific API of Cisco ISE and Cisco ISE-PIC could allow an unauthenticated, remote attacker to execute arbitrary code on the underlying operating system as root. The attacker does not require any valid credentials to exploit this vulnerability.

This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by submitting a crafted API request. A successful exploit could allow the attacker to obtain root privileges on an affected device.



- [https://github.com/abrewer251/CVE-2025-20281-2-Cisco-ISE-RCE](https://github.com/abrewer251/CVE-2025-20281-2-Cisco-ISE-RCE) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-20281-2-Cisco-ISE-RCE.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-20281-2-Cisco-ISE-RCE.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-20281](https://github.com/B1ack4sh/Blackash-CVE-2025-20281) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-20281.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-20281.svg)

- [https://github.com/grupooruss/CVE-2025-20281-Cisco](https://github.com/grupooruss/CVE-2025-20281-Cisco) :  ![starts](https://img.shields.io/github/stars/grupooruss/CVE-2025-20281-Cisco.svg) ![forks](https://img.shields.io/github/forks/grupooruss/CVE-2025-20281-Cisco.svg)

- [https://github.com/ill-deed/Cisco-CVE-2025-20281-illdeed](https://github.com/ill-deed/Cisco-CVE-2025-20281-illdeed) :  ![starts](https://img.shields.io/github/stars/ill-deed/Cisco-CVE-2025-20281-illdeed.svg) ![forks](https://img.shields.io/github/forks/ill-deed/Cisco-CVE-2025-20281-illdeed.svg)

## CVE-2025-20265
 A vulnerability in the RADIUS subsystem implementation of Cisco Secure Firewall Management Center (FMC) Software could allow an unauthenticated, remote attacker to inject arbitrary shell commands that are executed by the device.&nbsp;

This vulnerability is due to a lack of proper handling of user input during the authentication phase. An attacker could exploit this vulnerability by sending crafted input when entering credentials that will be authenticated at the configured RADIUS server. A successful exploit could allow the attacker to execute commands at a high&nbsp;privilege level.
Note: For this vulnerability to be exploited, Cisco Secure FMC Software must be configured for RADIUS authentication for the web-based management interface, SSH management, or both.



- [https://github.com/jordan922/cve2025-20265](https://github.com/jordan922/cve2025-20265) :  ![starts](https://img.shields.io/github/stars/jordan922/cve2025-20265.svg) ![forks](https://img.shields.io/github/forks/jordan922/cve2025-20265.svg)

- [https://github.com/saruman9/cve_2025_20265](https://github.com/saruman9/cve_2025_20265) :  ![starts](https://img.shields.io/github/stars/saruman9/cve_2025_20265.svg) ![forks](https://img.shields.io/github/forks/saruman9/cve_2025_20265.svg)

- [https://github.com/amalpvatayam67/day08-CISCO-fmc-sim](https://github.com/amalpvatayam67/day08-CISCO-fmc-sim) :  ![starts](https://img.shields.io/github/stars/amalpvatayam67/day08-CISCO-fmc-sim.svg) ![forks](https://img.shields.io/github/forks/amalpvatayam67/day08-CISCO-fmc-sim.svg)

## CVE-2025-20125
 A vulnerability in an API of Cisco ISE could allow an authenticated, remote attacker with valid read-only credentials to obtain sensitive information, change node configurations, and restart the node.

This vulnerability is due to a lack of authorization in a specific API and improper validation of user-supplied data. An attacker could exploit this vulnerability by sending a crafted HTTP request to a specific API on the device. A successful exploit could allow the attacker to attacker to obtain information, modify system configuration, and reload the device.
Note:&nbsp;To successfully exploit this vulnerability, the attacker must have valid read-only administrative credentials. In a single-node deployment, new devices will not be able to authenticate during the reload time.



- [https://github.com/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125](https://github.com/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125.svg)

## CVE-2025-20124
 A vulnerability in an API of Cisco ISE could allow an authenticated, remote attacker to execute arbitrary commands as the root user on an affected device.

This vulnerability is due to insecure deserialization of user-supplied Java byte streams by the affected software. An attacker could exploit this vulnerability by sending a crafted serialized Java object to an affected API. A successful exploit could allow the attacker to execute arbitrary commands on the device and elevate privileges.
Note:&nbsp;To successfully exploit this vulnerability, the attacker must have valid read-only administrative credentials. In a single-node deployment, new devices will not be able to authenticate during the reload time.



- [https://github.com/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125](https://github.com/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-20124_and_CVE-2025-20125.svg)

- [https://github.com/137f/Cisco-ISE-3.0---Remote-Code-Execution-RCE-](https://github.com/137f/Cisco-ISE-3.0---Remote-Code-Execution-RCE-) :  ![starts](https://img.shields.io/github/stars/137f/Cisco-ISE-3.0---Remote-Code-Execution-RCE-.svg) ![forks](https://img.shields.io/github/forks/137f/Cisco-ISE-3.0---Remote-Code-Execution-RCE-.svg)

## CVE-2025-20029
 Command injection vulnerability exists in iControl REST and BIG-IP TMOS Shell (tmsh) save command, which may allow an authenticated attacker to execute arbitrary system commands.

 


Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/mbadanoiu/CVE-2025-20029](https://github.com/mbadanoiu/CVE-2025-20029) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2025-20029.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2025-20029.svg)

- [https://github.com/schoi1337/CVE-2025-20029-simulation](https://github.com/schoi1337/CVE-2025-20029-simulation) :  ![starts](https://img.shields.io/github/stars/schoi1337/CVE-2025-20029-simulation.svg) ![forks](https://img.shields.io/github/forks/schoi1337/CVE-2025-20029-simulation.svg)

## CVE-2025-11833
 The Post SMTP – Complete SMTP Solution with Logs, Alerts, Backup SMTP & Mobile App plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the __construct function in all versions up to, and including, 3.6.0. This makes it possible for unauthenticated attackers to read arbitrary logged emails sent through the Post SMTP plugin, including password reset emails containing password reset links, which can lead to account takeover.



- [https://github.com/modhopmarrow1973/CVE-2025-11833-LAB](https://github.com/modhopmarrow1973/CVE-2025-11833-LAB) :  ![starts](https://img.shields.io/github/stars/modhopmarrow1973/CVE-2025-11833-LAB.svg) ![forks](https://img.shields.io/github/forks/modhopmarrow1973/CVE-2025-11833-LAB.svg)

## CVE-2025-11832
 Allocation of Resources Without Limits or Throttling vulnerability in Azure Access Technology BLU-IC2, Azure Access Technology BLU-IC4 allows Flooding.This issue affects BLU-IC2: through 1.19.5; BLU-IC4: through 1.19.5.



- [https://github.com/blackhatlegend/CVE-2025-11832](https://github.com/blackhatlegend/CVE-2025-11832) :  ![starts](https://img.shields.io/github/stars/blackhatlegend/CVE-2025-11832.svg) ![forks](https://img.shields.io/github/forks/blackhatlegend/CVE-2025-11832.svg)

## CVE-2025-11579
 github.com/nwaples/rardecode versions =2.1.1 fail to restrict the dictionary size when reading large RAR dictionary sizes, which allows an attacker to provide a specially crafted RAR file and cause Denial of Service via an Out Of Memory Crash.



- [https://github.com/shinigami-777/PoC_CVE-2025-11579](https://github.com/shinigami-777/PoC_CVE-2025-11579) :  ![starts](https://img.shields.io/github/stars/shinigami-777/PoC_CVE-2025-11579.svg) ![forks](https://img.shields.io/github/forks/shinigami-777/PoC_CVE-2025-11579.svg)

## CVE-2025-11554
 A security vulnerability has been detected in Portabilis i-Educar up to 2.9.10. Affected by this issue is some unknown functionality of the file app/Http/Controllers/AccessLevelController.php of the component User Type Handler. The manipulation leads to insecure inherited permissions. The attack may be initiated remotely. The exploit has been disclosed publicly and may be used.



- [https://github.com/m3m0o/portabilis-ieducar-user-type-privilege-escalation](https://github.com/m3m0o/portabilis-ieducar-user-type-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/m3m0o/portabilis-ieducar-user-type-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/m3m0o/portabilis-ieducar-user-type-privilege-escalation.svg)

## CVE-2025-11499
 The Tablesome Table – Contact Form DB – WPForms, CF7, Gravity, Forminator, Fluent plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the set_featured_image_from_external_url() function in all versions up to, and including, 1.1.32. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible in configurations where unauthenticated users have been provided with a method for adding featured images, and the workflow trigger is created.



- [https://github.com/Hazelooks/CVE-2025-11499-Exploit](https://github.com/Hazelooks/CVE-2025-11499-Exploit) :  ![starts](https://img.shields.io/github/stars/Hazelooks/CVE-2025-11499-Exploit.svg) ![forks](https://img.shields.io/github/forks/Hazelooks/CVE-2025-11499-Exploit.svg)

- [https://github.com/rootreapers/CVE-2025-11499](https://github.com/rootreapers/CVE-2025-11499) :  ![starts](https://img.shields.io/github/stars/rootreapers/CVE-2025-11499.svg) ![forks](https://img.shields.io/github/forks/rootreapers/CVE-2025-11499.svg)

- [https://github.com/usjnx72726w/CVE-2025-11499-LAB](https://github.com/usjnx72726w/CVE-2025-11499-LAB) :  ![starts](https://img.shields.io/github/stars/usjnx72726w/CVE-2025-11499-LAB.svg) ![forks](https://img.shields.io/github/forks/usjnx72726w/CVE-2025-11499-LAB.svg)

## CVE-2025-11450
 ServiceNow has addressed a reflected cross-site scripting vulnerability that was identified in the ServiceNow AI Platform. This vulnerability could result in arbitrary code being executed within the browsers of ServiceNow users who click on a specially crafted link.  

ServiceNow has addressed this vulnerability by deploying a relevant security update to the majority of hosted instances.  Relevant security updates also have been provided to ServiceNow self-hosted customers, partners, and hosted customers with unique configurations. Further, the vulnerability is addressed in the listed patches and hot fixes. We recommend customers promptly apply appropriate updates or upgrade if they have not already done so.



- [https://github.com/DanielMadsenDK/ServiceNow-CVE-2025-11449-CVE-2025-11450-Mitigation-Script](https://github.com/DanielMadsenDK/ServiceNow-CVE-2025-11449-CVE-2025-11450-Mitigation-Script) :  ![starts](https://img.shields.io/github/stars/DanielMadsenDK/ServiceNow-CVE-2025-11449-CVE-2025-11450-Mitigation-Script.svg) ![forks](https://img.shields.io/github/forks/DanielMadsenDK/ServiceNow-CVE-2025-11449-CVE-2025-11450-Mitigation-Script.svg)

## CVE-2025-11449
 ServiceNow has addressed a reflected cross-site scripting vulnerability that was identified in the ServiceNow AI Platform. This vulnerability could result in arbitrary code being executed within the browsers of ServiceNow users who click on a specially crafted link.   





ServiceNow has addressed this vulnerability by deploying a relevant security update to the majority of hosted instances.  Relevant security updates also have been provided to ServiceNow self-hosted customers, partners, and hosted customers with unique configuration. Further, the vulnerability is addressed in the listed patches and hot fixes. We recommend customers promptly apply appropriate updates or upgrade if they have not already done so.



- [https://github.com/DanielMadsenDK/ServiceNow-CVE-2025-11449-CVE-2025-11450-Mitigation-Script](https://github.com/DanielMadsenDK/ServiceNow-CVE-2025-11449-CVE-2025-11450-Mitigation-Script) :  ![starts](https://img.shields.io/github/stars/DanielMadsenDK/ServiceNow-CVE-2025-11449-CVE-2025-11450-Mitigation-Script.svg) ![forks](https://img.shields.io/github/forks/DanielMadsenDK/ServiceNow-CVE-2025-11449-CVE-2025-11450-Mitigation-Script.svg)

## CVE-2025-11391
 The PPOM – Product Addons & Custom Fields for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the image cropper functionality in all versions up to, and including, 33.0.15. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. While the vulnerable code is in the free version, this only affected users with the paid version of the software installed and activated.



- [https://github.com/aritlhq/CVE-2025-11391](https://github.com/aritlhq/CVE-2025-11391) :  ![starts](https://img.shields.io/github/stars/aritlhq/CVE-2025-11391.svg) ![forks](https://img.shields.io/github/forks/aritlhq/CVE-2025-11391.svg)

## CVE-2025-11371
 In the default installation and configuration of Gladinet CentreStack and TrioFox, there is an unauthenticated Local File Inclusion Flaw that allows unintended disclosure of system files. Exploitation of this vulnerability has been observed in the wild. 

This issue impacts Gladinet CentreStack and Triofox: All versions prior to and including 16.7.10368.56560



- [https://github.com/rxerium/CVE-2025-11371](https://github.com/rxerium/CVE-2025-11371) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-11371.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-11371.svg)

- [https://github.com/NetVanguard-cmd/CVE-2025-11371](https://github.com/NetVanguard-cmd/CVE-2025-11371) :  ![starts](https://img.shields.io/github/stars/NetVanguard-cmd/CVE-2025-11371.svg) ![forks](https://img.shields.io/github/forks/NetVanguard-cmd/CVE-2025-11371.svg)

- [https://github.com/lap1nou/CVE-2025-11371](https://github.com/lap1nou/CVE-2025-11371) :  ![starts](https://img.shields.io/github/stars/lap1nou/CVE-2025-11371.svg) ![forks](https://img.shields.io/github/forks/lap1nou/CVE-2025-11371.svg)

## CVE-2025-11171
 The Chartify – WordPress Chart Plugin for WordPress is vulnerable to Missing Authentication for Critical Function in all versions up to, and including, 3.5.9. This is due to the plugin registering an unauthenticated AJAX action that dispatches to admin-class methods based on a request parameter, without any nonce or capability checks. This makes it possible for unauthenticated attackers to execute administrative functions via the wp-admin/admin-ajax.php endpoint granted they can identify callable method names.



- [https://github.com/SnailSploit/CVE-2025-11171---GitHub-Security-Advisory](https://github.com/SnailSploit/CVE-2025-11171---GitHub-Security-Advisory) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2025-11171---GitHub-Security-Advisory.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2025-11171---GitHub-Security-Advisory.svg)

## CVE-2025-11077
 A vulnerability was determined in Campcodes Online Learning Management System 1.0. Affected is an unknown function of the file /admin/add_content.php. Executing manipulation of the argument Title can lead to sql injection. The attack can be executed remotely. The exploit has been publicly disclosed and may be utilized.



- [https://github.com/byteReaper77/CVE-2025-11077](https://github.com/byteReaper77/CVE-2025-11077) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-11077.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-11077.svg)

## CVE-2025-10874
 The Orbit Fox: Duplicate Page, Menu Icons, SVG Support, Cookie Notice, Custom Fonts & More WordPress plugin before 3.0.2 does not limit URLs which may be used for the stock photo import feature, allowing the user to specify arbitrary URLs. This leads to a server-side request forgery as the user may force the server to access any URL of their choosing.



- [https://github.com/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874](https://github.com/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874) :  ![starts](https://img.shields.io/github/stars/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874.svg) ![forks](https://img.shields.io/github/forks/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874.svg)

## CVE-2025-10742
 The Truelysell Core plugin for WordPress is vulnerable to Arbitrary User Password Change in versions up to, and including, 1.8.6. This is due to the plugin providing user-controlled access to objects, letting a user bypass authorization and access system resources. This makes it possible for unauthenticated attackers to change user passwords and potentially take over administrator accounts. Note: This can only be exploited unauthenticated if the attacker knows which page contains the 'truelysell_edit_staff' shortcode.



- [https://github.com/netspecters/CVE-2025-10742](https://github.com/netspecters/CVE-2025-10742) :  ![starts](https://img.shields.io/github/stars/netspecters/CVE-2025-10742.svg) ![forks](https://img.shields.io/github/forks/netspecters/CVE-2025-10742.svg)

## CVE-2025-10720
 The WP Private Content Plus through 3.6.2 provides a global content protection feature that requires a password. However, the access control check is based only on the presence of an unprotected client-side cookie. As a result, an unauthenticated attacker can completely bypass the password protection by manually setting the cookie value in their browser.



- [https://github.com/lorenzocamilli/CVE-2025-10720-PoC](https://github.com/lorenzocamilli/CVE-2025-10720-PoC) :  ![starts](https://img.shields.io/github/stars/lorenzocamilli/CVE-2025-10720-PoC.svg) ![forks](https://img.shields.io/github/forks/lorenzocamilli/CVE-2025-10720-PoC.svg)

## CVE-2025-10585
 Type confusion in V8 in Google Chrome prior to 140.0.7339.185 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/AdityaBhatt3010/CVE-2025-10585-The-Chrome-V8-Zero-Day](https://github.com/AdityaBhatt3010/CVE-2025-10585-The-Chrome-V8-Zero-Day) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-10585-The-Chrome-V8-Zero-Day.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-10585-The-Chrome-V8-Zero-Day.svg)

## CVE-2025-10377
 The System Dashboard plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 2.8.20. This is due to missing nonce validation on the sd_toggle_logs() function. This makes it possible for unauthenticated attackers to toggle critical logging settings including Page Access Logs, Error Logs, and Email Delivery Logs via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/NagisaYumaa/CVE-2025-10377](https://github.com/NagisaYumaa/CVE-2025-10377) :  ![starts](https://img.shields.io/github/stars/NagisaYumaa/CVE-2025-10377.svg) ![forks](https://img.shields.io/github/forks/NagisaYumaa/CVE-2025-10377.svg)

## CVE-2025-10353
 File upload leading to remote code execution (RCE) in the “melis-cms-slider” module of Melis Technology's Melis Platform. This vulnerability allows an attacker to upload a malicious file via a POST request to '/melis/MelisCmsSlider/MelisCmsSliderDetails/saveDetailsForm' using the 'mcsdetail_img' parameter.



- [https://github.com/ivansmc00/CVE-2025-10353-POC](https://github.com/ivansmc00/CVE-2025-10353-POC) :  ![starts](https://img.shields.io/github/stars/ivansmc00/CVE-2025-10353-POC.svg) ![forks](https://img.shields.io/github/forks/ivansmc00/CVE-2025-10353-POC.svg)

## CVE-2025-10352
 Vulnerability in the melis-core module of Melis Technology's Melis Platform, which, if exploited, allows an unauthenticated attacker to create an administrator account via a request to '/melis/MelisCore/ToolUser/addNewUser'.



- [https://github.com/ivansmc00/CVE-2025-10352-POC](https://github.com/ivansmc00/CVE-2025-10352-POC) :  ![starts](https://img.shields.io/github/stars/ivansmc00/CVE-2025-10352-POC.svg) ![forks](https://img.shields.io/github/forks/ivansmc00/CVE-2025-10352-POC.svg)

## CVE-2025-10351
 SQL injection vulnerability based on the melis-cms module of the Melis platform from Melis Technology. This vulnerability allows an attacker to retrieve, create, update, and delete databases through the 'idPage' parameter in the '/melis/MelisCms/PageEdition/getTinyTemplates' endpoint.



- [https://github.com/ivansmc00/CVE-2025-10351-POC](https://github.com/ivansmc00/CVE-2025-10351-POC) :  ![starts](https://img.shields.io/github/stars/ivansmc00/CVE-2025-10351-POC.svg) ![forks](https://img.shields.io/github/forks/ivansmc00/CVE-2025-10351-POC.svg)

## CVE-2025-10184
 The vulnerability allows any application installed on the device to read SMS/MMS data and metadata from the system-provided Telephony provider without permission, user interaction, or consent. The user is also not notified that SMS data is being accessed. This could lead to sensitive information disclosure and could effectively break the security provided by SMS-based Multi-Factor Authentication (MFA) checks. 

The root cause is a combination of missing permissions for write operations in several content providers (com.android.providers.telephony.PushMessageProvider, com.android.providers.telephony.PushShopProvider, com.android.providers.telephony.ServiceNumberProvider), and a blind SQL injection in the update method of those providers.



- [https://github.com/yuuouu/ColorOS-CVE-2025-10184](https://github.com/yuuouu/ColorOS-CVE-2025-10184) :  ![starts](https://img.shields.io/github/stars/yuuouu/ColorOS-CVE-2025-10184.svg) ![forks](https://img.shields.io/github/forks/yuuouu/ColorOS-CVE-2025-10184.svg)

- [https://github.com/People-11/CVE-2025-10184_PoC](https://github.com/People-11/CVE-2025-10184_PoC) :  ![starts](https://img.shields.io/github/stars/People-11/CVE-2025-10184_PoC.svg) ![forks](https://img.shields.io/github/forks/People-11/CVE-2025-10184_PoC.svg)

- [https://github.com/Webpage-gh/CVE-2025-10184-PoC](https://github.com/Webpage-gh/CVE-2025-10184-PoC) :  ![starts](https://img.shields.io/github/stars/Webpage-gh/CVE-2025-10184-PoC.svg) ![forks](https://img.shields.io/github/forks/Webpage-gh/CVE-2025-10184-PoC.svg)

## CVE-2025-10175
 The WP Links Page plugin for WordPress is vulnerable to SQL Injection via the 'id' parameter in all versions up to, and including, 4.9.6 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with Subscriber-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.



- [https://github.com/MooseLoveti/WP-Links-Page-CVE-Report](https://github.com/MooseLoveti/WP-Links-Page-CVE-Report) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/WP-Links-Page-CVE-Report.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/WP-Links-Page-CVE-Report.svg)

## CVE-2025-10142
 The PagBank / PagSeguro Connect para WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'status' parameter in all versions up to, and including, 4.44.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with Shop Manager-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.



- [https://github.com/MooseLoveti/PagSeguro-Connect-Para-WooCommerce-CVE-Report](https://github.com/MooseLoveti/PagSeguro-Connect-Para-WooCommerce-CVE-Report) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/PagSeguro-Connect-Para-WooCommerce-CVE-Report.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/PagSeguro-Connect-Para-WooCommerce-CVE-Report.svg)

## CVE-2025-10046
 The ELEX WooCommerce Google Shopping (Google Product Feed) plugin for WordPress is vulnerable to SQL Injection via the 'file_to_delete' parameter in all versions up to, and including, 1.4.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with Administrator-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.



- [https://github.com/byteReaper77/CVE-2025-10046](https://github.com/byteReaper77/CVE-2025-10046) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-10046.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-10046.svg)

## CVE-2025-10041
 The Flex QR Code Generator plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in thesave_qr_code_to_db() function in all versions up to, and including, 1.2.5. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2025-10041](https://github.com/Nxploited/CVE-2025-10041) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-10041.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-10041.svg)

- [https://github.com/Kai-One001/WordPress-Flex-QR-Code-Generator---CVE-2025-10041](https://github.com/Kai-One001/WordPress-Flex-QR-Code-Generator---CVE-2025-10041) :  ![starts](https://img.shields.io/github/stars/Kai-One001/WordPress-Flex-QR-Code-Generator---CVE-2025-10041.svg) ![forks](https://img.shields.io/github/forks/Kai-One001/WordPress-Flex-QR-Code-Generator---CVE-2025-10041.svg)

## CVE-2025-10035
 A deserialization vulnerability in the License Servlet of Fortra's GoAnywhere MFT allows an actor with a validly forged license response signature to deserialize an arbitrary actor-controlled object, possibly leading to command injection.



- [https://github.com/rxerium/CVE-2025-10035](https://github.com/rxerium/CVE-2025-10035) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-10035.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-10035.svg)

- [https://github.com/ThemeHackers/CVE-2025-10035](https://github.com/ThemeHackers/CVE-2025-10035) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-10035.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-10035.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-10035](https://github.com/B1ack4sh/Blackash-CVE-2025-10035) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-10035.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-10035.svg)

- [https://github.com/orange0Mint/CVE-2025-10035_GoAnywhere](https://github.com/orange0Mint/CVE-2025-10035_GoAnywhere) :  ![starts](https://img.shields.io/github/stars/orange0Mint/CVE-2025-10035_GoAnywhere.svg) ![forks](https://img.shields.io/github/forks/orange0Mint/CVE-2025-10035_GoAnywhere.svg)

## CVE-2025-9998
 The sequence of packets received by a Networking server are not correctly checked.

An attacker could exploit this vulnerability to send specially crafted messages to force the application to stop.



- [https://github.com/balajigund/Research-on-CVE-2025-9998](https://github.com/balajigund/Research-on-CVE-2025-9998) :  ![starts](https://img.shields.io/github/stars/balajigund/Research-on-CVE-2025-9998.svg) ![forks](https://img.shields.io/github/forks/balajigund/Research-on-CVE-2025-9998.svg)

## CVE-2025-9983
 GALAYOU G2 cameras stream video output via RTSP streams. By default these streams are protected by randomly generated credentials. However these credentials are not required to access the stream. Changing these values does not change camera's behavior.

The vendor did not respond in any way. Only version 11.100001.01.28 was tested, other versions might also be vulnerable.



- [https://github.com/sohaibeb/CVE-2025-9983](https://github.com/sohaibeb/CVE-2025-9983) :  ![starts](https://img.shields.io/github/stars/sohaibeb/CVE-2025-9983.svg) ![forks](https://img.shields.io/github/forks/sohaibeb/CVE-2025-9983.svg)

## CVE-2025-9967
 The Orion SMS OTP Verification plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 1.1.7. This is due to the plugin not properly validating a user's identity prior to updating their password. This makes it possible for unauthenticated attackers to change arbitrary user's password to a one-time password if the attacker knows the user's phone number



- [https://github.com/glitchhawks/CVE-2025-9967](https://github.com/glitchhawks/CVE-2025-9967) :  ![starts](https://img.shields.io/github/stars/glitchhawks/CVE-2025-9967.svg) ![forks](https://img.shields.io/github/forks/glitchhawks/CVE-2025-9967.svg)

## CVE-2025-9952
 The Trinity Audio – Text to Speech AI audio player to convert content into audio plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the 'range-date' parameter in all versions up to, and including, 5.20.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.



- [https://github.com/MooseLoveti/Trinity-Audio-CVE-Report2](https://github.com/MooseLoveti/Trinity-Audio-CVE-Report2) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/Trinity-Audio-CVE-Report2.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/Trinity-Audio-CVE-Report2.svg)

## CVE-2025-9886
 The Trinity Audio – Text to Speech AI audio player to convert content into audio plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 5.20.2. This is due to missing or incorrect nonce validation in the '/admin/inc/post-management.php' file. This makes it possible for unauthenticated attackers to activate/deactivate posts via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/MooseLoveti/Trinity-Audio-CVE-Report2](https://github.com/MooseLoveti/Trinity-Audio-CVE-Report2) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/Trinity-Audio-CVE-Report2.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/Trinity-Audio-CVE-Report2.svg)

## CVE-2025-9784
 A flaw was found in Undertow where malformed client requests can trigger server-side stream resets without triggering abuse counters. This issue, referred to as the "MadeYouReset" attack, allows malicious clients to induce excessive server workload by repeatedly causing server-side stream aborts. While not a protocol bug, this highlights a common implementation weakness that can be exploited to cause a denial of service (DoS).



- [https://github.com/drackyjr/CVE-2025-9784](https://github.com/drackyjr/CVE-2025-9784) :  ![starts](https://img.shields.io/github/stars/drackyjr/CVE-2025-9784.svg) ![forks](https://img.shields.io/github/forks/drackyjr/CVE-2025-9784.svg)

## CVE-2025-9776
 The CatFolders – Tame Your WordPress Media Library by Category plugin for WordPress is vulnerable to time-based SQL Injection via the CSV Import contents in all versions up to, and including, 2.5.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with Author-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.



- [https://github.com/SnailSploit/CVE-2025-9776](https://github.com/SnailSploit/CVE-2025-9776) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2025-9776.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2025-9776.svg)

## CVE-2025-9744
 A weakness has been identified in Campcodes Online Loan Management System 1.0. The affected element is an unknown function of the file /ajax.php?action=login. Executing manipulation of the argument Username can lead to sql injection. The attack can be launched remotely. The exploit has been made available to the public and could be exploited.



- [https://github.com/godfatherofexps/CVE-2025-9744-PoC](https://github.com/godfatherofexps/CVE-2025-9744-PoC) :  ![starts](https://img.shields.io/github/stars/godfatherofexps/CVE-2025-9744-PoC.svg) ![forks](https://img.shields.io/github/forks/godfatherofexps/CVE-2025-9744-PoC.svg)

## CVE-2025-9728
 A security vulnerability has been detected in givanz Vvveb 1.0.7.2. This affects an unknown part of the file app/template/user/login.tpl. Such manipulation of the argument Email/Password leads to cross site scripting. The attack can be executed remotely. The name of the patch is bbd4c42c66ab818142240348173a669d1d2537fe. Applying a patch is advised to resolve this issue.



- [https://github.com/kwerty138/Reflected-XSS-in-Vvveb-CMS-v1.0.7.2](https://github.com/kwerty138/Reflected-XSS-in-Vvveb-CMS-v1.0.7.2) :  ![starts](https://img.shields.io/github/stars/kwerty138/Reflected-XSS-in-Vvveb-CMS-v1.0.7.2.svg) ![forks](https://img.shields.io/github/forks/kwerty138/Reflected-XSS-in-Vvveb-CMS-v1.0.7.2.svg)

## CVE-2025-9519
 The Easy Timer plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.2.1 via the plugin's shortcodes. This is due to insufficient restriction of shortcode attributes. This makes it possible for authenticated attackers, with Editor-level access and above, to execute code on the server.



- [https://github.com/Nimisha17/Poc-CVE-2025-9519](https://github.com/Nimisha17/Poc-CVE-2025-9519) :  ![starts](https://img.shields.io/github/stars/Nimisha17/Poc-CVE-2025-9519.svg) ![forks](https://img.shields.io/github/forks/Nimisha17/Poc-CVE-2025-9519.svg)

- [https://github.com/coramarcet/WordPressCVEExploitProject](https://github.com/coramarcet/WordPressCVEExploitProject) :  ![starts](https://img.shields.io/github/stars/coramarcet/WordPressCVEExploitProject.svg) ![forks](https://img.shields.io/github/forks/coramarcet/WordPressCVEExploitProject.svg)

## CVE-2025-9478
 Use after free in ANGLE in Google Chrome prior to 139.0.7258.154 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)



- [https://github.com/Kamgreen50/STIG-Edge-RCE-CVE2025-9478](https://github.com/Kamgreen50/STIG-Edge-RCE-CVE2025-9478) :  ![starts](https://img.shields.io/github/stars/Kamgreen50/STIG-Edge-RCE-CVE2025-9478.svg) ![forks](https://img.shields.io/github/forks/Kamgreen50/STIG-Edge-RCE-CVE2025-9478.svg)

## CVE-2025-9345
 The File Manager, Code Editor, and Backup by Managefy plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 1.4.8 via the ajax_downloadfile() function. This makes it possible for authenticated attackers, with Subscriber-level access and above, to perform actions on files outside of the originally intended directory.



- [https://github.com/NagisaYumaa/CVE-2025-9345](https://github.com/NagisaYumaa/CVE-2025-9345) :  ![starts](https://img.shields.io/github/stars/NagisaYumaa/CVE-2025-9345.svg) ![forks](https://img.shields.io/github/forks/NagisaYumaa/CVE-2025-9345.svg)

## CVE-2025-9286
 The Appy Pie Connect for WooCommerce plugin for WordPress is vulnerable to Privilege Escalation due to missing authorization within the reset_user_password() REST handler in all versions up to, and including, 1.1.2. This makes it possible for unauthenticated attackers to to reset the password of arbitrary users, including administrators, thereby gaining administrative access.



- [https://github.com/Nxploited/CVE-2025-9286](https://github.com/Nxploited/CVE-2025-9286) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-9286.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-9286.svg)

## CVE-2025-9267
 In Seagate Toolkit on Windows a vulnerability exists in the Toolkit Installer prior to versions 2.35.0.6 where it attempts to load DLLs from the current working directory without validating their origin or integrity. This behavior can be exploited by placing a malicious DLL in the same directory as the installer executable, leading to arbitrary code execution with the privileges of the user running the installer. The issue stems from the use of insecure DLL loading practices, such as relying on relative paths or failing to specify fully qualified paths when invoking system libraries.



- [https://github.com/Tiger3080/CVE-2025-9267](https://github.com/Tiger3080/CVE-2025-9267) :  ![starts](https://img.shields.io/github/stars/Tiger3080/CVE-2025-9267.svg) ![forks](https://img.shields.io/github/forks/Tiger3080/CVE-2025-9267.svg)

## CVE-2025-9242
 An Out-of-bounds Write vulnerability in WatchGuard Fireware OS may allow a remote unauthenticated attacker to execute arbitrary code. This vulnerability affects both the Mobile User VPN with IKEv2 and the Branch Office VPN using IKEv2 when configured with a dynamic gateway peer.This vulnerability affects Fireware OS 11.10.2 up to and including 11.12.4_Update1, 12.0 up to and including 12.11.3 and 2025.1.



- [https://github.com/watchtowrlabs/watchTowr-vs-WatchGuard-CVE-2025-9242](https://github.com/watchtowrlabs/watchTowr-vs-WatchGuard-CVE-2025-9242) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-WatchGuard-CVE-2025-9242.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-WatchGuard-CVE-2025-9242.svg)

## CVE-2025-9216
 The StoreEngine – Powerful WordPress eCommerce Plugin for Payments, Memberships, Affiliates, Sales & More plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the import() function in all versions up to, and including, 1.5.0. This makes it possible for authenticated attackers, with Subscriber-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/d0n601/CVE-2025-9216](https://github.com/d0n601/CVE-2025-9216) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-9216.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-9216.svg)

## CVE-2025-9215
 The StoreEngine – Powerful WordPress eCommerce Plugin for Payments, Memberships, Affiliates, Sales & More plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 1.5.0 via the file_download() function. This makes it possible for authenticated attackers, with Subscriber-level access and above, to read the contents of arbitrary files on the server, which can contain sensitive information.



- [https://github.com/d0n601/CVE-2025-9215](https://github.com/d0n601/CVE-2025-9215) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-9215.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-9215.svg)

## CVE-2025-9196
 The Trinity Audio – Text to Speech AI audio player to convert content into audio plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 5.21.0 via the ~/admin/inc/phpinfo.php file that gets created on install. This makes it possible for unauthenticated attackers to extract sensitive data including configuration data.



- [https://github.com/MooseLoveti/Trinity-Audio-CVE-Report](https://github.com/MooseLoveti/Trinity-Audio-CVE-Report) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/Trinity-Audio-CVE-Report.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/Trinity-Audio-CVE-Report.svg)

- [https://github.com/godfatherofexps/CVE-2025-9196-PoC](https://github.com/godfatherofexps/CVE-2025-9196-PoC) :  ![starts](https://img.shields.io/github/stars/godfatherofexps/CVE-2025-9196-PoC.svg) ![forks](https://img.shields.io/github/forks/godfatherofexps/CVE-2025-9196-PoC.svg)

## CVE-2025-9090
 A vulnerability was identified in Tenda AC20 16.03.08.12. Affected is the function websFormDefine of the file /goform/telnet of the component Telnet Service. The manipulation leads to command injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/byteReaper77/CVE-2025-9090](https://github.com/byteReaper77/CVE-2025-9090) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-9090.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-9090.svg)

## CVE-2025-9074
 A vulnerability was identified in Docker Desktop that allows local running Linux containers to access the Docker Engine API via the configured Docker subnet, at 192.168.65.7:2375 by default. This vulnerability occurs with or without Enhanced Container Isolation (ECI) enabled, and with or without the "Expose daemon on tcp://localhost:2375 without TLS" option enabled.
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.



- [https://github.com/zenzue/CVE-2025-9074](https://github.com/zenzue/CVE-2025-9074) :  ![starts](https://img.shields.io/github/stars/zenzue/CVE-2025-9074.svg) ![forks](https://img.shields.io/github/forks/zenzue/CVE-2025-9074.svg)

- [https://github.com/fortihack/CVE-2025-9074](https://github.com/fortihack/CVE-2025-9074) :  ![starts](https://img.shields.io/github/stars/fortihack/CVE-2025-9074.svg) ![forks](https://img.shields.io/github/forks/fortihack/CVE-2025-9074.svg)

- [https://github.com/j3r1ch0123/CVE-2025-9074](https://github.com/j3r1ch0123/CVE-2025-9074) :  ![starts](https://img.shields.io/github/stars/j3r1ch0123/CVE-2025-9074.svg) ![forks](https://img.shields.io/github/forks/j3r1ch0123/CVE-2025-9074.svg)

- [https://github.com/pucagit/CVE-2025-9074](https://github.com/pucagit/CVE-2025-9074) :  ![starts](https://img.shields.io/github/stars/pucagit/CVE-2025-9074.svg) ![forks](https://img.shields.io/github/forks/pucagit/CVE-2025-9074.svg)

- [https://github.com/OilSeller2001/PoC-for-CVE-2025-9074](https://github.com/OilSeller2001/PoC-for-CVE-2025-9074) :  ![starts](https://img.shields.io/github/stars/OilSeller2001/PoC-for-CVE-2025-9074.svg) ![forks](https://img.shields.io/github/forks/OilSeller2001/PoC-for-CVE-2025-9074.svg)

## CVE-2025-8971
 A vulnerability was determined in itsourcecode Online Tour and Travel Management System 1.0. This vulnerability affects unknown code of the file /admin/operations/travellers.php. The manipulation of the argument val-username leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/byteReaper77/CVE-2025-8971](https://github.com/byteReaper77/CVE-2025-8971) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-8971.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-8971.svg)

## CVE-2025-8889
 The Compress & Upload WordPress plugin before 1.0.5 does not properly validate uploaded files, allowing high privilege users such as admin to upload arbitrary files on the server even when they should not be allowed to (for example in multisite setup)



- [https://github.com/siberkampus/CVE-2025-8889](https://github.com/siberkampus/CVE-2025-8889) :  ![starts](https://img.shields.io/github/stars/siberkampus/CVE-2025-8889.svg) ![forks](https://img.shields.io/github/forks/siberkampus/CVE-2025-8889.svg)

## CVE-2025-8876
 Improper Input Validation vulnerability in N-able N-central allows OS Command Injection.This issue affects N-central: before 2025.3.1.



- [https://github.com/rxerium/CVE-2025-8875-CVE-2025-8876](https://github.com/rxerium/CVE-2025-8875-CVE-2025-8876) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-8875-CVE-2025-8876.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-8875-CVE-2025-8876.svg)

## CVE-2025-8875
 Deserialization of Untrusted Data vulnerability in N-able N-central allows Local Execution of Code.This issue affects N-central: before 2025.3.1.



- [https://github.com/rxerium/CVE-2025-8875-CVE-2025-8876](https://github.com/rxerium/CVE-2025-8875-CVE-2025-8876) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-8875-CVE-2025-8876.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-8875-CVE-2025-8876.svg)

## CVE-2025-8730
 A vulnerability was found in Belkin F9K1009 and F9K1010 2.00.04/2.00.09 and classified as critical. Affected by this issue is some unknown functionality of the component Web Interface. The manipulation leads to hard-coded credentials. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/byteReaper77/CVE-2025-8730](https://github.com/byteReaper77/CVE-2025-8730) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-8730.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-8730.svg)

## CVE-2025-8723
 The Cloudflare Image Resizing plugin for WordPress is vulnerable to Remote Code Execution due to missing authentication and insufficient sanitization within its hook_rest_pre_dispatch() method in all versions up to, and including, 1.5.6. This makes it possible for unauthenticated attackers to inject arbitrary PHP into the codebase, achieving remote code execution.



- [https://github.com/Nxploited/CVE-2025-8723](https://github.com/Nxploited/CVE-2025-8723) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-8723.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-8723.svg)

## CVE-2025-8714
 Untrusted data inclusion in pg_dump in PostgreSQL allows a malicious superuser of the origin server to inject arbitrary code for restore-time execution as the client operating system account running psql to restore the dump, via psql meta-commands.  pg_dumpall is also affected.  pg_restore is affected when used to generate a plain-format dump.  This is similar to MySQL CVE-2024-21096.  Versions before PostgreSQL 17.6, 16.10, 15.14, 14.19, and 13.22 are affected.



- [https://github.com/orderby99/CVE-2025-8714-POC](https://github.com/orderby99/CVE-2025-8714-POC) :  ![starts](https://img.shields.io/github/stars/orderby99/CVE-2025-8714-POC.svg) ![forks](https://img.shields.io/github/forks/orderby99/CVE-2025-8714-POC.svg)

## CVE-2025-8671
 A mismatch caused by client-triggered server-sent stream resets between HTTP/2 specifications and the internal architectures of some HTTP/2 implementations may result in excessive server resource consumption leading to denial-of-service (DoS).  By opening streams and then rapidly triggering the server to reset them—using malformed frames or flow control errors—an attacker can exploit incorrect stream accounting. Streams reset by the server are considered closed at the protocol level, even though backend processing continues. This allows a client to cause the server to handle an unbounded number of concurrent streams on a single connection. This CVE will be updated as affected product details are released.



- [https://github.com/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS](https://github.com/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2025-8671-MadeYouReset-HTTP-2-DDoS.svg)

- [https://github.com/mateusm1403/PoC-CVE-2025-8671-MadeYouReset-HTTP-2](https://github.com/mateusm1403/PoC-CVE-2025-8671-MadeYouReset-HTTP-2) :  ![starts](https://img.shields.io/github/stars/mateusm1403/PoC-CVE-2025-8671-MadeYouReset-HTTP-2.svg) ![forks](https://img.shields.io/github/forks/mateusm1403/PoC-CVE-2025-8671-MadeYouReset-HTTP-2.svg)

- [https://github.com/abiyeenzo/CVE-2025-8671](https://github.com/abiyeenzo/CVE-2025-8671) :  ![starts](https://img.shields.io/github/stars/abiyeenzo/CVE-2025-8671.svg) ![forks](https://img.shields.io/github/forks/abiyeenzo/CVE-2025-8671.svg)

## CVE-2025-8625
 The Copypress Rest API plugin for WordPress is vulnerable to Remote Code Execution via copyreap_handle_image() Function in versions 1.1 to 1.2. The plugin falls back to a hard-coded JWT signing key when no secret is defined and does not restrict which file types can be fetched and saved as attachments. As a result, unauthenticated attackers can forge a valid token to gain elevated privileges and upload an arbitrary file (e.g. a PHP script) through the image handler, leading to remote code execution.



- [https://github.com/Nxploited/CVE-2025-8625](https://github.com/Nxploited/CVE-2025-8625) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-8625.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-8625.svg)

- [https://github.com/ret0x2A/CVE-2025-8625](https://github.com/ret0x2A/CVE-2025-8625) :  ![starts](https://img.shields.io/github/stars/ret0x2A/CVE-2025-8625.svg) ![forks](https://img.shields.io/github/forks/ret0x2A/CVE-2025-8625.svg)

## CVE-2025-8571
 Concrete CMS 9 to 9.4.2 and versions below 8.5.21 are vulnerable to Reflected Cross-Site Scripting (XSS) in the Conversation Messages Dashboard Page. Unsanitized input could cause theft of session cookies or tokens, defacement of web content, redirection to malicious sites, and (if victim is an admin), the execution of unauthorized actions. The Concrete CMS security team gave this vulnerability a CVSS v.4.0 score of 4.8 with vector CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N. Thanks  Fortbridge https://fortbridge.co.uk/  for performing a penetration test and vulnerability assessment on Concrete CMS and reporting this issue.



- [https://github.com/chimdi2700/CVE-2025-8571](https://github.com/chimdi2700/CVE-2025-8571) :  ![starts](https://img.shields.io/github/stars/chimdi2700/CVE-2025-8571.svg) ![forks](https://img.shields.io/github/forks/chimdi2700/CVE-2025-8571.svg)

## CVE-2025-8570
 The BeyondCart Connector plugin for WordPress is vulnerable to Privilege Escalation due to improper JWT secret management and authorization within the determine_current_user filter in versions 1.4.2 through 2.1.0. This makes it possible for unauthenticated attackers to craft valid tokens and assume any user’s identity.



- [https://github.com/Nxploited/CVE-2025-8570](https://github.com/Nxploited/CVE-2025-8570) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-8570.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-8570.svg)

- [https://github.com/chimdi2700/CVE-2025-8570](https://github.com/chimdi2700/CVE-2025-8570) :  ![starts](https://img.shields.io/github/stars/chimdi2700/CVE-2025-8570.svg) ![forks](https://img.shields.io/github/forks/chimdi2700/CVE-2025-8570.svg)

## CVE-2025-8550
 A vulnerability was found in atjiu pybbs up to 6.0.0. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file /admin/topic/list. The manipulation of the argument Username leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The patch is named 2fe4a51afbce0068c291bc1818bbc8f7f3b01a22. It is recommended to apply a patch to fix this issue.



- [https://github.com/byteReaper77/CVE-2025-8550](https://github.com/byteReaper77/CVE-2025-8550) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-8550.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-8550.svg)

## CVE-2025-8518
 A vulnerability was found in givanz Vvveb 1.0.5. It has been rated as critical. Affected by this issue is the function Save of the file admin/controller/editor/code.php of the component Code Editor. The manipulation leads to code injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 1.0.6 is able to address this issue. The name of the patch is f684f3e374d04db715730fc4796e102f5ebcacb2. It is recommended to upgrade the affected component.



- [https://github.com/maestro-ant/Vvveb-CMS-CVE-2025-8518](https://github.com/maestro-ant/Vvveb-CMS-CVE-2025-8518) :  ![starts](https://img.shields.io/github/stars/maestro-ant/Vvveb-CMS-CVE-2025-8518.svg) ![forks](https://img.shields.io/github/forks/maestro-ant/Vvveb-CMS-CVE-2025-8518.svg)

## CVE-2025-8517
 A vulnerability was detected in givanz Vvveb 1.0.6.1. Impacted is an unknown function. The manipulation results in session fixiation. The attack can be launched remotely. The exploit is now public and may be used. Upgrading to version 1.0.7 is recommended to address this issue. The patch is identified as d4b1e030066417b77d15b4ac505eed5ae7bf2c5e. You should upgrade the affected component.



- [https://github.com/kwerty138/Session-Fixation-in-Vvveb-CMS-v1.0.6.1](https://github.com/kwerty138/Session-Fixation-in-Vvveb-CMS-v1.0.6.1) :  ![starts](https://img.shields.io/github/stars/kwerty138/Session-Fixation-in-Vvveb-CMS-v1.0.6.1.svg) ![forks](https://img.shields.io/github/forks/kwerty138/Session-Fixation-in-Vvveb-CMS-v1.0.6.1.svg)

## CVE-2025-8471
 A vulnerability, which was classified as critical, has been found in projectworlds Online Admission System 1.0. This issue affects some unknown processing of the file /adminlogin.php. The manipulation of the argument a_id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/byteReaper77/CVE-2025-8471](https://github.com/byteReaper77/CVE-2025-8471) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-8471.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-8471.svg)

## CVE-2025-8422
 The Propovoice: All-in-One Client Management System plugin for WordPress is vulnerable to Arbitrary File Read in all versions up to, and including, 1.7.6.7 via the send_email() function. This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server, which can contain sensitive information.



- [https://github.com/RandomRobbieBF/CVE-2025-8422](https://github.com/RandomRobbieBF/CVE-2025-8422) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-8422.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-8422.svg)

## CVE-2025-8359
 The AdForest theme for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 6.0.9. This is due to the plugin not properly verifying a user's identity prior to authenticating them. This makes it possible for unauthenticated attackers to log in as other users, including administrators, without access to a password.



- [https://github.com/Nxploited/CVE-2025-8359](https://github.com/Nxploited/CVE-2025-8359) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-8359.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-8359.svg)

## CVE-2025-8220
 A vulnerability has been found in Engeman Web up to 12.0.0.2. The affected element is an unknown function of the file /Login/RecoveryPass of the component Password Recovery Page. The manipulation of the argument LanguageCombobox as part of Cookie leads to sql injection. The attack is possible to be carried out remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 12.0.0.3 is sufficient to fix this issue. Upgrading the affected component is advised. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/m3m0o/engeman-web-language-combobox-sqli](https://github.com/m3m0o/engeman-web-language-combobox-sqli) :  ![starts](https://img.shields.io/github/stars/m3m0o/engeman-web-language-combobox-sqli.svg) ![forks](https://img.shields.io/github/forks/m3m0o/engeman-web-language-combobox-sqli.svg)

## CVE-2025-8191
 A vulnerability, which was classified as problematic, was found in macrozheng mall up to 1.0.3. Affected is an unknown function of the file /swagger-ui/index.html of the component Swagger UI. The manipulation of the argument configUrl leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor deleted the GitHub issue for this vulnerability without any explanation. Afterwards the vendor was contacted early about this disclosure via email but did not respond in any way.



- [https://github.com/byteReaper77/CVE-2025-8191](https://github.com/byteReaper77/CVE-2025-8191) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-8191.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-8191.svg)

## CVE-2025-8091
 The EventON Lite plugin for WordPress is vulnerable to Information Exposure in all versions less than, or equal to, 2.4.6 via the add_single_eventon and add_eventon shortcodes due to insufficient restrictions on which posts can be included. This makes it possible for unauthenticated attackers to extract data from password protected, private, or draft posts that they should not have access to.



- [https://github.com/MooseLoveti/EventON-Lite-CVE-Report](https://github.com/MooseLoveti/EventON-Lite-CVE-Report) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/EventON-Lite-CVE-Report.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/EventON-Lite-CVE-Report.svg)

## CVE-2025-8088
 A path traversal vulnerability affecting the Windows version of WinRAR allows the attackers to execute arbitrary code by crafting malicious archive files. This vulnerability was exploited in the wild and was discovered by Anton Cherepanov, Peter Košinár, and Peter Strýček
     from ESET.



- [https://github.com/sxyrxyy/CVE-2025-8088-WinRAR-Proof-of-Concept-PoC-Exploit-](https://github.com/sxyrxyy/CVE-2025-8088-WinRAR-Proof-of-Concept-PoC-Exploit-) :  ![starts](https://img.shields.io/github/stars/sxyrxyy/CVE-2025-8088-WinRAR-Proof-of-Concept-PoC-Exploit-.svg) ![forks](https://img.shields.io/github/forks/sxyrxyy/CVE-2025-8088-WinRAR-Proof-of-Concept-PoC-Exploit-.svg)

- [https://github.com/knight0x07/WinRAR-CVE-2025-8088-PoC-RAR](https://github.com/knight0x07/WinRAR-CVE-2025-8088-PoC-RAR) :  ![starts](https://img.shields.io/github/stars/knight0x07/WinRAR-CVE-2025-8088-PoC-RAR.svg) ![forks](https://img.shields.io/github/forks/knight0x07/WinRAR-CVE-2025-8088-PoC-RAR.svg)

- [https://github.com/mocred/cve-2025-8088](https://github.com/mocred/cve-2025-8088) :  ![starts](https://img.shields.io/github/stars/mocred/cve-2025-8088.svg) ![forks](https://img.shields.io/github/forks/mocred/cve-2025-8088.svg)

- [https://github.com/onlytoxi/CVE-2025-8088-Winrar-Tool](https://github.com/onlytoxi/CVE-2025-8088-Winrar-Tool) :  ![starts](https://img.shields.io/github/stars/onlytoxi/CVE-2025-8088-Winrar-Tool.svg) ![forks](https://img.shields.io/github/forks/onlytoxi/CVE-2025-8088-Winrar-Tool.svg)

- [https://github.com/pentestfunctions/CVE-2025-8088-Multi-Document](https://github.com/pentestfunctions/CVE-2025-8088-Multi-Document) :  ![starts](https://img.shields.io/github/stars/pentestfunctions/CVE-2025-8088-Multi-Document.svg) ![forks](https://img.shields.io/github/forks/pentestfunctions/CVE-2025-8088-Multi-Document.svg)

- [https://github.com/jordan922/CVE-2025-8088](https://github.com/jordan922/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/jordan922/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/jordan922/CVE-2025-8088.svg)

- [https://github.com/hexsecteam/CVE-2025-8088-Winrar-Tool](https://github.com/hexsecteam/CVE-2025-8088-Winrar-Tool) :  ![starts](https://img.shields.io/github/stars/hexsecteam/CVE-2025-8088-Winrar-Tool.svg) ![forks](https://img.shields.io/github/forks/hexsecteam/CVE-2025-8088-Winrar-Tool.svg)

- [https://github.com/kitsuneshade/WinRAR-Exploit-Tool---Rust-Edition](https://github.com/kitsuneshade/WinRAR-Exploit-Tool---Rust-Edition) :  ![starts](https://img.shields.io/github/stars/kitsuneshade/WinRAR-Exploit-Tool---Rust-Edition.svg) ![forks](https://img.shields.io/github/forks/kitsuneshade/WinRAR-Exploit-Tool---Rust-Edition.svg)

- [https://github.com/pentestfunctions/best-CVE-2025-8088](https://github.com/pentestfunctions/best-CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/pentestfunctions/best-CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/pentestfunctions/best-CVE-2025-8088.svg)

- [https://github.com/lucyna77/winrar-exploit](https://github.com/lucyna77/winrar-exploit) :  ![starts](https://img.shields.io/github/stars/lucyna77/winrar-exploit.svg) ![forks](https://img.shields.io/github/forks/lucyna77/winrar-exploit.svg)

- [https://github.com/AdityaBhatt3010/CVE-2025-8088-WinRAR-Zero-Day-Path-Traversal](https://github.com/AdityaBhatt3010/CVE-2025-8088-WinRAR-Zero-Day-Path-Traversal) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-8088-WinRAR-Zero-Day-Path-Traversal.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-8088-WinRAR-Zero-Day-Path-Traversal.svg)

- [https://github.com/Syrins/CVE-2025-8088-Winrar-Tool-Gui](https://github.com/Syrins/CVE-2025-8088-Winrar-Tool-Gui) :  ![starts](https://img.shields.io/github/stars/Syrins/CVE-2025-8088-Winrar-Tool-Gui.svg) ![forks](https://img.shields.io/github/forks/Syrins/CVE-2025-8088-Winrar-Tool-Gui.svg)

- [https://github.com/travisbgreen/cve-2025-8088](https://github.com/travisbgreen/cve-2025-8088) :  ![starts](https://img.shields.io/github/stars/travisbgreen/cve-2025-8088.svg) ![forks](https://img.shields.io/github/forks/travisbgreen/cve-2025-8088.svg)

- [https://github.com/pexlexity/WinRAR-CVE-2025-8088-Path-Traversal-PoC](https://github.com/pexlexity/WinRAR-CVE-2025-8088-Path-Traversal-PoC) :  ![starts](https://img.shields.io/github/stars/pexlexity/WinRAR-CVE-2025-8088-Path-Traversal-PoC.svg) ![forks](https://img.shields.io/github/forks/pexlexity/WinRAR-CVE-2025-8088-Path-Traversal-PoC.svg)

- [https://github.com/pescada-dev/-CVE-2025-8088](https://github.com/pescada-dev/-CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/pescada-dev/-CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/pescada-dev/-CVE-2025-8088.svg)

- [https://github.com/Shinkirou789/Cve-2025-8088-WinRar-vulnerability](https://github.com/Shinkirou789/Cve-2025-8088-WinRar-vulnerability) :  ![starts](https://img.shields.io/github/stars/Shinkirou789/Cve-2025-8088-WinRar-vulnerability.svg) ![forks](https://img.shields.io/github/forks/Shinkirou789/Cve-2025-8088-WinRar-vulnerability.svg)

- [https://github.com/nhattanhh/CVE-2025-8088](https://github.com/nhattanhh/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/nhattanhh/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/nhattanhh/CVE-2025-8088.svg)

- [https://github.com/ghostn4444/CVE-2025-8088](https://github.com/ghostn4444/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/ghostn4444/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/ghostn4444/CVE-2025-8088.svg)

- [https://github.com/walidpyh/CVE-2025-8088](https://github.com/walidpyh/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/walidpyh/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/walidpyh/CVE-2025-8088.svg)

- [https://github.com/Fathi-MO/POC-CVE-2025-8088](https://github.com/Fathi-MO/POC-CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/Fathi-MO/POC-CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/Fathi-MO/POC-CVE-2025-8088.svg)

- [https://github.com/techcorp/CVE-2025-8088-Exploit](https://github.com/techcorp/CVE-2025-8088-Exploit) :  ![starts](https://img.shields.io/github/stars/techcorp/CVE-2025-8088-Exploit.svg) ![forks](https://img.shields.io/github/forks/techcorp/CVE-2025-8088-Exploit.svg)

- [https://github.com/hbesljx/CVE-2025-8088-EXP](https://github.com/hbesljx/CVE-2025-8088-EXP) :  ![starts](https://img.shields.io/github/stars/hbesljx/CVE-2025-8088-EXP.svg) ![forks](https://img.shields.io/github/forks/hbesljx/CVE-2025-8088-EXP.svg)

- [https://github.com/papcaii2004/CVE-2025-8088-WinRAR-builder](https://github.com/papcaii2004/CVE-2025-8088-WinRAR-builder) :  ![starts](https://img.shields.io/github/stars/papcaii2004/CVE-2025-8088-WinRAR-builder.svg) ![forks](https://img.shields.io/github/forks/papcaii2004/CVE-2025-8088-WinRAR-builder.svg)

- [https://github.com/DeepBlue-dot/CVE-2025-8088-WinRAR-Startup-PoC](https://github.com/DeepBlue-dot/CVE-2025-8088-WinRAR-Startup-PoC) :  ![starts](https://img.shields.io/github/stars/DeepBlue-dot/CVE-2025-8088-WinRAR-Startup-PoC.svg) ![forks](https://img.shields.io/github/forks/DeepBlue-dot/CVE-2025-8088-WinRAR-Startup-PoC.svg)

- [https://github.com/0xAbolfazl/CVE-2025-8088-WinRAR-PathTraversal-PoC](https://github.com/0xAbolfazl/CVE-2025-8088-WinRAR-PathTraversal-PoC) :  ![starts](https://img.shields.io/github/stars/0xAbolfazl/CVE-2025-8088-WinRAR-PathTraversal-PoC.svg) ![forks](https://img.shields.io/github/forks/0xAbolfazl/CVE-2025-8088-WinRAR-PathTraversal-PoC.svg)

## CVE-2025-8081
 The Elementor plugin for WordPress is vulnerable to Arbitrary File Read in all versions up to, and including, 3.30.2 via the Import_Images::import() function due to insufficient controls on the filename specified. This makes it possible for authenticated attackers, with administrator-level access and above, to read the contents of arbitrary files on the server, which can contain sensitive information.



- [https://github.com/LyesH4ck/CVE-2025-8081-Elementor](https://github.com/LyesH4ck/CVE-2025-8081-Elementor) :  ![starts](https://img.shields.io/github/stars/LyesH4ck/CVE-2025-8081-Elementor.svg) ![forks](https://img.shields.io/github/forks/LyesH4ck/CVE-2025-8081-Elementor.svg)

## CVE-2025-8067
 A flaw was found in the Udisks daemon, where it allows unprivileged users to create loop devices using the D-BUS system. This is achieved via the loop device handler, which handles requests sent through the D-BUS interface. As two of the parameters of this handle, it receives the file descriptor list and index specifying the file where the loop device should be backed. The function itself validates the index value to ensure it isn't bigger than the maximum value allowed. However, it fails to validate the lower bound, allowing the index parameter to be a negative value. Under these circumstances, an attacker can cause the UDisks daemon to crash or perform a local privilege escalation by gaining access to files owned by privileged users.



- [https://github.com/born0monday/CVE-2025-8067](https://github.com/born0monday/CVE-2025-8067) :  ![starts](https://img.shields.io/github/stars/born0monday/CVE-2025-8067.svg) ![forks](https://img.shields.io/github/forks/born0monday/CVE-2025-8067.svg)

## CVE-2025-8061
 A potential insufficient access control vulnerability was reported in the Lenovo Dispatcher 3.0 and Dispatcher 3.1 drivers used by some Lenovo consumer notebooks that could allow an authenticated local user to execute code with elevated privileges. The Lenovo Dispatcher 3.2 driver is not affected. This vulnerability does not affect systems when the Windows feature Core Isolation Memory Integrity is enabled. Lenovo systems preloaded with Windows 11 have this feature enabled by default.



- [https://github.com/symeonp/Lenovo-CVE-2025-8061](https://github.com/symeonp/Lenovo-CVE-2025-8061) :  ![starts](https://img.shields.io/github/stars/symeonp/Lenovo-CVE-2025-8061.svg) ![forks](https://img.shields.io/github/forks/symeonp/Lenovo-CVE-2025-8061.svg)

## CVE-2025-8018
 A vulnerability was found in code-projects Food Ordering Review System 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /user/reservation_page.php. The manipulation of the argument reg_Id leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.



- [https://github.com/drackyjr/CVE-2025-8018](https://github.com/drackyjr/CVE-2025-8018) :  ![starts](https://img.shields.io/github/stars/drackyjr/CVE-2025-8018.svg) ![forks](https://img.shields.io/github/forks/drackyjr/CVE-2025-8018.svg)

## CVE-2025-7955
 The RingCentral Communications plugin for WordPress is vulnerable to Authentication Bypass due to improper validation within the ringcentral_admin_login_2fa_verify() function in versions 1.5 to 1.6.8. This makes it possible for unauthenticated attackers to log in as any user simply by supplying identical bogus codes.



- [https://github.com/Nxploited/CVE-2025-7955](https://github.com/Nxploited/CVE-2025-7955) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-7955.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-7955.svg)

## CVE-2025-7847
 The AI Engine plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the rest_simpleFileUpload() function in versions 2.9.3 and 2.9.4. This makes it possible for authenticated attackers, with Subscriber-level access and above, to upload arbitrary files on the affected site's server when the REST API is enabled, which may make remote code execution possible.



- [https://github.com/EricArdiansa/CVE-2025-7847-POC](https://github.com/EricArdiansa/CVE-2025-7847-POC) :  ![starts](https://img.shields.io/github/stars/EricArdiansa/CVE-2025-7847-POC.svg) ![forks](https://img.shields.io/github/forks/EricArdiansa/CVE-2025-7847-POC.svg)

## CVE-2025-7840
 A vulnerability was found in Campcodes Online Movie Theater Seat Reservation System 1.0. It has been classified as problematic. This affects an unknown part of the file /index.php?page=reserve of the component Reserve Your Seat Page. The manipulation of the argument Firstname/Lastname leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/byteReaper77/CVE-2025-7840](https://github.com/byteReaper77/CVE-2025-7840) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-7840.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-7840.svg)

## CVE-2025-7795
 A vulnerability, which was classified as critical, has been found in Tenda FH451 1.0.0.9. Affected by this issue is the function fromP2pListFilter of the file /goform/P2pListFilter. The manipulation of the argument page leads to stack-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/byteReaper77/CVE-2025-7795](https://github.com/byteReaper77/CVE-2025-7795) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-7795.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-7795.svg)

## CVE-2025-7783
 Use of Insufficiently Random Values vulnerability in form-data allows HTTP Parameter Pollution (HPP). This vulnerability is associated with program files lib/form_data.Js.

This issue affects form-data:  2.5.4, 3.0.0 - 3.0.3, 4.0.0 - 4.0.3.



- [https://github.com/benweissmann/CVE-2025-7783-poc](https://github.com/benweissmann/CVE-2025-7783-poc) :  ![starts](https://img.shields.io/github/stars/benweissmann/CVE-2025-7783-poc.svg) ![forks](https://img.shields.io/github/forks/benweissmann/CVE-2025-7783-poc.svg)

## CVE-2025-7775
 Memory overflow vulnerability leading to Remote Code Execution and/or Denial of Service in NetScaler ADC and NetScaler Gateway when NetScaler is configured as Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server

(OR)

NetScaler ADC and NetScaler Gateway 13.1, 14.1, 13.1-FIPS and NDcPP: LB virtual servers of type (HTTP, SSL or HTTP_QUIC) bound with IPv6 services or servicegroups bound with IPv6 servers 

(OR)

NetScaler ADC and NetScaler Gateway 13.1, 14.1, 13.1-FIPS and NDcPP: LB virtual servers of type (HTTP, SSL or HTTP_QUIC) bound with DBS IPv6 services or servicegroups bound with IPv6 DBS servers

(OR)

CR virtual server with type HDX



- [https://github.com/fox-it/citrix-netscaler-triage](https://github.com/fox-it/citrix-netscaler-triage) :  ![starts](https://img.shields.io/github/stars/fox-it/citrix-netscaler-triage.svg) ![forks](https://img.shields.io/github/forks/fox-it/citrix-netscaler-triage.svg)

- [https://github.com/hacker-r3volv3r/CVE-2025-7775-PoC](https://github.com/hacker-r3volv3r/CVE-2025-7775-PoC) :  ![starts](https://img.shields.io/github/stars/hacker-r3volv3r/CVE-2025-7775-PoC.svg) ![forks](https://img.shields.io/github/forks/hacker-r3volv3r/CVE-2025-7775-PoC.svg)

- [https://github.com/rxerium/CVE-2025-7775](https://github.com/rxerium/CVE-2025-7775) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-7775.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-7775.svg)

- [https://github.com/mr-r3b00t/CVE-2025-7775](https://github.com/mr-r3b00t/CVE-2025-7775) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2025-7775.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2025-7775.svg)

- [https://github.com/Aaqilyousuf/CVE-2025-7775-vulnerable-lab](https://github.com/Aaqilyousuf/CVE-2025-7775-vulnerable-lab) :  ![starts](https://img.shields.io/github/stars/Aaqilyousuf/CVE-2025-7775-vulnerable-lab.svg) ![forks](https://img.shields.io/github/forks/Aaqilyousuf/CVE-2025-7775-vulnerable-lab.svg)

## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.



- [https://github.com/fxrstor/ThrottleStopPoC](https://github.com/fxrstor/ThrottleStopPoC) :  ![starts](https://img.shields.io/github/stars/fxrstor/ThrottleStopPoC.svg) ![forks](https://img.shields.io/github/forks/fxrstor/ThrottleStopPoC.svg)

- [https://github.com/Gabriel-Lacorte/CVE-2025-7771](https://github.com/Gabriel-Lacorte/CVE-2025-7771) :  ![starts](https://img.shields.io/github/stars/Gabriel-Lacorte/CVE-2025-7771.svg) ![forks](https://img.shields.io/github/forks/Gabriel-Lacorte/CVE-2025-7771.svg)

- [https://github.com/Demoo1337/ThrottleStop](https://github.com/Demoo1337/ThrottleStop) :  ![starts](https://img.shields.io/github/stars/Demoo1337/ThrottleStop.svg) ![forks](https://img.shields.io/github/forks/Demoo1337/ThrottleStop.svg)

- [https://github.com/Yuri08loveElaina/CVE-2025-7771](https://github.com/Yuri08loveElaina/CVE-2025-7771) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-7771.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-7771.svg)

## CVE-2025-7769
 Tigo Energy's CCA is vulnerable to a command injection vulnerability in the /cgi-bin/mobile_api endpoint when the DEVICE_PING command is called, allowing remote code execution due to improper handling of user input. When used with default credentials, this enables attackers to execute arbitrary commands on the device that could cause potential unauthorized access, service disruption, and data exposure.



- [https://github.com/byteReaper77/CVE-2025-7769](https://github.com/byteReaper77/CVE-2025-7769) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-7769.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-7769.svg)

## CVE-2025-7766
 Lantronix Provisioning Manager is vulnerable to XML external entity attacks in configuration files supplied by network devices, leading to unauthenticated remote code execution on hosts with Provisioning Manager installed.



- [https://github.com/byteReaper77/CVE-2025-7766](https://github.com/byteReaper77/CVE-2025-7766) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-7766.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-7766.svg)

## CVE-2025-7753
 A vulnerability was found in code-projects Online Appointment Booking System 1.0. It has been classified as critical. This affects an unknown part of the file /admin/adddoctor.php. The manipulation of the argument Username leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/byteReaper77/CVE-2025-7753](https://github.com/byteReaper77/CVE-2025-7753) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-7753.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-7753.svg)

## CVE-2025-7620
 The cross-browser document creation component produced by Digitware System Integration Corporation has a Remote Code Execution vulnerability. If a user visits a malicious website while the component is active, remote attackers can cause the system to download and execute arbitrary programs.



- [https://github.com/Yuri08loveElaina/cve_2025_7620](https://github.com/Yuri08loveElaina/cve_2025_7620) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/cve_2025_7620.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/cve_2025_7620.svg)

## CVE-2025-7606
 A vulnerability classified as critical has been found in code-projects AVL Rooms 1.0. This affects an unknown part of the file /city.php. The manipulation of the argument city leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/sunhuiHi666/CVE-2025-7606](https://github.com/sunhuiHi666/CVE-2025-7606) :  ![starts](https://img.shields.io/github/stars/sunhuiHi666/CVE-2025-7606.svg) ![forks](https://img.shields.io/github/forks/sunhuiHi666/CVE-2025-7606.svg)

## CVE-2025-7605
 A vulnerability was found in code-projects AVL Rooms 1.0. It has been rated as critical. Affected by this issue is some unknown functionality of the file /profile.php. The manipulation of the argument first_name leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/sunhuiHi666/CVE-2025-7605](https://github.com/sunhuiHi666/CVE-2025-7605) :  ![starts](https://img.shields.io/github/stars/sunhuiHi666/CVE-2025-7605.svg) ![forks](https://img.shields.io/github/forks/sunhuiHi666/CVE-2025-7605.svg)

## CVE-2025-7558
 A vulnerability was found in code-projects Voting System 1.0 and classified as critical. Affected by this issue is some unknown functionality of the file /admin/positions_add.php. The manipulation of the argument description leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/rundas-r00t/CVE-2025-7558-PoC](https://github.com/rundas-r00t/CVE-2025-7558-PoC) :  ![starts](https://img.shields.io/github/stars/rundas-r00t/CVE-2025-7558-PoC.svg) ![forks](https://img.shields.io/github/forks/rundas-r00t/CVE-2025-7558-PoC.svg)

## CVE-2025-7461
 A vulnerability was found in code-projects Modern Bag 1.0 and classified as critical. Affected by this issue is some unknown functionality of the file /action.php. The manipulation of the argument proId leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/bx33661/CVE-2025-7461](https://github.com/bx33661/CVE-2025-7461) :  ![starts](https://img.shields.io/github/stars/bx33661/CVE-2025-7461.svg) ![forks](https://img.shields.io/github/forks/bx33661/CVE-2025-7461.svg)

## CVE-2025-7441
 The StoryChief plugin for WordPress is vulnerable to arbitrary file uploads in all versions up to, and including, 1.0.42. This vulnerability occurs through the /wp-json/storychief/webhook REST-API endpoint that does not have sufficient filetype validation. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Pwdnx1337/CVE-2025-7441](https://github.com/Pwdnx1337/CVE-2025-7441) :  ![starts](https://img.shields.io/github/stars/Pwdnx1337/CVE-2025-7441.svg) ![forks](https://img.shields.io/github/forks/Pwdnx1337/CVE-2025-7441.svg)

- [https://github.com/Nxploited/CVE-2025-7441](https://github.com/Nxploited/CVE-2025-7441) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-7441.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-7441.svg)

## CVE-2025-7431
 The Knowledge Base plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin slug setting in all versions up to, and including, 2.3.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level access, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.



- [https://github.com/NagisaYumaa/CVE-2025-7431](https://github.com/NagisaYumaa/CVE-2025-7431) :  ![starts](https://img.shields.io/github/stars/NagisaYumaa/CVE-2025-7431.svg) ![forks](https://img.shields.io/github/forks/NagisaYumaa/CVE-2025-7431.svg)

## CVE-2025-7404
 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability in Calibre Web, Autocaliweb allows Blind OS Command Injection.This issue affects Calibre Web: 0.6.24 (Nicolette); Autocaliweb: from 0.7.0 before 0.7.1.



- [https://github.com/mind2hex/CVE-2025-7404-CalibreWeb-0.6.24-BlindCommandInjection](https://github.com/mind2hex/CVE-2025-7404-CalibreWeb-0.6.24-BlindCommandInjection) :  ![starts](https://img.shields.io/github/stars/mind2hex/CVE-2025-7404-CalibreWeb-0.6.24-BlindCommandInjection.svg) ![forks](https://img.shields.io/github/forks/mind2hex/CVE-2025-7404-CalibreWeb-0.6.24-BlindCommandInjection.svg)

## CVE-2025-7401
 The Premium Age Verification / Restriction for WordPress plugin for WordPress is vulnerable to arbitrary file read and write due to the existence of an insufficiently protected remote support functionality in remote_tunnel.php in all versions up to, and including, 3.0.2. This makes it possible for unauthenticated attackers to read from or write to arbitrary files on the affected site's server which may make the exposure of sensitive information or remote code execution possible.



- [https://github.com/Nxploited/CVE-2025-7401](https://github.com/Nxploited/CVE-2025-7401) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-7401.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-7401.svg)

## CVE-2025-7340
 The HT Contact Form Widget For Elementor Page Builder & Gutenberg Blocks & Form Builder. plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the temp_file_upload function in all versions up to, and including, 2.2.1. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2025-7340](https://github.com/Nxploited/CVE-2025-7340) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-7340.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-7340.svg)

- [https://github.com/Kai-One001/WordPress-HT-Contact-CVE-2025-7340-RCE](https://github.com/Kai-One001/WordPress-HT-Contact-CVE-2025-7340-RCE) :  ![starts](https://img.shields.io/github/stars/Kai-One001/WordPress-HT-Contact-CVE-2025-7340-RCE.svg) ![forks](https://img.shields.io/github/forks/Kai-One001/WordPress-HT-Contact-CVE-2025-7340-RCE.svg)

## CVE-2025-6998
 ReDoS in strip_whitespaces() function in cps/string_helper.py in Calibre Web and Autocaliweb allows unauthenticated remote attackers to cause denial of service via specially crafted username parameter that triggers catastrophic backtracking during login. This issue affects Calibre Web: 0.6.24 (Nicolette); Autocaliweb: from 0.7.0 before 0.7.1.



- [https://github.com/mind2hex/CVE-2025-6998-CalibreWeb-0.6.24-ReDoS](https://github.com/mind2hex/CVE-2025-6998-CalibreWeb-0.6.24-ReDoS) :  ![starts](https://img.shields.io/github/stars/mind2hex/CVE-2025-6998-CalibreWeb-0.6.24-ReDoS.svg) ![forks](https://img.shields.io/github/forks/mind2hex/CVE-2025-6998-CalibreWeb-0.6.24-ReDoS.svg)

## CVE-2025-6970
 The Events Manager – Calendar, Bookings, Tickets, and more! plugin for WordPress is vulnerable to time-based SQL Injection via the ‘orderby’ parameter in all versions up to, and including, 7.0.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.



- [https://github.com/RandomRobbieBF/CVE-2025-6970](https://github.com/RandomRobbieBF/CVE-2025-6970) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-6970.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-6970.svg)

## CVE-2025-6934
 The Opal Estate Pro – Property Management and Submission plugin for WordPress, used by the FullHouse - Real Estate Responsive WordPress Theme, is vulnerable to privilege escalation via in all versions up to, and including, 1.7.5. This is due to a lack of role restriction during registration in the 'on_regiser_user' function. This makes it possible for unauthenticated attackers to arbitrarily choose the role, including the Administrator role, assigned when registering.



- [https://github.com/Nxploited/CVE-2025-6934](https://github.com/Nxploited/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-6934.svg)

- [https://github.com/yukinime/CVE-2025-6934](https://github.com/yukinime/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/yukinime/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/yukinime/CVE-2025-6934.svg)

- [https://github.com/MrjHaxcore/CVE-2025-6934](https://github.com/MrjHaxcore/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/MrjHaxcore/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/MrjHaxcore/CVE-2025-6934.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-6934](https://github.com/0xgh057r3c0n/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-6934.svg)

- [https://github.com/Pwdnx1337/CVE-2025-6934](https://github.com/Pwdnx1337/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/Pwdnx1337/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/Pwdnx1337/CVE-2025-6934.svg)

- [https://github.com/Rosemary1337/CVE-2025-6934](https://github.com/Rosemary1337/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/Rosemary1337/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/Rosemary1337/CVE-2025-6934.svg)

- [https://github.com/Jenderal92/WP-CVE-2025-6934](https://github.com/Jenderal92/WP-CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/Jenderal92/WP-CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/WP-CVE-2025-6934.svg)

## CVE-2025-6916
 A vulnerability, which was classified as critical, was found in TOTOLINK T6 4.1.5cu.748_B20211015. This affects the function Form_Login of the file /formLoginAuth.htm. The manipulation of the argument authCode/goURL leads to missing authentication. The attack needs to be initiated within the local network. The exploit has been disclosed to the public and may be used.



- [https://github.com/c0nyy/IoT_vuln](https://github.com/c0nyy/IoT_vuln) :  ![starts](https://img.shields.io/github/stars/c0nyy/IoT_vuln.svg) ![forks](https://img.shields.io/github/forks/c0nyy/IoT_vuln.svg)

## CVE-2025-6907
 A vulnerability classified as critical was found in code-projects Car Rental System 1.0. This vulnerability affects unknown code of the file /book_car.php. The manipulation of the argument fname leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/byteReaper77/cve-2025-6907](https://github.com/byteReaper77/cve-2025-6907) :  ![starts](https://img.shields.io/github/stars/byteReaper77/cve-2025-6907.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/cve-2025-6907.svg)

## CVE-2025-6860
 A vulnerability was found in SourceCodester Best Salon Management System 1.0. It has been declared as critical. This vulnerability affects unknown code of the file /panel/staff_commision.php. The manipulation of the argument fromdate/todate leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/byteReaper77/CVE-2025-6860](https://github.com/byteReaper77/CVE-2025-6860) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-6860.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-6860.svg)

## CVE-2025-6759
 Local Privilege escalation allows a low-privileged user to gain SYSTEM privileges in Windows Virtual Delivery Agent for CVAD and Citrix DaaS



- [https://github.com/olljanat/TestCitrixException](https://github.com/olljanat/TestCitrixException) :  ![starts](https://img.shields.io/github/stars/olljanat/TestCitrixException.svg) ![forks](https://img.shields.io/github/forks/olljanat/TestCitrixException.svg)

## CVE-2025-6758
 The Real Spaces - WordPress Properties Directory Theme theme for WordPress is vulnerable to privilege escalation via the 'imic_agent_register' function in all versions up to, and including, 3.6. This is due to a lack of restriction in the registration role. This makes it possible for unauthenticated attackers to arbitrarily choose their role, including the Administrator role, during user registration.



- [https://github.com/Nxploited/CVE-2025-6758](https://github.com/Nxploited/CVE-2025-6758) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-6758.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-6758.svg)

## CVE-2025-6713
 An unauthorized user may leverage a specially crafted aggregation pipeline to access data without proper authorization due to improper handling of the $mergeCursors stage in MongoDB Server. This may lead to access to data without further authorisation. This issue affects MongoDB Server MongoDB Server v8.0 versions prior to 8.0.7, MongoDB Server v7.0 versions prior to 7.0.19 and MongoDB Server v6.0 versions prior to 6.0.22



- [https://github.com/c137req/CVE-2025-6713](https://github.com/c137req/CVE-2025-6713) :  ![starts](https://img.shields.io/github/stars/c137req/CVE-2025-6713.svg) ![forks](https://img.shields.io/github/forks/c137req/CVE-2025-6713.svg)

## CVE-2025-6586
 The Download Plugin plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the dpwap_plugin_locInstall function in all versions up to, and including, 2.2.8. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/d0n601/CVE-2025-6586](https://github.com/d0n601/CVE-2025-6586) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-6586.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-6586.svg)

## CVE-2025-6558
 Insufficient validation of untrusted input in ANGLE and GPU in Google Chrome prior to 138.0.7204.157 allowed a remote attacker to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/DevBuiHieu/CVE-2025-6558-Proof-Of-Concept](https://github.com/DevBuiHieu/CVE-2025-6558-Proof-Of-Concept) :  ![starts](https://img.shields.io/github/stars/DevBuiHieu/CVE-2025-6558-Proof-Of-Concept.svg) ![forks](https://img.shields.io/github/forks/DevBuiHieu/CVE-2025-6558-Proof-Of-Concept.svg)

- [https://github.com/gmh5225/CVE-2025-6558-exp](https://github.com/gmh5225/CVE-2025-6558-exp) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2025-6558-exp.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2025-6558-exp.svg)

## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/mistymntncop/CVE-2025-6554](https://github.com/mistymntncop/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/mistymntncop/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/mistymntncop/CVE-2025-6554.svg)

- [https://github.com/jopraveen/CVE-2025-6554](https://github.com/jopraveen/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/jopraveen/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/jopraveen/CVE-2025-6554.svg)

- [https://github.com/gmh5225/CVE-2025-6554-2](https://github.com/gmh5225/CVE-2025-6554-2) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2025-6554-2.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2025-6554-2.svg)

- [https://github.com/PwnToday/CVE-2025-6554](https://github.com/PwnToday/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/PwnToday/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/PwnToday/CVE-2025-6554.svg)

- [https://github.com/ghostn4444/POC-CVE-2025-6554](https://github.com/ghostn4444/POC-CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/ghostn4444/POC-CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/ghostn4444/POC-CVE-2025-6554.svg)

- [https://github.com/LordBheem/CVE-2025-6554](https://github.com/LordBheem/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/LordBheem/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/LordBheem/CVE-2025-6554.svg)

- [https://github.com/gmh5225/CVE-2025-6554](https://github.com/gmh5225/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2025-6554.svg)

## CVE-2025-6543
 Memory overflow vulnerability leading to unintended control flow and Denial of Service in NetScaler ADC and NetScaler Gateway when configured as Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server



- [https://github.com/fox-it/citrix-netscaler-triage](https://github.com/fox-it/citrix-netscaler-triage) :  ![starts](https://img.shields.io/github/stars/fox-it/citrix-netscaler-triage.svg) ![forks](https://img.shields.io/github/forks/fox-it/citrix-netscaler-triage.svg)

- [https://github.com/abrewer251/CVE-2025-6543_CitrixNetScaler_PoC](https://github.com/abrewer251/CVE-2025-6543_CitrixNetScaler_PoC) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-6543_CitrixNetScaler_PoC.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-6543_CitrixNetScaler_PoC.svg)

- [https://github.com/grupooruss/Citrix-cve-2025-6543](https://github.com/grupooruss/Citrix-cve-2025-6543) :  ![starts](https://img.shields.io/github/stars/grupooruss/Citrix-cve-2025-6543.svg) ![forks](https://img.shields.io/github/forks/grupooruss/Citrix-cve-2025-6543.svg)

- [https://github.com/lex1010/CVE-2025-6543](https://github.com/lex1010/CVE-2025-6543) :  ![starts](https://img.shields.io/github/stars/lex1010/CVE-2025-6543.svg) ![forks](https://img.shields.io/github/forks/lex1010/CVE-2025-6543.svg)

## CVE-2025-6514
 mcp-remote is exposed to OS command injection when connecting to untrusted MCP servers due to crafted input from the authorization_endpoint response URL



- [https://github.com/Cyberency/CVE-2025-6514](https://github.com/Cyberency/CVE-2025-6514) :  ![starts](https://img.shields.io/github/stars/Cyberency/CVE-2025-6514.svg) ![forks](https://img.shields.io/github/forks/Cyberency/CVE-2025-6514.svg)

- [https://github.com/ChaseHCS/CVE-2025-6514](https://github.com/ChaseHCS/CVE-2025-6514) :  ![starts](https://img.shields.io/github/stars/ChaseHCS/CVE-2025-6514.svg) ![forks](https://img.shields.io/github/forks/ChaseHCS/CVE-2025-6514.svg)

## CVE-2025-6440
 The WooCommerce Designer Pro plugin for WordPress, used by the Pricom - Printing Company & Design Services WordPress theme, is vulnerable to arbitrary file uploads due to missing file type validation in the 'wcdp_save_canvas_design_ajax' function in all versions up to, and including, 1.9.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Pwdnx1337/CVE-2025-6440](https://github.com/Pwdnx1337/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/Pwdnx1337/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/Pwdnx1337/CVE-2025-6440.svg)

## CVE-2025-6384
 Improper Control of Dynamically-Managed Code Resources vulnerability in Crafter Studio of CrafterCMS allows authenticated developers to execute OS commands via Groovy Sandbox Bypass.

By inserting malicious Groovy elements, an attacker may bypass Sandbox restrictions and obtain RCE (Remote Code Execution).

This issue affects CrafterCMS: from 4.0.0 through 4.2.2.



- [https://github.com/mbadanoiu/CVE-2025-6384](https://github.com/mbadanoiu/CVE-2025-6384) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2025-6384.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2025-6384.svg)

- [https://github.com/maestro-ant/CrafterCMS-CVE-2025-6384](https://github.com/maestro-ant/CrafterCMS-CVE-2025-6384) :  ![starts](https://img.shields.io/github/stars/maestro-ant/CrafterCMS-CVE-2025-6384.svg) ![forks](https://img.shields.io/github/forks/maestro-ant/CrafterCMS-CVE-2025-6384.svg)

## CVE-2025-6335
 A vulnerability was found in DedeCMS up to 5.7.2 and classified as critical. This issue affects some unknown processing of the file /include/dedetag.class.php of the component Template Handler. The manipulation of the argument notes leads to command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/jujubooom/CVE-2025-6335](https://github.com/jujubooom/CVE-2025-6335) :  ![starts](https://img.shields.io/github/stars/jujubooom/CVE-2025-6335.svg) ![forks](https://img.shields.io/github/forks/jujubooom/CVE-2025-6335.svg)

## CVE-2025-6220
 The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'save_options' function in all versions up to, and including, 3.5.12. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/d0n601/CVE-2025-6220](https://github.com/d0n601/CVE-2025-6220) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-6220.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-6220.svg)

## CVE-2025-6218
 RARLAB WinRAR Directory Traversal Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of RARLAB WinRAR. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the handling of file paths within archive files. A crafted file path can cause the process to traverse to unintended directories. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-27198.



- [https://github.com/skimask1690/CVE-2025-6218-POC](https://github.com/skimask1690/CVE-2025-6218-POC) :  ![starts](https://img.shields.io/github/stars/skimask1690/CVE-2025-6218-POC.svg) ![forks](https://img.shields.io/github/forks/skimask1690/CVE-2025-6218-POC.svg)

- [https://github.com/speinador/CVE-2025-6218_WinRAR](https://github.com/speinador/CVE-2025-6218_WinRAR) :  ![starts](https://img.shields.io/github/stars/speinador/CVE-2025-6218_WinRAR.svg) ![forks](https://img.shields.io/github/forks/speinador/CVE-2025-6218_WinRAR.svg)

- [https://github.com/ignis-sec/CVE-2025-6218](https://github.com/ignis-sec/CVE-2025-6218) :  ![starts](https://img.shields.io/github/stars/ignis-sec/CVE-2025-6218.svg) ![forks](https://img.shields.io/github/forks/ignis-sec/CVE-2025-6218.svg)

- [https://github.com/mulwareX/CVE-2025-6218-POC](https://github.com/mulwareX/CVE-2025-6218-POC) :  ![starts](https://img.shields.io/github/stars/mulwareX/CVE-2025-6218-POC.svg) ![forks](https://img.shields.io/github/forks/mulwareX/CVE-2025-6218-POC.svg)

- [https://github.com/absholi7ly/CVE-2025-6218-WinRAR-Directory-Traversal-RCE](https://github.com/absholi7ly/CVE-2025-6218-WinRAR-Directory-Traversal-RCE) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2025-6218-WinRAR-Directory-Traversal-RCE.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2025-6218-WinRAR-Directory-Traversal-RCE.svg)

## CVE-2025-6202
 Vulnerability in SK Hynix DDR5 on x86 allows a local attacker to trigger Rowhammer bit flips impacting the Hardware Integrity and the system's security. This issue affects DDR5: DIMMs produced from 2021-1 until 2024-12.



- [https://github.com/demining/Phoenix-Rowhammer-Attack-CVE-2025-6202](https://github.com/demining/Phoenix-Rowhammer-Attack-CVE-2025-6202) :  ![starts](https://img.shields.io/github/stars/demining/Phoenix-Rowhammer-Attack-CVE-2025-6202.svg) ![forks](https://img.shields.io/github/forks/demining/Phoenix-Rowhammer-Attack-CVE-2025-6202.svg)

## CVE-2025-6169
 The WIMP website co-construction management platform from HAMASTAR Technology has a SQL Injection vulnerability, allowing unauthenticated remote attackers to inject arbitrary SQL commands to read, modify, and delete database contents.



- [https://github.com/Yuri08loveElaina/CVE_2025_6169](https://github.com/Yuri08loveElaina/CVE_2025_6169) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_6169.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_6169.svg)

## CVE-2025-6130
 A vulnerability, which was classified as critical, has been found in TOTOLINK EX1200T 4.1.2cu.5232_B20210713. This issue affects some unknown processing of the file /boafrm/formStats of the component HTTP POST Request Handler. The manipulation leads to buffer overflow. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/pentastic-be/CVE-2025-61304](https://github.com/pentastic-be/CVE-2025-61304) :  ![starts](https://img.shields.io/github/stars/pentastic-be/CVE-2025-61304.svg) ![forks](https://img.shields.io/github/forks/pentastic-be/CVE-2025-61304.svg)

## CVE-2025-6091
 A vulnerability was found in H3C GR-3000AX V100R007L50. It has been classified as critical. Affected is the function UpdateWanParamsMulti/UpdateIpv6Params of the file /routing/goform/aspForm. The manipulation of the argument param leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor confirms the existence of this issue. Because they assess the risk as low, they do not have immediate plans for remediation.



- [https://github.com/Mp-97/CVE-2025-60910](https://github.com/Mp-97/CVE-2025-60910) :  ![starts](https://img.shields.io/github/stars/Mp-97/CVE-2025-60910.svg) ![forks](https://img.shields.io/github/forks/Mp-97/CVE-2025-60910.svg)

## CVE-2025-6085
 The Make Connector plugin for WordPress is vulnerable to arbitrary file uploads due to misconfigured file type validation in the 'upload_media' function in all versions up to, and including, 1.5.10. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/d0n601/CVE-2025-6085](https://github.com/d0n601/CVE-2025-6085) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-6085.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-6085.svg)

## CVE-2025-6083
 In ExtremeCloud Universal ZTNA, a syntax error in the 'searchKeyword' condition caused queries to bypass the owner_id filter. This issue may allow users to search data across the entire table instead of being restricted to their specific owner_id.



- [https://github.com/Yuri08loveElaina/CVE_2025_6083](https://github.com/Yuri08loveElaina/CVE_2025_6083) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_6083.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_6083.svg)

## CVE-2025-6082
 The Birth Chart Compatibility plugin for WordPress is vulnerable to Full Path Disclosure in all versions up to, and including, 2.0. This is due to insufficient protection against directly accessing the plugin's index.php file, which causes an error exposing the full path. This makes it possible for unauthenticated attackers to retrieve the full path of the web application, which can be used to aid other attacks. The information displayed is not useful on its own, and requires another vulnerability to be present for damage to an affected website.



- [https://github.com/byteReaper77/CVE-2025-6082](https://github.com/byteReaper77/CVE-2025-6082) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-6082.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-6082.svg)

## CVE-2025-6075
 If the value passed to os.path.expandvars() is user-controlled a 
performance degradation is possible when expanding environment 
variables.



- [https://github.com/zer0matt/CVE-2025-60752](https://github.com/zer0matt/CVE-2025-60752) :  ![starts](https://img.shields.io/github/stars/zer0matt/CVE-2025-60752.svg) ![forks](https://img.shields.io/github/forks/zer0matt/CVE-2025-60752.svg)

## CVE-2025-6073
 Stack-based Buffer Overflow vulnerability in ABB RMC-100, ABB RMC-100 LITE.

When the REST interface is enabled by the user, and an attacker gains access to
the control network, and user/password broker authentication is enabled, and
CVE-2025-6074 is exploited, the attacker can overflow the buffer for username or
password.




This issue affects RMC-100: from 2105457-043 through 2105457-045; RMC-100 LITE: from 2106229-015 through 2106229-016.



- [https://github.com/WinDyAlphA/CVE-2025-60736](https://github.com/WinDyAlphA/CVE-2025-60736) :  ![starts](https://img.shields.io/github/stars/WinDyAlphA/CVE-2025-60736.svg) ![forks](https://img.shields.io/github/forks/WinDyAlphA/CVE-2025-60736.svg)

## CVE-2025-6070
 The Restrict File Access plugin for WordPress is vulnerable to Directory Traversal in all versions up to, and including, 1.1.2 via the output() function. This makes it possible for authenticated attackers, with Subscriber-level access and above, to read the contents of arbitrary files on the server, which can contain sensitive information.



- [https://github.com/Yuri08loveElaina/CVE_2025_6070](https://github.com/Yuri08loveElaina/CVE_2025_6070) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_6070.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_6070.svg)

## CVE-2025-6065
 The Image Resizer On The Fly plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the 'delete' task in all versions up to, and including, 1.1. This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php).



- [https://github.com/Yuri08loveElaina/CVE_2025_6065](https://github.com/Yuri08loveElaina/CVE_2025_6065) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_6065.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_6065.svg)

## CVE-2025-6058
 The WPBookit plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the image_upload_handle() function hooked via the 'add_booking_type' route in all versions up to, and including, 1.0.4. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2025-6058](https://github.com/Nxploited/CVE-2025-6058) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-6058.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-6058.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-6058](https://github.com/0xgh057r3c0n/CVE-2025-6058) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-6058.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-6058.svg)

- [https://github.com/JayVillain/Scan-CVE-2025-6058](https://github.com/JayVillain/Scan-CVE-2025-6058) :  ![starts](https://img.shields.io/github/stars/JayVillain/Scan-CVE-2025-6058.svg) ![forks](https://img.shields.io/github/forks/JayVillain/Scan-CVE-2025-6058.svg)

## CVE-2025-6050
 Mezzanine CMS, in versions prior to 6.1.1, contains a Stored Cross-Site Scripting (XSS) vulnerability in the admin interface. The vulnerability exists in the "displayable_links_js" function, which fails to properly sanitize blog post titles before including them in JSON responses served via "/admin/displayable_links.js". An authenticated admin user can create a blog post with a malicious JavaScript payload in the title field, then trick another admin user into clicking a direct link to the "/admin/displayable_links.js" endpoint, causing the malicious script to execute in their browser.



- [https://github.com/H4zaz/CVE-2025-60503](https://github.com/H4zaz/CVE-2025-60503) :  ![starts](https://img.shields.io/github/stars/H4zaz/CVE-2025-60503.svg) ![forks](https://img.shields.io/github/forks/H4zaz/CVE-2025-60503.svg)

## CVE-2025-6042
 The Lisfinity Core - Lisfinity Core plugin used for pebas® Lisfinity WordPress theme plugin for WordPress is vulnerable to privilege escalation in all versions up to, and including, 1.4.0. This is due to the plugin assigning the editor role by default. While limitations with respect to capabilities are put in place, use of the API is not restricted. This vulnerability can be leveraged together with CVE-2025-6038 to obtain admin privileges.



- [https://github.com/Zephyr1ng/CVE-2025-60423](https://github.com/Zephyr1ng/CVE-2025-60423) :  ![starts](https://img.shields.io/github/stars/Zephyr1ng/CVE-2025-60423.svg) ![forks](https://img.shields.io/github/forks/Zephyr1ng/CVE-2025-60423.svg)

## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.



- [https://github.com/guinea-offensive-security/CVE-2025-6019](https://github.com/guinea-offensive-security/CVE-2025-6019) :  ![starts](https://img.shields.io/github/stars/guinea-offensive-security/CVE-2025-6019.svg) ![forks](https://img.shields.io/github/forks/guinea-offensive-security/CVE-2025-6019.svg)

- [https://github.com/And-oss/CVE-2025-6019-exploit](https://github.com/And-oss/CVE-2025-6019-exploit) :  ![starts](https://img.shields.io/github/stars/And-oss/CVE-2025-6019-exploit.svg) ![forks](https://img.shields.io/github/forks/And-oss/CVE-2025-6019-exploit.svg)

- [https://github.com/dreysanox/CVE-2025-6018_Poc](https://github.com/dreysanox/CVE-2025-6018_Poc) :  ![starts](https://img.shields.io/github/stars/dreysanox/CVE-2025-6018_Poc.svg) ![forks](https://img.shields.io/github/forks/dreysanox/CVE-2025-6018_Poc.svg)

- [https://github.com/neko205-mx/CVE-2025-6019_Exploit](https://github.com/neko205-mx/CVE-2025-6019_Exploit) :  ![starts](https://img.shields.io/github/stars/neko205-mx/CVE-2025-6019_Exploit.svg) ![forks](https://img.shields.io/github/forks/neko205-mx/CVE-2025-6019_Exploit.svg)

- [https://github.com/harshitvarma05/CVE-2025-6019](https://github.com/harshitvarma05/CVE-2025-6019) :  ![starts](https://img.shields.io/github/stars/harshitvarma05/CVE-2025-6019.svg) ![forks](https://img.shields.io/github/forks/harshitvarma05/CVE-2025-6019.svg)

- [https://github.com/mistrustt/PAM-UDisks-PrivEsc-Metasploit](https://github.com/mistrustt/PAM-UDisks-PrivEsc-Metasploit) :  ![starts](https://img.shields.io/github/stars/mistrustt/PAM-UDisks-PrivEsc-Metasploit.svg) ![forks](https://img.shields.io/github/forks/mistrustt/PAM-UDisks-PrivEsc-Metasploit.svg)

## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.



- [https://github.com/ibrahmsql/CVE-2025-6018](https://github.com/ibrahmsql/CVE-2025-6018) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2025-6018.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2025-6018.svg)

- [https://github.com/dreysanox/CVE-2025-6018_Poc](https://github.com/dreysanox/CVE-2025-6018_Poc) :  ![starts](https://img.shields.io/github/stars/dreysanox/CVE-2025-6018_Poc.svg) ![forks](https://img.shields.io/github/forks/dreysanox/CVE-2025-6018_Poc.svg)

- [https://github.com/iamgithubber/CVE-2025-6018-19-exploit](https://github.com/iamgithubber/CVE-2025-6018-19-exploit) :  ![starts](https://img.shields.io/github/stars/iamgithubber/CVE-2025-6018-19-exploit.svg) ![forks](https://img.shields.io/github/forks/iamgithubber/CVE-2025-6018-19-exploit.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-6018](https://github.com/B1ack4sh/Blackash-CVE-2025-6018) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-6018.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-6018.svg)

- [https://github.com/mistrustt/PAM-UDisks-PrivEsc-Metasploit](https://github.com/mistrustt/PAM-UDisks-PrivEsc-Metasploit) :  ![starts](https://img.shields.io/github/stars/mistrustt/PAM-UDisks-PrivEsc-Metasploit.svg) ![forks](https://img.shields.io/github/forks/mistrustt/PAM-UDisks-PrivEsc-Metasploit.svg)

## CVE-2025-5964
 A path traversal issue in the API endpoint in M-Files Server before version 25.6.14925.0 allows an authenticated user to read files in the server.



- [https://github.com/byteReaper77/CVE-2025-5964-](https://github.com/byteReaper77/CVE-2025-5964-) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-5964-.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-5964-.svg)

## CVE-2025-5961
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'wpvivid_upload_import_files' function in all versions up to, and including, 0.9.116. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible. NOTE: Uploaded files are only accessible on WordPress instances running on the NGINX web server as the existing .htaccess within the target file upload folder prevents access on Apache servers.



- [https://github.com/Nxploited/CVE-2025-5961](https://github.com/Nxploited/CVE-2025-5961) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5961.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5961.svg)

- [https://github.com/d0n601/CVE-2025-5961](https://github.com/d0n601/CVE-2025-5961) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-5961.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-5961.svg)

## CVE-2025-5947
 The Service Finder Bookings plugin for WordPress is vulnerable to privilege escalation via authentication bypass in all versions up to, and including, 6.0. This is due to the plugin not properly validating a user's cookie value prior to logging them in through the service_finder_switch_back() function. This makes it possible for unauthenticated attackers to login as any user including admins.



- [https://github.com/NightlyAudit/CVE-2025-5947](https://github.com/NightlyAudit/CVE-2025-5947) :  ![starts](https://img.shields.io/github/stars/NightlyAudit/CVE-2025-5947.svg) ![forks](https://img.shields.io/github/forks/NightlyAudit/CVE-2025-5947.svg)

- [https://github.com/M4rgs/CVE-2025-5947_Exploit](https://github.com/M4rgs/CVE-2025-5947_Exploit) :  ![starts](https://img.shields.io/github/stars/M4rgs/CVE-2025-5947_Exploit.svg) ![forks](https://img.shields.io/github/forks/M4rgs/CVE-2025-5947_Exploit.svg)

## CVE-2025-5840
 A vulnerability, which was classified as critical, was found in SourceCodester Client Database Management System 1.0. This affects an unknown part of the file /user_update_customer_order.php. The manipulation of the argument uploaded_file leads to unrestricted upload. It is possible to initiate the attack remotely.



- [https://github.com/haxerr9/CVE-2025-5840](https://github.com/haxerr9/CVE-2025-5840) :  ![starts](https://img.shields.io/github/stars/haxerr9/CVE-2025-5840.svg) ![forks](https://img.shields.io/github/forks/haxerr9/CVE-2025-5840.svg)

## CVE-2025-5815
 The Traffic Monitor plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the tfcm_maybe_set_bot_flags() function in all versions up to, and including, 3.2.2. This makes it possible for unauthenticated attackers to disabled bot logging.



- [https://github.com/RootHarpy/CVE-2025-5815-Nuclei-Template](https://github.com/RootHarpy/CVE-2025-5815-Nuclei-Template) :  ![starts](https://img.shields.io/github/stars/RootHarpy/CVE-2025-5815-Nuclei-Template.svg) ![forks](https://img.shields.io/github/forks/RootHarpy/CVE-2025-5815-Nuclei-Template.svg)

## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server



- [https://github.com/fox-it/citrix-netscaler-triage](https://github.com/fox-it/citrix-netscaler-triage) :  ![starts](https://img.shields.io/github/stars/fox-it/citrix-netscaler-triage.svg) ![forks](https://img.shields.io/github/forks/fox-it/citrix-netscaler-triage.svg)

- [https://github.com/win3zz/CVE-2025-5777](https://github.com/win3zz/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/win3zz/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/win3zz/CVE-2025-5777.svg)

- [https://github.com/bughuntar/CVE-2025-5777](https://github.com/bughuntar/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/bughuntar/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/bughuntar/CVE-2025-5777.svg)

- [https://github.com/mingshenhk/CitrixBleed-2-CVE-2025-5777-PoC-](https://github.com/mingshenhk/CitrixBleed-2-CVE-2025-5777-PoC-) :  ![starts](https://img.shields.io/github/stars/mingshenhk/CitrixBleed-2-CVE-2025-5777-PoC-.svg) ![forks](https://img.shields.io/github/forks/mingshenhk/CitrixBleed-2-CVE-2025-5777-PoC-.svg)

- [https://github.com/Chocapikk/CVE-2025-5777](https://github.com/Chocapikk/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-5777.svg)

- [https://github.com/soltanali0/CVE-2025-5777-Exploit](https://github.com/soltanali0/CVE-2025-5777-Exploit) :  ![starts](https://img.shields.io/github/stars/soltanali0/CVE-2025-5777-Exploit.svg) ![forks](https://img.shields.io/github/forks/soltanali0/CVE-2025-5777-Exploit.svg)

- [https://github.com/ndr-repo/CVE-2025-5777](https://github.com/ndr-repo/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/ndr-repo/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/ndr-repo/CVE-2025-5777.svg)

- [https://github.com/Shivshantp/CVE-2025-5777-TrendMicro-ApexCentral-RCE](https://github.com/Shivshantp/CVE-2025-5777-TrendMicro-ApexCentral-RCE) :  ![starts](https://img.shields.io/github/stars/Shivshantp/CVE-2025-5777-TrendMicro-ApexCentral-RCE.svg) ![forks](https://img.shields.io/github/forks/Shivshantp/CVE-2025-5777-TrendMicro-ApexCentral-RCE.svg)

- [https://github.com/nocerainfosec/cve-2025-5777](https://github.com/nocerainfosec/cve-2025-5777) :  ![starts](https://img.shields.io/github/stars/nocerainfosec/cve-2025-5777.svg) ![forks](https://img.shields.io/github/forks/nocerainfosec/cve-2025-5777.svg)

- [https://github.com/orange0Mint/CitrixBleed-2-CVE-2025-5777](https://github.com/orange0Mint/CitrixBleed-2-CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/orange0Mint/CitrixBleed-2-CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/orange0Mint/CitrixBleed-2-CVE-2025-5777.svg)

- [https://github.com/cyberleelawat/ExploitVeer](https://github.com/cyberleelawat/ExploitVeer) :  ![starts](https://img.shields.io/github/stars/cyberleelawat/ExploitVeer.svg) ![forks](https://img.shields.io/github/forks/cyberleelawat/ExploitVeer.svg)

- [https://github.com/RickGeex/CVE-2025-5777-CitrixBleed](https://github.com/RickGeex/CVE-2025-5777-CitrixBleed) :  ![starts](https://img.shields.io/github/stars/RickGeex/CVE-2025-5777-CitrixBleed.svg) ![forks](https://img.shields.io/github/forks/RickGeex/CVE-2025-5777-CitrixBleed.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-5777](https://github.com/0xgh057r3c0n/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-5777.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-5777](https://github.com/B1ack4sh/Blackash-CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-5777.svg)

- [https://github.com/FrenzisRed/CVE-2025-5777](https://github.com/FrenzisRed/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/FrenzisRed/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/FrenzisRed/CVE-2025-5777.svg)

- [https://github.com/SleepNotF0und/CVE-2025-5777](https://github.com/SleepNotF0und/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/SleepNotF0und/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/SleepNotF0und/CVE-2025-5777.svg)

- [https://github.com/idobarel/CVE-2025-5777](https://github.com/idobarel/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/idobarel/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/idobarel/CVE-2025-5777.svg)

- [https://github.com/rob0tstxt/POC-CVE-2025-5777](https://github.com/rob0tstxt/POC-CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/rob0tstxt/POC-CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/rob0tstxt/POC-CVE-2025-5777.svg)

- [https://github.com/RaR1991/citrix_bleed_2](https://github.com/RaR1991/citrix_bleed_2) :  ![starts](https://img.shields.io/github/stars/RaR1991/citrix_bleed_2.svg) ![forks](https://img.shields.io/github/forks/RaR1991/citrix_bleed_2.svg)

- [https://github.com/below0day/Honeypot-Logs-CVE-2025-5777](https://github.com/below0day/Honeypot-Logs-CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/below0day/Honeypot-Logs-CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/below0day/Honeypot-Logs-CVE-2025-5777.svg)

- [https://github.com/rootxsushant/Citrix-NetScaler-Memory-Leak-CVE-2025-5777](https://github.com/rootxsushant/Citrix-NetScaler-Memory-Leak-CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/rootxsushant/Citrix-NetScaler-Memory-Leak-CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/rootxsushant/Citrix-NetScaler-Memory-Leak-CVE-2025-5777.svg)

## CVE-2025-5755
 A vulnerability was found in SourceCodester Open Source Clinic Management System 1.0. It has been classified as critical. Affected is an unknown function of the file /email_config.php. The manipulation of the argument email leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/cyberajju/cve-2025-5755](https://github.com/cyberajju/cve-2025-5755) :  ![starts](https://img.shields.io/github/stars/cyberajju/cve-2025-5755.svg) ![forks](https://img.shields.io/github/forks/cyberajju/cve-2025-5755.svg)

## CVE-2025-5752
 The Vertical scroll image slideshow gallery plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘width’ parameter in all versions up to, and including, 11.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/songqb-xx/CVE-2025-57529](https://github.com/songqb-xx/CVE-2025-57529) :  ![starts](https://img.shields.io/github/stars/songqb-xx/CVE-2025-57529.svg) ![forks](https://img.shields.io/github/forks/songqb-xx/CVE-2025-57529.svg)

## CVE-2025-5701
 The HyperComments plugin for WordPress is vulnerable to unauthorized modification of data that can lead to privilege escalation due to a missing capability check on the hc_request_handler function in all versions up to, and including, 1.2.2. This makes it possible for unauthenticated attackers to update arbitrary options on the WordPress site. This can be leveraged to update the default role for registration to administrator and enable user registration for attackers to gain administrative user access to a vulnerable site.



- [https://github.com/Nxploited/CVE-2025-5701](https://github.com/Nxploited/CVE-2025-5701) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5701.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5701.svg)

- [https://github.com/RandomRobbieBF/CVE-2025-5701](https://github.com/RandomRobbieBF/CVE-2025-5701) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-5701.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-5701.svg)

## CVE-2025-5677
 A vulnerability was found in Campcodes Online Recruitment Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /admin/ajax.php?action=save_application. The manipulation of the argument position_id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/RRespxwnss/CVE-2025-56771](https://github.com/RRespxwnss/CVE-2025-56771) :  ![starts](https://img.shields.io/github/stars/RRespxwnss/CVE-2025-56771.svg) ![forks](https://img.shields.io/github/forks/RRespxwnss/CVE-2025-56771.svg)

- [https://github.com/RRespxwnss/CVE-2025-56772](https://github.com/RRespxwnss/CVE-2025-56772) :  ![starts](https://img.shields.io/github/stars/RRespxwnss/CVE-2025-56772.svg) ![forks](https://img.shields.io/github/forks/RRespxwnss/CVE-2025-56772.svg)

## CVE-2025-5670
 A vulnerability, which was classified as critical, has been found in PHPGurukul Medical Card Generation System 1.0. This issue affects some unknown processing of the file /admin/manage-card.php. The manipulation of the argument ID leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/xkaneiki/rtty_CVE-2025-56708-CVE-2025-56709](https://github.com/xkaneiki/rtty_CVE-2025-56708-CVE-2025-56709) :  ![starts](https://img.shields.io/github/stars/xkaneiki/rtty_CVE-2025-56708-CVE-2025-56709.svg) ![forks](https://img.shields.io/github/forks/xkaneiki/rtty_CVE-2025-56708-CVE-2025-56709.svg)

## CVE-2025-5660
 A vulnerability, which was classified as critical, has been found in PHPGurukul Complaint Management System 2.0. Affected by this issue is some unknown functionality of the file /user/register-complaint.php. The manipulation of the argument noc leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/Userr404/CVE-2025-56605](https://github.com/Userr404/CVE-2025-56605) :  ![starts](https://img.shields.io/github/stars/Userr404/CVE-2025-56605.svg) ![forks](https://img.shields.io/github/forks/Userr404/CVE-2025-56605.svg)

## CVE-2025-5652
 A vulnerability, which was classified as critical, was found in PHPGurukul Complaint Management System 2.0. Affected is an unknown function of the file /admin/between-date-complaintreport.php. The manipulation of the argument fromdate/todate leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/Dong-hui-li/CVE-2025-56521andCVE-2025-56522](https://github.com/Dong-hui-li/CVE-2025-56521andCVE-2025-56522) :  ![starts](https://img.shields.io/github/stars/Dong-hui-li/CVE-2025-56521andCVE-2025-56522.svg) ![forks](https://img.shields.io/github/forks/Dong-hui-li/CVE-2025-56521andCVE-2025-56522.svg)

## CVE-2025-5650
 A vulnerability classified as critical was found in 1000projects Online Notice Board 1.0. This vulnerability affects unknown code of the file /register.php. The manipulation of the argument fname leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.



- [https://github.com/secxplorers/CVE-2025-56503](https://github.com/secxplorers/CVE-2025-56503) :  ![starts](https://img.shields.io/github/stars/secxplorers/CVE-2025-56503.svg) ![forks](https://img.shields.io/github/forks/secxplorers/CVE-2025-56503.svg)

## CVE-2025-5640
 A vulnerability was found in PX4-Autopilot 1.12.3. It has been classified as problematic. This affects the function MavlinkReceiver::handle_message_trajectory_representation_waypoints of the file mavlink_receiver.cpp of the component TRAJECTORY_REPRESENTATION_WAYPOINTS Message Handler. The manipulation leads to stack-based buffer overflow. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used.



- [https://github.com/mbanyamer/PX4-Military-UAV-Autopilot-1.12.3-Stack-Buffer-Overflow-Exploit-CVE-2025-5640-](https://github.com/mbanyamer/PX4-Military-UAV-Autopilot-1.12.3-Stack-Buffer-Overflow-Exploit-CVE-2025-5640-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/PX4-Military-UAV-Autopilot-1.12.3-Stack-Buffer-Overflow-Exploit-CVE-2025-5640-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/PX4-Military-UAV-Autopilot-1.12.3-Stack-Buffer-Overflow-Exploit-CVE-2025-5640-.svg)

## CVE-2025-5589
 The StreamWeasels Kick Integration plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘status-classic-offline-text’ parameter in all versions up to, and including, 1.1.3 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/terribledactyl/CVE-2025-55891](https://github.com/terribledactyl/CVE-2025-55891) :  ![starts](https://img.shields.io/github/stars/terribledactyl/CVE-2025-55891.svg) ![forks](https://img.shields.io/github/forks/terribledactyl/CVE-2025-55891.svg)

## CVE-2025-5585
 The SiteOrigin Widgets Bundle plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the `data-url` DOM Element Attribute in all versions up to, and including, 1.68.4 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/PushkarAyengar/CVE-2025-55854-PoC](https://github.com/PushkarAyengar/CVE-2025-55854-PoC) :  ![starts](https://img.shields.io/github/stars/PushkarAyengar/CVE-2025-55854-PoC.svg) ![forks](https://img.shields.io/github/forks/PushkarAyengar/CVE-2025-55854-PoC.svg)

## CVE-2025-5581
 A vulnerability was found in CodeAstro Real Estate Management System 1.0. It has been declared as critical. This vulnerability affects unknown code of the file /admin/index.php. The manipulation of the argument User leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/5qu1n7/CVE-2025-55817](https://github.com/5qu1n7/CVE-2025-55817) :  ![starts](https://img.shields.io/github/stars/5qu1n7/CVE-2025-55817.svg) ![forks](https://img.shields.io/github/forks/5qu1n7/CVE-2025-55817.svg)

## CVE-2025-5561
 A vulnerability was found in PHPGurukul Curfew e-Pass Management System 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /admin/view-pass-detail.php. The manipulation of the argument viewid leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/livepwn/CVE-2025-55616](https://github.com/livepwn/CVE-2025-55616) :  ![starts](https://img.shields.io/github/stars/livepwn/CVE-2025-55616.svg) ![forks](https://img.shields.io/github/forks/livepwn/CVE-2025-55616.svg)

## CVE-2025-5555
 A vulnerability has been found in Nixdorf Wincor PORT IO Driver up to 1.0.0.1. This affects the function sub_11100 in the library wnport.sys of the component IOCTL Handler. Such manipulation leads to stack-based buffer overflow. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used. Upgrading to version 3.0.0.1 is able to mitigate this issue. Upgrading the affected component is recommended. The vendor was contacted beforehand and was able to provide a patch very early.



- [https://github.com/aydin5245/CVE-2025-55555-CVE](https://github.com/aydin5245/CVE-2025-55555-CVE) :  ![starts](https://img.shields.io/github/stars/aydin5245/CVE-2025-55555-CVE.svg) ![forks](https://img.shields.io/github/forks/aydin5245/CVE-2025-55555-CVE.svg)

## CVE-2025-5534
 The ESV Bible Shortcode for WordPress plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'esv' shortcode in all versions up to, and including, 1.0.2 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/GoldenTicketLabs/CVE-2025-55349](https://github.com/GoldenTicketLabs/CVE-2025-55349) :  ![starts](https://img.shields.io/github/stars/GoldenTicketLabs/CVE-2025-55349.svg) ![forks](https://img.shields.io/github/forks/GoldenTicketLabs/CVE-2025-55349.svg)

## CVE-2025-5419
 Out of bounds read and write in V8 in Google Chrome prior to 137.0.7151.68 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/mistymntncop/CVE-2025-5419](https://github.com/mistymntncop/CVE-2025-5419) :  ![starts](https://img.shields.io/github/stars/mistymntncop/CVE-2025-5419.svg) ![forks](https://img.shields.io/github/forks/mistymntncop/CVE-2025-5419.svg)

- [https://github.com/itsShotgun/chrome_v8_cve_checker](https://github.com/itsShotgun/chrome_v8_cve_checker) :  ![starts](https://img.shields.io/github/stars/itsShotgun/chrome_v8_cve_checker.svg) ![forks](https://img.shields.io/github/forks/itsShotgun/chrome_v8_cve_checker.svg)

- [https://github.com/riemannj/CVE-2025-5419](https://github.com/riemannj/CVE-2025-5419) :  ![starts](https://img.shields.io/github/stars/riemannj/CVE-2025-5419.svg) ![forks](https://img.shields.io/github/forks/riemannj/CVE-2025-5419.svg)

## CVE-2025-5394
 The Alone – Charity Multipurpose Non-profit WordPress Theme theme for WordPress is vulnerable to arbitrary file uploads due to a missing capability check on the alone_import_pack_install_plugin() function in all versions up to, and including, 7.8.3. This makes it possible for unauthenticated attackers to upload zip files containing webshells disguised as plugins from remote locations to achieve remote code execution.



- [https://github.com/Nxploited/CVE-2025-5394](https://github.com/Nxploited/CVE-2025-5394) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5394.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5394.svg)

- [https://github.com/fokda-prodz/CVE-2025-5394](https://github.com/fokda-prodz/CVE-2025-5394) :  ![starts](https://img.shields.io/github/stars/fokda-prodz/CVE-2025-5394.svg) ![forks](https://img.shields.io/github/forks/fokda-prodz/CVE-2025-5394.svg)

- [https://github.com/Yucaerin/CVE-2025-5394](https://github.com/Yucaerin/CVE-2025-5394) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-5394.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-5394.svg)

## CVE-2025-5349
 Improper access control on the NetScaler Management Interface in NetScaler ADC and NetScaler Gateway



- [https://github.com/olimpiofreitas/CVE-2025-5349-Scanner](https://github.com/olimpiofreitas/CVE-2025-5349-Scanner) :  ![starts](https://img.shields.io/github/stars/olimpiofreitas/CVE-2025-5349-Scanner.svg) ![forks](https://img.shields.io/github/forks/olimpiofreitas/CVE-2025-5349-Scanner.svg)

## CVE-2025-5309
 The chat feature within Remote Support (RS) and Privileged Remote Access (PRA) is vulnerable to a Server-Side Template Injection vulnerability which can lead to remote code execution.



- [https://github.com/issamjr/CVE-2025-5309-Scanner](https://github.com/issamjr/CVE-2025-5309-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-5309-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-5309-Scanner.svg)

## CVE-2025-5304
 The PT Project Notebooks plugin for WordPress is vulnerable to Privilege Escalation due to missing authorization in the wpnb_pto_new_users_add() function in versions 1.0.0 through 1.1.3. This makes it possible for unauthenticated attackers to elevate their privileges to that of an administrator.



- [https://github.com/Nxploited/CVE-2025-5304](https://github.com/Nxploited/CVE-2025-5304) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5304.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5304.svg)

## CVE-2025-5288
 The REST API | Custom API Generator For Cross Platform And Import Export In WP plugin for WordPress is vulnerable to Privilege Escalation due to a missing capability check on the process_handler() function in versions 1.0.0 to 2.0.3. This makes it possible for unauthenticated attackers to POST an arbitrary import_api URL, import specially crafted JSON, and thereby create a new user with full Administrator privileges.



- [https://github.com/Nxploited/CVE-2025-5288](https://github.com/Nxploited/CVE-2025-5288) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5288.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5288.svg)

## CVE-2025-5287
 The Likes and Dislikes Plugin plugin for WordPress is vulnerable to SQL Injection via the 'post' parameter in all versions up to, and including, 1.0.0 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.



- [https://github.com/wiseep/CVE-2025-5287](https://github.com/wiseep/CVE-2025-5287) :  ![starts](https://img.shields.io/github/stars/wiseep/CVE-2025-5287.svg) ![forks](https://img.shields.io/github/forks/wiseep/CVE-2025-5287.svg)

- [https://github.com/Nxploited/CVE-2025-5287](https://github.com/Nxploited/CVE-2025-5287) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5287.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5287.svg)

- [https://github.com/RandomRobbieBF/CVE-2025-5287](https://github.com/RandomRobbieBF/CVE-2025-5287) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-5287.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-5287.svg)

- [https://github.com/RootHarpy/CVE-2025-5287](https://github.com/RootHarpy/CVE-2025-5287) :  ![starts](https://img.shields.io/github/stars/RootHarpy/CVE-2025-5287.svg) ![forks](https://img.shields.io/github/forks/RootHarpy/CVE-2025-5287.svg)

- [https://github.com/coramarcet/WordPressCVEExploitProject](https://github.com/coramarcet/WordPressCVEExploitProject) :  ![starts](https://img.shields.io/github/stars/coramarcet/WordPressCVEExploitProject.svg) ![forks](https://img.shields.io/github/forks/coramarcet/WordPressCVEExploitProject.svg)

## CVE-2025-5252
 A vulnerability was found in PHPGurukul News Portal Project 4.1. It has been declared as critical. This vulnerability affects unknown code of the file /admin/edit-subadmin.php. The manipulation of the argument emailid leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/aydin5245/CVE-2025-5252-CVE-ivanti](https://github.com/aydin5245/CVE-2025-5252-CVE-ivanti) :  ![starts](https://img.shields.io/github/stars/aydin5245/CVE-2025-5252-CVE-ivanti.svg) ![forks](https://img.shields.io/github/forks/aydin5245/CVE-2025-5252-CVE-ivanti.svg)

## CVE-2025-5241
 Overly Restrictive Account Lockout Mechanism vulnerability in Mitsubishi Electric Corporation MELSEC iQ-F Series allows a remote unauthenticated attacker to lockout legitimate users for a certain period by repeatedly attempting to login with incorrect passwords. The legitimate users will be unable to login until a certain period has passed after the lockout or until the product is reset.



- [https://github.com/GoldenTicketLabs/CVE-2025-52413](https://github.com/GoldenTicketLabs/CVE-2025-52413) :  ![starts](https://img.shields.io/github/stars/GoldenTicketLabs/CVE-2025-52413.svg) ![forks](https://img.shields.io/github/forks/GoldenTicketLabs/CVE-2025-52413.svg)

## CVE-2025-5239
 The Domain For Sale plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘class_name’ parameter in all versions up to, and including, 3.0.10 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/Userr404/CVE-2025-52399-SQLi-Institute-of-Current-Students](https://github.com/Userr404/CVE-2025-52399-SQLi-Institute-of-Current-Students) :  ![starts](https://img.shields.io/github/stars/Userr404/CVE-2025-52399-SQLi-Institute-of-Current-Students.svg) ![forks](https://img.shields.io/github/forks/Userr404/CVE-2025-52399-SQLi-Institute-of-Current-Students.svg)

- [https://github.com/gmh5225/CVE-2025-52399-SQLi-Institute-of-Current-Students](https://github.com/gmh5225/CVE-2025-52399-SQLi-Institute-of-Current-Students) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2025-52399-SQLi-Institute-of-Current-Students.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2025-52399-SQLi-Institute-of-Current-Students.svg)

## CVE-2025-5222
 A stack buffer overflow was found in Internationl components for unicode (ICU ). While running the genrb binary, the 'subtag' struct overflowed at the SRBRoot::addTag function. This issue may lead to memory corruption and local arbitrary code execution.



- [https://github.com/berkley4/icu-74-debian](https://github.com/berkley4/icu-74-debian) :  ![starts](https://img.shields.io/github/stars/berkley4/icu-74-debian.svg) ![forks](https://img.shields.io/github/forks/berkley4/icu-74-debian.svg)

## CVE-2025-5210
 A vulnerability has been found in PHPGurukul Employee Record Management System 1.3 and classified as critical. This vulnerability affects unknown code of the file /loginerms.php. The manipulation of the argument Email leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/changyaoyou/CVE-2025-52100](https://github.com/changyaoyou/CVE-2025-52100) :  ![starts](https://img.shields.io/github/stars/changyaoyou/CVE-2025-52100.svg) ![forks](https://img.shields.io/github/forks/changyaoyou/CVE-2025-52100.svg)

## CVE-2025-5209
 The Ivory Search  WordPress plugin before 5.5.10 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Cross-Site Scripting attacks even when unfiltered_html is disallowed



- [https://github.com/rwilsonecs/CVE-2025-52097](https://github.com/rwilsonecs/CVE-2025-52097) :  ![starts](https://img.shields.io/github/stars/rwilsonecs/CVE-2025-52097.svg) ![forks](https://img.shields.io/github/forks/rwilsonecs/CVE-2025-52097.svg)

## CVE-2025-5196
 A vulnerability has been found in Wing FTP Server up to 7.4.3 and classified as critical. Affected by this vulnerability is an unknown functionality of the component Lua Admin Console. The manipulation leads to execution with unnecessary privileges. The attack can be launched remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. Upgrading to version 7.4.4 is able to address this issue. It is recommended to upgrade the affected component. The vendor explains: "[W]e do not consider it as a security vulnerability, because the system admin in WingFTP has full permissions [...], but you can suggest the user run WingFTP service as Normal User rather than SYSTEM/Root, it will be safer."



- [https://github.com/Nouvexr/Wing-FTP-Server-7.4.4-RCE-Authenticated](https://github.com/Nouvexr/Wing-FTP-Server-7.4.4-RCE-Authenticated) :  ![starts](https://img.shields.io/github/stars/Nouvexr/Wing-FTP-Server-7.4.4-RCE-Authenticated.svg) ![forks](https://img.shields.io/github/forks/Nouvexr/Wing-FTP-Server-7.4.4-RCE-Authenticated.svg)

## CVE-2025-5182
 A vulnerability has been found in Summer Pearl Group Vacation Rental Management Platform up to 1.0.1 and classified as critical. This vulnerability affects unknown code of the component Listing Handler. The manipulation leads to authorization bypass. The attack can be initiated remotely. Upgrading to version 1.0.2 is able to address this issue. It is recommended to upgrade the affected component.



- [https://github.com/shk-mubashshir/CVE-2025-51820](https://github.com/shk-mubashshir/CVE-2025-51820) :  ![starts](https://img.shields.io/github/stars/shk-mubashshir/CVE-2025-51820.svg) ![forks](https://img.shields.io/github/forks/shk-mubashshir/CVE-2025-51820.svg)

## CVE-2025-5104
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.



- [https://github.com/0xMesh-X/CVE-2025-51046](https://github.com/0xMesh-X/CVE-2025-51046) :  ![starts](https://img.shields.io/github/stars/0xMesh-X/CVE-2025-51046.svg) ![forks](https://img.shields.io/github/forks/0xMesh-X/CVE-2025-51046.svg)

## CVE-2025-5095
 Burk Technology ARC Solo's password change mechanism can be utilized without proper 
authentication procedures, allowing an attacker to take over the device.
 A password change request can be sent directly to the device's HTTP 
endpoint without providing valid credentials. The system does not 
enforce proper authentication or session validation, allowing the 
password change to proceed without verifying the request's legitimacy.



- [https://github.com/TeteuXD2/CVE-2025-5095-POC](https://github.com/TeteuXD2/CVE-2025-5095-POC) :  ![starts](https://img.shields.io/github/stars/TeteuXD2/CVE-2025-5095-POC.svg) ![forks](https://img.shields.io/github/forks/TeteuXD2/CVE-2025-5095-POC.svg)

## CVE-2025-5058
 The eMagicOne Store Manager for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the set_image() function in all versions up to, and including, 1.2.5. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. This is only exploitable by unauthenticated attackers in default configurations where the the default password is left as 1:1, or where the attacker gains access to the credentials.



- [https://github.com/d0n601/CVE-2025-5058](https://github.com/d0n601/CVE-2025-5058) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-5058.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-5058.svg)

## CVE-2025-5054
 Race condition in Canonical apport up to and including 2.32.0 allows a local attacker to leak sensitive information via PID-reuse by leveraging namespaces.




When handling a crash, the function `_check_global_pid_and_forward`, which detects if the crashing process resided in a container, was being called before `consistency_checks`, which attempts to detect if the crashing process had been replaced. Because of this, if a process crashed and was quickly replaced with a containerized one, apport could be made to forward the core dump to the container, potentially leaking sensitive information. `consistency_checks` is now being called before `_check_global_pid_and_forward`. Additionally, given that the PID-reuse race condition cannot be reliably detected from userspace alone, crashes are only forwarded to containers if the kernel provided a pidfd, or if the crashing process was unprivileged (i.e., if dump mode == 1).



- [https://github.com/daryllundy/cve-2025-5054](https://github.com/daryllundy/cve-2025-5054) :  ![starts](https://img.shields.io/github/stars/daryllundy/cve-2025-5054.svg) ![forks](https://img.shields.io/github/forks/daryllundy/cve-2025-5054.svg)

## CVE-2025-5036
 A maliciously crafted RFA file, when linked or imported into Autodesk Revit, can force a Use-After-Free vulnerability. A malicious actor can leverage this vulnerability to cause a crash, read sensitive data, or execute arbitrary code in the context of the current process.



- [https://github.com/1h3ll/CVE2025-50366_CSRF_MAID_MANAGE-phpgurukul-CVE](https://github.com/1h3ll/CVE2025-50366_CSRF_MAID_MANAGE-phpgurukul-CVE) :  ![starts](https://img.shields.io/github/stars/1h3ll/CVE2025-50366_CSRF_MAID_MANAGE-phpgurukul-CVE.svg) ![forks](https://img.shields.io/github/forks/1h3ll/CVE2025-50366_CSRF_MAID_MANAGE-phpgurukul-CVE.svg)

- [https://github.com/Ch1keen/CVE-2025-50361](https://github.com/Ch1keen/CVE-2025-50361) :  ![starts](https://img.shields.io/github/stars/Ch1keen/CVE-2025-50361.svg) ![forks](https://img.shields.io/github/forks/Ch1keen/CVE-2025-50361.svg)

- [https://github.com/Ch1keen/CVE-2025-50360](https://github.com/Ch1keen/CVE-2025-50360) :  ![starts](https://img.shields.io/github/stars/Ch1keen/CVE-2025-50360.svg) ![forks](https://img.shields.io/github/forks/Ch1keen/CVE-2025-50360.svg)

- [https://github.com/1h3ll/CVE-2025-50363_BXSS_CVE](https://github.com/1h3ll/CVE-2025-50363_BXSS_CVE) :  ![starts](https://img.shields.io/github/stars/1h3ll/CVE-2025-50363_BXSS_CVE.svg) ![forks](https://img.shields.io/github/forks/1h3ll/CVE-2025-50363_BXSS_CVE.svg)

- [https://github.com/1h3ll/CVE-2025-50365_CSRF_DELETE_CATEGORY-phpgurukul-CVE](https://github.com/1h3ll/CVE-2025-50365_CSRF_DELETE_CATEGORY-phpgurukul-CVE) :  ![starts](https://img.shields.io/github/stars/1h3ll/CVE-2025-50365_CSRF_DELETE_CATEGORY-phpgurukul-CVE.svg) ![forks](https://img.shields.io/github/forks/1h3ll/CVE-2025-50365_CSRF_DELETE_CATEGORY-phpgurukul-CVE.svg)

- [https://github.com/1h3ll/CVE-2025-50364_CSRF_ADD_CATEGORY-phpgurukul-CVE](https://github.com/1h3ll/CVE-2025-50364_CSRF_ADD_CATEGORY-phpgurukul-CVE) :  ![starts](https://img.shields.io/github/stars/1h3ll/CVE-2025-50364_CSRF_ADD_CATEGORY-phpgurukul-CVE.svg) ![forks](https://img.shields.io/github/forks/1h3ll/CVE-2025-50364_CSRF_ADD_CATEGORY-phpgurukul-CVE.svg)

## CVE-2025-5025
 libcurl supports *pinning* of the server certificate public key for HTTPS transfers. Due to an omission, this check is not performed when connecting with QUIC for HTTP/3, when the TLS backend is wolfSSL. Documentation says the option works with wolfSSL, failing to specify that it does not for QUIC and HTTP/3. Since pinning makes the transfer succeed if the pin is fine, users could unwittingly connect to an impostor server without noticing.



- [https://github.com/KiPhuong/cve-2025-5025](https://github.com/KiPhuong/cve-2025-5025) :  ![starts](https://img.shields.io/github/stars/KiPhuong/cve-2025-5025.svg) ![forks](https://img.shields.io/github/forks/KiPhuong/cve-2025-5025.svg)

## CVE-2025-5000
 A vulnerability was found in Linksys FGW3000-AH and FGW3000-HK up to 1.0.17.000000. It has been classified as critical. This affects the function control_panel_sw of the file /cgi-bin/sysconf.cgi of the component HTTP POST Request Handler. The manipulation of the argument filename leads to command injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/adiivascu/CVE-2025-50000](https://github.com/adiivascu/CVE-2025-50000) :  ![starts](https://img.shields.io/github/stars/adiivascu/CVE-2025-50000.svg) ![forks](https://img.shields.io/github/forks/adiivascu/CVE-2025-50000.svg)

## CVE-2025-4866
 A vulnerability was found in weibocom rill-flow 0.1.18. It has been classified as critical. Affected is an unknown function of the component Management Console. The manipulation leads to code injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/bloodcode-spasov/ble-cve2025-attack-new-version](https://github.com/bloodcode-spasov/ble-cve2025-attack-new-version) :  ![starts](https://img.shields.io/github/stars/bloodcode-spasov/ble-cve2025-attack-new-version.svg) ![forks](https://img.shields.io/github/forks/bloodcode-spasov/ble-cve2025-attack-new-version.svg)

## CVE-2025-4840
 The inprosysmedia-likes-dislikes-post WordPress plugin through 1.0.0 does not properly sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection



- [https://github.com/RandomRobbieBF/CVE-2025-4840](https://github.com/RandomRobbieBF/CVE-2025-4840) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-4840.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-4840.svg)

## CVE-2025-4822
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Bayraktar Solar Energies ScadaWatt Otopilot allows SQL Injection.This issue affects ScadaWatt Otopilot: before 27.05.2025.



- [https://github.com/sahici/CVE-2025-4822](https://github.com/sahici/CVE-2025-4822) :  ![starts](https://img.shields.io/github/stars/sahici/CVE-2025-4822.svg) ![forks](https://img.shields.io/github/forks/sahici/CVE-2025-4822.svg)

## CVE-2025-4796
 The Eventin plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 4.0.34. This is due to the plugin not properly validating a user's identity or capability prior to updating their details like email in the 'Eventin\Speaker\Api\SpeakerController::update_item' function. This makes it possible for unauthenticated attackers with contributor-level and above permissions to change arbitrary user's email addresses, including administrators, and leverage that to reset the user's password and gain access to their account.



- [https://github.com/Nxploited/CVE-2025-4796](https://github.com/Nxploited/CVE-2025-4796) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-4796.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-4796.svg)

## CVE-2025-4784
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Moderec Tourtella allows SQL Injection.This issue affects Tourtella: before 26.05.2025.



- [https://github.com/sahici/CVE-2025-4784](https://github.com/sahici/CVE-2025-4784) :  ![starts](https://img.shields.io/github/stars/sahici/CVE-2025-4784.svg) ![forks](https://img.shields.io/github/forks/sahici/CVE-2025-4784.svg)

## CVE-2025-4781
 A vulnerability classified as critical has been found in PHPGurukul Park Ticketing Management System 2.0. Affected is an unknown function of the file /forgot-password.php. The manipulation of the argument email/contactno leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/ptrstr/CVE-2025-47810](https://github.com/ptrstr/CVE-2025-47810) :  ![starts](https://img.shields.io/github/stars/ptrstr/CVE-2025-47810.svg) ![forks](https://img.shields.io/github/forks/ptrstr/CVE-2025-47810.svg)

## CVE-2025-4688
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in BGS Interactive SINAV.LINK Exam Result Module allows SQL Injection.This issue affects SINAV.LINK Exam Result Module: before 1.2.



- [https://github.com/sahici/CVE-2025-4688](https://github.com/sahici/CVE-2025-4688) :  ![starts](https://img.shields.io/github/stars/sahici/CVE-2025-4688.svg) ![forks](https://img.shields.io/github/forks/sahici/CVE-2025-4688.svg)

## CVE-2025-4664
 Insufficient policy enforcement in Loader in Google Chrome prior to 136.0.7103.113 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/Leviticus-Triage/ChromSploit-Framework](https://github.com/Leviticus-Triage/ChromSploit-Framework) :  ![starts](https://img.shields.io/github/stars/Leviticus-Triage/ChromSploit-Framework.svg) ![forks](https://img.shields.io/github/forks/Leviticus-Triage/ChromSploit-Framework.svg)

- [https://github.com/amalmurali47/cve-2025-4664](https://github.com/amalmurali47/cve-2025-4664) :  ![starts](https://img.shields.io/github/stars/amalmurali47/cve-2025-4664.svg) ![forks](https://img.shields.io/github/forks/amalmurali47/cve-2025-4664.svg)

- [https://github.com/speinador/CVE-2025-4664](https://github.com/speinador/CVE-2025-4664) :  ![starts](https://img.shields.io/github/stars/speinador/CVE-2025-4664.svg) ![forks](https://img.shields.io/github/forks/speinador/CVE-2025-4664.svg)

## CVE-2025-4660
 A remote code execution vulnerability exists in the Windows agent component of SecureConnector due to improper access controls on a named pipe. The pipe is accessible to the Everyone group and does not restrict remote connections, allowing any network-based attacker to connect without authentication. By interacting with this pipe, an attacker can redirect the agent to communicate with a rogue server that can issue commands via the SecureConnector Agent. 



This does not impact Linux or OSX Secure Connector.



- [https://github.com/NetSPI/CVE-2025-4660](https://github.com/NetSPI/CVE-2025-4660) :  ![starts](https://img.shields.io/github/stars/NetSPI/CVE-2025-4660.svg) ![forks](https://img.shields.io/github/forks/NetSPI/CVE-2025-4660.svg)

## CVE-2025-4632
 Improper limitation of a pathname to a restricted directory vulnerability in Samsung MagicINFO 9 Server version before 21.1052 allows attackers to write arbitrary file as system authority.



- [https://github.com/MantisToboggan-git/CVE-2025-4632-POC](https://github.com/MantisToboggan-git/CVE-2025-4632-POC) :  ![starts](https://img.shields.io/github/stars/MantisToboggan-git/CVE-2025-4632-POC.svg) ![forks](https://img.shields.io/github/forks/MantisToboggan-git/CVE-2025-4632-POC.svg)

## CVE-2025-4631
 The Profitori plugin for WordPress is vulnerable to Privilege Escalation due to a missing capability check on the stocktend_object endpoint in versions 2.0.6.0 to 2.1.1.3. This makes it possible to trigger the save_object_as_user() function for objects whose '_datatype' is set to 'users',. This allows unauthenticated attackers to write arbitrary strings straight into the user’s wp_capabilities meta field, potentially elevating the privileges of an existing user account or a newly created one to that of an administrator.



- [https://github.com/Nxploited/CVE-2025-4631](https://github.com/Nxploited/CVE-2025-4631) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-4631.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-4631.svg)

## CVE-2025-4614
 An information disclosure vulnerability in Palo Alto Networks PAN-OS® software enables an authenticated administrator to view session tokens of users authenticated to the firewall web UI. This may allow impersonation of users whose session tokens are leaked.  

The security risk posed by this issue is significantly minimized when CLI access is restricted to a limited group of administrators.

Cloud NGFW and Prisma® Access are not affected by this vulnerability.



- [https://github.com/AugustusSploits/CVE-2025-46142](https://github.com/AugustusSploits/CVE-2025-46142) :  ![starts](https://img.shields.io/github/stars/AugustusSploits/CVE-2025-46142.svg) ![forks](https://img.shields.io/github/forks/AugustusSploits/CVE-2025-46142.svg)

## CVE-2025-4611
 The Slim SEO – Fast & Automated WordPress SEO Plugin plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's slim_seo_breadcrumbs shortcode in all versions up to, and including, 4.5.3 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/x6vrn/CVE-2025-4611-PoC](https://github.com/x6vrn/CVE-2025-4611-PoC) :  ![starts](https://img.shields.io/github/stars/x6vrn/CVE-2025-4611-PoC.svg) ![forks](https://img.shields.io/github/forks/x6vrn/CVE-2025-4611-PoC.svg)

## CVE-2025-4606
 The Sala - Startup & SaaS WordPress Theme theme for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 1.1.4. This is due to the theme not properly validating a user's identity prior to updating their details like password. This makes it possible for unauthenticated attackers to change arbitrary user's passwords, including administrators, and leverage that to gain access to their account.



- [https://github.com/Yucaerin/CVE-2025-4606](https://github.com/Yucaerin/CVE-2025-4606) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-4606.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-4606.svg)

- [https://github.com/UcenHaxor07/CVE-2025-4606](https://github.com/UcenHaxor07/CVE-2025-4606) :  ![starts](https://img.shields.io/github/stars/UcenHaxor07/CVE-2025-4606.svg) ![forks](https://img.shields.io/github/forks/UcenHaxor07/CVE-2025-4606.svg)

## CVE-2025-4603
 The eMagicOne Store Manager for WooCommerce plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the delete_file() function in all versions up to, and including, 1.2.5. This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php). This is only exploitable by unauthenticated attackers in default configurations where the the default password is left as 1:1, or where the attacker gains access to the credentials.



- [https://github.com/d0n601/CVE-2025-4603](https://github.com/d0n601/CVE-2025-4603) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-4603.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-4603.svg)

## CVE-2025-4602
 The eMagicOne Store Manager for WooCommerce plugin for WordPress is vulnerable to Arbitrary File Reads in all versions up to, and including, 1.2.5 via the get_file() function. This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server, which can contain sensitive information. This is only exploitable by unauthenticated attackers in default configurations where the the default password is left as 1:1, or where the attacker gains access to the credentials.



- [https://github.com/d0n601/CVE-2025-4602](https://github.com/d0n601/CVE-2025-4602) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-4602.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-4602.svg)

## CVE-2025-4601
 The "RH - Real Estate WordPress Theme" theme for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 4.4.0. This is due to the theme not properly restricting user roles that can be updated as part of the inspiry_update_profile() function. This makes it possible for authenticated attackers, with subscriber-level access and above, to set their role to that of an administrator. The vulnerability was partially patched in version 4.4.0, and fully patched in version 4.4.1.



- [https://github.com/Yucaerin/CVE-2025-4601](https://github.com/Yucaerin/CVE-2025-4601) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-4601.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-4601.svg)

## CVE-2025-4578
 The File Provider WordPress plugin through 1.2.3 does not properly sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection



- [https://github.com/RandomRobbieBF/CVE-2025-4578](https://github.com/RandomRobbieBF/CVE-2025-4578) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-4578.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-4578.svg)

- [https://github.com/ahmetumitbayram/CVE-2025-45781-Kemal-Framework-Path-Traversal-Vulnerability-PoC](https://github.com/ahmetumitbayram/CVE-2025-45781-Kemal-Framework-Path-Traversal-Vulnerability-PoC) :  ![starts](https://img.shields.io/github/stars/ahmetumitbayram/CVE-2025-45781-Kemal-Framework-Path-Traversal-Vulnerability-PoC.svg) ![forks](https://img.shields.io/github/forks/ahmetumitbayram/CVE-2025-45781-Kemal-Framework-Path-Traversal-Vulnerability-PoC.svg)

## CVE-2025-4571
 The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to unauthorized view and modification of data due to an insufficient capability check on the permissionsCheck functions in all versions up to, and including, 4.3.0. This makes it possible for authenticated attackers, with Contributor-level access and above, to view or delete fundraising campaigns, view donors' data, modify campaign events, etc.



- [https://github.com/partywavesec/CVE-2025-45710](https://github.com/partywavesec/CVE-2025-45710) :  ![starts](https://img.shields.io/github/stars/partywavesec/CVE-2025-45710.svg) ![forks](https://img.shields.io/github/forks/partywavesec/CVE-2025-45710.svg)

## CVE-2025-4540
 A vulnerability was found in MTSoftware C-Lodop 6.6.1.1 on Windows. It has been rated as critical. This issue affects some unknown processing of the component CLodopPrintService. The manipulation leads to unquoted search path. The attack needs to be approached locally. The complexity of an attack is rather high. The exploitation is known to be difficult. The exploit has been disclosed to the public and may be used. Upgrading to version 6.6.13 is able to address this issue. It is recommended to upgrade the affected component.



- [https://github.com/yallasec/CVE-2025-45407](https://github.com/yallasec/CVE-2025-45407) :  ![starts](https://img.shields.io/github/stars/yallasec/CVE-2025-45407.svg) ![forks](https://img.shields.io/github/forks/yallasec/CVE-2025-45407.svg)

## CVE-2025-4524
 The Madara – Responsive and modern WordPress theme for manga sites theme for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.2.2 via the 'template' parameter. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.



- [https://github.com/ptrstr/CVE-2025-4524](https://github.com/ptrstr/CVE-2025-4524) :  ![starts](https://img.shields.io/github/stars/ptrstr/CVE-2025-4524.svg) ![forks](https://img.shields.io/github/forks/ptrstr/CVE-2025-4524.svg)

## CVE-2025-4476
 A denial-of-service vulnerability has been identified in the libsoup HTTP client library. This flaw can be triggered when a libsoup client receives a 401 (Unauthorized) HTTP response containing a specifically crafted domain parameter within the WWW-Authenticate header. Processing this malformed header can lead to a crash of the client application using libsoup. An attacker could exploit this by setting up a malicious HTTP server. If a user's application using the vulnerable libsoup library connects to this malicious server, it could result in a denial-of-service. Successful exploitation requires tricking a user's client application into connecting to the attacker's malicious server.



- [https://github.com/soltanali0/CVE-2025-4476-Exploit](https://github.com/soltanali0/CVE-2025-4476-Exploit) :  ![starts](https://img.shields.io/github/stars/soltanali0/CVE-2025-4476-Exploit.svg) ![forks](https://img.shields.io/github/forks/soltanali0/CVE-2025-4476-Exploit.svg)

## CVE-2025-4460
 A vulnerability classified as problematic has been found in TOTOLINK N150RT 3.4.0-B20190525. This affects an unknown part of the component URL Filtering Page. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/Moulish2004/CVE-2025-44603-CSRF-Leads_to_Create_FakeUsers](https://github.com/Moulish2004/CVE-2025-44603-CSRF-Leads_to_Create_FakeUsers) :  ![starts](https://img.shields.io/github/stars/Moulish2004/CVE-2025-44603-CSRF-Leads_to_Create_FakeUsers.svg) ![forks](https://img.shields.io/github/forks/Moulish2004/CVE-2025-44603-CSRF-Leads_to_Create_FakeUsers.svg)

## CVE-2025-4428
 Remote Code Execution in API component in Ivanti Endpoint Manager Mobile 12.5.0.0 and prior on unspecified platforms allows authenticated attackers to execute arbitrary code via crafted API requests.



- [https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428](https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428.svg)

- [https://github.com/xie-22/CVE-2025-4428](https://github.com/xie-22/CVE-2025-4428) :  ![starts](https://img.shields.io/github/stars/xie-22/CVE-2025-4428.svg) ![forks](https://img.shields.io/github/forks/xie-22/CVE-2025-4428.svg)

- [https://github.com/rxerium/CVE-2025-4427-CVE-2025-4428](https://github.com/rxerium/CVE-2025-4427-CVE-2025-4428) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-4427-CVE-2025-4428.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-4427-CVE-2025-4428.svg)

## CVE-2025-4427
 An authentication bypass in the API component of Ivanti Endpoint Manager Mobile 12.5.0.0 and prior allows attackers to access protected resources without proper credentials via the API.



- [https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428](https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428.svg)

- [https://github.com/rxerium/CVE-2025-4427-CVE-2025-4428](https://github.com/rxerium/CVE-2025-4427-CVE-2025-4428) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-4427-CVE-2025-4428.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-4427-CVE-2025-4428.svg)

## CVE-2025-4404
 A privilege escalation from host to domain vulnerability was found in the FreeIPA project. The FreeIPA package fails to validate the uniqueness of the `krbCanonicalName` for the admin account by default, allowing users to create services with the same canonical name as the REALM admin. When a successful attack happens, the user can retrieve a Kerberos ticket in the name of this service, containing the admin@REALM credential. This flaw allows an attacker to perform administrative tasks over the REALM, leading to access to sensitive data and sensitive data exfiltration.



- [https://github.com/Cyxow/CVE-2025-4404-POC](https://github.com/Cyxow/CVE-2025-4404-POC) :  ![starts](https://img.shields.io/github/stars/Cyxow/CVE-2025-4404-POC.svg) ![forks](https://img.shields.io/github/forks/Cyxow/CVE-2025-4404-POC.svg)

## CVE-2025-4403
 The Drag and Drop Multiple File Upload for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads in all versions up to, and including, 1.1.6 due to accepting a user‐supplied supported_type string and the uploaded filename without enforcing real extension or MIME checks within the upload() function. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Yucaerin/CVE-2025-4403](https://github.com/Yucaerin/CVE-2025-4403) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-4403.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-4403.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-4403](https://github.com/B1ack4sh/Blackash-CVE-2025-4403) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-4403.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-4403.svg)

## CVE-2025-4389
 The Crawlomatic Multipage Scraper Post Generator plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the crawlomatic_generate_featured_image() function in all versions up to, and including, 2.6.8.1. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Yucaerin/CVE-2025-4389](https://github.com/Yucaerin/CVE-2025-4389) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-4389.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-4389.svg)

## CVE-2025-4380
 The Ads Pro Plugin - Multi-Purpose WordPress Advertising Manager plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 4.89 via the 'bsa_template' parameter of the `bsa_preview_callback` function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases .php files can can be uploaded and included, or already exist on the site.



- [https://github.com/r0otk3r/CVE-2025-4380](https://github.com/r0otk3r/CVE-2025-4380) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2025-4380.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2025-4380.svg)

## CVE-2025-4336
 The eMagicOne Store Manager for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the set_file() function in all versions up to, and including, 1.2.5. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. This is only exploitable by unauthenticated attackers in default configurations where the the default password is left as 1:1, or where the attacker gains access to the credentials.



- [https://github.com/d0n601/CVE-2025-4336](https://github.com/d0n601/CVE-2025-4336) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-4336.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-4336.svg)

## CVE-2025-4334
 The Simple User Registration plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 6.3. This is due to insufficient restrictions on user meta values that can be supplied during registration. This makes it possible for unauthenticated attackers to register as an administrator.



- [https://github.com/Nxploited/CVE-2025-4334](https://github.com/Nxploited/CVE-2025-4334) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-4334.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-4334.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-4334](https://github.com/0xgh057r3c0n/CVE-2025-4334) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-4334.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-4334.svg)

- [https://github.com/vinodwick/CVE-2025-4334](https://github.com/vinodwick/CVE-2025-4334) :  ![starts](https://img.shields.io/github/stars/vinodwick/CVE-2025-4334.svg) ![forks](https://img.shields.io/github/forks/vinodwick/CVE-2025-4334.svg)

## CVE-2025-4322
 The Motors theme for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 5.6.67. This is due to the theme not properly validating a user's identity prior to updating their password. This makes it possible for unauthenticated attackers to change arbitrary user passwords, including those of administrators, and leverage that to gain access to their account.



- [https://github.com/IndominusRexes/CVE-2025-4322-Exploit](https://github.com/IndominusRexes/CVE-2025-4322-Exploit) :  ![starts](https://img.shields.io/github/stars/IndominusRexes/CVE-2025-4322-Exploit.svg) ![forks](https://img.shields.io/github/forks/IndominusRexes/CVE-2025-4322-Exploit.svg)

- [https://github.com/Yucaerin/CVE-2025-4322](https://github.com/Yucaerin/CVE-2025-4322) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-4322.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-4322.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-4322](https://github.com/B1ack4sh/Blackash-CVE-2025-4322) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-4322.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-4322.svg)

## CVE-2025-4275
 A vulnerability in the digital signature verification process does not properly validate variable attributes which allows an attacker to bypass signature verification by creating a non-authenticated NVRAM variable. An attacker may to execute arbitrary signed UEFI code and bypass Secure Boot.



- [https://github.com/NikolajSchlej/Hydroph0bia](https://github.com/NikolajSchlej/Hydroph0bia) :  ![starts](https://img.shields.io/github/stars/NikolajSchlej/Hydroph0bia.svg) ![forks](https://img.shields.io/github/forks/NikolajSchlej/Hydroph0bia.svg)

## CVE-2025-4190
 The CSV Mass Importer WordPress plugin through 1.2 does not properly validate uploaded files, allowing high privilege users such as admin to upload arbitrary files on the server even when they should not be allowed to (for example in multisite setup)



- [https://github.com/Nxploited/CVE-2025-4190](https://github.com/Nxploited/CVE-2025-4190) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-4190.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-4190.svg)

- [https://github.com/GadaLuBau1337/CVE-2025-4190](https://github.com/GadaLuBau1337/CVE-2025-4190) :  ![starts](https://img.shields.io/github/stars/GadaLuBau1337/CVE-2025-4190.svg) ![forks](https://img.shields.io/github/forks/GadaLuBau1337/CVE-2025-4190.svg)

## CVE-2025-4162
 A vulnerability classified as critical was found in PCMan FTP Server up to 2.0.7. This vulnerability affects unknown code of the component ASCII Command Handler. The manipulation leads to buffer overflow. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/NotItsSixtyN3in/CVE-2025-4162029](https://github.com/NotItsSixtyN3in/CVE-2025-4162029) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162029.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162029.svg)

- [https://github.com/NotItsSixtyN3in/CVE-2025-4162030](https://github.com/NotItsSixtyN3in/CVE-2025-4162030) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162030.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162030.svg)

- [https://github.com/NotItsSixtyN3in/CVE-2025-4162027](https://github.com/NotItsSixtyN3in/CVE-2025-4162027) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162027.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162027.svg)

- [https://github.com/NotItsSixtyN3in/CVE-2025-4162028](https://github.com/NotItsSixtyN3in/CVE-2025-4162028) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162028.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162028.svg)

- [https://github.com/NotItsSixtyN3in/CVE-2025-4162025](https://github.com/NotItsSixtyN3in/CVE-2025-4162025) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162025.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162025.svg)

- [https://github.com/NotItsSixtyN3in/CVE-2025-4162026](https://github.com/NotItsSixtyN3in/CVE-2025-4162026) :  ![starts](https://img.shields.io/github/stars/NotItsSixtyN3in/CVE-2025-4162026.svg) ![forks](https://img.shields.io/github/forks/NotItsSixtyN3in/CVE-2025-4162026.svg)

## CVE-2025-4126
 The EG-Series plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's [series] shortcode in all versions up to, and including, 2.1.1 due to insufficient input sanitization and output escaping on user supplied attributes in the shortcode_title function. This makes it possible for authenticated attackers - with contributor-level access and above, on sites with the Classic Editor plugin activated - to inject arbitrary JavaScript code in the titletag attribute that will execute whenever a user access an injected page.



- [https://github.com/Slow-Mist/CVE-2025-4126](https://github.com/Slow-Mist/CVE-2025-4126) :  ![starts](https://img.shields.io/github/stars/Slow-Mist/CVE-2025-4126.svg) ![forks](https://img.shields.io/github/forks/Slow-Mist/CVE-2025-4126.svg)

## CVE-2025-4123
 A cross-site scripting (XSS) vulnerability exists in Grafana caused by combining a client path traversal and open redirect. This allows attackers to redirect users to a website that hosts a frontend plugin that will execute arbitrary JavaScript. This vulnerability does not require editor permissions and if anonymous access is enabled, the XSS will work. If the Grafana Image Renderer plugin is installed, it is possible to exploit the open redirect to achieve a full read SSRF.

The default Content-Security-Policy (CSP) in Grafana will block the XSS though the `connect-src` directive.



- [https://github.com/NightBloodz/CVE-2025-4123](https://github.com/NightBloodz/CVE-2025-4123) :  ![starts](https://img.shields.io/github/stars/NightBloodz/CVE-2025-4123.svg) ![forks](https://img.shields.io/github/forks/NightBloodz/CVE-2025-4123.svg)

- [https://github.com/ynsmroztas/CVE-2025-4123-Exploit-Tool-Grafana-](https://github.com/ynsmroztas/CVE-2025-4123-Exploit-Tool-Grafana-) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/CVE-2025-4123-Exploit-Tool-Grafana-.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/CVE-2025-4123-Exploit-Tool-Grafana-.svg)

- [https://github.com/punitdarji/Grafana-cve-2025-4123](https://github.com/punitdarji/Grafana-cve-2025-4123) :  ![starts](https://img.shields.io/github/stars/punitdarji/Grafana-cve-2025-4123.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Grafana-cve-2025-4123.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-4123](https://github.com/B1ack4sh/Blackash-CVE-2025-4123) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-4123.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-4123.svg)

- [https://github.com/kk12-30/CVE-2025-4123](https://github.com/kk12-30/CVE-2025-4123) :  ![starts](https://img.shields.io/github/stars/kk12-30/CVE-2025-4123.svg) ![forks](https://img.shields.io/github/forks/kk12-30/CVE-2025-4123.svg)

- [https://github.com/ItsNee/Grafana-CVE-2025-4123-POC](https://github.com/ItsNee/Grafana-CVE-2025-4123-POC) :  ![starts](https://img.shields.io/github/stars/ItsNee/Grafana-CVE-2025-4123-POC.svg) ![forks](https://img.shields.io/github/forks/ItsNee/Grafana-CVE-2025-4123-POC.svg)

- [https://github.com/MorphyKutay/CVE-2025-4123-Exploit](https://github.com/MorphyKutay/CVE-2025-4123-Exploit) :  ![starts](https://img.shields.io/github/stars/MorphyKutay/CVE-2025-4123-Exploit.svg) ![forks](https://img.shields.io/github/forks/MorphyKutay/CVE-2025-4123-Exploit.svg)

- [https://github.com/imbas007/CVE-2025-4123-template](https://github.com/imbas007/CVE-2025-4123-template) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-4123-template.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-4123-template.svg)

## CVE-2025-4094
 The DIGITS: WordPress Mobile Number Signup and Login WordPress plugin before 8.4.6.1 does not rate limit OTP validation attempts, making it straightforward for attackers to bruteforce them.



- [https://github.com/POCPioneer/CVE-2025-4094-POC](https://github.com/POCPioneer/CVE-2025-4094-POC) :  ![starts](https://img.shields.io/github/stars/POCPioneer/CVE-2025-4094-POC.svg) ![forks](https://img.shields.io/github/forks/POCPioneer/CVE-2025-4094-POC.svg)

- [https://github.com/starawneh/CVE-2025-4094](https://github.com/starawneh/CVE-2025-4094) :  ![starts](https://img.shields.io/github/stars/starawneh/CVE-2025-4094.svg) ![forks](https://img.shields.io/github/forks/starawneh/CVE-2025-4094.svg)

## CVE-2025-3969
 A vulnerability was found in codeprojects News Publishing Site Dashboard 1.0. It has been rated as critical. This issue affects some unknown processing of the file /edit-category.php of the component Edit Category Page. The manipulation of the argument category_image leads to unrestricted upload. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/Stuub/CVE-2025-3969-Exploit](https://github.com/Stuub/CVE-2025-3969-Exploit) :  ![starts](https://img.shields.io/github/stars/Stuub/CVE-2025-3969-Exploit.svg) ![forks](https://img.shields.io/github/forks/Stuub/CVE-2025-3969-Exploit.svg)

## CVE-2025-3915
 The Aeropage Sync for Airtable plugin for WordPress is vulnerable to unauthorized loss of data due to a missing capability check on the 'aeropageDeletePost' function in all versions up to, and including, 3.2.0. This makes it possible for authenticated attackers, with Subscriber-level access and above, to delete arbitrary posts.



- [https://github.com/LvL23HT/PoC-CVE-2025-3914-Aeropage-WordPress-File-Upload](https://github.com/LvL23HT/PoC-CVE-2025-3914-Aeropage-WordPress-File-Upload) :  ![starts](https://img.shields.io/github/stars/LvL23HT/PoC-CVE-2025-3914-Aeropage-WordPress-File-Upload.svg) ![forks](https://img.shields.io/github/forks/LvL23HT/PoC-CVE-2025-3914-Aeropage-WordPress-File-Upload.svg)

## CVE-2025-3914
 The Aeropage Sync for Airtable plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'aeropage_media_downloader' function in all versions up to, and including, 3.2.0. This makes it possible for authenticated attackers, with Subscriber-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/LvL23HT/PoC-CVE-2025-3914-Aeropage-WordPress-File-Upload](https://github.com/LvL23HT/PoC-CVE-2025-3914-Aeropage-WordPress-File-Upload) :  ![starts](https://img.shields.io/github/stars/LvL23HT/PoC-CVE-2025-3914-Aeropage-WordPress-File-Upload.svg) ![forks](https://img.shields.io/github/forks/LvL23HT/PoC-CVE-2025-3914-Aeropage-WordPress-File-Upload.svg)

## CVE-2025-3855
 A vulnerability was found in CodeCanyon RISE Ultimate Project Manager 3.8.2 and classified as problematic. Affected by this issue is some unknown functionality of the file /index.php/team_members/save_profile_image/ of the component Profile Picture Handler. The manipulation of the argument profile_image_file leads to improper control of resource identifiers. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/L4zyFox/RISE-Ultimate_Project_Manager_e_CRM](https://github.com/L4zyFox/RISE-Ultimate_Project_Manager_e_CRM) :  ![starts](https://img.shields.io/github/stars/L4zyFox/RISE-Ultimate_Project_Manager_e_CRM.svg) ![forks](https://img.shields.io/github/forks/L4zyFox/RISE-Ultimate_Project_Manager_e_CRM.svg)

## CVE-2025-3776
 The Verification SMS with TargetSMS plugin for WordPress is vulnerable to limited Remote Code Execution in all versions up to, and including, 1.5 via the 'targetvr_ajax_handler' function. This is due to a lack of validation on the type of function that can be called. This makes it possible for unauthenticated attackers to execute any callable function on the site, such as phpinfo().



- [https://github.com/Nxploited/CVE-2025-3776](https://github.com/Nxploited/CVE-2025-3776) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-3776.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-3776.svg)

## CVE-2025-3639
 Liferay Portal 7.3.0 through 7.4.3.132, and Liferay DXP 2025.Q1 through 2025.Q1.6, 2024.Q4.0 through 2024.Q4.7, 2024.Q3.1 through 2024.Q3.13, 2024.Q2.0 through 2024.Q2.13, 2024.Q1.1 through 2024.Q1.15, 7.4 GA through update 92 and 7.3 GA through update 36 allows unauthenticated users with valid credentials to bypass the login process by changing the POST method to GET, once the site has MFA enabled.



- [https://github.com/6lj/CVE-2025-3639](https://github.com/6lj/CVE-2025-3639) :  ![starts](https://img.shields.io/github/stars/6lj/CVE-2025-3639.svg) ![forks](https://img.shields.io/github/forks/6lj/CVE-2025-3639.svg)

## CVE-2025-3605
 The Frontend Login and Registration Blocks plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 1.0.7. This is due to the plugin not properly validating a user's identity prior to updating their details like email via the flr_blocks_user_settings_handle_ajax_callback() function. This makes it possible for unauthenticated attackers to change arbitrary user's email addresses, including administrators, and leverage that to reset the user's password and gain access to their account.



- [https://github.com/Nxploited/CVE-2025-3605](https://github.com/Nxploited/CVE-2025-3605) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-3605.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-3605.svg)

- [https://github.com/GadaLuBau1337/CVE-2025-3605](https://github.com/GadaLuBau1337/CVE-2025-3605) :  ![starts](https://img.shields.io/github/stars/GadaLuBau1337/CVE-2025-3605.svg) ![forks](https://img.shields.io/github/forks/GadaLuBau1337/CVE-2025-3605.svg)

## CVE-2025-3604
 The Flynax Bridge plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 2.2.0. This is due to the plugin not properly validating a user's identity prior to updating their details like email. This makes it possible for unauthenticated attackers to change arbitrary user's email addresses, including administrators, and leverage that to reset the user's password and gain access to their account.



- [https://github.com/Nxploited/CVE-2025-3604](https://github.com/Nxploited/CVE-2025-3604) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-3604.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-3604.svg)

## CVE-2025-3568
 A vulnerability has been found in Webkul Krayin CRM up to 2.1.0 and classified as problematic. Affected by this vulnerability is an unknown functionality of the file /admin/settings/users/edit/ of the component SVG File Handler. The manipulation leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The vendor prepares a fix for the next major release and explains that he does not think therefore that this should qualify for a CVE.



- [https://github.com/shellkraft/CVE-2025-3568](https://github.com/shellkraft/CVE-2025-3568) :  ![starts](https://img.shields.io/github/stars/shellkraft/CVE-2025-3568.svg) ![forks](https://img.shields.io/github/forks/shellkraft/CVE-2025-3568.svg)

## CVE-2025-3515
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file uploads due to insufficient file type validation in all versions up to, and including, 1.3.8.9. This makes it possible for unauthenticated attackers to bypass the plugin's blacklist and upload .phar or other dangerous file types on the affected site's server, which may make remote code execution possible on the servers that are configured to handle .phar files as executable PHP scripts, particularly in default Apache+mod_php configurations where the file extension is not strictly validated before being passed to the PHP interpreter.



- [https://github.com/brokendreamsclub/CVE-2025-3515](https://github.com/brokendreamsclub/CVE-2025-3515) :  ![starts](https://img.shields.io/github/stars/brokendreamsclub/CVE-2025-3515.svg) ![forks](https://img.shields.io/github/forks/brokendreamsclub/CVE-2025-3515.svg)

- [https://github.com/ImBIOS/lab-cve-2025-3515](https://github.com/ImBIOS/lab-cve-2025-3515) :  ![starts](https://img.shields.io/github/stars/ImBIOS/lab-cve-2025-3515.svg) ![forks](https://img.shields.io/github/forks/ImBIOS/lab-cve-2025-3515.svg)

- [https://github.com/Professor6T9/CVE-2025-3515](https://github.com/Professor6T9/CVE-2025-3515) :  ![starts](https://img.shields.io/github/stars/Professor6T9/CVE-2025-3515.svg) ![forks](https://img.shields.io/github/forks/Professor6T9/CVE-2025-3515.svg)

## CVE-2025-3419
 The Event Manager, Events Calendar, Tickets, Registrations – Eventin plugin for WordPress is vulnerable to arbitrary file read in all versions up to, and including, 4.0.26 via the proxy_image() function. This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server, which can contain sensitive information.



- [https://github.com/Yucaerin/CVE-2025-3419](https://github.com/Yucaerin/CVE-2025-3419) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-3419.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-3419.svg)

## CVE-2025-3248
 Langflow versions prior to 1.3.0 are susceptible to code injection in 
the /api/v1/validate/code endpoint. A remote and unauthenticated attacker can send crafted HTTP requests to execute arbitrary
code.



- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance](https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg)

- [https://github.com/ynsmroztas/CVE-2025-3248-Langflow-RCE](https://github.com/ynsmroztas/CVE-2025-3248-Langflow-RCE) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/CVE-2025-3248-Langflow-RCE.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/CVE-2025-3248-Langflow-RCE.svg)

- [https://github.com/verylazytech/CVE-2025-3248](https://github.com/verylazytech/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/verylazytech/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/verylazytech/CVE-2025-3248.svg)

- [https://github.com/xuemian168/CVE-2025-3248](https://github.com/xuemian168/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/xuemian168/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/xuemian168/CVE-2025-3248.svg)

- [https://github.com/0-d3y/langflow-rce-exploit](https://github.com/0-d3y/langflow-rce-exploit) :  ![starts](https://img.shields.io/github/stars/0-d3y/langflow-rce-exploit.svg) ![forks](https://img.shields.io/github/forks/0-d3y/langflow-rce-exploit.svg)

- [https://github.com/dennisec/Mass-CVE-2025-3248](https://github.com/dennisec/Mass-CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/dennisec/Mass-CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/dennisec/Mass-CVE-2025-3248.svg)

- [https://github.com/Kiraly07/Demo_CVE-2025-3248](https://github.com/Kiraly07/Demo_CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/Kiraly07/Demo_CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/Kiraly07/Demo_CVE-2025-3248.svg)

- [https://github.com/issamjr/CVE-2025-3248-Scanner](https://github.com/issamjr/CVE-2025-3248-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-3248-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-3248-Scanner.svg)

- [https://github.com/Praison001/CVE-2025-3248](https://github.com/Praison001/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/Praison001/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/Praison001/CVE-2025-3248.svg)

- [https://github.com/r0otk3r/CVE-2025-3248](https://github.com/r0otk3r/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2025-3248.svg)

- [https://github.com/zapstiko/CVE-2025-3248](https://github.com/zapstiko/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/zapstiko/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/zapstiko/CVE-2025-3248.svg)

- [https://github.com/vigilante-1337/CVE-2025-3248](https://github.com/vigilante-1337/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/vigilante-1337/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/vigilante-1337/CVE-2025-3248.svg)

- [https://github.com/imbas007/CVE-2025-3248](https://github.com/imbas007/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-3248.svg)

- [https://github.com/tiemio/RCE-CVE-2025-3248](https://github.com/tiemio/RCE-CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/tiemio/RCE-CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/tiemio/RCE-CVE-2025-3248.svg)

- [https://github.com/PuddinCat/CVE-2025-3248-POC](https://github.com/PuddinCat/CVE-2025-3248-POC) :  ![starts](https://img.shields.io/github/stars/PuddinCat/CVE-2025-3248-POC.svg) ![forks](https://img.shields.io/github/forks/PuddinCat/CVE-2025-3248-POC.svg)

- [https://github.com/dennisec/CVE-2025-3248](https://github.com/dennisec/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/dennisec/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/dennisec/CVE-2025-3248.svg)

- [https://github.com/min8282/CVE-2025-3248](https://github.com/min8282/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/min8282/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/min8282/CVE-2025-3248.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-3248](https://github.com/0xgh057r3c0n/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-3248.svg)

- [https://github.com/EQSTLab/CVE-2025-3248](https://github.com/EQSTLab/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2025-3248.svg)

- [https://github.com/Vip3rLi0n/CVE-2025-3248](https://github.com/Vip3rLi0n/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/Vip3rLi0n/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/Vip3rLi0n/CVE-2025-3248.svg)

- [https://github.com/bambooqj/cve-2025-3248](https://github.com/bambooqj/cve-2025-3248) :  ![starts](https://img.shields.io/github/stars/bambooqj/cve-2025-3248.svg) ![forks](https://img.shields.io/github/forks/bambooqj/cve-2025-3248.svg)

- [https://github.com/wand3rlust/CVE-2025-3248](https://github.com/wand3rlust/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/wand3rlust/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/wand3rlust/CVE-2025-3248.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-3248](https://github.com/B1ack4sh/Blackash-CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-3248.svg)

- [https://github.com/ill-deed/Langflow-CVE-2025-3248-Multi-target](https://github.com/ill-deed/Langflow-CVE-2025-3248-Multi-target) :  ![starts](https://img.shields.io/github/stars/ill-deed/Langflow-CVE-2025-3248-Multi-target.svg) ![forks](https://img.shields.io/github/forks/ill-deed/Langflow-CVE-2025-3248-Multi-target.svg)

## CVE-2025-3102
 The SureTriggers: All-in-One Automation Platform plugin for WordPress is vulnerable to an authentication bypass leading to administrative account creation due to a missing empty value check on the 'secret_key' value in the 'autheticate_user' function in all versions up to, and including, 1.0.78. This makes it possible for unauthenticated attackers to create administrator accounts on the target website when the plugin is installed and activated but not configured with an API key.



- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance](https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg)

- [https://github.com/Nxploited/CVE-2025-3102](https://github.com/Nxploited/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-3102.svg)

- [https://github.com/itsismarcos/vanda-CVE-2025-3102](https://github.com/itsismarcos/vanda-CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/itsismarcos/vanda-CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/itsismarcos/vanda-CVE-2025-3102.svg)

- [https://github.com/rhz0d/CVE-2025-3102](https://github.com/rhz0d/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/rhz0d/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/rhz0d/CVE-2025-3102.svg)

- [https://github.com/SUPRAAA-1337/CVE-2025-3102-exploit](https://github.com/SUPRAAA-1337/CVE-2025-3102-exploit) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/CVE-2025-3102-exploit.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/CVE-2025-3102-exploit.svg)

- [https://github.com/SUPRAAA-1337/CVE-2025-3102](https://github.com/SUPRAAA-1337/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/CVE-2025-3102.svg)

- [https://github.com/dennisec/CVE-2025-3102](https://github.com/dennisec/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/dennisec/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/dennisec/CVE-2025-3102.svg)

- [https://github.com/0xgh057r3c0n/CVE-2025-3102](https://github.com/0xgh057r3c0n/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-3102.svg)

- [https://github.com/baribut/CVE-2025-3102](https://github.com/baribut/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/baribut/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/baribut/CVE-2025-3102.svg)

- [https://github.com/SUPRAAA-1337/CVE-2025-3102_v2](https://github.com/SUPRAAA-1337/CVE-2025-3102_v2) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/CVE-2025-3102_v2.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/CVE-2025-3102_v2.svg)

## CVE-2025-3054
 The WP User Frontend Pro plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the upload_files() function in all versions up to, and including, 4.1.3. This makes it possible for authenticated attackers, with Subscriber-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible. Please note that this requires the 'Private Message' module to be enabled and the Business version of the PRO software to be in use.



- [https://github.com/frogchung/CVE-2025-3054-Exploit](https://github.com/frogchung/CVE-2025-3054-Exploit) :  ![starts](https://img.shields.io/github/stars/frogchung/CVE-2025-3054-Exploit.svg) ![forks](https://img.shields.io/github/forks/frogchung/CVE-2025-3054-Exploit.svg)

## CVE-2025-3052
 An arbitrary write vulnerability in Microsoft signed UEFI firmware allows for code execution of untrusted software. This allows an attacker to control its value, leading to arbitrary memory writes, including modification of critical firmware settings stored in NVRAM. Exploiting this vulnerability could enable security bypasses, persistence mechanisms, or full system compromise.



- [https://github.com/yonatanasd232132/talkingBen](https://github.com/yonatanasd232132/talkingBen) :  ![starts](https://img.shields.io/github/stars/yonatanasd232132/talkingBen.svg) ![forks](https://img.shields.io/github/forks/yonatanasd232132/talkingBen.svg)

## CVE-2025-3048
 After completing a build with AWS Serverless Application Model Command Line Interface (SAM CLI) which include symlinks, the content of those symlinks are copied to the cache of the local workspace as regular files or directories. As a result, a user who does not have access to those symlinks outside of the Docker container would now have access via the local workspace.

Users should upgrade to version 1.134.0 and ensure any forked or derivative code is patched to incorporate the new fixes. After upgrading, users must re-build their applications using the sam build --use-container to update the symlinks.



- [https://github.com/murataydemir/AWS-SAM-CLI-Vulnerabilities](https://github.com/murataydemir/AWS-SAM-CLI-Vulnerabilities) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-SAM-CLI-Vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-SAM-CLI-Vulnerabilities.svg)

## CVE-2025-3047
 When running the AWS Serverless Application Model Command Line Interface (SAM CLI) build process with Docker and symlinks are included in the build files, the container environment allows a user to access privileged files on the host by leveraging the elevated permissions granted to the tool. A user could leverage the elevated permissions to access restricted files via symlinks and copy them to a more permissive location on the container. 

Users should upgrade to v1.133.0 or newer and ensure any forked or derivative code is patched to incorporate the new fixes.



- [https://github.com/murataydemir/AWS-SAM-CLI-Vulnerabilities](https://github.com/murataydemir/AWS-SAM-CLI-Vulnerabilities) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-SAM-CLI-Vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-SAM-CLI-Vulnerabilities.svg)

## CVE-2025-2995
 A vulnerability has been found in Tenda FH1202 1.2.0.14(408) and classified as critical. This vulnerability affects unknown code of the file /goform/SysToolChangePwd of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/huynguyen12536/CVE-2025-2995](https://github.com/huynguyen12536/CVE-2025-2995) :  ![starts](https://img.shields.io/github/stars/huynguyen12536/CVE-2025-2995.svg) ![forks](https://img.shields.io/github/forks/huynguyen12536/CVE-2025-2995.svg)

## CVE-2025-2971
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.



- [https://github.com/SteamPunk424/CVE-2025-29711-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Incorrect-Access-Control](https://github.com/SteamPunk424/CVE-2025-29711-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Incorrect-Access-Control) :  ![starts](https://img.shields.io/github/stars/SteamPunk424/CVE-2025-29711-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Incorrect-Access-Control.svg) ![forks](https://img.shields.io/github/forks/SteamPunk424/CVE-2025-29711-TAKASHI-Wireless-Instant-Router-And-Repeater-WebApp-Incorrect-Access-Control.svg)

## CVE-2025-2945
 Remote Code Execution security vulnerability in pgAdmin 4  (Query Tool and Cloud Deployment modules).

The vulnerability is associated with the 2 POST endpoints; /sqleditor/query_tool/download, where the query_commited parameter and /cloud/deploy endpoint, where the high_availability parameter is unsafely passed to the Python eval() function, allowing arbitrary code execution.


This issue affects pgAdmin 4: before 9.2.



- [https://github.com/abrewer251/CVE-2025-2945_PgAdmin_PoC](https://github.com/abrewer251/CVE-2025-2945_PgAdmin_PoC) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-2945_PgAdmin_PoC.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-2945_PgAdmin_PoC.svg)

- [https://github.com/Cycloctane/cve-2025-2945-poc](https://github.com/Cycloctane/cve-2025-2945-poc) :  ![starts](https://img.shields.io/github/stars/Cycloctane/cve-2025-2945-poc.svg) ![forks](https://img.shields.io/github/forks/Cycloctane/cve-2025-2945-poc.svg)

## CVE-2025-2927
 A vulnerability was found in ESAFENET CDG 5.6.3.154.205. It has been classified as critical. Affected is an unknown function of the file /parameter/getFileTypeList.jsp. The manipulation of the argument typename leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/0xBl4nk/CVE-2025-29279](https://github.com/0xBl4nk/CVE-2025-29279) :  ![starts](https://img.shields.io/github/stars/0xBl4nk/CVE-2025-29279.svg) ![forks](https://img.shields.io/github/forks/0xBl4nk/CVE-2025-29279.svg)

- [https://github.com/0xBl4nk/CVE-2025-29278](https://github.com/0xBl4nk/CVE-2025-29278) :  ![starts](https://img.shields.io/github/stars/0xBl4nk/CVE-2025-29278.svg) ![forks](https://img.shields.io/github/forks/0xBl4nk/CVE-2025-29278.svg)

- [https://github.com/0xBl4nk/CVE-2025-29275](https://github.com/0xBl4nk/CVE-2025-29275) :  ![starts](https://img.shields.io/github/stars/0xBl4nk/CVE-2025-29275.svg) ![forks](https://img.shields.io/github/forks/0xBl4nk/CVE-2025-29275.svg)

- [https://github.com/0xBl4nk/CVE-2025-29277](https://github.com/0xBl4nk/CVE-2025-29277) :  ![starts](https://img.shields.io/github/stars/0xBl4nk/CVE-2025-29277.svg) ![forks](https://img.shields.io/github/forks/0xBl4nk/CVE-2025-29277.svg)

- [https://github.com/0xBl4nk/CVE-2025-29276](https://github.com/0xBl4nk/CVE-2025-29276) :  ![starts](https://img.shields.io/github/stars/0xBl4nk/CVE-2025-29276.svg) ![forks](https://img.shields.io/github/forks/0xBl4nk/CVE-2025-29276.svg)

## CVE-2025-2907
 The Order Delivery Date WordPress plugin before 12.3.1 does not have authorization and CSRF checks when importing settings. Furthermore it also lacks proper checks to only update options relevant to the Order Delivery Date WordPress plugin before 12.3.1. This leads to attackers being able to modify the default_user_role to administrator and users_can_register, allowing them to register as an administrator of the site for complete site takeover.



- [https://github.com/Yucaerin/CVE-2025-2907](https://github.com/Yucaerin/CVE-2025-2907) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-2907.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-2907.svg)

## CVE-2025-2888
 During a snapshot rollback, the client incorrectly caches the timestamp metadata. If the client checks the cache when attempting to perform the next update, the update timestamp validation will fail, preventing the next update until the cache is cleared. Users should upgrade to tough version 0.20.0 or later and ensure any forked or derivative code is patched to incorporate the new fixes.



- [https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs](https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg)

## CVE-2025-2887
 During a target rollback, the client fails to detect the rollback for delegated targets. This could cause the client to fetch a target from an incorrect source, altering the target contents. Users should upgrade to tough version 0.20.0 or later and ensure any forked or derivative code is patched to incorporate the new fixes.



- [https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs](https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg)

## CVE-2025-2886
 Missing validation of terminating delegation causes the client to continue searching the defined delegation list, even after searching a terminating delegation. This could cause the client to fetch a target from an incorrect source, altering the target contents. Users should upgrade to tough version 0.20.0 or later and ensure any forked or derivative code is patched to incorporate the new fixes.



- [https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs](https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg)

## CVE-2025-2885
 Missing validation of the root metatdata version number could allow an actor to supply an arbitrary version number to the client instead of the intended version in the root metadata file, altering the version fetched by the client. Users should upgrade to tough version 0.20.0 or later and ensure any forked or derivative code is patched to incorporate the new fixes.



- [https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs](https://github.com/murataydemir/AWS-Tough-Library-Multiple-CVEs) :  ![starts](https://img.shields.io/github/stars/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg) ![forks](https://img.shields.io/github/forks/murataydemir/AWS-Tough-Library-Multiple-CVEs.svg)

## CVE-2025-2857
 Following the recent Chrome sandbox escape (CVE-2025-2783), various Firefox developers identified a similar pattern in our IPC code. A compromised child process could cause the parent process to return an unintentionally powerful handle, leading to a sandbox escape. 
The original vulnerability was being exploited in the wild. 
*This only affects Firefox on Windows. Other operating systems are unaffected.* This vulnerability affects Firefox  136.0.4, Firefox ESR  128.8.1, and Firefox ESR  115.21.1.



- [https://github.com/Leviticus-Triage/ChromSploit-Framework](https://github.com/Leviticus-Triage/ChromSploit-Framework) :  ![starts](https://img.shields.io/github/stars/Leviticus-Triage/ChromSploit-Framework.svg) ![forks](https://img.shields.io/github/forks/Leviticus-Triage/ChromSploit-Framework.svg)

## CVE-2025-2828
 A Server-Side Request Forgery (SSRF) vulnerability exists in the RequestsToolkit component of the langchain-community package (specifically, langchain_community.agent_toolkits.openapi.toolkit.RequestsToolkit) in langchain-ai/langchain version 0.0.27. This vulnerability occurs because the toolkit does not enforce restrictions on requests to remote internet addresses, allowing it to also access local addresses. As a result, an attacker could exploit this flaw to perform port scans, access local services, retrieve instance metadata from cloud environments (e.g., Azure, AWS), and interact with servers on the local network. This issue has been fixed in version 0.0.28.



- [https://github.com/B1ack4sh/Blackash-CVE-2025-2828](https://github.com/B1ack4sh/Blackash-CVE-2025-2828) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-2828.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-2828.svg)

## CVE-2025-2825
 DO NOT USE THIS CVE RECORD. ConsultIDs: CVE-2025-31161. Reason: This Record is a reservation duplicate of CVE-2025-31161. Notes: All CVE users should reference CVE-2025-31161 instead of this Record. All references and descriptions in this Record have been removed to prevent accidental usage.



- [https://github.com/Immersive-Labs-Sec/CVE-2025-31161](https://github.com/Immersive-Labs-Sec/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/CVE-2025-31161.svg)

- [https://github.com/ghostsec420/ShatteredFTP](https://github.com/ghostsec420/ShatteredFTP) :  ![starts](https://img.shields.io/github/stars/ghostsec420/ShatteredFTP.svg) ![forks](https://img.shields.io/github/forks/ghostsec420/ShatteredFTP.svg)

- [https://github.com/Shivshantp/CVE-2025-2825-CrushFTP-AuthBypass](https://github.com/Shivshantp/CVE-2025-2825-CrushFTP-AuthBypass) :  ![starts](https://img.shields.io/github/stars/Shivshantp/CVE-2025-2825-CrushFTP-AuthBypass.svg) ![forks](https://img.shields.io/github/forks/Shivshantp/CVE-2025-2825-CrushFTP-AuthBypass.svg)

- [https://github.com/WOOOOONG/CVE-2025-2825](https://github.com/WOOOOONG/CVE-2025-2825) :  ![starts](https://img.shields.io/github/stars/WOOOOONG/CVE-2025-2825.svg) ![forks](https://img.shields.io/github/forks/WOOOOONG/CVE-2025-2825.svg)

- [https://github.com/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825](https://github.com/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825.svg)

- [https://github.com/iteride/CVE-2025-2825](https://github.com/iteride/CVE-2025-2825) :  ![starts](https://img.shields.io/github/stars/iteride/CVE-2025-2825.svg) ![forks](https://img.shields.io/github/forks/iteride/CVE-2025-2825.svg)

- [https://github.com/punitdarji/crushftp-CVE-2025-2825](https://github.com/punitdarji/crushftp-CVE-2025-2825) :  ![starts](https://img.shields.io/github/stars/punitdarji/crushftp-CVE-2025-2825.svg) ![forks](https://img.shields.io/github/forks/punitdarji/crushftp-CVE-2025-2825.svg)

## CVE-2025-2812
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Mydata Informatics Ticket Sales Automation allows Blind SQL Injection.This issue affects Ticket Sales Automation: before 03.04.2025 (DD.MM.YYYY).



- [https://github.com/sahici/CVE-2025-2812](https://github.com/sahici/CVE-2025-2812) :  ![starts](https://img.shields.io/github/stars/sahici/CVE-2025-2812.svg) ![forks](https://img.shields.io/github/forks/sahici/CVE-2025-2812.svg)

## CVE-2025-2807
 The Motors – Car Dealership & Classified Listings Plugin plugin for WordPress is vulnerable to arbitrary plugin installations due to a missing capability check in the mvl_setup_wizard_install_plugin() function in all versions up to, and including, 1.4.64. This makes it possible for authenticated attackers, with Subscriber-level access and above, to install and activate arbitrary plugins on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2025-2807](https://github.com/Nxploited/CVE-2025-2807) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-2807.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-2807.svg)

## CVE-2025-2783
 Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 134.0.6998.177 allowed a remote attacker to perform a sandbox escape via a malicious file. (Chromium security severity: High)



- [https://github.com/Alchemist3dot14/CVE-2025-2783](https://github.com/Alchemist3dot14/CVE-2025-2783) :  ![starts](https://img.shields.io/github/stars/Alchemist3dot14/CVE-2025-2783.svg) ![forks](https://img.shields.io/github/forks/Alchemist3dot14/CVE-2025-2783.svg)

- [https://github.com/Leviticus-Triage/ChromSploit-Framework](https://github.com/Leviticus-Triage/ChromSploit-Framework) :  ![starts](https://img.shields.io/github/stars/Leviticus-Triage/ChromSploit-Framework.svg) ![forks](https://img.shields.io/github/forks/Leviticus-Triage/ChromSploit-Framework.svg)

- [https://github.com/byteReaper77/CVE-2025-2783](https://github.com/byteReaper77/CVE-2025-2783) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-2783.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-2783.svg)

## CVE-2025-2778
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.



- [https://github.com/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain](https://github.com/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain.svg)

## CVE-2025-2777
 SysAid On-Prem versions = 23.3.40 are vulnerable to an unauthenticated XML External Entity (XXE) vulnerability in the lshw processing functionality,  allowing for administrator account takeover and file read primitives.



- [https://github.com/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain](https://github.com/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain.svg)

## CVE-2025-2776
 SysAid On-Prem versions = 23.3.40 are vulnerable to an unauthenticated XML External Entity (XXE) vulnerability in the Server URL processing functionality, allowing for administrator account takeover and file read primitives.



- [https://github.com/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain](https://github.com/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain.svg)

- [https://github.com/mrk336/From-EternalBlue-to-CVE-2025-2776-The-Evolution-of-an-SMB-Attack](https://github.com/mrk336/From-EternalBlue-to-CVE-2025-2776-The-Evolution-of-an-SMB-Attack) :  ![starts](https://img.shields.io/github/stars/mrk336/From-EternalBlue-to-CVE-2025-2776-The-Evolution-of-an-SMB-Attack.svg) ![forks](https://img.shields.io/github/forks/mrk336/From-EternalBlue-to-CVE-2025-2776-The-Evolution-of-an-SMB-Attack.svg)

## CVE-2025-2775
 SysAid On-Prem versions = 23.3.40 are vulnerable to an unauthenticated XML External Entity (XXE) vulnerability in the Checkin processing functionality,  allowing for administrator account takeover and file read primitives.



- [https://github.com/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain](https://github.com/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-SysAid-PreAuth-RCE-Chain.svg)

## CVE-2025-2748
 The Kentico Xperience application does not fully validate or filter files uploaded via the multiple-file upload functionality, which allows for stored XSS.This issue affects Kentico Xperience through 13.0.178.



- [https://github.com/xirtam2669/Kentico-Xperience-before-13.0.178---XSS-POC](https://github.com/xirtam2669/Kentico-Xperience-before-13.0.178---XSS-POC) :  ![starts](https://img.shields.io/github/stars/xirtam2669/Kentico-Xperience-before-13.0.178---XSS-POC.svg) ![forks](https://img.shields.io/github/forks/xirtam2669/Kentico-Xperience-before-13.0.178---XSS-POC.svg)

## CVE-2025-2624
 A vulnerability was found in westboy CicadasCMS 1.0. It has been rated as critical. Affected by this issue is some unknown functionality of the file /system/cms/content/save. The manipulation of the argument content/fujian/laiyuan leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/Habuon/CVE-2025-26240](https://github.com/Habuon/CVE-2025-26240) :  ![starts](https://img.shields.io/github/stars/Habuon/CVE-2025-26240.svg) ![forks](https://img.shields.io/github/forks/Habuon/CVE-2025-26240.svg)

- [https://github.com/JaRm222/CVE-2025-26244](https://github.com/JaRm222/CVE-2025-26244) :  ![starts](https://img.shields.io/github/stars/JaRm222/CVE-2025-26244.svg) ![forks](https://img.shields.io/github/forks/JaRm222/CVE-2025-26244.svg)

## CVE-2025-2620
 A vulnerability has been found in D-Link DAP-1620 1.03 and classified as critical. This vulnerability affects the function mod_graph_auth_uri_handler of the file /storage of the component Authentication Handler. The manipulation leads to stack-based buffer overflow. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. This vulnerability only affects products that are no longer supported by the maintainer.



- [https://github.com/Otsmane-Ahmed/CVE-2025-2620-poc](https://github.com/Otsmane-Ahmed/CVE-2025-2620-poc) :  ![starts](https://img.shields.io/github/stars/Otsmane-Ahmed/CVE-2025-2620-poc.svg) ![forks](https://img.shields.io/github/forks/Otsmane-Ahmed/CVE-2025-2620-poc.svg)

## CVE-2025-2596
 Session logout could be overwritten in Checkmk GmbH's Checkmk versions 2.3.0p30, 2.2.0p41, and 2.1.0p49 (EOL)



- [https://github.com/Sudo-Sakib/CVE-2025-25964](https://github.com/Sudo-Sakib/CVE-2025-25964) :  ![starts](https://img.shields.io/github/stars/Sudo-Sakib/CVE-2025-25964.svg) ![forks](https://img.shields.io/github/forks/Sudo-Sakib/CVE-2025-25964.svg)

- [https://github.com/Sudo-Sakib/CVE-2025-25965](https://github.com/Sudo-Sakib/CVE-2025-25965) :  ![starts](https://img.shields.io/github/stars/Sudo-Sakib/CVE-2025-25965.svg) ![forks](https://img.shields.io/github/forks/Sudo-Sakib/CVE-2025-25965.svg)

## CVE-2025-2594
 The User Registration & Membership WordPress plugin before 4.1.3 does not properly validate data in an AJAX action when the Membership Addon is enabled, allowing attackers to authenticate as any user, including administrators, by simply using the target account's user ID.



- [https://github.com/ubaydev/CVE-2025-2594](https://github.com/ubaydev/CVE-2025-2594) :  ![starts](https://img.shields.io/github/stars/ubaydev/CVE-2025-2594.svg) ![forks](https://img.shields.io/github/forks/ubaydev/CVE-2025-2594.svg)

## CVE-2025-2570
 Mattermost versions 10.5.x = 10.5.3, 9.11.x = 9.11.11 fail to check `RestrictSystemAdmin` setting if user doesn't have access to `ExperimentalSettings` which allows a System Manager to access `ExperimentSettings` when `RestrictSystemAdmin` is true via System Console.



- [https://github.com/Cotherm/CVE-2025-25705](https://github.com/Cotherm/CVE-2025-25705) :  ![starts](https://img.shields.io/github/stars/Cotherm/CVE-2025-25705.svg) ![forks](https://img.shields.io/github/forks/Cotherm/CVE-2025-25705.svg)

- [https://github.com/Cotherm/CVE-2025-25706](https://github.com/Cotherm/CVE-2025-25706) :  ![starts](https://img.shields.io/github/stars/Cotherm/CVE-2025-25706.svg) ![forks](https://img.shields.io/github/forks/Cotherm/CVE-2025-25706.svg)

## CVE-2025-2568
 The Vayu Blocks – Gutenberg Blocks for WordPress & WooCommerce plugin for WordPress is vulnerable to unauthorized access and modification of data due to missing capability checks on the 'vayu_blocks_get_toggle_switch_values_callback' and 'vayu_blocks_save_toggle_switch_callback' function in versions 1.0.4 to 1.2.1. This makes it possible for unauthenticated attackers to read plugin options and update any option with a key name ending in '_value'.



- [https://github.com/shinigami-777/PoC_CVE-2025-2568](https://github.com/shinigami-777/PoC_CVE-2025-2568) :  ![starts](https://img.shields.io/github/stars/shinigami-777/PoC_CVE-2025-2568.svg) ![forks](https://img.shields.io/github/forks/shinigami-777/PoC_CVE-2025-2568.svg)

## CVE-2025-2563
 The User Registration & Membership  WordPress plugin before 4.1.2 does not prevent users to set their account role when the Membership Addon is enabled, leading to a privilege escalation issue and allowing unauthenticated users to gain admin privileges



- [https://github.com/ubaydev/CVE-2025-2563](https://github.com/ubaydev/CVE-2025-2563) :  ![starts](https://img.shields.io/github/stars/ubaydev/CVE-2025-2563.svg) ![forks](https://img.shields.io/github/forks/ubaydev/CVE-2025-2563.svg)

## CVE-2025-2559
 A flaw was found in Keycloak. When the configuration uses JWT tokens for authentication, the tokens are cached until expiration. If a client uses JWT tokens with an excessively long expiration time, for example, 24 or 48 hours, the cache can grow indefinitely, leading to an OutOfMemoryError. This issue could result in a denial of service condition, preventing legitimate users from accessing the system.



- [https://github.com/Certitude-Consulting/CVE-2025-25599](https://github.com/Certitude-Consulting/CVE-2025-25599) :  ![starts](https://img.shields.io/github/stars/Certitude-Consulting/CVE-2025-25599.svg) ![forks](https://img.shields.io/github/forks/Certitude-Consulting/CVE-2025-25599.svg)

## CVE-2025-2539
 The File Away plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the ajax() function in all versions up to, and including, 3.9.9.0.1. This makes it possible for unauthenticated attackers, leveraging the use of a reversible weak algorithm,  to read the contents of arbitrary files on the server, which can contain sensitive information.



- [https://github.com/verylazytech/CVE-2025-2539](https://github.com/verylazytech/CVE-2025-2539) :  ![starts](https://img.shields.io/github/stars/verylazytech/CVE-2025-2539.svg) ![forks](https://img.shields.io/github/forks/verylazytech/CVE-2025-2539.svg)

- [https://github.com/RootHarpy/CVE-2025-2539](https://github.com/RootHarpy/CVE-2025-2539) :  ![starts](https://img.shields.io/github/stars/RootHarpy/CVE-2025-2539.svg) ![forks](https://img.shields.io/github/forks/RootHarpy/CVE-2025-2539.svg)

- [https://github.com/Yucaerin/CVE-2025-2539](https://github.com/Yucaerin/CVE-2025-2539) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-2539.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-2539.svg)

- [https://github.com/AlvaXPloit/CVE-2025-2539](https://github.com/AlvaXPloit/CVE-2025-2539) :  ![starts](https://img.shields.io/github/stars/AlvaXPloit/CVE-2025-2539.svg) ![forks](https://img.shields.io/github/forks/AlvaXPloit/CVE-2025-2539.svg)

- [https://github.com/d4rkh0rse/CVE-2025-2539](https://github.com/d4rkh0rse/CVE-2025-2539) :  ![starts](https://img.shields.io/github/stars/d4rkh0rse/CVE-2025-2539.svg) ![forks](https://img.shields.io/github/forks/d4rkh0rse/CVE-2025-2539.svg)

## CVE-2025-2536
 Cross-site scripting (XSS) vulnerability on Liferay Portal 7.4.3.82 through 7.4.3.128, and Liferay DXP 2024.Q3.0, 2024.Q2.0 through 2024.Q2.13, 2024.Q1.1 through 2024.Q1.12, 2023.Q4.0 through 2023.Q4.10, 2023.Q3.1 through 2023.Q3.10, 7.4 update 82 through update 92 in the Frontend JS module's layout-taglib/__liferay__/index.js allows remote attackers to inject arbitrary web script or HTML via toastData parameter



- [https://github.com/lkasjkasj/CVE-2025-25369](https://github.com/lkasjkasj/CVE-2025-25369) :  ![starts](https://img.shields.io/github/stars/lkasjkasj/CVE-2025-25369.svg) ![forks](https://img.shields.io/github/forks/lkasjkasj/CVE-2025-25369.svg)

## CVE-2025-2533
 IBM Db2 for Linux 12.1.0, 12.1.1, and 12.1.2 is vulnerable to a denial of service as the server may crash under certain conditions with a specially crafted query.



- [https://github.com/l00neyhacker/CVE-2025-25335](https://github.com/l00neyhacker/CVE-2025-25335) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2025-25335.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2025-25335.svg)

- [https://github.com/l00neyhacker/CVE-2025-25338](https://github.com/l00neyhacker/CVE-2025-25338) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2025-25338.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2025-25338.svg)

- [https://github.com/l00neyhacker/CVE-2025-25337](https://github.com/l00neyhacker/CVE-2025-25337) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2025-25337.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2025-25337.svg)

- [https://github.com/l00neyhacker/CVE-2025-25339](https://github.com/l00neyhacker/CVE-2025-25339) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2025-25339.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2025-25339.svg)

## CVE-2025-2502
 An improper default permissions vulnerability was reported in Lenovo PC Manager that could allow a local attacker to elevate privileges.



- [https://github.com/IHK-ONE/CVE-2025-2502](https://github.com/IHK-ONE/CVE-2025-2502) :  ![starts](https://img.shields.io/github/stars/IHK-ONE/CVE-2025-2502.svg) ![forks](https://img.shields.io/github/forks/IHK-ONE/CVE-2025-2502.svg)

## CVE-2025-2404
 Improper Neutralization of Input During Web Page Generation (XSS or 'Cross-site Scripting') vulnerability in Ubit Information Technologies STOYS allows Cross-Site Scripting (XSS).This issue affects STOYS: from 2 before 20250916.



- [https://github.com/sahici/CVE-2025-2404](https://github.com/sahici/CVE-2025-2404) :  ![starts](https://img.shields.io/github/stars/sahici/CVE-2025-2404.svg) ![forks](https://img.shields.io/github/forks/sahici/CVE-2025-2404.svg)

## CVE-2025-2301
 Authorization Bypass Through User-Controlled Key vulnerability in Akbim Software Online Exam Registration allows Exploitation of Trusted Identifiers.This issue affects Online Exam Registration: before 14.03.2025.



- [https://github.com/sahici/CVE-2025-2301](https://github.com/sahici/CVE-2025-2301) :  ![starts](https://img.shields.io/github/stars/sahici/CVE-2025-2301.svg) ![forks](https://img.shields.io/github/forks/sahici/CVE-2025-2301.svg)

## CVE-2025-2294
 The Kubio AI Page Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.5.1 via thekubio_hybrid_theme_load_template function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.



- [https://github.com/Nxploited/CVE-2025-2294](https://github.com/Nxploited/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-2294.svg)

- [https://github.com/Yucaerin/CVE-2025-2294](https://github.com/Yucaerin/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-2294.svg)

- [https://github.com/mrrivaldo/CVE-2025-2294](https://github.com/mrrivaldo/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/mrrivaldo/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/mrrivaldo/CVE-2025-2294.svg)

- [https://github.com/iteride/CVE-2025-2294](https://github.com/iteride/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/iteride/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/iteride/CVE-2025-2294.svg)

- [https://github.com/0xWhoami35/CVE-2025-2294](https://github.com/0xWhoami35/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/0xWhoami35/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/0xWhoami35/CVE-2025-2294.svg)

- [https://github.com/r0otk3r/CVE-2025-2294](https://github.com/r0otk3r/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2025-2294.svg)

- [https://github.com/rhz0d/CVE-2025-2294](https://github.com/rhz0d/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/rhz0d/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/rhz0d/CVE-2025-2294.svg)

- [https://github.com/romanedutov/CVE-2025-2294](https://github.com/romanedutov/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/romanedutov/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/romanedutov/CVE-2025-2294.svg)

## CVE-2025-2266
 The Checkout Mestres do WP for WooCommerce plugin for WordPress is vulnerable to unauthorized modification of data that can lead to privilege escalation due to a missing capability check on the cwmpUpdateOptions() function in versions 8.6.5 to 8.7.5. This makes it possible for unauthenticated attackers to update arbitrary options on the WordPress site. This can be leveraged to update the default role for registration to administrator and enable user registration for attackers to gain administrative user access to a vulnerable site.



- [https://github.com/Nxploited/CVE-2025-2266](https://github.com/Nxploited/CVE-2025-2266) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-2266.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-2266.svg)

## CVE-2025-2249
 The SoJ SoundSlides plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the soj_soundslides_options_subpanel() function in all versions up to, and including, 1.2.2. This makes it possible for authenticated attackers, with Contributor-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2025-2249](https://github.com/Nxploited/CVE-2025-2249) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-2249.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-2249.svg)

## CVE-2025-2135
 Type Confusion in V8 in Google Chrome prior to 134.0.6998.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/Wa1nut4/CVE-2025-2135](https://github.com/Wa1nut4/CVE-2025-2135) :  ![starts](https://img.shields.io/github/stars/Wa1nut4/CVE-2025-2135.svg) ![forks](https://img.shields.io/github/forks/Wa1nut4/CVE-2025-2135.svg)

- [https://github.com/sangnguyenthien/CVE-2025-2135](https://github.com/sangnguyenthien/CVE-2025-2135) :  ![starts](https://img.shields.io/github/stars/sangnguyenthien/CVE-2025-2135.svg) ![forks](https://img.shields.io/github/forks/sangnguyenthien/CVE-2025-2135.svg)

## CVE-2025-2082
 Tesla Model 3 VCSEC Integer Overflow Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected Tesla Model 3 vehicles. Authentication is not required to exploit this vulnerability.

The specific flaw exists within the VCSEC module. By manipulating the certificate response sent from the Tire Pressure Monitoring System (TPMS), an attacker can trigger an integer overflow before writing to memory. An attacker can leverage this vulnerability to execute code in the context of the VCSEC module and send arbitrary messages to the vehicle CAN bus. Was ZDI-CAN-23800.



- [https://github.com/Burak1320demiroz/cve-2025-2082](https://github.com/Burak1320demiroz/cve-2025-2082) :  ![starts](https://img.shields.io/github/stars/Burak1320demiroz/cve-2025-2082.svg) ![forks](https://img.shields.io/github/forks/Burak1320demiroz/cve-2025-2082.svg)

- [https://github.com/shirabo/cve-2025-2082-POV](https://github.com/shirabo/cve-2025-2082-POV) :  ![starts](https://img.shields.io/github/stars/shirabo/cve-2025-2082-POV.svg) ![forks](https://img.shields.io/github/forks/shirabo/cve-2025-2082-POV.svg)

## CVE-2025-2011
 The Slider & Popup Builder by Depicter plugin for WordPress is vulnerable to generic SQL Injection via the ‘s' parameter in all versions up to, and including, 3.6.1 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.



- [https://github.com/datagoboom/CVE-2025-2011](https://github.com/datagoboom/CVE-2025-2011) :  ![starts](https://img.shields.io/github/stars/datagoboom/CVE-2025-2011.svg) ![forks](https://img.shields.io/github/forks/datagoboom/CVE-2025-2011.svg)

## CVE-2025-2005
 The Front End Users plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the file uploads field of the registration form in all versions up to, and including, 3.2.32. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2025-2005](https://github.com/Nxploited/CVE-2025-2005) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-2005.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-2005.svg)

- [https://github.com/mrmtwoj/CVE-2025-2005](https://github.com/mrmtwoj/CVE-2025-2005) :  ![starts](https://img.shields.io/github/stars/mrmtwoj/CVE-2025-2005.svg) ![forks](https://img.shields.io/github/forks/mrmtwoj/CVE-2025-2005.svg)

- [https://github.com/h4ckxel/CVE-2025-2005](https://github.com/h4ckxel/CVE-2025-2005) :  ![starts](https://img.shields.io/github/stars/h4ckxel/CVE-2025-2005.svg) ![forks](https://img.shields.io/github/forks/h4ckxel/CVE-2025-2005.svg)

## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)



- [https://github.com/hakaioffsec/IngressNightmare-PoC](https://github.com/hakaioffsec/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/IngressNightmare-PoC.svg)

- [https://github.com/sandumjacob/IngressNightmare-POCs](https://github.com/sandumjacob/IngressNightmare-POCs) :  ![starts](https://img.shields.io/github/stars/sandumjacob/IngressNightmare-POCs.svg) ![forks](https://img.shields.io/github/forks/sandumjacob/IngressNightmare-POCs.svg)

- [https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps](https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps) :  ![starts](https://img.shields.io/github/stars/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg) ![forks](https://img.shields.io/github/forks/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg)

- [https://github.com/yoshino-s/CVE-2025-1974](https://github.com/yoshino-s/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/yoshino-s/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/yoshino-s/CVE-2025-1974.svg)

- [https://github.com/lufeirider/IngressNightmare-PoC](https://github.com/lufeirider/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/lufeirider/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/lufeirider/IngressNightmare-PoC.svg)

- [https://github.com/zwxxb/CVE-2025-1974](https://github.com/zwxxb/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/zwxxb/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/zwxxb/CVE-2025-1974.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-1974](https://github.com/B1ack4sh/Blackash-CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-1974.svg)

- [https://github.com/hi-unc1e/CVE-2025-1974-poc](https://github.com/hi-unc1e/CVE-2025-1974-poc) :  ![starts](https://img.shields.io/github/stars/hi-unc1e/CVE-2025-1974-poc.svg) ![forks](https://img.shields.io/github/forks/hi-unc1e/CVE-2025-1974-poc.svg)

- [https://github.com/rjhaikal/POC-IngressNightmare-CVE-2025-1974](https://github.com/rjhaikal/POC-IngressNightmare-CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/rjhaikal/POC-IngressNightmare-CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/rjhaikal/POC-IngressNightmare-CVE-2025-1974.svg)

- [https://github.com/chhhd/CVE-2025-1974](https://github.com/chhhd/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/chhhd/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/chhhd/CVE-2025-1974.svg)

- [https://github.com/Rubby2001/CVE-2025-1974-go](https://github.com/Rubby2001/CVE-2025-1974-go) :  ![starts](https://img.shields.io/github/stars/Rubby2001/CVE-2025-1974-go.svg) ![forks](https://img.shields.io/github/forks/Rubby2001/CVE-2025-1974-go.svg)

- [https://github.com/dttuss/IngressNightmare-RCE-POC](https://github.com/dttuss/IngressNightmare-RCE-POC) :  ![starts](https://img.shields.io/github/stars/dttuss/IngressNightmare-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/dttuss/IngressNightmare-RCE-POC.svg)

- [https://github.com/tuladhar/ingress-nightmare](https://github.com/tuladhar/ingress-nightmare) :  ![starts](https://img.shields.io/github/stars/tuladhar/ingress-nightmare.svg) ![forks](https://img.shields.io/github/forks/tuladhar/ingress-nightmare.svg)

- [https://github.com/zulloper/CVE-2025-1974](https://github.com/zulloper/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/zulloper/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/zulloper/CVE-2025-1974.svg)

- [https://github.com/salt318/CVE-2025-1974](https://github.com/salt318/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/salt318/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/salt318/CVE-2025-1974.svg)

- [https://github.com/iteride/CVE-2025-1974](https://github.com/iteride/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/iteride/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/iteride/CVE-2025-1974.svg)

- [https://github.com/yanmarques/CVE-2025-1974](https://github.com/yanmarques/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/yanmarques/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/yanmarques/CVE-2025-1974.svg)

- [https://github.com/0xBingo/CVE-2025-1974](https://github.com/0xBingo/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/0xBingo/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/0xBingo/CVE-2025-1974.svg)

- [https://github.com/Rickerd12/exploit-cve-2025-1974](https://github.com/Rickerd12/exploit-cve-2025-1974) :  ![starts](https://img.shields.io/github/stars/Rickerd12/exploit-cve-2025-1974.svg) ![forks](https://img.shields.io/github/forks/Rickerd12/exploit-cve-2025-1974.svg)

- [https://github.com/Armand2002/Exploit-CVE-2025-1974-Lab](https://github.com/Armand2002/Exploit-CVE-2025-1974-Lab) :  ![starts](https://img.shields.io/github/stars/Armand2002/Exploit-CVE-2025-1974-Lab.svg) ![forks](https://img.shields.io/github/forks/Armand2002/Exploit-CVE-2025-1974-Lab.svg)

- [https://github.com/BiiTts/POC-IngressNightmare-CVE-2025-1974](https://github.com/BiiTts/POC-IngressNightmare-CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/BiiTts/POC-IngressNightmare-CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/BiiTts/POC-IngressNightmare-CVE-2025-1974.svg)

- [https://github.com/abrewer251/CVE-2025-1974_IngressNightmare_PoC](https://github.com/abrewer251/CVE-2025-1974_IngressNightmare_PoC) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-1974_IngressNightmare_PoC.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-1974_IngressNightmare_PoC.svg)

- [https://github.com/m-q-t/ingressnightmare-detection-poc](https://github.com/m-q-t/ingressnightmare-detection-poc) :  ![starts](https://img.shields.io/github/stars/m-q-t/ingressnightmare-detection-poc.svg) ![forks](https://img.shields.io/github/forks/m-q-t/ingressnightmare-detection-poc.svg)

- [https://github.com/gian2dchris/ingress-nightmare-poc](https://github.com/gian2dchris/ingress-nightmare-poc) :  ![starts](https://img.shields.io/github/stars/gian2dchris/ingress-nightmare-poc.svg) ![forks](https://img.shields.io/github/forks/gian2dchris/ingress-nightmare-poc.svg)

- [https://github.com/Ar05un05kau05ndal/2025-1](https://github.com/Ar05un05kau05ndal/2025-1) :  ![starts](https://img.shields.io/github/stars/Ar05un05kau05ndal/2025-1.svg) ![forks](https://img.shields.io/github/forks/Ar05un05kau05ndal/2025-1.svg)

## CVE-2025-1793
 Multiple vector store integrations in run-llama/llama_index version v0.12.21 have SQL injection vulnerabilities. These vulnerabilities allow an attacker to read and write data using SQL, potentially leading to unauthorized access to data of other users depending on the usage of the llama-index library in a web application.



- [https://github.com/Usama-Figueira/-CVE-2025-1793-poc](https://github.com/Usama-Figueira/-CVE-2025-1793-poc) :  ![starts](https://img.shields.io/github/stars/Usama-Figueira/-CVE-2025-1793-poc.svg) ![forks](https://img.shields.io/github/forks/Usama-Figueira/-CVE-2025-1793-poc.svg)

## CVE-2025-1734
 In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19, from 8.4.* before 8.4.5, when receiving headers from HTTP server, the headers missing a colon (:) are treated as valid headers even though they are not. This may confuse applications into accepting invalid headers.



- [https://github.com/WolfThere/cve_2025-1734](https://github.com/WolfThere/cve_2025-1734) :  ![starts](https://img.shields.io/github/stars/WolfThere/cve_2025-1734.svg) ![forks](https://img.shields.io/github/forks/WolfThere/cve_2025-1734.svg)

## CVE-2025-1718
 An authenticated user with file access privilege via FTP access can cause the Relion 670/650 and SAM600-IO series device to reboot due to improper disk space management.



- [https://github.com/issamjr/CVE-2025-1718-Scanner](https://github.com/issamjr/CVE-2025-1718-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-1718-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-1718-Scanner.svg)

## CVE-2025-1716
 picklescan before 0.0.21 does not treat 'pip' as an unsafe global. An attacker could craft a malicious model that uses Pickle to pull in a malicious PyPI package (hosted, for example, on pypi.org or GitHub) via `pip.main()`. Because pip is not a restricted global, the model, when scanned with picklescan, would pass security checks and appear to be safe, when it could instead prove to be problematic.



- [https://github.com/shybu9/poc_CVE-2025-1716](https://github.com/shybu9/poc_CVE-2025-1716) :  ![starts](https://img.shields.io/github/stars/shybu9/poc_CVE-2025-1716.svg) ![forks](https://img.shields.io/github/forks/shybu9/poc_CVE-2025-1716.svg)

## CVE-2025-1661
 The HUSKY – Products Filter Professional for WooCommerce plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 1.3.6.5 via the 'template' parameter of the woof_text_search AJAX action. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.



- [https://github.com/gbrsh/CVE-2025-1661](https://github.com/gbrsh/CVE-2025-1661) :  ![starts](https://img.shields.io/github/stars/gbrsh/CVE-2025-1661.svg) ![forks](https://img.shields.io/github/forks/gbrsh/CVE-2025-1661.svg)

- [https://github.com/shahwarshah/CVE-2025-1661](https://github.com/shahwarshah/CVE-2025-1661) :  ![starts](https://img.shields.io/github/stars/shahwarshah/CVE-2025-1661.svg) ![forks](https://img.shields.io/github/forks/shahwarshah/CVE-2025-1661.svg)

- [https://github.com/MuhammadWaseem29/CVE-2025-1661](https://github.com/MuhammadWaseem29/CVE-2025-1661) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-1661.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-1661.svg)

## CVE-2025-1639
 The Animation Addons for Elementor Pro plugin for WordPress is vulnerable to unauthorized arbitrary plugin installation due to a missing capability check on the install_elementor_plugin_handler() function in all versions up to, and including, 1.6. This makes it possible for authenticated attackers, with Subscriber-level access and above, to install and activate arbitrary plugins which can be leveraged to further infect a victim when Elementor is not activated on a vulnerable site.



- [https://github.com/Nxploited/CVE-2025-1639](https://github.com/Nxploited/CVE-2025-1639) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-1639.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-1639.svg)

## CVE-2025-1562
 The Recover WooCommerce Cart Abandonment, Newsletter, Email Marketing, Marketing Automation By FunnelKit plugin for WordPress is vulnerable to unauthorized arbitrary plugin installation due to a missing capability check on the install_or_activate_addon_plugins() function and a weak nonce hash in all versions up to, and including, 3.5.3. This makes it possible for unauthenticated attackers to install arbitrary plugins on the site that can be leveraged to further infect a vulnerable site.



- [https://github.com/gmh5225/CVE-2025-1562](https://github.com/gmh5225/CVE-2025-1562) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2025-1562.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2025-1562.svg)

## CVE-2025-1550
 The Keras Model.load_model function permits arbitrary code execution, even with safe_mode=True, through a manually constructed, malicious .keras archive. By altering the config.json file within the archive, an attacker can specify arbitrary Python modules and functions, along with their arguments, to be loaded and executed during model loading.



- [https://github.com/ChCh0i/cve-2025-1550](https://github.com/ChCh0i/cve-2025-1550) :  ![starts](https://img.shields.io/github/stars/ChCh0i/cve-2025-1550.svg) ![forks](https://img.shields.io/github/forks/ChCh0i/cve-2025-1550.svg)

## CVE-2025-1461
 Improper neutralization of the value of the 'eventMoreText' property of the 'VCalendar' component in Vuetify allows unsanitized HTML to be inserted into the page. This can lead to a  Cross-Site Scripting (XSS) https://owasp.org/www-community/attacks/xss  attack. The vulnerability occurs because the default Vuetify translator will return the translation key as the translation, if it can't find an actual translation.

This issue affects Vuetify versions greater than or equal to 2.0.0 and less than 3.0.0.

Note:
Version 2.x of Vuetify is End-of-Life and will not receive any updates to address this issue. For more information see  here https://v2.vuetifyjs.com/en/about/eol/ .



- [https://github.com/neverendingsupport/nes-vuetify-cve-2025-1461](https://github.com/neverendingsupport/nes-vuetify-cve-2025-1461) :  ![starts](https://img.shields.io/github/stars/neverendingsupport/nes-vuetify-cve-2025-1461.svg) ![forks](https://img.shields.io/github/forks/neverendingsupport/nes-vuetify-cve-2025-1461.svg)

## CVE-2025-1338
 A vulnerability was found in NUUO Camera up to 20250203. It has been declared as critical. This vulnerability affects the function print_file of the file /handle_config.php. The manipulation of the argument log leads to command injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/jxcaxtc/CVE-2025-1338](https://github.com/jxcaxtc/CVE-2025-1338) :  ![starts](https://img.shields.io/github/stars/jxcaxtc/CVE-2025-1338.svg) ![forks](https://img.shields.io/github/forks/jxcaxtc/CVE-2025-1338.svg)

## CVE-2025-1337
 A vulnerability was found in Eastnets PaymentSafe 2.5.26.0. It has been classified as problematic. This affects an unknown part of the component BIC Search. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely. Upgrading to version 2.5.27.0 is able to address this issue.



- [https://github.com/ada-z3r0/CVE-2025-1337-PoC](https://github.com/ada-z3r0/CVE-2025-1337-PoC) :  ![starts](https://img.shields.io/github/stars/ada-z3r0/CVE-2025-1337-PoC.svg) ![forks](https://img.shields.io/github/forks/ada-z3r0/CVE-2025-1337-PoC.svg)

## CVE-2025-1323
 The WP-Recall – Registration, Profile, Commerce & More plugin for WordPress is vulnerable to SQL Injection via the 'databeat' parameter in all versions up to, and including, 16.26.10 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.



- [https://github.com/p33d/cve-2025-1323](https://github.com/p33d/cve-2025-1323) :  ![starts](https://img.shields.io/github/stars/p33d/cve-2025-1323.svg) ![forks](https://img.shields.io/github/forks/p33d/cve-2025-1323.svg)

## CVE-2025-1307
 The Newscrunch theme for WordPress is vulnerable to arbitrary file uploads due to a missing capability check in the newscrunch_install_and_activate_plugin() function in all versions up to, and including, 1.8.4.1. This makes it possible for authenticated attackers, with Subscriber-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2025-1307](https://github.com/Nxploited/CVE-2025-1307) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-1307.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-1307.svg)

## CVE-2025-1306
 The Newscrunch theme for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 1.8.4. This is due to missing or incorrect nonce validation on the newscrunch_install_and_activate_plugin() function. This makes it possible for unauthenticated attackers to upload arbitrary files via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/Nxploited/CVE-2025-1306](https://github.com/Nxploited/CVE-2025-1306) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-1306.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-1306.svg)

## CVE-2025-1304
 The NewsBlogger theme for WordPress is vulnerable to arbitrary file uploads due to a missing capability check on the newsblogger_install_and_activate_plugin() function in all versions up to, and including, 0.2.5.1. This makes it possible for authenticated attackers, with subscriber-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2025-1304](https://github.com/Nxploited/CVE-2025-1304) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-1304.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-1304.svg)

## CVE-2025-1302
 Versions of the package jsonpath-plus before 10.3.0 are vulnerable to Remote Code Execution (RCE) due to improper input sanitization. An attacker can execute aribitrary code on the system by exploiting the unsafe default usage of eval='safe' mode.**Note:**This is caused by an incomplete fix for [CVE-2024-21534](https://security.snyk.io/vuln/SNYK-JS-JSONPATHPLUS-7945884).



- [https://github.com/EQSTLab/CVE-2025-1302](https://github.com/EQSTLab/CVE-2025-1302) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2025-1302.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2025-1302.svg)

- [https://github.com/abrewer251/CVE-2025-1302_jsonpath-plus_RCE](https://github.com/abrewer251/CVE-2025-1302_jsonpath-plus_RCE) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-1302_jsonpath-plus_RCE.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-1302_jsonpath-plus_RCE.svg)

## CVE-2025-1219
 In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19, from 8.4.* before 8.4.5, when requesting a HTTP resource using the DOM or SimpleXML extensions, the wrong content-type header is used to determine the charset when the requested resource performs a redirect. This may cause the resulting document to be parsed incorrectly or bypass validations.



- [https://github.com/BreadSquad/ediop3PHP](https://github.com/BreadSquad/ediop3PHP) :  ![starts](https://img.shields.io/github/stars/BreadSquad/ediop3PHP.svg) ![forks](https://img.shields.io/github/forks/BreadSquad/ediop3PHP.svg)

## CVE-2025-1122
 Out-Of-Bounds Write in TPM2 Reference Library in Google ChromeOS 15753.50.0  stable on Cr50 Boards allows an attacker with root access to gain persistence and 
Bypass operating system verification via exploiting the NV_Read functionality during the Challenge-Response process.



- [https://github.com/FWNavy/RMASmoke](https://github.com/FWNavy/RMASmoke) :  ![starts](https://img.shields.io/github/stars/FWNavy/RMASmoke.svg) ![forks](https://img.shields.io/github/forks/FWNavy/RMASmoke.svg)

## CVE-2025-1100
 A CWE-259 "Use of Hard-coded Password" for the root account in Q-Free MaxTime less than or equal to version 2.11.0 allows an unauthenticated remote attacker to execute arbitrary code with root privileges via SSH.



- [https://github.com/pacbypass/CVE-2025-11001](https://github.com/pacbypass/CVE-2025-11001) :  ![starts](https://img.shields.io/github/stars/pacbypass/CVE-2025-11001.svg) ![forks](https://img.shields.io/github/forks/pacbypass/CVE-2025-11001.svg)

- [https://github.com/litolito54/CVE-2025-11001](https://github.com/litolito54/CVE-2025-11001) :  ![starts](https://img.shields.io/github/stars/litolito54/CVE-2025-11001.svg) ![forks](https://img.shields.io/github/forks/litolito54/CVE-2025-11001.svg)

## CVE-2025-1098
 A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `mirror-target` and `mirror-host` Ingress annotations can be used to inject arbitrary configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)



- [https://github.com/hakaioffsec/IngressNightmare-PoC](https://github.com/hakaioffsec/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/IngressNightmare-PoC.svg)

- [https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps](https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps) :  ![starts](https://img.shields.io/github/stars/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg) ![forks](https://img.shields.io/github/forks/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg)

- [https://github.com/lufeirider/IngressNightmare-PoC](https://github.com/lufeirider/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/lufeirider/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/lufeirider/IngressNightmare-PoC.svg)

## CVE-2025-1097
 A security issue was discovered in  ingress-nginx https://github.com/kubernetes/ingress-nginx  where the `auth-tls-match-cn` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)



- [https://github.com/hakaioffsec/IngressNightmare-PoC](https://github.com/hakaioffsec/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/IngressNightmare-PoC.svg)

- [https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps](https://github.com/Esonhugh/ingressNightmare-CVE-2025-1974-exps) :  ![starts](https://img.shields.io/github/stars/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg) ![forks](https://img.shields.io/github/forks/Esonhugh/ingressNightmare-CVE-2025-1974-exps.svg)

- [https://github.com/lufeirider/IngressNightmare-PoC](https://github.com/lufeirider/IngressNightmare-PoC) :  ![starts](https://img.shields.io/github/stars/lufeirider/IngressNightmare-PoC.svg) ![forks](https://img.shields.io/github/forks/lufeirider/IngressNightmare-PoC.svg)

## CVE-2025-1094
 Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.



- [https://github.com/soltanali0/CVE-2025-1094-Exploit](https://github.com/soltanali0/CVE-2025-1094-Exploit) :  ![starts](https://img.shields.io/github/stars/soltanali0/CVE-2025-1094-Exploit.svg) ![forks](https://img.shields.io/github/forks/soltanali0/CVE-2025-1094-Exploit.svg)

- [https://github.com/ishwardeepp/CVE-2025-1094-PoC-Postgre-SQLi](https://github.com/ishwardeepp/CVE-2025-1094-PoC-Postgre-SQLi) :  ![starts](https://img.shields.io/github/stars/ishwardeepp/CVE-2025-1094-PoC-Postgre-SQLi.svg) ![forks](https://img.shields.io/github/forks/ishwardeepp/CVE-2025-1094-PoC-Postgre-SQLi.svg)

- [https://github.com/shacojx/CVE-2025-1094-Exploit](https://github.com/shacojx/CVE-2025-1094-Exploit) :  ![starts](https://img.shields.io/github/stars/shacojx/CVE-2025-1094-Exploit.svg) ![forks](https://img.shields.io/github/forks/shacojx/CVE-2025-1094-Exploit.svg)

- [https://github.com/PinkArmor/CVE-2025-1094-Lab-Setup](https://github.com/PinkArmor/CVE-2025-1094-Lab-Setup) :  ![starts](https://img.shields.io/github/stars/PinkArmor/CVE-2025-1094-Lab-Setup.svg) ![forks](https://img.shields.io/github/forks/PinkArmor/CVE-2025-1094-Lab-Setup.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-1094](https://github.com/B1ack4sh/Blackash-CVE-2025-1094) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-1094.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-1094.svg)

- [https://github.com/aninfosec/CVE-2025-1094](https://github.com/aninfosec/CVE-2025-1094) :  ![starts](https://img.shields.io/github/stars/aninfosec/CVE-2025-1094.svg) ![forks](https://img.shields.io/github/forks/aninfosec/CVE-2025-1094.svg)

## CVE-2025-1055
 A vulnerability in the K7RKScan.sys driver, part of the K7 Security Anti-Malware suite, allows a local low-privilege user to send crafted IOCTL requests to terminate a wide range of processes running with administrative or system-level privileges, with the exception of those inherently protected by the operating system. This flaw stems from missing access control in the driver's IOCTL handler, enabling unprivileged users to perform privileged actions in kernel space. Successful exploitation can lead to denial of service by disrupting critical services or privileged applications.



- [https://github.com/BlackSnufkin/BYOVD](https://github.com/BlackSnufkin/BYOVD) :  ![starts](https://img.shields.io/github/stars/BlackSnufkin/BYOVD.svg) ![forks](https://img.shields.io/github/forks/BlackSnufkin/BYOVD.svg)

- [https://github.com/diego-tella/CVE-2025-1055-poc](https://github.com/diego-tella/CVE-2025-1055-poc) :  ![starts](https://img.shields.io/github/stars/diego-tella/CVE-2025-1055-poc.svg) ![forks](https://img.shields.io/github/forks/diego-tella/CVE-2025-1055-poc.svg)

## CVE-2025-1023
 A vulnerability exists in ChurchCRM 5.13.0 and prior that allows an attacker to execute arbitrary SQL queries by exploiting a time-based blind SQL Injection vulnerability in the EditEventTypes functionality. The newCountName parameter is directly concatenated into an SQL query without proper sanitization, allowing an attacker to manipulate database queries and execute arbitrary commands, potentially leading to data exfiltration, modification, or deletion.



- [https://github.com/dptsec/CVE-2025-10230](https://github.com/dptsec/CVE-2025-10230) :  ![starts](https://img.shields.io/github/stars/dptsec/CVE-2025-10230.svg) ![forks](https://img.shields.io/github/forks/dptsec/CVE-2025-10230.svg)

## CVE-2025-1015
 The Thunderbird Address Book URI fields contained unsanitized links. This could be used by an attacker to create and export an address book containing a malicious payload in a field. For example, in the “Other” field of the Instant Messaging section. If another user imported the address book, clicking on the link could result in opening a web page inside Thunderbird, and that page could execute (unprivileged) JavaScript. This vulnerability affects Thunderbird  128.7 and Thunderbird  135.



- [https://github.com/r3m0t3nu11/CVE-2025-1015](https://github.com/r3m0t3nu11/CVE-2025-1015) :  ![starts](https://img.shields.io/github/stars/r3m0t3nu11/CVE-2025-1015.svg) ![forks](https://img.shields.io/github/forks/r3m0t3nu11/CVE-2025-1015.svg)

## CVE-2025-0994
 Trimble Cityworks versions prior to 15.8.9 and Cityworks with office companion versions prior to 23.10 are vulnerable to a deserialization vulnerability. This could allow an authenticated user to perform a remote code execution attack against a customer’s Microsoft Internet Information Services (IIS) web server.



- [https://github.com/rxerium/CVE-2025-0994](https://github.com/rxerium/CVE-2025-0994) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-0994.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-0994.svg)

## CVE-2025-0924
 The WP Activity Log plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘message’ parameter in all versions up to, and including, 5.2.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/skrkcb2/CVE-2025-0924-different](https://github.com/skrkcb2/CVE-2025-0924-different) :  ![starts](https://img.shields.io/github/stars/skrkcb2/CVE-2025-0924-different.svg) ![forks](https://img.shields.io/github/forks/skrkcb2/CVE-2025-0924-different.svg)

## CVE-2025-0886
 An incorrect permissions vulnerability was reported in Elliptic Labs Virtual Lock Sensor that could allow a local, authenticated user to escalate privileges.



- [https://github.com/JNDataRT/VirtualLockSensorLPE](https://github.com/JNDataRT/VirtualLockSensorLPE) :  ![starts](https://img.shields.io/github/stars/JNDataRT/VirtualLockSensorLPE.svg) ![forks](https://img.shields.io/github/forks/JNDataRT/VirtualLockSensorLPE.svg)

## CVE-2025-0868
 A vulnerability, that could result in Remote Code Execution (RCE), has been found in DocsGPT. Due to improper parsing of JSON data using eval() an unauthorized attacker could send arbitrary Python code to be executed via /api/remote endpoint..

This issue affects DocsGPT: from 0.8.1 through 0.12.0.



- [https://github.com/aidana-gift/CVE-2025-0868](https://github.com/aidana-gift/CVE-2025-0868) :  ![starts](https://img.shields.io/github/stars/aidana-gift/CVE-2025-0868.svg) ![forks](https://img.shields.io/github/forks/aidana-gift/CVE-2025-0868.svg)

## CVE-2025-0851
 A path traversal issue in ZipUtils.unzip and TarUtils.untar in Deep Java Library (DJL) on all platforms allows a bad actor to write files to arbitrary locations.



- [https://github.com/skrkcb2/CVE-2025-0851](https://github.com/skrkcb2/CVE-2025-0851) :  ![starts](https://img.shields.io/github/stars/skrkcb2/CVE-2025-0851.svg) ![forks](https://img.shields.io/github/forks/skrkcb2/CVE-2025-0851.svg)

## CVE-2025-0411
 7-Zip Mark-of-the-Web Bypass Vulnerability. This vulnerability allows remote attackers to bypass the Mark-of-the-Web protection mechanism on affected installations of 7-Zip. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the handling of archived files. When extracting files from a crafted archive that bears the Mark-of-the-Web, 7-Zip does not propagate the Mark-of-the-Web to the extracted files. An attacker can leverage this vulnerability to execute arbitrary code in the context of the current user. Was ZDI-CAN-25456.



- [https://github.com/dhmosfunk/7-Zip-CVE-2025-0411-POC](https://github.com/dhmosfunk/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/dhmosfunk/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/dhmosfunk/7-Zip-CVE-2025-0411-POC.svg)

- [https://github.com/dpextreme/7-Zip-CVE-2025-0411-POC](https://github.com/dpextreme/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/dpextreme/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/dpextreme/7-Zip-CVE-2025-0411-POC.svg)

- [https://github.com/cesarbtakeda/7-Zip-CVE-2025-0411-POC](https://github.com/cesarbtakeda/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/cesarbtakeda/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/cesarbtakeda/7-Zip-CVE-2025-0411-POC.svg)

- [https://github.com/iSee857/CVE-2025-0411-PoC](https://github.com/iSee857/CVE-2025-0411-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-0411-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-0411-PoC.svg)

- [https://github.com/ishwardeepp/CVE-2025-0411-MoTW-PoC](https://github.com/ishwardeepp/CVE-2025-0411-MoTW-PoC) :  ![starts](https://img.shields.io/github/stars/ishwardeepp/CVE-2025-0411-MoTW-PoC.svg) ![forks](https://img.shields.io/github/forks/ishwardeepp/CVE-2025-0411-MoTW-PoC.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-0411](https://github.com/B1ack4sh/Blackash-CVE-2025-0411) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-0411.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-0411.svg)

- [https://github.com/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC](https://github.com/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/RustMacrosRecoil/7-Zip-CVE-2025-0411-POC.svg)

- [https://github.com/betulssahin/CVE-2025-0411-7-Zip-Mark-of-the-Web-Bypass](https://github.com/betulssahin/CVE-2025-0411-7-Zip-Mark-of-the-Web-Bypass) :  ![starts](https://img.shields.io/github/stars/betulssahin/CVE-2025-0411-7-Zip-Mark-of-the-Web-Bypass.svg) ![forks](https://img.shields.io/github/forks/betulssahin/CVE-2025-0411-7-Zip-Mark-of-the-Web-Bypass.svg)

## CVE-2025-0401
 A vulnerability classified as critical has been found in 1902756969 reggie 1.0. Affected is the function download of the file src/main/java/com/itheima/reggie/controller/CommonController.java. The manipulation of the argument name leads to path traversal. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.



- [https://github.com/CyberSecurityUP/CVE-2025-0401](https://github.com/CyberSecurityUP/CVE-2025-0401) :  ![starts](https://img.shields.io/github/stars/CyberSecurityUP/CVE-2025-0401.svg) ![forks](https://img.shields.io/github/forks/CyberSecurityUP/CVE-2025-0401.svg)

- [https://github.com/Darabium/Gombruc](https://github.com/Darabium/Gombruc) :  ![starts](https://img.shields.io/github/stars/Darabium/Gombruc.svg) ![forks](https://img.shields.io/github/forks/Darabium/Gombruc.svg)

## CVE-2025-0364
 BigAntSoft BigAnt Server, up to and including version 5.6.06, is vulnerable to unauthenticated remote code execution via account registration. An unauthenticated remote attacker can create an administrative user through the default exposed SaaS registration mechanism. Once an administrator, the attacker can upload and execute arbitrary PHP code using the "Cloud Storage Addin," leading to unauthenticated code execution.



- [https://github.com/vulncheck-oss/cve-2025-0364](https://github.com/vulncheck-oss/cve-2025-0364) :  ![starts](https://img.shields.io/github/stars/vulncheck-oss/cve-2025-0364.svg) ![forks](https://img.shields.io/github/forks/vulncheck-oss/cve-2025-0364.svg)

## CVE-2025-0316
 The WP Directorybox Manager plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 2.5. This is due to incorrect authentication in the 'wp_dp_enquiry_agent_contact_form_submit_callback' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they have access to the username.



- [https://github.com/MrPayloadC/CVE-2025-0316-Exploit](https://github.com/MrPayloadC/CVE-2025-0316-Exploit) :  ![starts](https://img.shields.io/github/stars/MrPayloadC/CVE-2025-0316-Exploit.svg) ![forks](https://img.shields.io/github/forks/MrPayloadC/CVE-2025-0316-Exploit.svg)

## CVE-2025-0309
 An insufficient validation on the server connection endpoint in Netskope Client allows local users to elevate privileges on the system. The insufficient validation allows Netskope Client to connect to any other server with Public Signed CA TLS certificates and send specially crafted responses to elevate privileges.



- [https://github.com/AmberWolfCyber/UpSkope](https://github.com/AmberWolfCyber/UpSkope) :  ![starts](https://img.shields.io/github/stars/AmberWolfCyber/UpSkope.svg) ![forks](https://img.shields.io/github/forks/AmberWolfCyber/UpSkope.svg)

## CVE-2025-0288
 Various Paragon Software products contain an arbitrary kernel memory vulnerability within biontdrv.sys, facilitated by the memmove function, which does not validate or sanitize user controlled input, allowing an attacker the ability to write arbitrary kernel memory and perform privilege escalation.



- [https://github.com/barhen12/CVE-2025-0288](https://github.com/barhen12/CVE-2025-0288) :  ![starts](https://img.shields.io/github/stars/barhen12/CVE-2025-0288.svg) ![forks](https://img.shields.io/github/forks/barhen12/CVE-2025-0288.svg)

## CVE-2025-0282
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.



- [https://github.com/absholi7ly/CVE-2025-0282-Ivanti-exploit](https://github.com/absholi7ly/CVE-2025-0282-Ivanti-exploit) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2025-0282-Ivanti-exploit.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2025-0282-Ivanti-exploit.svg)

- [https://github.com/sfewer-r7/CVE-2025-0282](https://github.com/sfewer-r7/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2025-0282.svg)

- [https://github.com/watchtowrlabs/CVE-2025-0282](https://github.com/watchtowrlabs/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/CVE-2025-0282.svg)

- [https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser](https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser) :  ![starts](https://img.shields.io/github/stars/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg) ![forks](https://img.shields.io/github/forks/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg)

- [https://github.com/punitdarji/Ivanti-CVE-2025-0282](https://github.com/punitdarji/Ivanti-CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/punitdarji/Ivanti-CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Ivanti-CVE-2025-0282.svg)

- [https://github.com/AnonStorks/CVE-2025-0282-Full-version](https://github.com/AnonStorks/CVE-2025-0282-Full-version) :  ![starts](https://img.shields.io/github/stars/AnonStorks/CVE-2025-0282-Full-version.svg) ![forks](https://img.shields.io/github/forks/AnonStorks/CVE-2025-0282-Full-version.svg)

- [https://github.com/almanatra/CVE-2025-0282](https://github.com/almanatra/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/almanatra/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/almanatra/CVE-2025-0282.svg)

- [https://github.com/AdaniKamal/CVE-2025-0282](https://github.com/AdaniKamal/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/AdaniKamal/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/AdaniKamal/CVE-2025-0282.svg)

- [https://github.com/44xo/CVE-2025-0282](https://github.com/44xo/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/44xo/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/44xo/CVE-2025-0282.svg)

- [https://github.com/rxwx/pulse-meter](https://github.com/rxwx/pulse-meter) :  ![starts](https://img.shields.io/github/stars/rxwx/pulse-meter.svg) ![forks](https://img.shields.io/github/forks/rxwx/pulse-meter.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-0282](https://github.com/B1ack4sh/Blackash-CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-0282.svg)

## CVE-2025-0133
 A reflected cross-site scripting (XSS) vulnerability in the GlobalProtect™ gateway and portal features of Palo Alto Networks PAN-OS® software enables execution of malicious JavaScript in the context of an authenticated Captive Portal user's browser when they click on a specially crafted link. The primary risk is phishing attacks that can lead to credential theft—particularly if you enabled Clientless VPN.

There is no availability impact to GlobalProtect features or GlobalProtect users. Attackers cannot use this vulnerability to tamper with or modify contents or configurations of the GlobalProtect portal or gateways. The integrity impact of this vulnerability is limited to enabling an attacker to create phishing and credential-stealing links that appear to be hosted on the GlobalProtect portal.



For GlobalProtect users with Clientless VPN enabled, there is a limited impact on confidentiality due to inherent risks of Clientless VPN that facilitate credential theft. You can read more about this risk in the informational bulletin  PAN-SA-2025-0005 https://security.paloaltonetworks.com/PAN-SA-2025-0005   https://security.paloaltonetworks.com/PAN-SA-2025-0005 . There is no impact to confidentiality for GlobalProtect users if you did not enable (or you disable) Clientless VPN.



- [https://github.com/ynsmroztas/-CVE-2025-0133-GlobalProtect-XSS](https://github.com/ynsmroztas/-CVE-2025-0133-GlobalProtect-XSS) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/-CVE-2025-0133-GlobalProtect-XSS.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/-CVE-2025-0133-GlobalProtect-XSS.svg)

- [https://github.com/INTELEON404/CVE-2025-0133](https://github.com/INTELEON404/CVE-2025-0133) :  ![starts](https://img.shields.io/github/stars/INTELEON404/CVE-2025-0133.svg) ![forks](https://img.shields.io/github/forks/INTELEON404/CVE-2025-0133.svg)

- [https://github.com/dodiorne/cve-2025-0133](https://github.com/dodiorne/cve-2025-0133) :  ![starts](https://img.shields.io/github/stars/dodiorne/cve-2025-0133.svg) ![forks](https://img.shields.io/github/forks/dodiorne/cve-2025-0133.svg)

- [https://github.com/adhamelhansye/CVE-2025-0133](https://github.com/adhamelhansye/CVE-2025-0133) :  ![starts](https://img.shields.io/github/stars/adhamelhansye/CVE-2025-0133.svg) ![forks](https://img.shields.io/github/forks/adhamelhansye/CVE-2025-0133.svg)

- [https://github.com/wiseep/CVE-2025-0133](https://github.com/wiseep/CVE-2025-0133) :  ![starts](https://img.shields.io/github/stars/wiseep/CVE-2025-0133.svg) ![forks](https://img.shields.io/github/forks/wiseep/CVE-2025-0133.svg)

- [https://github.com/shawarkhanethicalhacker/CVE-2025-0133-exploit](https://github.com/shawarkhanethicalhacker/CVE-2025-0133-exploit) :  ![starts](https://img.shields.io/github/stars/shawarkhanethicalhacker/CVE-2025-0133-exploit.svg) ![forks](https://img.shields.io/github/forks/shawarkhanethicalhacker/CVE-2025-0133-exploit.svg)

## CVE-2025-0108
 An authentication bypass in the Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to bypass the authentication otherwise required by the PAN-OS management web interface and invoke certain PHP scripts. While invoking these PHP scripts does not enable remote code execution, it can negatively impact integrity and confidentiality of PAN-OS.

You can greatly reduce the risk of this issue by restricting access to the management web interface to only trusted internal IP addresses according to our recommended  best practices deployment guidelines https://live.paloaltonetworks.com/t5/community-blogs/tips-amp-tricks-how-to-secure-the-management-access-of-your-palo/ba-p/464431 .

This issue does not affect Cloud NGFW or Prisma Access software.



- [https://github.com/iSee857/CVE-2025-0108-PoC](https://github.com/iSee857/CVE-2025-0108-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-0108-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-0108-PoC.svg)

- [https://github.com/FOLKS-iwd/CVE-2025-0108-PoC](https://github.com/FOLKS-iwd/CVE-2025-0108-PoC) :  ![starts](https://img.shields.io/github/stars/FOLKS-iwd/CVE-2025-0108-PoC.svg) ![forks](https://img.shields.io/github/forks/FOLKS-iwd/CVE-2025-0108-PoC.svg)

- [https://github.com/becrevex/CVE-2025-0108](https://github.com/becrevex/CVE-2025-0108) :  ![starts](https://img.shields.io/github/stars/becrevex/CVE-2025-0108.svg) ![forks](https://img.shields.io/github/forks/becrevex/CVE-2025-0108.svg)

- [https://github.com/fr4nc1stein/CVE-2025-0108-SCAN](https://github.com/fr4nc1stein/CVE-2025-0108-SCAN) :  ![starts](https://img.shields.io/github/stars/fr4nc1stein/CVE-2025-0108-SCAN.svg) ![forks](https://img.shields.io/github/forks/fr4nc1stein/CVE-2025-0108-SCAN.svg)

- [https://github.com/B1ack4sh/Blackash-CVE-2025-0108](https://github.com/B1ack4sh/Blackash-CVE-2025-0108) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-0108.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-0108.svg)

- [https://github.com/sohaibeb/CVE-2025-0108](https://github.com/sohaibeb/CVE-2025-0108) :  ![starts](https://img.shields.io/github/stars/sohaibeb/CVE-2025-0108.svg) ![forks](https://img.shields.io/github/forks/sohaibeb/CVE-2025-0108.svg)

- [https://github.com/barcrange/CVE-2025-0108-Authentication-Bypass-checker](https://github.com/barcrange/CVE-2025-0108-Authentication-Bypass-checker) :  ![starts](https://img.shields.io/github/stars/barcrange/CVE-2025-0108-Authentication-Bypass-checker.svg) ![forks](https://img.shields.io/github/forks/barcrange/CVE-2025-0108-Authentication-Bypass-checker.svg)

## CVE-2025-0087
 In onCreate of UninstallerActivity.java, there is a possible way to uninstall a different user's app due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.



- [https://github.com/SpiralBL0CK/CVE-2025-0087-](https://github.com/SpiralBL0CK/CVE-2025-0087-) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2025-0087-.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2025-0087-.svg)

- [https://github.com/SpiralBL0CK/CVE-2025-0087](https://github.com/SpiralBL0CK/CVE-2025-0087) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2025-0087.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2025-0087.svg)

## CVE-2025-0054
 SAP NetWeaver Application Server Java does not sufficiently handle user input, resulting in a stored cross-site scripting vulnerability. The application allows attackers with basic user privileges to store a Javascript payload on the server, which could be later executed in the victim's web browser. With this the attacker might be able to read or modify information associated with the vulnerable web page.



- [https://github.com/z3usx01/CVE-2025-0054](https://github.com/z3usx01/CVE-2025-0054) :  ![starts](https://img.shields.io/github/stars/z3usx01/CVE-2025-0054.svg) ![forks](https://img.shields.io/github/forks/z3usx01/CVE-2025-0054.svg)

## CVE-2025-0011
 Improper removal of sensitive information before storage or transfer in AMD Crash Defender could allow an attacker to obtain kernel address information potentially resulting in loss of confidentiality.



- [https://github.com/binarywarm/kentico-xperience13-AuthBypass-CVE-2025-0011](https://github.com/binarywarm/kentico-xperience13-AuthBypass-CVE-2025-0011) :  ![starts](https://img.shields.io/github/stars/binarywarm/kentico-xperience13-AuthBypass-CVE-2025-0011.svg) ![forks](https://img.shields.io/github/forks/binarywarm/kentico-xperience13-AuthBypass-CVE-2025-0011.svg)
