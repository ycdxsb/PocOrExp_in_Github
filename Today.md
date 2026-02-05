# Update 2026-02-05
## CVE-2026-25130
 Cybersecurity AI (CAI) is a framework for AI Security. In versions up to and including 0.5.10, the CAI (Cybersecurity AI) framework contains multiple argument injection vulnerabilities in its function tools. User-controlled input is passed directly to shell commands via `subprocess.Popen()` with `shell=True`, allowing attackers to execute arbitrary commands on the host system. The `find_file()` tool executes without requiring user approval because find is considered a "safe" pre-approved command. This means an attacker can achieve Remote Code Execution (RCE) by injecting malicious arguments (like -exec) into the args parameter, completely bypassing any human-in-the-loop safety mechanisms. Commit e22a1220f764e2d7cf9da6d6144926f53ca01cde contains a fix.

- [https://github.com/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10](https://github.com/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10.svg)


## CVE-2026-24854
 ChurchCRM is an open-source church management system. A SQL Injection vulnerability exists in endpoint `/PaddleNumEditor.php` in ChurchCRM prior to version 6.7.2. Any authenticated user, including one with zero assigned permissions, can exploit SQL injection through the `PerID` parameter. Version 6.7.2 contains a patch for the issue.

- [https://github.com/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection](https://github.com/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/obrunolima1910/CVE-2026-24061](https://github.com/obrunolima1910/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/obrunolima1910/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/obrunolima1910/CVE-2026-24061.svg)
- [https://github.com/Good123321-bot/CVE-2026-24061-POC](https://github.com/Good123321-bot/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/Good123321-bot/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/Good123321-bot/CVE-2026-24061-POC.svg)
- [https://github.com/Good123321-bot/good123321-bot.github.io](https://github.com/Good123321-bot/good123321-bot.github.io) :  ![starts](https://img.shields.io/github/stars/Good123321-bot/good123321-bot.github.io.svg) ![forks](https://img.shields.io/github/forks/Good123321-bot/good123321-bot.github.io.svg)
- [https://github.com/Moxxic1/Tell-Me-Root](https://github.com/Moxxic1/Tell-Me-Root) :  ![starts](https://img.shields.io/github/stars/Moxxic1/Tell-Me-Root.svg) ![forks](https://img.shields.io/github/forks/Moxxic1/Tell-Me-Root.svg)
- [https://github.com/obrunolima1910/obrunolima1910.github.io](https://github.com/obrunolima1910/obrunolima1910.github.io) :  ![starts](https://img.shields.io/github/stars/obrunolima1910/obrunolima1910.github.io.svg) ![forks](https://img.shields.io/github/forks/obrunolima1910/obrunolima1910.github.io.svg)
- [https://github.com/Moxxic1/moxxic1.github.io](https://github.com/Moxxic1/moxxic1.github.io) :  ![starts](https://img.shields.io/github/stars/Moxxic1/moxxic1.github.io.svg) ![forks](https://img.shields.io/github/forks/Moxxic1/moxxic1.github.io.svg)


## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).

- [https://github.com/gregk4sec/CVE-2026-21962](https://github.com/gregk4sec/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2026-21962.svg)


## CVE-2026-21721
 The dashboard permissions API does not verify the target dashboard scope and only checks the dashboards.permissions:* action. As a result, a user who has permission management rights on one dashboard can read and modify permissions on other dashboards. This is an organization‑internal privilege escalation.

- [https://github.com/Leonideath/Exploit-LPE-CVE-2026-21721](https://github.com/Leonideath/Exploit-LPE-CVE-2026-21721) :  ![starts](https://img.shields.io/github/stars/Leonideath/Exploit-LPE-CVE-2026-21721.svg) ![forks](https://img.shields.io/github/forks/Leonideath/Exploit-LPE-CVE-2026-21721.svg)


## CVE-2025-70849
 Arbitrary File Upload in podinfo thru 6.9.0 allows unauthenticated attackers to upload arbitrary files via crafted POST request to the /store endpoint. The application renders uploaded content without a restrictive Content-Security-Policy (CSP) or adequate Content-Type validation, leading to Stored Cross-Site Scripting (XSS).

- [https://github.com/kazisabu/CVE-2025-70849-Podinfo](https://github.com/kazisabu/CVE-2025-70849-Podinfo) :  ![starts](https://img.shields.io/github/stars/kazisabu/CVE-2025-70849-Podinfo.svg) ![forks](https://img.shields.io/github/forks/kazisabu/CVE-2025-70849-Podinfo.svg)


## CVE-2025-69848
 NetBox is an open-source infrastructure resource modeling and IP address management platform. A reflected cross-site scripting (XSS) vulnerability exists in versions 2.11.0 through 3.7.x in the ProtectedError handling logic, where object names are included in HTML error messages without proper escaping. This allows user-controlled content to be rendered in the web interface when a delete operation fails due to protected relationships, potentially enabling execution of arbitrary client-side code in the context of a privileged user.

- [https://github.com/alkimcoskun/security-advisories](https://github.com/alkimcoskun/security-advisories) :  ![starts](https://img.shields.io/github/stars/alkimcoskun/security-advisories.svg) ![forks](https://img.shields.io/github/forks/alkimcoskun/security-advisories.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/MuhammadUwais/React2Shell](https://github.com/MuhammadUwais/React2Shell) :  ![starts](https://img.shields.io/github/stars/MuhammadUwais/React2Shell.svg) ![forks](https://img.shields.io/github/forks/MuhammadUwais/React2Shell.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-61506
 An issue was discovered in MediaCrush thru 1.0.1 allowing remote unauthenticated attackers to upload arbitrary files of any size to the /upload endpoint.

- [https://github.com/pescada-dev/CVE-2025-61506](https://github.com/pescada-dev/CVE-2025-61506) :  ![starts](https://img.shields.io/github/stars/pescada-dev/CVE-2025-61506.svg) ![forks](https://img.shields.io/github/forks/pescada-dev/CVE-2025-61506.svg)


## CVE-2025-57529
 YouDataSum CPAS Audit Management System =v4.9 is vulnerable to SQL Injection in /cpasList/findArchiveReportByDah due to insufficient input validation. This allows remote unauthenticated attackers to execute arbitrary SQL commands via crafted input to the parameter. Successful exploitation could lead to unauthorized data access

- [https://github.com/songqb-xx/CVE-2025-57529](https://github.com/songqb-xx/CVE-2025-57529) :  ![starts](https://img.shields.io/github/stars/songqb-xx/CVE-2025-57529.svg) ![forks](https://img.shields.io/github/forks/songqb-xx/CVE-2025-57529.svg)


## CVE-2025-54068
 Livewire is a full-stack framework for Laravel. In Livewire v3 up to and including v3.6.3, a vulnerability allows unauthenticated attackers to achieve remote command execution in specific scenarios. The issue stems from how certain component property updates are hydrated. This vulnerability is unique to Livewire v3 and does not affect prior major versions. Exploitation requires a component to be mounted and configured in a particular way, but does not require authentication or user interaction. This issue has been patched in Livewire v3.6.4. All users are strongly encouraged to upgrade to this version or later as soon as possible. No known workarounds are available.

- [https://github.com/Jenderal92/livewire-vuln-scanner](https://github.com/Jenderal92/livewire-vuln-scanner) :  ![starts](https://img.shields.io/github/stars/Jenderal92/livewire-vuln-scanner.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/livewire-vuln-scanner.svg)


## CVE-2025-37899
be in the smb2_sess_setup function which makes use of sess-user.

- [https://github.com/ccss17/o3_finds_cve-2025-37899](https://github.com/ccss17/o3_finds_cve-2025-37899) :  ![starts](https://img.shields.io/github/stars/ccss17/o3_finds_cve-2025-37899.svg) ![forks](https://img.shields.io/github/forks/ccss17/o3_finds_cve-2025-37899.svg)


## CVE-2025-24132
 The issue was addressed with improved memory handling. This issue is fixed in AirPlay audio SDK 2.7.1, AirPlay video SDK 3.6.0.126, CarPlay Communication Plug-in R18.1. An attacker on the local network may cause an unexpected app termination.

- [https://github.com/TheGamingGallifreyan/LiberationPlay-CVE-2025-24132-AirBourne-Crash-POC](https://github.com/TheGamingGallifreyan/LiberationPlay-CVE-2025-24132-AirBourne-Crash-POC) :  ![starts](https://img.shields.io/github/stars/TheGamingGallifreyan/LiberationPlay-CVE-2025-24132-AirBourne-Crash-POC.svg) ![forks](https://img.shields.io/github/forks/TheGamingGallifreyan/LiberationPlay-CVE-2025-24132-AirBourne-Crash-POC.svg)


## CVE-2025-15467
OpenSSL 1.1.1 and 1.0.2 are not affected by this issue.

- [https://github.com/mr-r3b00t/CVE-2025-15467](https://github.com/mr-r3b00t/CVE-2025-15467) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2025-15467.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2025-15467.svg)


## CVE-2025-10878
 A SQL injection vulnerability exists in the login functionality of Fikir Odalari AdminPando 1.0.1 before 2026-01-26. The username and password parameters are vulnerable to SQL injection, allowing unauthenticated attackers to bypass authentication completely. Successful exploitation grants full administrative access to the application, including the ability to manipulate the public-facing website content (HTML/DOM manipulation).

- [https://github.com/onurcangnc/CVE-2025-10878-AdminPandov1.0.1-SQLi](https://github.com/onurcangnc/CVE-2025-10878-AdminPandov1.0.1-SQLi) :  ![starts](https://img.shields.io/github/stars/onurcangnc/CVE-2025-10878-AdminPandov1.0.1-SQLi.svg) ![forks](https://img.shields.io/github/forks/onurcangnc/CVE-2025-10878-AdminPandov1.0.1-SQLi.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/DeathShotXD/0xKern3lCrush-Foreverday-BYOVD-CVE-2026-0828](https://github.com/DeathShotXD/0xKern3lCrush-Foreverday-BYOVD-CVE-2026-0828) :  ![starts](https://img.shields.io/github/stars/DeathShotXD/0xKern3lCrush-Foreverday-BYOVD-CVE-2026-0828.svg) ![forks](https://img.shields.io/github/forks/DeathShotXD/0xKern3lCrush-Foreverday-BYOVD-CVE-2026-0828.svg)


## CVE-2025-6579
 A vulnerability was found in code-projects Car Rental System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /message_admin.php. The manipulation of the argument Message leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/rishavand1/CVE-2025-65791](https://github.com/rishavand1/CVE-2025-65791) :  ![starts](https://img.shields.io/github/stars/rishavand1/CVE-2025-65791.svg) ![forks](https://img.shields.io/github/forks/rishavand1/CVE-2025-65791.svg)


## CVE-2025-5319
NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/sahici/CVE-2025-5319](https://github.com/sahici/CVE-2025-5319) :  ![starts](https://img.shields.io/github/stars/sahici/CVE-2025-5319.svg) ![forks](https://img.shields.io/github/forks/sahici/CVE-2025-5319.svg)


## CVE-2024-46987
 Camaleon CMS is a dynamic and advanced content management system based on Ruby on Rails. A path traversal vulnerability accessible via MediaController's download_private_file method allows authenticated users to download any file on the web server Camaleon CMS is running on (depending on the file permissions). This issue may lead to Information Disclosure. This issue has been addressed in release version 2.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/L1337Xi/CVE-2024-46987](https://github.com/L1337Xi/CVE-2024-46987) :  ![starts](https://img.shields.io/github/stars/L1337Xi/CVE-2024-46987.svg) ![forks](https://img.shields.io/github/forks/L1337Xi/CVE-2024-46987.svg)
- [https://github.com/Ik0nw/CVE-2024-46987](https://github.com/Ik0nw/CVE-2024-46987) :  ![starts](https://img.shields.io/github/stars/Ik0nw/CVE-2024-46987.svg) ![forks](https://img.shields.io/github/forks/Ik0nw/CVE-2024-46987.svg)


## CVE-2024-31317
 In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/kalibb/CVE-2024-31317-Deployer](https://github.com/kalibb/CVE-2024-31317-Deployer) :  ![starts](https://img.shields.io/github/stars/kalibb/CVE-2024-31317-Deployer.svg) ![forks](https://img.shields.io/github/forks/kalibb/CVE-2024-31317-Deployer.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit](https://github.com/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/xeloxa/CVE-2024-28397-Js2Py-RCE-Exploit.svg)


## CVE-2024-21006
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/d3fudd/CVE-2024-21006_PoC](https://github.com/d3fudd/CVE-2024-21006_PoC) :  ![starts](https://img.shields.io/github/stars/d3fudd/CVE-2024-21006_PoC.svg) ![forks](https://img.shields.io/github/forks/d3fudd/CVE-2024-21006_PoC.svg)


## CVE-2024-5243
The specific flaw exists within the handling of DNS names. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-22523.

- [https://github.com/yi-barrack/CVE-2024-5243-pwn2own-toronto-2023](https://github.com/yi-barrack/CVE-2024-5243-pwn2own-toronto-2023) :  ![starts](https://img.shields.io/github/stars/yi-barrack/CVE-2024-5243-pwn2own-toronto-2023.svg) ![forks](https://img.shields.io/github/forks/yi-barrack/CVE-2024-5243-pwn2own-toronto-2023.svg)


## CVE-2023-27163
 request-baskets up to v1.2.1 was discovered to contain a Server-Side Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request.

- [https://github.com/thealchimist86/CVE-2023-27163---SSRF-Baskets-Requests](https://github.com/thealchimist86/CVE-2023-27163---SSRF-Baskets-Requests) :  ![starts](https://img.shields.io/github/stars/thealchimist86/CVE-2023-27163---SSRF-Baskets-Requests.svg) ![forks](https://img.shields.io/github/forks/thealchimist86/CVE-2023-27163---SSRF-Baskets-Requests.svg)
- [https://github.com/thealchimist86/CVE-2023-27163---Maltrail-0.53---RCE](https://github.com/thealchimist86/CVE-2023-27163---Maltrail-0.53---RCE) :  ![starts](https://img.shields.io/github/stars/thealchimist86/CVE-2023-27163---Maltrail-0.53---RCE.svg) ![forks](https://img.shields.io/github/forks/thealchimist86/CVE-2023-27163---Maltrail-0.53---RCE.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt](https://github.com/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt) :  ![starts](https://img.shields.io/github/stars/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt.svg) ![forks](https://img.shields.io/github/forks/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt.svg)

