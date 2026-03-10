# Update 2026-03-10
## CVE-2026-30863
 Parse Server is an open source backend that can be deployed to any infrastructure that can run Node.js. Prior to versions 8.6.10 and 9.5.0-alpha.11, the Google, Apple, and Facebook authentication adapters use JWT verification to validate identity tokens. When the adapter's audience configuration option is not set (clientId for Google/Apple, appIds for Facebook), JWT verification silently skips audience claim validation. This allows an attacker to use a validly signed JWT issued for a different application to authenticate as any user on the target Parse Server. This issue has been patched in versions 8.6.10 and 9.5.0-alpha.11.

- [https://github.com/Worthes/CVE-2026-30863-Exploit](https://github.com/Worthes/CVE-2026-30863-Exploit) :  ![starts](https://img.shields.io/github/stars/Worthes/CVE-2026-30863-Exploit.svg) ![forks](https://img.shields.io/github/forks/Worthes/CVE-2026-30863-Exploit.svg)


## CVE-2026-24512
 A security issue was discovered in ingress-nginx cthe `rules.http.paths.path` Ingress field can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/mghouse17/dependency-guardian-real-advisory-demo](https://github.com/mghouse17/dependency-guardian-real-advisory-demo) :  ![starts](https://img.shields.io/github/stars/mghouse17/dependency-guardian-real-advisory-demo.svg) ![forks](https://img.shields.io/github/forks/mghouse17/dependency-guardian-real-advisory-demo.svg)


## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).

- [https://github.com/gregk4sec/cve-2026-21962](https://github.com/gregk4sec/cve-2026-21962) :  ![starts](https://img.shields.io/github/stars/gregk4sec/cve-2026-21962.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/cve-2026-21962.svg)
- [https://github.com/gregk4sec/CVE-2026-21962-o](https://github.com/gregk4sec/CVE-2026-21962-o) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2026-21962-o.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2026-21962-o.svg)


## CVE-2026-20127
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;

- [https://github.com/abrahamsurf/sdwan-scanner-CVE-2026-20127](https://github.com/abrahamsurf/sdwan-scanner-CVE-2026-20127) :  ![starts](https://img.shields.io/github/stars/abrahamsurf/sdwan-scanner-CVE-2026-20127.svg) ![forks](https://img.shields.io/github/forks/abrahamsurf/sdwan-scanner-CVE-2026-20127.svg)


## CVE-2026-0770
The specific flaw exists within the handling of the exec_globals parameter provided to the validate endpoint. The issue results from the inclusion of a resource from an untrusted control sphere. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-27325.

- [https://github.com/Yetazyyy/CVE-2026-0770](https://github.com/Yetazyyy/CVE-2026-0770) :  ![starts](https://img.shields.io/github/stars/Yetazyyy/CVE-2026-0770.svg) ![forks](https://img.shields.io/github/forks/Yetazyyy/CVE-2026-0770.svg)


## CVE-2025-69985
 FUXA 1.2.8 and prior contains an Authentication Bypass vulnerability leading to Remote Code Execution (RCE). The vulnerability exists in the server/api/jwt-helper.js middleware, which improperly trusts the HTTP "Referer" header to validate internal requests. A remote unauthenticated attacker can bypass JWT authentication by spoofing the Referer header to match the server's host. Successful exploitation allows the attacker to access the protected /api/runscript endpoint and execute arbitrary Node.js code on the server.

- [https://github.com/tianarsamm/CVE-2025-69985](https://github.com/tianarsamm/CVE-2025-69985) :  ![starts](https://img.shields.io/github/stars/tianarsamm/CVE-2025-69985.svg) ![forks](https://img.shields.io/github/forks/tianarsamm/CVE-2025-69985.svg)


## CVE-2025-67303
 An issue in ComfyUI-Manager prior to version 3.38 allowed remote attackers to potentially manipulate its configuration and critical data. This was due to the application storing its files in an insufficiently protected location that was accessible via the web interface

- [https://github.com/Remnant-DB/CVE-2025-67303](https://github.com/Remnant-DB/CVE-2025-67303) :  ![starts](https://img.shields.io/github/stars/Remnant-DB/CVE-2025-67303.svg) ![forks](https://img.shields.io/github/forks/Remnant-DB/CVE-2025-67303.svg)


## CVE-2025-60787
 MotionEye v0.43.1b4 and before is vulnerable to OS Command Injection in configuration parameters such as image_file_name. Unsanitized user input is written to Motion configuration files, allowing remote authenticated attackers with admin access to achieve code execution when Motion is restarted.

- [https://github.com/lil0xplorer/CVE-2025-60787_PoC](https://github.com/lil0xplorer/CVE-2025-60787_PoC) :  ![starts](https://img.shields.io/github/stars/lil0xplorer/CVE-2025-60787_PoC.svg) ![forks](https://img.shields.io/github/forks/lil0xplorer/CVE-2025-60787_PoC.svg)
- [https://github.com/gunzf0x/CVE-2025-60787](https://github.com/gunzf0x/CVE-2025-60787) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2025-60787.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2025-60787.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/rippxsec/CVE-2025-49132-PHP-PEAR](https://github.com/rippxsec/CVE-2025-49132-PHP-PEAR) :  ![starts](https://img.shields.io/github/stars/rippxsec/CVE-2025-49132-PHP-PEAR.svg) ![forks](https://img.shields.io/github/forks/rippxsec/CVE-2025-49132-PHP-PEAR.svg)


## CVE-2025-32434
 PyTorch is a Python package that provides tensor computation with strong GPU acceleration and deep neural networks built on a tape-based autograd system. In version 2.5.1 and prior, a Remote Command Execution (RCE) vulnerability exists in PyTorch when loading a model using torch.load with weights_only=True. This issue has been patched in version 2.6.0.

- [https://github.com/Soildworks/Agentic-CLIP-Benchmark](https://github.com/Soildworks/Agentic-CLIP-Benchmark) :  ![starts](https://img.shields.io/github/stars/Soildworks/Agentic-CLIP-Benchmark.svg) ![forks](https://img.shields.io/github/forks/Soildworks/Agentic-CLIP-Benchmark.svg)


## CVE-2025-15030
 The User Profile Builder  WordPress plugin before 3.15.2 does not have a proper password reset process, allowing a few unauthenticated requests to reset the password of any user by knowing their username, such as administrator ones, and therefore gain access to their account

- [https://github.com/BastianXploited/CVE-2025-15030](https://github.com/BastianXploited/CVE-2025-15030) :  ![starts](https://img.shields.io/github/stars/BastianXploited/CVE-2025-15030.svg) ![forks](https://img.shields.io/github/forks/BastianXploited/CVE-2025-15030.svg)


## CVE-2025-6440
 The WooCommerce Designer Pro plugin for WordPress, used by the Pricom - Printing Company & Design Services WordPress theme, is vulnerable to arbitrary file uploads due to missing file type validation in the 'wcdp_save_canvas_design_ajax' function in all versions up to, and including, 1.9.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/0axz-tools/CVE-2025-6440](https://github.com/0axz-tools/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/0axz-tools/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/0axz-tools/CVE-2025-6440.svg)


## CVE-2025-3194
 Versions of the package bigint-buffer from 0.0.0 are vulnerable to Buffer Overflow in the toBigIntLE() function. Attackers can exploit this to crash the application.

- [https://github.com/LoserLab/bigint-buffer-safe](https://github.com/LoserLab/bigint-buffer-safe) :  ![starts](https://img.shields.io/github/stars/LoserLab/bigint-buffer-safe.svg) ![forks](https://img.shields.io/github/forks/LoserLab/bigint-buffer-safe.svg)


## CVE-2024-58239
did some work.

- [https://github.com/khoatran107/cve-2024-58239](https://github.com/khoatran107/cve-2024-58239) :  ![starts](https://img.shields.io/github/stars/khoatran107/cve-2024-58239.svg) ![forks](https://img.shields.io/github/forks/khoatran107/cve-2024-58239.svg)
- [https://github.com/khoatran107/cve-2025-39682](https://github.com/khoatran107/cve-2025-39682) :  ![starts](https://img.shields.io/github/stars/khoatran107/cve-2025-39682.svg) ![forks](https://img.shields.io/github/forks/khoatran107/cve-2025-39682.svg)


## CVE-2024-56348
 In JetBrains TeamCity before 2024.12 improper access control allowed viewing details of unauthorized agents

- [https://github.com/joshuavanderpoll/cve-2024-56348](https://github.com/joshuavanderpoll/cve-2024-56348) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/cve-2024-56348.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/cve-2024-56348.svg)


## CVE-2024-51482
 ZoneMinder is a free, open source closed-circuit television software application. ZoneMinder v1.37.* = 1.37.64 is vulnerable to boolean-based SQL Injection in function of web/ajax/event.php. This is fixed in 1.37.65.

- [https://github.com/plur1bu5/CVE-2024-51482-PoC](https://github.com/plur1bu5/CVE-2024-51482-PoC) :  ![starts](https://img.shields.io/github/stars/plur1bu5/CVE-2024-51482-PoC.svg) ![forks](https://img.shields.io/github/forks/plur1bu5/CVE-2024-51482-PoC.svg)
- [https://github.com/Gh0s7Ops/CVE-2024-51482-Multi-Stage-Surveillance-System-Exploit](https://github.com/Gh0s7Ops/CVE-2024-51482-Multi-Stage-Surveillance-System-Exploit) :  ![starts](https://img.shields.io/github/stars/Gh0s7Ops/CVE-2024-51482-Multi-Stage-Surveillance-System-Exploit.svg) ![forks](https://img.shields.io/github/forks/Gh0s7Ops/CVE-2024-51482-Multi-Stage-Surveillance-System-Exploit.svg)
- [https://github.com/BridgerAlderson/CVE-2024-51482](https://github.com/BridgerAlderson/CVE-2024-51482) :  ![starts](https://img.shields.io/github/stars/BridgerAlderson/CVE-2024-51482.svg) ![forks](https://img.shields.io/github/forks/BridgerAlderson/CVE-2024-51482.svg)
- [https://github.com/Ravi-lk/CVE-2024-51482-ZoneMinder-v1.37.-1.37.64-SQL-Injection-POC](https://github.com/Ravi-lk/CVE-2024-51482-ZoneMinder-v1.37.-1.37.64-SQL-Injection-POC) :  ![starts](https://img.shields.io/github/stars/Ravi-lk/CVE-2024-51482-ZoneMinder-v1.37.-1.37.64-SQL-Injection-POC.svg) ![forks](https://img.shields.io/github/forks/Ravi-lk/CVE-2024-51482-ZoneMinder-v1.37.-1.37.64-SQL-Injection-POC.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/E-m-e-k-a/Moniker-Link-Lab-Setup](https://github.com/E-m-e-k-a/Moniker-Link-Lab-Setup) :  ![starts](https://img.shields.io/github/stars/E-m-e-k-a/Moniker-Link-Lab-Setup.svg) ![forks](https://img.shields.io/github/forks/E-m-e-k-a/Moniker-Link-Lab-Setup.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/Remnant-DB/CVE-2024-6387](https://github.com/Remnant-DB/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/Remnant-DB/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/Remnant-DB/CVE-2024-6387.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/John-Popovici/CVE-2024-4367-pdfjs-exploit](https://github.com/John-Popovici/CVE-2024-4367-pdfjs-exploit) :  ![starts](https://img.shields.io/github/stars/John-Popovici/CVE-2024-4367-pdfjs-exploit.svg) ![forks](https://img.shields.io/github/forks/John-Popovici/CVE-2024-4367-pdfjs-exploit.svg)


## CVE-2024-2083
 A directory traversal vulnerability exists in the zenml-io/zenml repository, specifically within the /api/v1/steps endpoint. Attackers can exploit this vulnerability by manipulating the 'logs' URI path in the request to fetch arbitrary file content, bypassing intended access restrictions. The vulnerability arises due to the lack of validation for directory traversal patterns, allowing attackers to access files outside of the restricted directory.

- [https://github.com/Saptaktdk/zenml-CVE-2024-2083-POC](https://github.com/Saptaktdk/zenml-CVE-2024-2083-POC) :  ![starts](https://img.shields.io/github/stars/Saptaktdk/zenml-CVE-2024-2083-POC.svg) ![forks](https://img.shields.io/github/forks/Saptaktdk/zenml-CVE-2024-2083-POC.svg)


## CVE-2023-21688
 NT OS Kernel Elevation of Privilege Vulnerability

- [https://github.com/hyunjungg/CVE-2023-21688](https://github.com/hyunjungg/CVE-2023-21688) :  ![starts](https://img.shields.io/github/stars/hyunjungg/CVE-2023-21688.svg) ![forks](https://img.shields.io/github/forks/hyunjungg/CVE-2023-21688.svg)


## CVE-2023-20198
 Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-2023-20198 to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system. Cisco has assigned CVE-2023-20273 to this issue. CVE-2023-20198 has been assigned a CVSS Score of 10.0. CVE-2023-20273 has been assigned a CVSS Score of 7.2. Both of these CVEs are being tracked by CSCwh87343.

- [https://github.com/gustavorobertux/cisco-cve-2023-20198-checker](https://github.com/gustavorobertux/cisco-cve-2023-20198-checker) :  ![starts](https://img.shields.io/github/stars/gustavorobertux/cisco-cve-2023-20198-checker.svg) ![forks](https://img.shields.io/github/forks/gustavorobertux/cisco-cve-2023-20198-checker.svg)


## CVE-2021-33044
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/nasimanpha-create/ing-switch](https://github.com/nasimanpha-create/ing-switch) :  ![starts](https://img.shields.io/github/stars/nasimanpha-create/ing-switch.svg) ![forks](https://img.shields.io/github/forks/nasimanpha-create/ing-switch.svg)


## CVE-2021-24762
 The Perfect Survey WordPress plugin before 1.5.2 does not validate and escape the question_id GET parameter before using it in a SQL statement in the get_question AJAX action, allowing unauthenticated users to perform SQL injection.

- [https://github.com/NT1410/CVE-2021-24762](https://github.com/NT1410/CVE-2021-24762) :  ![starts](https://img.shields.io/github/stars/NT1410/CVE-2021-24762.svg) ![forks](https://img.shields.io/github/forks/NT1410/CVE-2021-24762.svg)

