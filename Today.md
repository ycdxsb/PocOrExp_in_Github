# Update 2026-02-11
## CVE-2026-25916
 Roundcube Webmail before 1.5.13 and 1.6 before 1.6.13, when "Block remote images" is used, does not block SVG feImage.

- [https://github.com/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute](https://github.com/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute.svg)


## CVE-2026-25049
 n8n is an open source workflow automation platform. Prior to versions 1.123.17 and 2.5.2, an authenticated user with permission to create or modify workflows could abuse crafted expressions in workflow parameters to trigger unintended system command execution on the host running n8n. This issue has been patched in versions 1.123.17 and 2.5.2.

- [https://github.com/otakuliu/Expression-Sandbox-Escape-Simulation-Lab](https://github.com/otakuliu/Expression-Sandbox-Escape-Simulation-Lab) :  ![starts](https://img.shields.io/github/stars/otakuliu/Expression-Sandbox-Escape-Simulation-Lab.svg) ![forks](https://img.shields.io/github/forks/otakuliu/Expression-Sandbox-Escape-Simulation-Lab.svg)


## CVE-2026-23723
 WeGIA is a web manager for charitable institutions. Prior to 3.6.2, an authenticated SQL Injection vulnerability was identified in the Atendido_ocorrenciaControle endpoint via the id_memorando parameter. This flaw allows for full database exfiltration, exposure of sensitive PII, and potential arbitrary file reads in misconfigured environments. This vulnerability is fixed in 3.6.2.

- [https://github.com/Ch35h1r3c47/CVE-2026-23723-POC](https://github.com/Ch35h1r3c47/CVE-2026-23723-POC) :  ![starts](https://img.shields.io/github/stars/Ch35h1r3c47/CVE-2026-23723-POC.svg) ![forks](https://img.shields.io/github/forks/Ch35h1r3c47/CVE-2026-23723-POC.svg)


## CVE-2026-22187
 Bio-Formats versions up to and including 8.3.0 perform unsafe Java deserialization of attacker-controlled memoization cache files (.bfmemo) during image processing. The loci.formats.Memoizer class automatically loads and deserializes memo files associated with images without validation, integrity checks, or trust enforcement. An attacker who can supply a crafted .bfmemo file alongside an image can trigger deserialization of untrusted data, which may result in denial of service, logic manipulation, or potentially remote code execution in environments where suitable gadget chains are present on the classpath.

- [https://github.com/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo](https://github.com/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo.svg)


## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).

- [https://github.com/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-](https://github.com/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-.svg)


## CVE-2026-20404
 In Modem, there is a possible system crash due to improper input validation. This could lead to remote denial of service, if a UE has connected to a rogue base station controlled by the attacker, with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: MOLY01689248; Issue ID: MSV-4837.

- [https://github.com/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-](https://github.com/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-.svg)


## CVE-2025-69516
 A Server-Side Template Injection (SSTI) vulnerability in the /reporting/templates/preview/ endpoint of Amidaware Tactical RMM, affecting versions equal to or earlier than v1.3.1, allows low-privileged users with Report Viewer or Report Manager permissions to achieve remote command execution on the server. This occurs due to improper sanitization of the template_md parameter, enabling direct injection of Jinja2 templates. This occurs due to misuse of the generate_html() function, the user-controlled value is inserted into `env.from_string`, a function that processes Jinja2 templates arbitrarily, making an SSTI possible.

- [https://github.com/NtGabrielGomes/CVE-2025-69516](https://github.com/NtGabrielGomes/CVE-2025-69516) :  ![starts](https://img.shields.io/github/stars/NtGabrielGomes/CVE-2025-69516.svg) ![forks](https://img.shields.io/github/forks/NtGabrielGomes/CVE-2025-69516.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-65856
 Authentication bypass vulnerability in Xiongmai XM530 IP cameras on Firmware V5.00.R02.000807D8.10010.346624.S.ONVIF 21.06 allows unauthenticated remote attackers to access sensitive device information and live video streams. The ONVIF implementation fails to enforce authentication on 31 critical endpoints, enabling direct unauthorized video stream access.

- [https://github.com/KostasEreksonas/XM_ONVIF_auth_bypass](https://github.com/KostasEreksonas/XM_ONVIF_auth_bypass) :  ![starts](https://img.shields.io/github/stars/KostasEreksonas/XM_ONVIF_auth_bypass.svg) ![forks](https://img.shields.io/github/forks/KostasEreksonas/XM_ONVIF_auth_bypass.svg)


## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/George0Papasotiriou/CVE-2025-61882-Oracle-BI-Publisher-RCE](https://github.com/George0Papasotiriou/CVE-2025-61882-Oracle-BI-Publisher-RCE) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2025-61882-Oracle-BI-Publisher-RCE.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2025-61882-Oracle-BI-Publisher-RCE.svg)


## CVE-2025-59470
 This vulnerability allows a Backup Operator to perform remote code execution (RCE) as the postgres user by sending a malicious interval or order parameter.

- [https://github.com/George0Papasotiriou/CVE-2025-59470-PostgreSQL-Command-Injection](https://github.com/George0Papasotiriou/CVE-2025-59470-PostgreSQL-Command-Injection) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2025-59470-PostgreSQL-Command-Injection.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2025-59470-PostgreSQL-Command-Injection.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/timsonner/React2Shell-CVE-2025-55182](https://github.com/timsonner/React2Shell-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/timsonner/React2Shell-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/timsonner/React2Shell-CVE-2025-55182.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Si-Ni/CVE-2025-29927-Proof-of-Concept](https://github.com/Si-Ni/CVE-2025-29927-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/Si-Ni/CVE-2025-29927-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/Si-Ni/CVE-2025-29927-Proof-of-Concept.svg)


## CVE-2025-26153
 A Stored XSS vulnerability exists in the message compose feature of Chamilo LMS 1.11.28. Attackers can inject malicious scripts into messages, which execute when victims, such as administrators, reply to the message.

- [https://github.com/mexeck88/CSRF-via-stored-XSS-for-PrivEsc](https://github.com/mexeck88/CSRF-via-stored-XSS-for-PrivEsc) :  ![starts](https://img.shields.io/github/stars/mexeck88/CSRF-via-stored-XSS-for-PrivEsc.svg) ![forks](https://img.shields.io/github/forks/mexeck88/CSRF-via-stored-XSS-for-PrivEsc.svg)


## CVE-2025-24367
 Cacti is an open source performance and fault management framework. An authenticated Cacti user can abuse graph creation and graph template functionality to create arbitrary PHP scripts in the web root of the application, leading to remote code execution on the server. This vulnerability is fixed in 1.2.29.

- [https://github.com/ShoshinMaster/CVE-2025-24367](https://github.com/ShoshinMaster/CVE-2025-24367) :  ![starts](https://img.shields.io/github/stars/ShoshinMaster/CVE-2025-24367.svg) ![forks](https://img.shields.io/github/forks/ShoshinMaster/CVE-2025-24367.svg)


## CVE-2025-15556
 Notepad++ versions prior to 8.8.9, when using the WinGUp updater, contain an update integrity verification vulnerability where downloaded update metadata and installers are not cryptographically verified. An attacker able to intercept or redirect update traffic can cause the updater to download and execute an attacker-controlled installer, resulting in arbitrary code execution with the privileges of the user.

- [https://github.com/George0Papasotiriou/CVE-2025-15556-Notepad-WinGUp-Updater-RCE](https://github.com/George0Papasotiriou/CVE-2025-15556-Notepad-WinGUp-Updater-RCE) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2025-15556-Notepad-WinGUp-Updater-RCE.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2025-15556-Notepad-WinGUp-Updater-RCE.svg)
- [https://github.com/renat0z3r0/notepadpp-supply-chain-iocs](https://github.com/renat0z3r0/notepadpp-supply-chain-iocs) :  ![starts](https://img.shields.io/github/stars/renat0z3r0/notepadpp-supply-chain-iocs.svg) ![forks](https://img.shields.io/github/forks/renat0z3r0/notepadpp-supply-chain-iocs.svg)


## CVE-2025-14174
 Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 143.0.7499.110 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/George0Papasotiriou/CVE-2025-14174-Chrome-Zero-Day](https://github.com/George0Papasotiriou/CVE-2025-14174-Chrome-Zero-Day) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2025-14174-Chrome-Zero-Day.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2025-14174-Chrome-Zero-Day.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/matesz44/CVE-2025-9074](https://github.com/matesz44/CVE-2025-9074) :  ![starts](https://img.shields.io/github/stars/matesz44/CVE-2025-9074.svg) ![forks](https://img.shields.io/github/forks/matesz44/CVE-2025-9074.svg)


## CVE-2025-8671
 A mismatch caused by client-triggered server-sent stream resets between HTTP/2 specifications and the internal architectures of some HTTP/2 implementations may result in excessive server resource consumption leading to denial-of-service (DoS).  By opening streams and then rapidly triggering the server to reset them—using malformed frames or flow control errors—an attacker can exploit incorrect stream accounting. Streams reset by the server are considered closed at the protocol level, even though backend processing continues. This allows a client to cause the server to handle an unbounded number of concurrent streams on a single connection. This CVE will be updated as affected product details are released.

- [https://github.com/mysara2022/CVE-2025-8671-vulnerability-POC-](https://github.com/mysara2022/CVE-2025-8671-vulnerability-POC-) :  ![starts](https://img.shields.io/github/stars/mysara2022/CVE-2025-8671-vulnerability-POC-.svg) ![forks](https://img.shields.io/github/forks/mysara2022/CVE-2025-8671-vulnerability-POC-.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/George0Papasotiriou/CVE-2025-8110-Gogs-Remote-Code-Execution](https://github.com/George0Papasotiriou/CVE-2025-8110-Gogs-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2025-8110-Gogs-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2025-8110-Gogs-Remote-Code-Execution.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/muyuanlove/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit](https://github.com/muyuanlove/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit) :  ![starts](https://img.shields.io/github/stars/muyuanlove/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit.svg) ![forks](https://img.shields.io/github/forks/muyuanlove/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit.svg)
- [https://github.com/0rionCollector/Exploit-Chain-CVE-2025-6018-6019](https://github.com/0rionCollector/Exploit-Chain-CVE-2025-6018-6019) :  ![starts](https://img.shields.io/github/stars/0rionCollector/Exploit-Chain-CVE-2025-6018-6019.svg) ![forks](https://img.shields.io/github/forks/0rionCollector/Exploit-Chain-CVE-2025-6018-6019.svg)
- [https://github.com/0x5chltz/CVE-2025-6019](https://github.com/0x5chltz/CVE-2025-6019) :  ![starts](https://img.shields.io/github/stars/0x5chltz/CVE-2025-6019.svg) ![forks](https://img.shields.io/github/forks/0x5chltz/CVE-2025-6019.svg)
- [https://github.com/AzureADTrent/CVE-2025-6018-and-CVE-2025-6019-Privilege-Escalation](https://github.com/AzureADTrent/CVE-2025-6018-and-CVE-2025-6019-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/AzureADTrent/CVE-2025-6018-and-CVE-2025-6019-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/AzureADTrent/CVE-2025-6018-and-CVE-2025-6019-Privilege-Escalation.svg)
- [https://github.com/MichaelVenturella/CVE-2025-6018-6019-PoC](https://github.com/MichaelVenturella/CVE-2025-6018-6019-PoC) :  ![starts](https://img.shields.io/github/stars/MichaelVenturella/CVE-2025-6018-6019-PoC.svg) ![forks](https://img.shields.io/github/forks/MichaelVenturella/CVE-2025-6018-6019-PoC.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/muyuanlove/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit](https://github.com/muyuanlove/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit) :  ![starts](https://img.shields.io/github/stars/muyuanlove/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit.svg) ![forks](https://img.shields.io/github/forks/muyuanlove/CVE-2025-6018-CVE-2025-6019-Privilege-Escalation-Exploit.svg)
- [https://github.com/0rionCollector/Exploit-Chain-CVE-2025-6018-6019](https://github.com/0rionCollector/Exploit-Chain-CVE-2025-6018-6019) :  ![starts](https://img.shields.io/github/stars/0rionCollector/Exploit-Chain-CVE-2025-6018-6019.svg) ![forks](https://img.shields.io/github/forks/0rionCollector/Exploit-Chain-CVE-2025-6018-6019.svg)
- [https://github.com/MichaelVenturella/CVE-2025-6018-6019-PoC](https://github.com/MichaelVenturella/CVE-2025-6018-6019-PoC) :  ![starts](https://img.shields.io/github/stars/MichaelVenturella/CVE-2025-6018-6019-PoC.svg) ![forks](https://img.shields.io/github/forks/MichaelVenturella/CVE-2025-6018-6019-PoC.svg)
- [https://github.com/AzureADTrent/CVE-2025-6018-and-CVE-2025-6019-Privilege-Escalation](https://github.com/AzureADTrent/CVE-2025-6018-and-CVE-2025-6019-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/AzureADTrent/CVE-2025-6018-and-CVE-2025-6019-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/AzureADTrent/CVE-2025-6018-and-CVE-2025-6019-Privilege-Escalation.svg)


## CVE-2024-9264
 The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.

- [https://github.com/ISabbiI/PoC---Implementation-Plan---Grafana-CVE-2024-9264-SQL-Injection-](https://github.com/ISabbiI/PoC---Implementation-Plan---Grafana-CVE-2024-9264-SQL-Injection-) :  ![starts](https://img.shields.io/github/stars/ISabbiI/PoC---Implementation-Plan---Grafana-CVE-2024-9264-SQL-Injection-.svg) ![forks](https://img.shields.io/github/forks/ISabbiI/PoC---Implementation-Plan---Grafana-CVE-2024-9264-SQL-Injection-.svg)


## CVE-2024-6386
 The WPML plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.6.12 via the Twig Server-Side Template Injection. This is due to missing input validation and sanitization on the render function. This makes it possible for authenticated attackers, with Contributor-level access and above, to execute code on the server.

- [https://github.com/bananoname/CVE-2024-6386-WPML-SSTI](https://github.com/bananoname/CVE-2024-6386-WPML-SSTI) :  ![starts](https://img.shields.io/github/stars/bananoname/CVE-2024-6386-WPML-SSTI.svg) ![forks](https://img.shields.io/github/forks/bananoname/CVE-2024-6386-WPML-SSTI.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/Syn2Much/Slayer-L7](https://github.com/Syn2Much/Slayer-L7) :  ![starts](https://img.shields.io/github/stars/Syn2Much/Slayer-L7.svg) ![forks](https://img.shields.io/github/forks/Syn2Much/Slayer-L7.svg)


## CVE-2023-26482
 Nextcloud server is an open source home cloud implementation. In affected versions a missing scope validation allowed users to create workflows which are designed to be only available for administrators. Some workflows are designed to be RCE by invoking defined scripts, in order to generate PDFs, invoking webhooks or running scripts on the server. Due to this combination depending on the available apps the issue can result in a RCE at the end. It is recommended that the Nextcloud Server is upgraded to 24.0.10 or 25.0.4. Users unable to upgrade should disable app `workflow_scripts` and `workflow_pdf_converter` as a mitigation.

- [https://github.com/ISabbiI/PoC---CVE-2023-26482-RCE-LAB-Nextcloud](https://github.com/ISabbiI/PoC---CVE-2023-26482-RCE-LAB-Nextcloud) :  ![starts](https://img.shields.io/github/stars/ISabbiI/PoC---CVE-2023-26482-RCE-LAB-Nextcloud.svg) ![forks](https://img.shields.io/github/forks/ISabbiI/PoC---CVE-2023-26482-RCE-LAB-Nextcloud.svg)


## CVE-2022-24251
 Extensis Portfolio v4.0 was discovered to contain an authenticated unrestricted file upload vulnerability via the Catalog Asset Upload function.

- [https://github.com/talilama/extensis_portfolio_rce_CVE-2022-24251](https://github.com/talilama/extensis_portfolio_rce_CVE-2022-24251) :  ![starts](https://img.shields.io/github/stars/talilama/extensis_portfolio_rce_CVE-2022-24251.svg) ![forks](https://img.shields.io/github/forks/talilama/extensis_portfolio_rce_CVE-2022-24251.svg)


## CVE-2019-1010091
 tinymce 4.7.11, 4.7.12 is affected by: CWE-79: Improper Neutralization of Input During Web Page Generation. The impact is: JavaScript code execution. The component is: Media element. The attack vector is: The victim must paste malicious content to media element's embed tab.

- [https://github.com/CQ-Tools/CVE-2019-1010091-fixed](https://github.com/CQ-Tools/CVE-2019-1010091-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-1010091-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-1010091-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-1010091-unfixed](https://github.com/CQ-Tools/CVE-2019-1010091-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-1010091-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-1010091-unfixed.svg)


## CVE-2019-20174
 Auth0 Lock before 11.21.0 allows XSS when additionalSignUpFields is used with an untrusted placeholder.

- [https://github.com/CQ-Tools/CVE-2019-20174-unfixed](https://github.com/CQ-Tools/CVE-2019-20174-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-20174-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-20174-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-20174-fixed](https://github.com/CQ-Tools/CVE-2019-20174-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-20174-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-20174-fixed.svg)


## CVE-2019-20149
 ctorName in index.js in kind-of v6.0.2 allows external user input to overwrite certain internal attributes via a conflicting name, as demonstrated by 'constructor': {'name':'Symbol'}. Hence, a crafted payload can overwrite this builtin attribute to manipulate the type detection result.

- [https://github.com/CQ-Tools/CVE-2019-20149-unfixed](https://github.com/CQ-Tools/CVE-2019-20149-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-20149-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-20149-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-20149-fixed](https://github.com/CQ-Tools/CVE-2019-20149-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-20149-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-20149-fixed.svg)


## CVE-2019-16769
 The serialize-javascript npm package before version 2.1.1 is vulnerable to Cross-site Scripting (XSS). It does not properly mitigate against unsafe characters in serialized regular expressions. This vulnerability is not affected on Node.js environment since Node.js's implementation of RegExp.prototype.toString() backslash-escapes all forward slashes in regular expressions. If serialized data of regular expression objects are used in an environment other than Node.js, it is affected by this vulnerability.

- [https://github.com/CQ-Tools/CVE-2019-16769-unfixed](https://github.com/CQ-Tools/CVE-2019-16769-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-16769-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-16769-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-16769-fixed](https://github.com/CQ-Tools/CVE-2019-16769-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-16769-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-16769-fixed.svg)


## CVE-2019-13506
 @nuxt/devalue before 1.2.3, as used in Nuxt.js before 2.6.2, mishandles object keys, leading to XSS.

- [https://github.com/CQ-Tools/CVE-2019-13506-fixed](https://github.com/CQ-Tools/CVE-2019-13506-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-13506-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-13506-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-13506-unfixed](https://github.com/CQ-Tools/CVE-2019-13506-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-13506-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-13506-unfixed.svg)


## CVE-2019-12043
 In remarkable 1.7.1, lib/parser_inline.js mishandles URL filtering, which allows attackers to trigger XSS via unprintable characters, as demonstrated by a \x0ejavascript: URL.

- [https://github.com/CQ-Tools/CVE-2019-12043-unfixed](https://github.com/CQ-Tools/CVE-2019-12043-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-12043-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-12043-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-12043-fixed](https://github.com/CQ-Tools/CVE-2019-12043-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-12043-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-12043-fixed.svg)


## CVE-2019-10785
 dojox is vulnerable to Cross-site Scripting in all versions before version 1.16.1, 1.15.2, 1.14.5, 1.13.6, 1.12.7 and 1.11.9. This is due to dojox.xmpp.util.xmlEncode only encoding the first occurrence of each character, not all of them.

- [https://github.com/CQ-Tools/CVE-2019-10785-unfixed](https://github.com/CQ-Tools/CVE-2019-10785-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10785-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10785-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-10785-fixed](https://github.com/CQ-Tools/CVE-2019-10785-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10785-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10785-fixed.svg)


## CVE-2019-10777
 In aws-lambda versions prior to version 1.0.5, the "config.FunctioName" is used to construct the argument used within the "exec" function without any sanitization. It is possible for a user to inject arbitrary commands to the "zipCmd" used within "config.FunctionName".

- [https://github.com/CQ-Tools/CVE-2019-10777-unfixed](https://github.com/CQ-Tools/CVE-2019-10777-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10777-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10777-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-10777-fixed](https://github.com/CQ-Tools/CVE-2019-10777-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10777-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10777-fixed.svg)


## CVE-2019-10776
 In "index.js" file line 240, the run command executes the git command with a user controlled variable called remoteUrl. This affects git-diff-apply all versions prior to 0.22.2.

- [https://github.com/CQ-Tools/CVE-2019-10776-fixed](https://github.com/CQ-Tools/CVE-2019-10776-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10776-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10776-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-10776-unfixed](https://github.com/CQ-Tools/CVE-2019-10776-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10776-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10776-unfixed.svg)


## CVE-2019-10761
 This affects the package vm2 before 3.6.11. It is possible to trigger a RangeError exception from the host rather than the "sandboxed" context by reaching the stack call limit with an infinite recursion. The returned object is then used to reference the mainModule property of the host code running the script allowing it to spawn a child_process and execute arbitrary code.

- [https://github.com/CQ-Tools/CVE-2019-10761-fixed](https://github.com/CQ-Tools/CVE-2019-10761-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10761-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10761-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-10761-unfixed](https://github.com/CQ-Tools/CVE-2019-10761-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10761-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10761-unfixed.svg)


## CVE-2019-10759
 safer-eval before 1.3.4 are vulnerable to Arbitrary Code Execution. A payload using constructor properties can escape the sandbox and execute arbitrary code.

- [https://github.com/CQ-Tools/CVE-2019-10759-fixed](https://github.com/CQ-Tools/CVE-2019-10759-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10759-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10759-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-10759-unfixed](https://github.com/CQ-Tools/CVE-2019-10759-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10759-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10759-unfixed.svg)


## CVE-2019-10757
 knex.js versions before 0.19.5 are vulnerable to SQL Injection attack. Identifiers are escaped incorrectly as part of the MSSQL dialect, allowing attackers to craft a malicious query to the host DB.

- [https://github.com/CQ-Tools/CVE-2019-10757-fixed](https://github.com/CQ-Tools/CVE-2019-10757-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10757-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10757-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-10757-unfixed](https://github.com/CQ-Tools/CVE-2019-10757-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10757-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10757-unfixed.svg)


## CVE-2019-10750
 deeply is vulnerable to Prototype Pollution in versions before 3.1.0. The function assign-deep could be tricked into adding or modifying properties of Object.prototype using using a _proto_ payload.

- [https://github.com/CQ-Tools/CVE-2019-10750-unfixed](https://github.com/CQ-Tools/CVE-2019-10750-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10750-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10750-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-10750-fixed](https://github.com/CQ-Tools/CVE-2019-10750-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10750-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10750-fixed.svg)


## CVE-2019-10747
 set-value is vulnerable to Prototype Pollution in versions lower than 3.0.1. The function mixin-deep could be tricked into adding or modifying properties of Object.prototype using any of the constructor, prototype and _proto_ payloads.

- [https://github.com/CQ-Tools/CVE-2019-10747-fixed](https://github.com/CQ-Tools/CVE-2019-10747-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10747-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10747-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-10747-unfixed](https://github.com/CQ-Tools/CVE-2019-10747-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10747-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10747-unfixed.svg)


## CVE-2019-10746
 mixin-deep is vulnerable to Prototype Pollution in versions before 1.3.2 and version 2.0.0. The function mixin-deep could be tricked into adding or modifying properties of Object.prototype using a constructor payload.

- [https://github.com/CQ-Tools/CVE-2019-10746-fixed](https://github.com/CQ-Tools/CVE-2019-10746-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10746-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10746-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-10746-unfixed](https://github.com/CQ-Tools/CVE-2019-10746-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10746-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10746-unfixed.svg)


## CVE-2019-10090
 On Apache JSPWiki, up to version 2.11.0.M4, a carefully crafted plugin link invocation could trigger an XSS vulnerability on Apache JSPWiki, related to the plain editor, which could allow the attacker to execute javascript in the victim's browser and get some sensitive information about the victim.

- [https://github.com/CQ-Tools/CVE-2019-10090-unfixed](https://github.com/CQ-Tools/CVE-2019-10090-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10090-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10090-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-10090-fixed](https://github.com/CQ-Tools/CVE-2019-10090-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10090-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10090-fixed.svg)


## CVE-2019-10061
 utils/find-opencv.js in node-opencv (aka OpenCV bindings for Node.js) prior to 6.1.0 is vulnerable to Command Injection. It does not validate user input allowing attackers to execute arbitrary commands.

- [https://github.com/CQ-Tools/CVE-2019-10061-unfixed](https://github.com/CQ-Tools/CVE-2019-10061-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10061-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10061-unfixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-10061-fixed](https://github.com/CQ-Tools/CVE-2019-10061-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-10061-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-10061-fixed.svg)


## CVE-2019-8331
 In Bootstrap before 3.4.1 and 4.3.x before 4.3.1, XSS is possible in the tooltip or popover data-template attribute.

- [https://github.com/CQ-Tools/CVE-2019-8331-fixed](https://github.com/CQ-Tools/CVE-2019-8331-fixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-8331-fixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-8331-fixed.svg)
- [https://github.com/CQ-Tools/CVE-2019-8331-unfixed](https://github.com/CQ-Tools/CVE-2019-8331-unfixed) :  ![starts](https://img.shields.io/github/stars/CQ-Tools/CVE-2019-8331-unfixed.svg) ![forks](https://img.shields.io/github/forks/CQ-Tools/CVE-2019-8331-unfixed.svg)

