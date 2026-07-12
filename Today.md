# Update 2026-07-12
## CVE-2026-56423
An authenticated attacker with the relevant broad role permission could abuse the affected bulk deletion endpoints to delete objects outside their organisation’s authorization scope, causing loss of event-report content or sharing-group configuration across the instance.

- [https://github.com/BiiTts/CVE-2026-56423-MISP-deleteSelection-BrokenAccessControl](https://github.com/BiiTts/CVE-2026-56423-MISP-deleteSelection-BrokenAccessControl) :  ![starts](https://img.shields.io/github/stars/BiiTts/CVE-2026-56423-MISP-deleteSelection-BrokenAccessControl.svg) ![forks](https://img.shields.io/github/forks/BiiTts/CVE-2026-56423-MISP-deleteSelection-BrokenAccessControl.svg)


## CVE-2026-54390
 JTL Shop versions 5.2.0 through 5.7.1 contains a server-side template injection vulnerability that allows unauthenticated attackers to inject malicious template syntax due to unsanitized user-supplied input passed to the Smarty template engine. Attackers can exploit this flaw to read sensitive server-side values such as database credentials and encryption keys, and on versions 5.4.0 through 5.7.1, leverage registered Smarty modifiers including unserialize and file_get_contents to write a webshell to the web root and execute arbitrary commands as the web server user.

- [https://github.com/shinthink/CVE-2026-54390](https://github.com/shinthink/CVE-2026-54390) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-54390.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-54390.svg)


## CVE-2026-51119
 An issue in Invixium IXM WEB v.2.3.85.25 allows an attacker to escalate privileges via the /SystemUsers/CreateAppUser components

- [https://github.com/A17-ba/CVE-2026-51119](https://github.com/A17-ba/CVE-2026-51119) :  ![starts](https://img.shields.io/github/stars/A17-ba/CVE-2026-51119.svg) ![forks](https://img.shields.io/github/forks/A17-ba/CVE-2026-51119.svg)


## CVE-2026-50181
 Langroid is a framework for building large-language-model-powered applications. Prior to version 0.64.0, Langroid's `ReadFileTool` and `WriteFileTool` appear to treat `curr_dir` as the intended working-directory boundary for file operations. However, the tools only change the process working directory to `curr_dir` and then operate on the user-supplied `file_path` without resolving and enforcing that the final path remains inside `curr_dir`. As a result, a tool caller can supply path traversal sequences such as `../secret.txt` to read files outside the configured current directory, or `../written_by_tool.txt` to write files outside that directory. This can impact applications that expose Langroid file tools to an LLM agent, user-controlled tool call, or delegated coding/documentation agent while relying on `curr_dir` to restrict file access to a project/workspace directory. Version 0.64.0 patches the issue.

- [https://github.com/chaitanyagarware/CVE-2026-50181](https://github.com/chaitanyagarware/CVE-2026-50181) :  ![starts](https://img.shields.io/github/stars/chaitanyagarware/CVE-2026-50181.svg) ![forks](https://img.shields.io/github/forks/chaitanyagarware/CVE-2026-50181.svg)


## CVE-2026-49049
 The Helix3 plugin for Joomla exposes an ajax handler task, that allows unauthenticated attackers to delete arbitrary files, write arbitrary JSON files and update template parameters.

- [https://github.com/Dr-D25/CVE-2026-49049](https://github.com/Dr-D25/CVE-2026-49049) :  ![starts](https://img.shields.io/github/stars/Dr-D25/CVE-2026-49049.svg) ![forks](https://img.shields.io/github/forks/Dr-D25/CVE-2026-49049.svg)


## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/aexdyhaxor/CVE-2026-46331](https://github.com/aexdyhaxor/CVE-2026-46331) :  ![starts](https://img.shields.io/github/stars/aexdyhaxor/CVE-2026-46331.svg) ![forks](https://img.shields.io/github/forks/aexdyhaxor/CVE-2026-46331.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/inforcqb/CVE-2026-43499-pja110](https://github.com/inforcqb/CVE-2026-43499-pja110) :  ![starts](https://img.shields.io/github/stars/inforcqb/CVE-2026-43499-pja110.svg) ![forks](https://img.shields.io/github/forks/inforcqb/CVE-2026-43499-pja110.svg)
- [https://github.com/caspy123/CVE-2026-43499](https://github.com/caspy123/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/caspy123/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/caspy123/CVE-2026-43499.svg)


## CVE-2026-40860
Users are recommended to upgrade to version 4.20.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.7. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.2.

- [https://github.com/oscerd/CVE-2026-40860](https://github.com/oscerd/CVE-2026-40860) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-40860.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-40860.svg)


## CVE-2026-40859
Users are recommended to upgrade to version 4.20.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. After upgrading, the deserialization performed by both helper utilities is constrained by a default ObjectInputFilter (allow-list java.**;javax.**;org.apache.camel.**;!*), which can be customised through the new deserializationFilter endpoint option or the JVM-wide -Djdk.serialFilter system property. For deployments that cannot upgrade immediately: do not enable transferException=true (or allowJavaSerializedObject=true) on producers that talk to untrusted or network-reachable backends; ensure producer connections use TLS (https) so that a response cannot be substituted by a man-in-the-middle; and, where the option is required, set an explicit -Djdk.serialFilter allow-list (for example java.**;org.apache.camel.**;!*) to constrain deserialization.

- [https://github.com/oscerd/CVE-2026-40859](https://github.com/oscerd/CVE-2026-40859) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-40859.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-40859.svg)


## CVE-2026-40858
The JIRA ticket:  https://issues.apache.org/jira/browse/CAMEL-23322  refers to the various commits that resolved the issue, and have more details. This issue follows the same class of vulnerability previously addressed in CVE-2024-22369, CVE-2024-23114 and CVE-2026-25747.

- [https://github.com/oscerd/CVE-2026-40858](https://github.com/oscerd/CVE-2026-40858) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-40858.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-40858.svg)


## CVE-2026-33317
 OP-TEE is a Trusted Execution Environment (TEE) designed as companion to a non-secure Linux kernel running on Arm; Cortex-A cores using the TrustZone technology. In versions 3.13.0 through 4.10.0, missing checks in `entry_get_attribute_value()`  in `ta/pkcs11/src/object.c` can lead to out-of-bounds read from the PKCS#11 TA heap or a crash. When chained with the OOB read, the PKCS#11 TA function `PKCS11_CMD_GET_ATTRIBUTE_VALUE`  or `entry_get_attribute_value()` can, with a bad template parameter, be tricked into reading at most 7 bytes beyond the end of the template buffer and writing beyond the end of the template buffer with the content of an attribute value of a PKCS#11 object. Commits e031c4e562023fd9f199e39fd2e85797e4cbdca9, 16926d5a46934c46e6656246b4fc18385a246900, and 149e8d7ecc4ef8bb00ab4a37fd2ccede6d79e1ca contain patches and are anticipated to be part of version 4.11.0.

- [https://github.com/0xbbdd/CVE-2026-33317](https://github.com/0xbbdd/CVE-2026-33317) :  ![starts](https://img.shields.io/github/stars/0xbbdd/CVE-2026-33317.svg) ![forks](https://img.shields.io/github/forks/0xbbdd/CVE-2026-33317.svg)


## CVE-2026-29519
 Lucee CFML Server versions across the 5.3.x, 6.1.x, 6.2.x, and 7.0.x release lines contain a reflected cross-site scripting vulnerability in URL path parsing that allows unauthenticated remote attackers to execute arbitrary JavaScript in a victim's browser by embedding HTML or JavaScript payloads within the request path. Attackers can craft a malicious URL containing injected script content that is reflected in the server's response without proper output encoding, enabling session hijacking or unauthorized actions against the Lucee administrative interface when a victim visits the crafted link.

- [https://github.com/L4V4D0/CVE-2026-29519-Lucee-Reflected-XSS](https://github.com/L4V4D0/CVE-2026-29519-Lucee-Reflected-XSS) :  ![starts](https://img.shields.io/github/stars/L4V4D0/CVE-2026-29519-Lucee-Reflected-XSS.svg) ![forks](https://img.shields.io/github/forks/L4V4D0/CVE-2026-29519-Lucee-Reflected-XSS.svg)


## CVE-2026-28992
 A memory corruption vulnerability was addressed with improved locking. This issue is fixed in iOS 18.7.9 and iPadOS 18.7.9, iOS 26.5 and iPadOS 26.5, macOS Sequoia 15.7.7, macOS Sonoma 14.8.7, macOS Tahoe 26.5, tvOS 26.5, visionOS 26.5, watchOS 26.5. An attacker may be able to cause unexpected app termination.

- [https://github.com/clogan9019-dotcom/IOHIDFamily-PoC-Research](https://github.com/clogan9019-dotcom/IOHIDFamily-PoC-Research) :  ![starts](https://img.shields.io/github/stars/clogan9019-dotcom/IOHIDFamily-PoC-Research.svg) ![forks](https://img.shields.io/github/forks/clogan9019-dotcom/IOHIDFamily-PoC-Research.svg)


## CVE-2026-27626
 OliveTin gives access to predefined shell commands from a web interface. In versions up to and including 3000.10.0, OliveTin's shell mode safety check (`checkShellArgumentSafety`) blocks several dangerous argument types but not `password`. A user supplying a `password`-typed argument can inject shell metacharacters that execute arbitrary OS commands. A second independent vector allows unauthenticated RCE via webhook-extracted JSON values that skip type safety checks entirely before reaching `sh -c`. When exploiting vector 1, any authenticated user (registration enabled by default, `authType: none` by default) can execute arbitrary OS commands on the OliveTin host with the permissions of the OliveTin process. When exploiting vector 2, an unauthenticated attacker can achieve the same if the instance receives webhooks from external sources, which is a primary OliveTin use case. When an attacker exploits both vectors, this results in unauthenticated RCE on any OliveTin instance using Shell mode with webhook-triggered actions. As of time of publication, a patched version is not available.

- [https://github.com/Cobrastrike62/CVE-2026-27626-POC](https://github.com/Cobrastrike62/CVE-2026-27626-POC) :  ![starts](https://img.shields.io/github/stars/Cobrastrike62/CVE-2026-27626-POC.svg) ![forks](https://img.shields.io/github/forks/Cobrastrike62/CVE-2026-27626-POC.svg)


## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.

- [https://github.com/cain66666/openclaw-hardening-check](https://github.com/cain66666/openclaw-hardening-check) :  ![starts](https://img.shields.io/github/stars/cain66666/openclaw-hardening-check.svg) ![forks](https://img.shields.io/github/forks/cain66666/openclaw-hardening-check.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/stoerti2/Abyssal](https://github.com/stoerti2/Abyssal) :  ![starts](https://img.shields.io/github/stars/stoerti2/Abyssal.svg) ![forks](https://img.shields.io/github/forks/stoerti2/Abyssal.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/0x77FSec/CVE-2026-23744](https://github.com/0x77FSec/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/0x77FSec/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/0x77FSec/CVE-2026-23744.svg)


## CVE-2026-12400
 The FlowForms – Conversational Form Builder plugin for WordPress is vulnerable to Insecure Direct Object Reference in all versions up to, and including, 1.1.1 via the update_form due to missing validation on a user controlled key. This makes it possible for authenticated attackers, with contributor-level access and above, to modify the content, design, and settings of, as well as publish or revert, any form on the site — including forms owned by administrators — by supplying an arbitrary form ID in the REST URL.

- [https://github.com/0x00phantom-hat/CVE-2026-12400-Exploit](https://github.com/0x00phantom-hat/CVE-2026-12400-Exploit) :  ![starts](https://img.shields.io/github/stars/0x00phantom-hat/CVE-2026-12400-Exploit.svg) ![forks](https://img.shields.io/github/forks/0x00phantom-hat/CVE-2026-12400-Exploit.svg)


## CVE-2026-9558
 A Server-Side Template Injection (SSTI) vulnerability exists in Mautic's theme engine. The platform renders uploaded Twig templates without a sandbox or strict function restrictions. Authenticated users with permissions to create or upload themes can abuse this to execute arbitrary code on the hosting server (Remote Code Execution) or access restricted system files and configuration settings.

- [https://github.com/covepseng/cve-2026-9558-poc](https://github.com/covepseng/cve-2026-9558-poc) :  ![starts](https://img.shields.io/github/stars/covepseng/cve-2026-9558-poc.svg) ![forks](https://img.shields.io/github/forks/covepseng/cve-2026-9558-poc.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-61155
 The GameDriverX64.sys kernel-mode anti-cheat driver (v7.23.4.7 and earlier) contains an access control vulnerability in one of its IOCTL handlers. A user-mode process can open a handle to the driver device and send specially crafted IOCTL requests. These requests are executed in kernel-mode context without proper authentication or access validation, allowing the attacker to terminate arbitrary processes, including critical system and security services, without requiring administrative privileges.

- [https://github.com/sys0xff/CVE-2025-61155](https://github.com/sys0xff/CVE-2025-61155) :  ![starts](https://img.shields.io/github/stars/sys0xff/CVE-2025-61155.svg) ![forks](https://img.shields.io/github/forks/sys0xff/CVE-2025-61155.svg)


## CVE-2025-60787
 MotionEye v0.43.1b4 and before is vulnerable to OS Command Injection in configuration parameters such as image_file_name. Unsanitized user input is written to Motion configuration files, allowing remote authenticated attackers with admin access to achieve code execution when Motion is restarted.

- [https://github.com/ozcanpng/CVE-2025-60787](https://github.com/ozcanpng/CVE-2025-60787) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2025-60787.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2025-60787.svg)


## CVE-2025-51482
 Remote Code Execution in letta.server.rest_api.routers.v1.tools.run_tool_from_source in letta-ai Letta 0.7.12 allows remote attackers to execute arbitrary Python code and system commands via crafted payloads to the /v1/tools/run endpoint, bypassing intended sandbox restrictions.

- [https://github.com/c0gnit00/CVE-2024-51482](https://github.com/c0gnit00/CVE-2024-51482) :  ![starts](https://img.shields.io/github/stars/c0gnit00/CVE-2024-51482.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/CVE-2024-51482.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/d3vn0mi/CVE-2025-471812-POC](https://github.com/d3vn0mi/CVE-2025-471812-POC) :  ![starts](https://img.shields.io/github/stars/d3vn0mi/CVE-2025-471812-POC.svg) ![forks](https://img.shields.io/github/forks/d3vn0mi/CVE-2025-471812-POC.svg)


## CVE-2025-20720
 In wlan AP driver, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote (proximal/adjacent) escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: WCNCR00418954; Issue ID: MSV-3569.

- [https://github.com/shinthink/CVE-2025-20720](https://github.com/shinthink/CVE-2025-20720) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2025-20720.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2025-20720.svg)


## CVE-2025-10035
 A deserialization vulnerability in the License Servlet of Fortra's GoAnywhere MFT allows an actor with a validly forged license response signature to deserialize an arbitrary actor-controlled object, possibly leading to command injection.

- [https://github.com/sentinel-aidefense/CVE-2025-10035](https://github.com/sentinel-aidefense/CVE-2025-10035) :  ![starts](https://img.shields.io/github/stars/sentinel-aidefense/CVE-2025-10035.svg) ![forks](https://img.shields.io/github/forks/sentinel-aidefense/CVE-2025-10035.svg)


## CVE-2025-5548
 A vulnerability, which was classified as critical, was found in FreeFloat FTP Server 1.0. Affected is an unknown function of the component NOOP Command Handler. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/sudoand3rs0n/CVE-2025-5548](https://github.com/sudoand3rs0n/CVE-2025-5548) :  ![starts](https://img.shields.io/github/stars/sudoand3rs0n/CVE-2025-5548.svg) ![forks](https://img.shields.io/github/forks/sudoand3rs0n/CVE-2025-5548.svg)


## CVE-2024-51482
 ZoneMinder is a free, open source closed-circuit television software application. ZoneMinder v1.37.* = 1.37.64 is vulnerable to boolean-based SQL Injection in function of web/ajax/event.php. This is fixed in 1.37.65.

- [https://github.com/c0gnit00/CVE-2024-51482](https://github.com/c0gnit00/CVE-2024-51482) :  ![starts](https://img.shields.io/github/stars/c0gnit00/CVE-2024-51482.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/CVE-2024-51482.svg)


## CVE-2024-47176
 CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL. When combined with other vulnerabilities, such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker can execute arbitrary commands remotely on the target machine without authentication when a malicious printer is printed to.

- [https://github.com/Stickxx00/Cups-RCE-Exploit](https://github.com/Stickxx00/Cups-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/Stickxx00/Cups-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/Stickxx00/Cups-RCE-Exploit.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/ArcticDU/Exploit-CVE-2024-36401](https://github.com/ArcticDU/Exploit-CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/ArcticDU/Exploit-CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/ArcticDU/Exploit-CVE-2024-36401.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/swimmmmy/CVE-2024-27198-teamcity-auth-bypass](https://github.com/swimmmmy/CVE-2024-27198-teamcity-auth-bypass) :  ![starts](https://img.shields.io/github/stars/swimmmmy/CVE-2024-27198-teamcity-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/swimmmmy/CVE-2024-27198-teamcity-auth-bypass.svg)


## CVE-2024-0258
 The issue was addressed with improved memory handling. This issue is fixed in iOS 17.4 and iPadOS 17.4, macOS Sonoma 14.4, tvOS 17.4, watchOS 10.4. An app may be able to execute arbitrary code out of its sandbox or with certain elevated privileges.

- [https://github.com/aliyabuz25/CVE-2024-0258](https://github.com/aliyabuz25/CVE-2024-0258) :  ![starts](https://img.shields.io/github/stars/aliyabuz25/CVE-2024-0258.svg) ![forks](https://img.shields.io/github/forks/aliyabuz25/CVE-2024-0258.svg)


## CVE-2023-41892
 Craft CMS is a platform for creating digital experiences. This is a high-impact, low-complexity attack vector. Users running Craft installations before 4.4.15 are encouraged to update to at least that version to mitigate the issue. This issue has been fixed in Craft CMS 4.4.15.

- [https://github.com/lyccyc/CVE-2023-41892_PoC](https://github.com/lyccyc/CVE-2023-41892_PoC) :  ![starts](https://img.shields.io/github/stars/lyccyc/CVE-2023-41892_PoC.svg) ![forks](https://img.shields.io/github/forks/lyccyc/CVE-2023-41892_PoC.svg)


## CVE-2023-28218
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability

- [https://github.com/h1bAna/CVE-2023-28218](https://github.com/h1bAna/CVE-2023-28218) :  ![starts](https://img.shields.io/github/stars/h1bAna/CVE-2023-28218.svg) ![forks](https://img.shields.io/github/forks/h1bAna/CVE-2023-28218.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability

- [https://github.com/h1bAna/CVE-2023-21768](https://github.com/h1bAna/CVE-2023-21768) :  ![starts](https://img.shields.io/github/stars/h1bAna/CVE-2023-21768.svg) ![forks](https://img.shields.io/github/forks/h1bAna/CVE-2023-21768.svg)


## CVE-2023-20696
 In preloader, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07856356 / ALPS07874388 (For MT6880 and MT6890 only); Issue ID: ALPS07856356 / ALPS07874388 (For MT6880 and MT6890 only).

- [https://github.com/kasnria001/pwnage24mtk](https://github.com/kasnria001/pwnage24mtk) :  ![starts](https://img.shields.io/github/stars/kasnria001/pwnage24mtk.svg) ![forks](https://img.shields.io/github/forks/kasnria001/pwnage24mtk.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/robertdebock/ansible-role-cve_2021_44228](https://github.com/robertdebock/ansible-role-cve_2021_44228) :  ![starts](https://img.shields.io/github/stars/robertdebock/ansible-role-cve_2021_44228.svg) ![forks](https://img.shields.io/github/forks/robertdebock/ansible-role-cve_2021_44228.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/Lim-ahmin/CVE-2021-43798](https://github.com/Lim-ahmin/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/Lim-ahmin/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/Lim-ahmin/CVE-2021-43798.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)


## CVE-2021-28235
 Authentication vulnerability found in Etcd-io v.3.4.10 allows remote attackers to escalate privileges via the debug function.

- [https://github.com/h3ck13r/CVE-2021-28235](https://github.com/h3ck13r/CVE-2021-28235) :  ![starts](https://img.shields.io/github/stars/h3ck13r/CVE-2021-28235.svg) ![forks](https://img.shields.io/github/forks/h3ck13r/CVE-2021-28235.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/wysssadda/ExchangeSmash](https://github.com/wysssadda/ExchangeSmash) :  ![starts](https://img.shields.io/github/stars/wysssadda/ExchangeSmash.svg) ![forks](https://img.shields.io/github/forks/wysssadda/ExchangeSmash.svg)


## CVE-2020-2576
 Vulnerability in the Oracle Outside In Technology product of Oracle Fusion Middleware (component: Outside In Filters). The supported version that is affected is 8.5.4. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Outside In Technology. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Outside In Technology accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Outside In Technology. Note: Outside In Technology is a suite of software development kits (SDKs). The protocol and CVSS score depend on the software that uses the Outside In Technology code. The CVSS score assumes that the software passes data received over a network directly to Outside In Technology code, but if data is not received over a network the CVSS score may be lower. CVSS 3.0 Base Score 6.5 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L).

- [https://github.com/defrancescojp/CVE-2020-25769](https://github.com/defrancescojp/CVE-2020-25769) :  ![starts](https://img.shields.io/github/stars/defrancescojp/CVE-2020-25769.svg) ![forks](https://img.shields.io/github/forks/defrancescojp/CVE-2020-25769.svg)


## CVE-2017-10271
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/shahdawadfallah-sys/Cybersecurity-Capstone-Project](https://github.com/shahdawadfallah-sys/Cybersecurity-Capstone-Project) :  ![starts](https://img.shields.io/github/stars/shahdawadfallah-sys/Cybersecurity-Capstone-Project.svg) ![forks](https://img.shields.io/github/forks/shahdawadfallah-sys/Cybersecurity-Capstone-Project.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/endgtryna/lenovo-a1000g-mt8317-A412_01_09_130907-kernel-3.4.0-root-cve-2016-5195](https://github.com/endgtryna/lenovo-a1000g-mt8317-A412_01_09_130907-kernel-3.4.0-root-cve-2016-5195) :  ![starts](https://img.shields.io/github/stars/endgtryna/lenovo-a1000g-mt8317-A412_01_09_130907-kernel-3.4.0-root-cve-2016-5195.svg) ![forks](https://img.shields.io/github/forks/endgtryna/lenovo-a1000g-mt8317-A412_01_09_130907-kernel-3.4.0-root-cve-2016-5195.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/mehedi-hasan-sami98/DVWA-ZAP-PENTEST](https://github.com/mehedi-hasan-sami98/DVWA-ZAP-PENTEST) :  ![starts](https://img.shields.io/github/stars/mehedi-hasan-sami98/DVWA-ZAP-PENTEST.svg) ![forks](https://img.shields.io/github/forks/mehedi-hasan-sami98/DVWA-ZAP-PENTEST.svg)

