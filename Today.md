# Update 2026-03-11
## CVE-2026-30862
 Appsmith is a platform to build admin panels, internal tools, and dashboards. Prior to 1.96, a Critical Stored XSS vulnerability exists in the Table Widget (TableWidgetV2). The root cause is a lack of HTML sanitization in the React component rendering pipeline, allowing malicious attributes to be interpolated into the DOM. By leveraging the "Invite Users" feature, an attacker with a regular user account (user@gmail.com) can force a System Administrator to execute a high-privileged API call (/api/v1/admin/env), resulting in a Full Administrative Account Takeover. This vulnerability is fixed in 1.96.

- [https://github.com/drkim-dev/CVE-2026-30862](https://github.com/drkim-dev/CVE-2026-30862) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-30862.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-30862.svg)


## CVE-2026-27959
 Koa is middleware for Node.js using ES2017 async functions. Prior to versions 3.1.2 and 2.16.4, Koa's `ctx.hostname` API performs naive parsing of the HTTP Host header, extracting everything before the first colon without validating the input conforms to RFC 3986 hostname syntax. When a malformed Host header containing a `@` symbol is received, `ctx.hostname` returns `evil[.]com` - an attacker-controlled value. Applications using `ctx.hostname` for URL generation, password reset links, email verification URLs, or routing decisions are vulnerable to Host header injection attacks. Versions 3.1.2 and 2.16.4 fix the issue.

- [https://github.com/mlouazir/CVE-2026-27959-mini-lab](https://github.com/mlouazir/CVE-2026-27959-mini-lab) :  ![starts](https://img.shields.io/github/stars/mlouazir/CVE-2026-27959-mini-lab.svg) ![forks](https://img.shields.io/github/forks/mlouazir/CVE-2026-27959-mini-lab.svg)


## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.

- [https://github.com/EQSTLab/CVE-2026-25253](https://github.com/EQSTLab/CVE-2026-25253) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-25253.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-25253.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/0xAshwesker/CVE-2026-24061](https://github.com/0xAshwesker/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0xAshwesker/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0xAshwesker/CVE-2026-24061.svg)


## CVE-2026-21533
 Improper privilege management in Windows Remote Desktop allows an authorized attacker to elevate privileges locally.

- [https://github.com/fevar54/CVE-2026-21533_Scanner.py](https://github.com/fevar54/CVE-2026-21533_Scanner.py) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-21533_Scanner.py.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-21533_Scanner.py.svg)


## CVE-2025-69516
 A Server-Side Template Injection (SSTI) vulnerability in the /reporting/templates/preview/ endpoint of Amidaware Tactical RMM, affecting versions equal to or earlier than v1.3.1, allows low-privileged users with Report Viewer or Report Manager permissions to achieve remote command execution on the server. This occurs due to improper sanitization of the template_md parameter, enabling direct injection of Jinja2 templates. This occurs due to misuse of the generate_html() function, the user-controlled value is inserted into `env.from_string`, a function that processes Jinja2 templates arbitrarily, making an SSTI possible.

- [https://github.com/NtGabrielGomes/CVE-2025-69516](https://github.com/NtGabrielGomes/CVE-2025-69516) :  ![starts](https://img.shields.io/github/stars/NtGabrielGomes/CVE-2025-69516.svg) ![forks](https://img.shields.io/github/forks/NtGabrielGomes/CVE-2025-69516.svg)


## CVE-2025-69219
You should upgrade to version 6.0.0 of the provider to avoid even that risk.

- [https://github.com/ahmetartuc/poc-cve-2025-69219](https://github.com/ahmetartuc/poc-cve-2025-69219) :  ![starts](https://img.shields.io/github/stars/ahmetartuc/poc-cve-2025-69219.svg) ![forks](https://img.shields.io/github/forks/ahmetartuc/poc-cve-2025-69219.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg)


## CVE-2025-64459
Django would like to thank cyberstan for reporting this issue.

- [https://github.com/joshualent/django-cve-2025-64459](https://github.com/joshualent/django-cve-2025-64459) :  ![starts](https://img.shields.io/github/stars/joshualent/django-cve-2025-64459.svg) ![forks](https://img.shields.io/github/forks/joshualent/django-cve-2025-64459.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/swoon69/CVE-2025-59287-Exercise-Use](https://github.com/swoon69/CVE-2025-59287-Exercise-Use) :  ![starts](https://img.shields.io/github/stars/swoon69/CVE-2025-59287-Exercise-Use.svg) ![forks](https://img.shields.io/github/forks/swoon69/CVE-2025-59287-Exercise-Use.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/0xAshwesker/CVE-2025-49844](https://github.com/0xAshwesker/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/0xAshwesker/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/0xAshwesker/CVE-2025-49844.svg)


## CVE-2025-46701
Users are recommended to upgrade to version 11.0.7, 10.1.41 or 9.0.105, which fixes the issue.

- [https://github.com/gregk4sec/CVE-2025-46701-o](https://github.com/gregk4sec/CVE-2025-46701-o) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-46701-o.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-46701-o.svg)


## CVE-2025-31651
Users are recommended to upgrade to version [FIXED_VERSION], which fixes the issue.

- [https://github.com/gregk4sec/CVE-2025-31651-o](https://github.com/gregk4sec/CVE-2025-31651-o) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-31651-o.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-31651-o.svg)
- [https://github.com/gregk4sec/cve-2025-31651](https://github.com/gregk4sec/cve-2025-31651) :  ![starts](https://img.shields.io/github/stars/gregk4sec/cve-2025-31651.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/cve-2025-31651.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/0xPThree/next.js_cve-2025-29927](https://github.com/0xPThree/next.js_cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPThree/next.js_cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPThree/next.js_cve-2025-29927.svg)


## CVE-2025-14558
resolvconf(8) is a shell script which does not validate its input.  A lack of quoting meant that shell commands pass as input to resolvconf(8) may be executed.

- [https://github.com/JohannesLks/CVE-2025-14558](https://github.com/JohannesLks/CVE-2025-14558) :  ![starts](https://img.shields.io/github/stars/JohannesLks/CVE-2025-14558.svg) ![forks](https://img.shields.io/github/forks/JohannesLks/CVE-2025-14558.svg)
- [https://github.com/rockmelodies/Blackash-CVE-2025-14558](https://github.com/rockmelodies/Blackash-CVE-2025-14558) :  ![starts](https://img.shields.io/github/stars/rockmelodies/Blackash-CVE-2025-14558.svg) ![forks](https://img.shields.io/github/forks/rockmelodies/Blackash-CVE-2025-14558.svg)


## CVE-2025-7033
 A memory abuse issue exists in the Rockwell Automation Arena® Simulation. A custom file can force Arena Simulation to read and write past the end of memory space. Successful use requires user action, such as opening a bad file or webpage. If used, a threat actor could execute code or disclose information.

- [https://github.com/TheMalwareGuardian/CVE-2025-70330](https://github.com/TheMalwareGuardian/CVE-2025-70330) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2025-70330.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2025-70330.svg)


## CVE-2025-5548
 A vulnerability, which was classified as critical, was found in FreeFloat FTP Server 1.0. Affected is an unknown function of the component NOOP Command Handler. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/TheMalwareGuardian/CVE-2025-5548](https://github.com/TheMalwareGuardian/CVE-2025-5548) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2025-5548.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2025-5548.svg)


## CVE-2024-51428
 An issue in Espressif Esp idf v5.3.0 allows attackers to cause a Denial of Service (DoS) via a crafted data channel packet.

- [https://github.com/D1se0/CVE-2024-51428-PoC](https://github.com/D1se0/CVE-2024-51428-PoC) :  ![starts](https://img.shields.io/github/stars/D1se0/CVE-2024-51428-PoC.svg) ![forks](https://img.shields.io/github/forks/D1se0/CVE-2024-51428-PoC.svg)


## CVE-2024-34064
 Jinja is an extensible templating engine. The `xmlattr` filter in affected versions of Jinja accepts keys containing non-attribute characters. XML/HTML attributes cannot contain spaces, `/`, ``, or `=`, as each would then be interpreted as starting a separate attribute. If an application accepts keys (as opposed to only values) as user input, and renders these in pages that other users see as well, an attacker could use this to inject other attributes and perform XSS. The fix for CVE-2024-22195 only addressed spaces but not other characters. Accepting keys as user input is now explicitly considered an unintended use case of the `xmlattr` filter, and code that does so without otherwise validating the input should be flagged as insecure, regardless of Jinja version. Accepting _values_ as user input continues to be safe. This vulnerability is fixed in 3.1.4.

- [https://github.com/SandBlastx/flask-vuln-baseline](https://github.com/SandBlastx/flask-vuln-baseline) :  ![starts](https://img.shields.io/github/stars/SandBlastx/flask-vuln-baseline.svg) ![forks](https://img.shields.io/github/forks/SandBlastx/flask-vuln-baseline.svg)
- [https://github.com/SandBlastx/flask-vuln-v5](https://github.com/SandBlastx/flask-vuln-v5) :  ![starts](https://img.shields.io/github/stars/SandBlastx/flask-vuln-v5.svg) ![forks](https://img.shields.io/github/forks/SandBlastx/flask-vuln-v5.svg)
- [https://github.com/SandBlastx/flask-vuln-v1](https://github.com/SandBlastx/flask-vuln-v1) :  ![starts](https://img.shields.io/github/stars/SandBlastx/flask-vuln-v1.svg) ![forks](https://img.shields.io/github/forks/SandBlastx/flask-vuln-v1.svg)
- [https://github.com/SandBlastx/flask-vuln-v4](https://github.com/SandBlastx/flask-vuln-v4) :  ![starts](https://img.shields.io/github/stars/SandBlastx/flask-vuln-v4.svg) ![forks](https://img.shields.io/github/forks/SandBlastx/flask-vuln-v4.svg)
- [https://github.com/SandBlastx/flask-vuln-v2](https://github.com/SandBlastx/flask-vuln-v2) :  ![starts](https://img.shields.io/github/stars/SandBlastx/flask-vuln-v2.svg) ![forks](https://img.shields.io/github/forks/SandBlastx/flask-vuln-v2.svg)
- [https://github.com/SandBlastx/flask-vuln-v3](https://github.com/SandBlastx/flask-vuln-v3) :  ![starts](https://img.shields.io/github/stars/SandBlastx/flask-vuln-v3.svg) ![forks](https://img.shields.io/github/forks/SandBlastx/flask-vuln-v3.svg)
- [https://github.com/SandBlastx/flask-vuln-v6](https://github.com/SandBlastx/flask-vuln-v6) :  ![starts](https://img.shields.io/github/stars/SandBlastx/flask-vuln-v6.svg) ![forks](https://img.shields.io/github/forks/SandBlastx/flask-vuln-v6.svg)


## CVE-2024-31317
 In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/GitAmanS/ZygoteExploitDemo](https://github.com/GitAmanS/ZygoteExploitDemo) :  ![starts](https://img.shields.io/github/stars/GitAmanS/ZygoteExploitDemo.svg) ![forks](https://img.shields.io/github/forks/GitAmanS/ZygoteExploitDemo.svg)


## CVE-2024-23222
 A type confusion issue was addressed with improved checks. This issue is fixed in iOS 17.3 and iPadOS 17.3, macOS Sonoma 14.3, tvOS 17.3. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited.

- [https://github.com/Rohitberiwala/CVE-2024-23222-Coruna-Exploit-Kit-Deobfuscated](https://github.com/Rohitberiwala/CVE-2024-23222-Coruna-Exploit-Kit-Deobfuscated) :  ![starts](https://img.shields.io/github/stars/Rohitberiwala/CVE-2024-23222-Coruna-Exploit-Kit-Deobfuscated.svg) ![forks](https://img.shields.io/github/forks/Rohitberiwala/CVE-2024-23222-Coruna-Exploit-Kit-Deobfuscated.svg)


## CVE-2024-22393
Users are recommended to upgrade to version [1.2.5], which fixes the issue.

- [https://github.com/Rk-000/Apache-Hunter](https://github.com/Rk-000/Apache-Hunter) :  ![starts](https://img.shields.io/github/stars/Rk-000/Apache-Hunter.svg) ![forks](https://img.shields.io/github/forks/Rk-000/Apache-Hunter.svg)
- [https://github.com/Rk-000/Pixel-Flood-Attack](https://github.com/Rk-000/Pixel-Flood-Attack) :  ![starts](https://img.shields.io/github/stars/Rk-000/Pixel-Flood-Attack.svg) ![forks](https://img.shields.io/github/forks/Rk-000/Pixel-Flood-Attack.svg)


## CVE-2024-2025
 The "BuddyPress WooCommerce My Account Integration. Create WooCommerce Member Pages" plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.4.20 via deserialization of untrusted input in the get_simple_request function. This makes it possible for authenticated attackers, with subscriber-level access and above, to inject a PHP Object. If a POP chain is present via an additional plugin or theme installed on the target system, it could allow the attacker to delete arbitrary files, retrieve sensitive data, or execute code.

- [https://github.com/lighit2/CVE_Moodle_3.5.x](https://github.com/lighit2/CVE_Moodle_3.5.x) :  ![starts](https://img.shields.io/github/stars/lighit2/CVE_Moodle_3.5.x.svg) ![forks](https://img.shields.io/github/forks/lighit2/CVE_Moodle_3.5.x.svg)


## CVE-2023-45612
 In JetBrains Ktor before 2.3.5 default configuration of ContentNegotiation with XML format was vulnerable to XXE

- [https://github.com/razvanclaudiu/ktor-xxe-poc](https://github.com/razvanclaudiu/ktor-xxe-poc) :  ![starts](https://img.shields.io/github/stars/razvanclaudiu/ktor-xxe-poc.svg) ![forks](https://img.shields.io/github/forks/razvanclaudiu/ktor-xxe-poc.svg)


## CVE-2022-46169
This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/0x0Jackal/CVE-2022-46169](https://github.com/0x0Jackal/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/0x0Jackal/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/0x0Jackal/CVE-2022-46169.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is "${prefix:name}", where "prefix" is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - "script" - execute expressions using the JVM script execution engine (javax.script) - "dns" - resolve dns records - "url" - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/engranaabubakar/CVE-2022-42889](https://github.com/engranaabubakar/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/engranaabubakar/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/engranaabubakar/CVE-2022-42889.svg)


## CVE-2022-24716
 Icinga Web 2 is an open source monitoring web interface, framework and command-line interface. Unauthenticated users can leak the contents of files of the local system accessible to the web-server user, including `icingaweb2` configuration files with database credentials. This issue has been resolved in versions 2.9.6 and 2.10 of Icinga Web 2. Database credentials should be rotated.

- [https://github.com/0x0Jackal/CVE-2022-24716](https://github.com/0x0Jackal/CVE-2022-24716) :  ![starts](https://img.shields.io/github/stars/0x0Jackal/CVE-2022-24716.svg) ![forks](https://img.shields.io/github/forks/0x0Jackal/CVE-2022-24716.svg)


## CVE-2022-21449
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries). Supported versions that are affected are Oracle Java SE: 17.0.2 and 18; Oracle GraalVM Enterprise Edition: 21.3.1 and 22.0.0.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 7.5 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).

- [https://github.com/fevra-dev/ClaimJumper](https://github.com/fevra-dev/ClaimJumper) :  ![starts](https://img.shields.io/github/stars/fevra-dev/ClaimJumper.svg) ![forks](https://img.shields.io/github/forks/fevra-dev/ClaimJumper.svg)


## CVE-2021-32537
 Realtek HAD contains a driver crashed vulnerability which allows local side attackers to send a special string to the kernel driver in a user’s mode. Due to unexpected commands, the kernel driver will cause the system crashed.

- [https://github.com/0vercl0k/CVE-2021-32537](https://github.com/0vercl0k/CVE-2021-32537) :  ![starts](https://img.shields.io/github/stars/0vercl0k/CVE-2021-32537.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/CVE-2021-32537.svg)


## CVE-2020-35488
 The fileop module of the NXLog service in NXLog Community Edition 2.10.2150 allows remote attackers to cause a denial of service (daemon crash) via a crafted Syslog payload to the Syslog service. This attack requires a specific configuration. Also, the name of the directory created must use a Syslog field. (For example, on Linux it is not possible to create a .. directory. On Windows, it is not possible to create a CON directory.)

- [https://github.com/GuillaumePetit84/CVE-2020-35488](https://github.com/GuillaumePetit84/CVE-2020-35488) :  ![starts](https://img.shields.io/github/stars/GuillaumePetit84/CVE-2020-35488.svg) ![forks](https://img.shields.io/github/forks/GuillaumePetit84/CVE-2020-35488.svg)
- [https://github.com/githubfoam/nxlog-ubuntu-githubactions](https://github.com/githubfoam/nxlog-ubuntu-githubactions) :  ![starts](https://img.shields.io/github/stars/githubfoam/nxlog-ubuntu-githubactions.svg) ![forks](https://img.shields.io/github/forks/githubfoam/nxlog-ubuntu-githubactions.svg)


## CVE-2020-29583
 Firmware version 4.60 of Zyxel USG devices contains an undocumented account (zyfwp) with an unchangeable password. The password for this account can be found in cleartext in the firmware. This account can be used by someone to login to the ssh server or web interface with admin privileges.

- [https://github.com/ruppde/scan_CVE-2020-29583](https://github.com/ruppde/scan_CVE-2020-29583) :  ![starts](https://img.shields.io/github/stars/ruppde/scan_CVE-2020-29583.svg) ![forks](https://img.shields.io/github/forks/ruppde/scan_CVE-2020-29583.svg)


## CVE-2020-9802
 A logic issue was addressed with improved restrictions. This issue is fixed in iOS 13.5 and iPadOS 13.5, tvOS 13.4.5, watchOS 6.2.5, Safari 13.1.1, iTunes 12.10.7 for Windows, iCloud for Windows 11.2, iCloud for Windows 7.19. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/Billy-Ellis/jitsploitation](https://github.com/Billy-Ellis/jitsploitation) :  ![starts](https://img.shields.io/github/stars/Billy-Ellis/jitsploitation.svg) ![forks](https://img.shields.io/github/forks/Billy-Ellis/jitsploitation.svg)
- [https://github.com/khcujw/CVE-2020-9802](https://github.com/khcujw/CVE-2020-9802) :  ![starts](https://img.shields.io/github/stars/khcujw/CVE-2020-9802.svg) ![forks](https://img.shields.io/github/forks/khcujw/CVE-2020-9802.svg)


## CVE-2020-9332
 ftusbbus2.sys in FabulaTech USB for Remote Desktop through 2020-02-19 allows privilege escalation via crafted IoCtl code related to a USB HID device.

- [https://github.com/Sentinel-One/CVE-2020-9332](https://github.com/Sentinel-One/CVE-2020-9332) :  ![starts](https://img.shields.io/github/stars/Sentinel-One/CVE-2020-9332.svg) ![forks](https://img.shields.io/github/forks/Sentinel-One/CVE-2020-9332.svg)


## CVE-2018-15599
 The recv_msg_userauth_request function in svr-auth.c in Dropbear through 2018.76 is prone to a user enumeration vulnerability because username validity affects how fields in SSH_MSG_USERAUTH messages are handled, a similar issue to CVE-2018-15473 in an unrelated codebase.

- [https://github.com/Remnant-DB/CVE-2018-15599](https://github.com/Remnant-DB/CVE-2018-15599) :  ![starts](https://img.shields.io/github/stars/Remnant-DB/CVE-2018-15599.svg) ![forks](https://img.shields.io/github/forks/Remnant-DB/CVE-2018-15599.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/Remnant-DB/CVE-2018-15473](https://github.com/Remnant-DB/CVE-2018-15473) :  ![starts](https://img.shields.io/github/stars/Remnant-DB/CVE-2018-15473.svg) ![forks](https://img.shields.io/github/forks/Remnant-DB/CVE-2018-15473.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/Remnant-DB/CVE-2018-10933](https://github.com/Remnant-DB/CVE-2018-10933) :  ![starts](https://img.shields.io/github/stars/Remnant-DB/CVE-2018-10933.svg) ![forks](https://img.shields.io/github/forks/Remnant-DB/CVE-2018-10933.svg)


## CVE-2018-0114
 A vulnerability in the Cisco node-jose open source library before 0.11.0 could allow an unauthenticated, remote attacker to re-sign tokens using a key that is embedded within the token. The vulnerability is due to node-jose following the JSON Web Signature (JWS) standard for JSON Web Tokens (JWTs). This standard specifies that a JSON Web Key (JWK) representing a public key can be embedded within the header of a JWS. This public key is then trusted for verification. An attacker could exploit this by forging valid JWS objects by removing the original signature, adding a new public key to the header, and then signing the object using the (attacker-owned) private key associated with the public key embedded in that JWS header.

- [https://github.com/fevra-dev/ClaimJumper](https://github.com/fevra-dev/ClaimJumper) :  ![starts](https://img.shields.io/github/stars/fevra-dev/ClaimJumper.svg) ![forks](https://img.shields.io/github/forks/fevra-dev/ClaimJumper.svg)

