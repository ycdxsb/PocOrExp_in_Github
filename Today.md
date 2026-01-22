# Update 2026-01-22
## CVE-2026-23885
 Alchemy is an open source content management system engine written in Ruby on Rails. Prior to versions 7.4.12 and 8.0.3, the application uses the Ruby `eval()` function to dynamically execute a string provided by the `resource_handler.engine_name` attribute in `Alchemy::ResourcesHelper#resource_url_proxy`. The vulnerability exists in `app/helpers/alchemy/resources_helper.rb` at line 28. The code explicitly bypasses security linting with `# rubocop:disable Security/Eval`, indicating that the use of a dangerous function was known but not properly mitigated. Since `engine_name` is sourced from module definitions that can be influenced by administrative configurations, it allows an authenticated attacker to escape the Ruby sandbox and execute arbitrary system commands on the host OS. Versions 7.4.12 and 8.0.3 fix the issue by replacing `eval()` with `send()`.

- [https://github.com/TheDeepOpc/CVE-2026-23885](https://github.com/TheDeepOpc/CVE-2026-23885) :  ![starts](https://img.shields.io/github/stars/TheDeepOpc/CVE-2026-23885.svg) ![forks](https://img.shields.io/github/forks/TheDeepOpc/CVE-2026-23885.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/boroeurnprach/CVE-2026-23744-PoC](https://github.com/boroeurnprach/CVE-2026-23744-PoC) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/CVE-2026-23744-PoC.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/CVE-2026-23744-PoC.svg)


## CVE-2026-22812
 OpenCode is an open source AI coding agent. Prior to 1.0.216, OpenCode automatically starts an unauthenticated HTTP server that allows any local process (or any website via permissive CORS) to execute arbitrary shell commands with the user's privileges. This vulnerability is fixed in 1.0.216.

- [https://github.com/CayberMods/CVE-2026-22812-POC](https://github.com/CayberMods/CVE-2026-22812-POC) :  ![starts](https://img.shields.io/github/stars/CayberMods/CVE-2026-22812-POC.svg) ![forks](https://img.shields.io/github/forks/CayberMods/CVE-2026-22812-POC.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/SystemVll/CVE-2026-21858](https://github.com/SystemVll/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2026-21858.svg)
- [https://github.com/sec-dojo-com/CVE-2026-21858](https://github.com/sec-dojo-com/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/sec-dojo-com/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/sec-dojo-com/CVE-2026-21858.svg)


## CVE-2026-0227
 A vulnerability in Palo Alto Networks PAN-OS software enables an unauthenticated attacker to cause a denial of service (DoS) to the firewall. Repeated attempts to trigger this issue results in the firewall entering into maintenance mode.

- [https://github.com/TeeyaR/CVE-2026-0227-Palo-Alto](https://github.com/TeeyaR/CVE-2026-0227-Palo-Alto) :  ![starts](https://img.shields.io/github/stars/TeeyaR/CVE-2026-0227-Palo-Alto.svg) ![forks](https://img.shields.io/github/forks/TeeyaR/CVE-2026-0227-Palo-Alto.svg)


## CVE-2025-67263
 Abacre Retail Point of Sale 14.0.0.396 is affected by a stored cross-site scripting (XSS) vulnerability in the Clients module. The application fails to properly sanitize user-supplied input stored in the Name and Surname fields. An attacker can insert malicious HTML or script content into these fields, which, persisted in the database.

- [https://github.com/Smarttfoxx/CVE-2025-67263](https://github.com/Smarttfoxx/CVE-2025-67263) :  ![starts](https://img.shields.io/github/stars/Smarttfoxx/CVE-2025-67263.svg) ![forks](https://img.shields.io/github/forks/Smarttfoxx/CVE-2025-67263.svg)


## CVE-2025-67261
 Abacre Retail Point of Sale 14.0.0.396 is vulnerable to content-based blind SQL injection. The vulnerability exists in the Search function of the Orders page.

- [https://github.com/Smarttfoxx/CVE-2025-67261](https://github.com/Smarttfoxx/CVE-2025-67261) :  ![starts](https://img.shields.io/github/stars/Smarttfoxx/CVE-2025-67261.svg) ![forks](https://img.shields.io/github/forks/Smarttfoxx/CVE-2025-67261.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-66417
 GLPI is a free asset and IT management software package. From 11.0.0,  11.0.3, an unauthenticated user can perform a SQL injection through the inventory endpoint. This vulnerability is fixed in 11.0.3.

- [https://github.com/lem0naids/CVE-2025-66417-POC](https://github.com/lem0naids/CVE-2025-66417-POC) :  ![starts](https://img.shields.io/github/stars/lem0naids/CVE-2025-66417-POC.svg) ![forks](https://img.shields.io/github/forks/lem0naids/CVE-2025-66417-POC.svg)


## CVE-2025-65482
 An XML External Entity (XXE) vulnerability in opensagres XDocReport v0.9.2 to v2.0.3 allows attackers to execute arbitrary code via uploading a crafted .docx file.

- [https://github.com/AT190510-Cuong/CVE-2025-65482-XXE-](https://github.com/AT190510-Cuong/CVE-2025-65482-XXE-) :  ![starts](https://img.shields.io/github/stars/AT190510-Cuong/CVE-2025-65482-XXE-.svg) ![forks](https://img.shields.io/github/forks/AT190510-Cuong/CVE-2025-65482-XXE-.svg)


## CVE-2025-64087
 A Server-Side Template Injection (SSTI) vulnerability in the FreeMarker component of opensagres XDocReport v1.0.0 to v2.1.0 allows attackers to execute arbitrary code via injecting crafted template expressions.

- [https://github.com/AT190510-Cuong/CVE-2025-64087-SSTI-](https://github.com/AT190510-Cuong/CVE-2025-64087-SSTI-) :  ![starts](https://img.shields.io/github/stars/AT190510-Cuong/CVE-2025-64087-SSTI-.svg) ![forks](https://img.shields.io/github/forks/AT190510-Cuong/CVE-2025-64087-SSTI-.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/logesh-GIT001/CVE-2025-55182](https://github.com/logesh-GIT001/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/logesh-GIT001/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/logesh-GIT001/CVE-2025-55182.svg)


## CVE-2025-54068
 Livewire is a full-stack framework for Laravel. In Livewire v3 up to and including v3.6.3, a vulnerability allows unauthenticated attackers to achieve remote command execution in specific scenarios. The issue stems from how certain component property updates are hydrated. This vulnerability is unique to Livewire v3 and does not affect prior major versions. Exploitation requires a component to be mounted and configured in a particular way, but does not require authentication or user interaction. This issue has been patched in Livewire v3.6.4. All users are strongly encouraged to upgrade to this version or later as soon as possible. No known workarounds are available.

- [https://github.com/haxorstars/CVE-2025-54068](https://github.com/haxorstars/CVE-2025-54068) :  ![starts](https://img.shields.io/github/stars/haxorstars/CVE-2025-54068.svg) ![forks](https://img.shields.io/github/forks/haxorstars/CVE-2025-54068.svg)


## CVE-2025-50154
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/MartinxMax/CVE-2025-50154](https://github.com/MartinxMax/CVE-2025-50154) :  ![starts](https://img.shields.io/github/stars/MartinxMax/CVE-2025-50154.svg) ![forks](https://img.shields.io/github/forks/MartinxMax/CVE-2025-50154.svg)


## CVE-2025-43529
 A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 26.2, Safari 26.2, iOS 18.7.3 and iPadOS 18.7.3, iOS 26.2 and iPadOS 26.2, macOS Tahoe 26.2, visionOS 26.2, tvOS 26.2. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 was also issued in response to this report.

- [https://github.com/SgtBattenHA/Analysis](https://github.com/SgtBattenHA/Analysis) :  ![starts](https://img.shields.io/github/stars/SgtBattenHA/Analysis.svg) ![forks](https://img.shields.io/github/forks/SgtBattenHA/Analysis.svg)


## CVE-2025-36911
 In key-based pairing, there is a possible ID due to a logic error in the code. This could lead to remote (proximal/adjacent) information disclosure of user's conversations and location with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/PivotChip/FrostedFastPair](https://github.com/PivotChip/FrostedFastPair) :  ![starts](https://img.shields.io/github/stars/PivotChip/FrostedFastPair.svg) ![forks](https://img.shields.io/github/forks/PivotChip/FrostedFastPair.svg)


## CVE-2025-29943
 Write what were condition within AMD CPUs may allow an admin-privileged attacker to modify the configuration of the CPU pipeline potentially resulting in the corruption of the stack pointer inside an SEV-SNP guest.

- [https://github.com/fevar54/POC_CVE-2025-29943_Write-what-where-Condition](https://github.com/fevar54/POC_CVE-2025-29943_Write-what-where-Condition) :  ![starts](https://img.shields.io/github/stars/fevar54/POC_CVE-2025-29943_Write-what-where-Condition.svg) ![forks](https://img.shields.io/github/forks/fevar54/POC_CVE-2025-29943_Write-what-where-Condition.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)


## CVE-2025-23970
 Incorrect Privilege Assignment vulnerability in aonetheme Service Finder Booking allows Privilege Escalation. This issue affects Service Finder Booking: from n/a through 6.0.

- [https://github.com/y0uki-sec/CVE-2025-23970](https://github.com/y0uki-sec/CVE-2025-23970) :  ![starts](https://img.shields.io/github/stars/y0uki-sec/CVE-2025-23970.svg) ![forks](https://img.shields.io/github/forks/y0uki-sec/CVE-2025-23970.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/amnnrth/CVE-2025-14847](https://github.com/amnnrth/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/amnnrth/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/amnnrth/CVE-2025-14847.svg)


## CVE-2025-14174
 Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 143.0.7499.110 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/SgtBattenHA/Analysis](https://github.com/SgtBattenHA/Analysis) :  ![starts](https://img.shields.io/github/stars/SgtBattenHA/Analysis.svg) ![forks](https://img.shields.io/github/forks/SgtBattenHA/Analysis.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/I3r1h0n/Sigurd](https://github.com/I3r1h0n/Sigurd) :  ![starts](https://img.shields.io/github/stars/I3r1h0n/Sigurd.svg) ![forks](https://img.shields.io/github/forks/I3r1h0n/Sigurd.svg)


## CVE-2025-7545
 A vulnerability classified as problematic was found in GNU Binutils 2.45. Affected by this vulnerability is the function copy_section of the file binutils/objcopy.c. The manipulation leads to heap-based buffer overflow. Attacking locally is a requirement. The exploit has been disclosed to the public and may be used. The patch is named 08c3cbe5926e4d355b5cb70bbec2b1eeb40c2944. It is recommended to apply a patch to fix this issue.

- [https://github.com/alxsourin/Firmware-CVE-2025-7545](https://github.com/alxsourin/Firmware-CVE-2025-7545) :  ![starts](https://img.shields.io/github/stars/alxsourin/Firmware-CVE-2025-7545.svg) ![forks](https://img.shields.io/github/forks/alxsourin/Firmware-CVE-2025-7545.svg)


## CVE-2025-6934
 The Opal Estate Pro – Property Management and Submission plugin for WordPress, used by the FullHouse - Real Estate Responsive WordPress Theme, is vulnerable to privilege escalation via in all versions up to, and including, 1.7.5. This is due to a lack of role restriction during registration in the 'on_regiser_user' function. This makes it possible for unauthenticated attackers to arbitrarily choose the role, including the Administrator role, assigned when registering.

- [https://github.com/y0uki-sec/CVE-2025-6934](https://github.com/y0uki-sec/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/y0uki-sec/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/y0uki-sec/CVE-2025-6934.svg)


## CVE-2025-6758
 The Real Spaces - WordPress Properties Directory Theme theme for WordPress is vulnerable to privilege escalation via the 'imic_agent_register' function in all versions up to, and including, 3.6. This is due to a lack of restriction in the registration role. This makes it possible for unauthenticated attackers to arbitrarily choose their role, including the Administrator role, during user registration.

- [https://github.com/y0uki-sec/CVE-2025-6758](https://github.com/y0uki-sec/CVE-2025-6758) :  ![starts](https://img.shields.io/github/stars/y0uki-sec/CVE-2025-6758.svg) ![forks](https://img.shields.io/github/forks/y0uki-sec/CVE-2025-6758.svg)


## CVE-2025-6712
 MongoDB Server may be susceptible to disruption caused by high memory usage, potentially leading to server crash. This condition is linked to inefficiencies in memory management related to internal operations. In scenarios where certain internal processes persist longer than anticipated, memory consumption can increase, potentially impacting server stability and availability. This issue affects MongoDB Server v8.0 versions prior to 8.0.10

- [https://github.com/ashshh1/CVE-2025-67126](https://github.com/ashshh1/CVE-2025-67126) :  ![starts](https://img.shields.io/github/stars/ashshh1/CVE-2025-67126.svg) ![forks](https://img.shields.io/github/forks/ashshh1/CVE-2025-67126.svg)


## CVE-2025-4796
 The Eventin plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 4.0.34. This is due to the plugin not properly validating a user's identity or capability prior to updating their details like email in the 'Eventin\Speaker\Api\SpeakerController::update_item' function. This makes it possible for unauthenticated attackers with contributor-level and above permissions to change arbitrary user's email addresses, including administrators, and leverage that to reset the user's password and gain access to their account.

- [https://github.com/AnotherSec/CVE-2025-4796](https://github.com/AnotherSec/CVE-2025-4796) :  ![starts](https://img.shields.io/github/stars/AnotherSec/CVE-2025-4796.svg) ![forks](https://img.shields.io/github/forks/AnotherSec/CVE-2025-4796.svg)


## CVE-2025-3102
 The SureTriggers: All-in-One Automation Platform plugin for WordPress is vulnerable to an authentication bypass leading to administrative account creation due to a missing empty value check on the 'secret_key' value in the 'autheticate_user' function in all versions up to, and including, 1.0.78. This makes it possible for unauthenticated attackers to create administrator accounts on the target website when the plugin is installed and activated but not configured with an API key.

- [https://github.com/y0uki-sec/CVE-2025-3102](https://github.com/y0uki-sec/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/y0uki-sec/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/y0uki-sec/CVE-2025-3102.svg)


## CVE-2025-1055
 A vulnerability in the K7RKScan.sys driver, part of the K7 Security Anti-Malware suite, allows a local low-privilege user to send crafted IOCTL requests to terminate a wide range of processes running with administrative or system-level privileges, with the exception of those inherently protected by the operating system. This flaw stems from missing access control in the driver's IOCTL handler, enabling unprivileged users to perform privileged actions in kernel space. Successful exploitation can lead to denial of service by disrupting critical services or privileged applications.

- [https://github.com/I3r1h0n/Sigurd](https://github.com/I3r1h0n/Sigurd) :  ![starts](https://img.shields.io/github/stars/I3r1h0n/Sigurd.svg) ![forks](https://img.shields.io/github/forks/I3r1h0n/Sigurd.svg)


## CVE-2024-51324
 An issue in the BdApiUtil driver of Baidu Antivirus v5.2.3.116083 allows attackers to terminate arbitrary process via executing a BYOVD (Bring Your Own Vulnerable Driver) attack.

- [https://github.com/I3r1h0n/Sigurd](https://github.com/I3r1h0n/Sigurd) :  ![starts](https://img.shields.io/github/stars/I3r1h0n/Sigurd.svg) ![forks](https://img.shields.io/github/forks/I3r1h0n/Sigurd.svg)


## CVE-2024-38063
 Windows TCP/IP Remote Code Execution Vulnerability

- [https://github.com/thealice01/CVE-2024-38063](https://github.com/thealice01/CVE-2024-38063) :  ![starts](https://img.shields.io/github/stars/thealice01/CVE-2024-38063.svg) ![forks](https://img.shields.io/github/forks/thealice01/CVE-2024-38063.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/BasyacatX/CVE-2024-32002-PoC_Chinese](https://github.com/BasyacatX/CVE-2024-32002-PoC_Chinese) :  ![starts](https://img.shields.io/github/stars/BasyacatX/CVE-2024-32002-PoC_Chinese.svg) ![forks](https://img.shields.io/github/forks/BasyacatX/CVE-2024-32002-PoC_Chinese.svg)


## CVE-2024-25641
 Cacti provides an operational monitoring and fault management framework. Prior to version 1.2.27, an arbitrary file write vulnerability, exploitable through the "Package Import" feature, allows authenticated users having the "Import Templates" permission to execute arbitrary PHP code on the web server. The vulnerability is located within the `import_package()` function defined into the `/lib/import.php` script. The function blindly trusts the filename and file content provided within the XML data, and writes such files into the Cacti base path (or even outside, since path traversal sequences are not filtered). This can be exploited to write or overwrite arbitrary files on the web server, leading to execution of arbitrary PHP code or other security impacts. Version 1.2.27 contains a patch for this issue.

- [https://github.com/GabrielCF10/CVE-2024-25641---Cacti](https://github.com/GabrielCF10/CVE-2024-25641---Cacti) :  ![starts](https://img.shields.io/github/stars/GabrielCF10/CVE-2024-25641---Cacti.svg) ![forks](https://img.shields.io/github/forks/GabrielCF10/CVE-2024-25641---Cacti.svg)


## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/khengar9274-web/moveit-transfer-2023-breach](https://github.com/khengar9274-web/moveit-transfer-2023-breach) :  ![starts](https://img.shields.io/github/stars/khengar9274-web/moveit-transfer-2023-breach.svg) ![forks](https://img.shields.io/github/forks/khengar9274-web/moveit-transfer-2023-breach.svg)


## CVE-2022-46169
This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/nou-man/CVE-2022-46169](https://github.com/nou-man/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/nou-man/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/nou-man/CVE-2022-46169.svg)


## CVE-2021-21425
 Grav Admin Plugin is an HTML user interface that provides a way to configure Grav and create and modify pages. In versions 1.10.7 and earlier, an unauthenticated user can execute some methods of administrator controller without needing any credentials. Particular method execution will result in arbitrary YAML file creation or content change of existing YAML files on the system. Successfully exploitation of that vulnerability results in configuration changes, such as general site information change, custom scheduler job definition, etc. Due to the nature of the vulnerability, an adversary can change some part of the webpage, or hijack an administrator account, or execute operating system command under the context of the web-server user. This vulnerability is fixed in version 1.10.8. Blocking access to the `/admin` path from untrusted sources can be applied as a workaround.

- [https://github.com/afifudinmtop/CVE-2021-21425](https://github.com/afifudinmtop/CVE-2021-21425) :  ![starts](https://img.shields.io/github/stars/afifudinmtop/CVE-2021-21425.svg) ![forks](https://img.shields.io/github/forks/afifudinmtop/CVE-2021-21425.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/DanielFEXKEX/CVE-Scanner](https://github.com/DanielFEXKEX/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/DanielFEXKEX/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/DanielFEXKEX/CVE-Scanner.svg)


## CVE-2019-16098
 The driver in Micro-Star MSI Afterburner 4.6.2.15658 (aka RTCore64.sys and RTCore32.sys) allows any authenticated user to read and write to arbitrary memory, I/O ports, and MSRs. This can be exploited for privilege escalation, code execution under high privileges, and information disclosure. These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.

- [https://github.com/VortexCry-Organization/VortexCry-Ransomware](https://github.com/VortexCry-Organization/VortexCry-Ransomware) :  ![starts](https://img.shields.io/github/stars/VortexCry-Organization/VortexCry-Ransomware.svg) ![forks](https://img.shields.io/github/forks/VortexCry-Organization/VortexCry-Ransomware.svg)


## CVE-2019-10149
 A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.

- [https://github.com/CybersRMUTL/CVE-2019-10149-Exim4-RCE](https://github.com/CybersRMUTL/CVE-2019-10149-Exim4-RCE) :  ![starts](https://img.shields.io/github/stars/CybersRMUTL/CVE-2019-10149-Exim4-RCE.svg) ![forks](https://img.shields.io/github/forks/CybersRMUTL/CVE-2019-10149-Exim4-RCE.svg)


## CVE-2019-9193
 In PostgreSQL 9.3 through 11.2, the "COPY TO/FROM PROGRAM" function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for ‘COPY TO/FROM PROGRAM’ is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the ‘COPY FROM PROGRAM’.

- [https://github.com/CybersRMUTL/CVE-2019-9193-Postgresql-RCE](https://github.com/CybersRMUTL/CVE-2019-9193-Postgresql-RCE) :  ![starts](https://img.shields.io/github/stars/CybersRMUTL/CVE-2019-9193-Postgresql-RCE.svg) ![forks](https://img.shields.io/github/forks/CybersRMUTL/CVE-2019-9193-Postgresql-RCE.svg)


## CVE-2017-14980
 Buffer overflow in Sync Breeze Enterprise 10.0.28 allows remote attackers to have unspecified impact via a long username parameter to /login.

- [https://github.com/DaviGSantana/Exploit-CVE-2017-14980](https://github.com/DaviGSantana/Exploit-CVE-2017-14980) :  ![starts](https://img.shields.io/github/stars/DaviGSantana/Exploit-CVE-2017-14980.svg) ![forks](https://img.shields.io/github/forks/DaviGSantana/Exploit-CVE-2017-14980.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/saaydmr/hikvision-exploiter](https://github.com/saaydmr/hikvision-exploiter) :  ![starts](https://img.shields.io/github/stars/saaydmr/hikvision-exploiter.svg) ![forks](https://img.shields.io/github/forks/saaydmr/hikvision-exploiter.svg)

