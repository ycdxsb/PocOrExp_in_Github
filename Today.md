# Update 2026-07-13
## CVE-2026-59734
 Coolify is an open-source and self-hostable tool for managing servers, applications, and databases. Prior to 4.0.0-beta.469, Coolify's app/Jobs/ApplicationDeploymentJob.php generate_healthcheck_commands() function directly interpolated the health_check_host, health_check_method, and health_check_path parameters into shell commands without proper sanitization, allowing authenticated users to execute arbitrary commands inside deployment containers. This issue is fixed in version 4.0.0-beta.469.

- [https://github.com/cybertechajju/CVE-2026-59734-POC](https://github.com/cybertechajju/CVE-2026-59734-POC) :  ![starts](https://img.shields.io/github/stars/cybertechajju/CVE-2026-59734-POC.svg) ![forks](https://img.shields.io/github/forks/cybertechajju/CVE-2026-59734-POC.svg)


## CVE-2026-57850
 RustDesk before 1.4.9 does not enforce a session's authorized connection scope on the server side, so a peer granted a limited session type (FileTransfer, PortForward, ViewCamera, or Terminal) can send control messages and login options reserved for a full Remote session. An authenticated remote peer can exploit this missing scope check to act outside its granted scope, injecting out-of-scope control messages to observe and control the host beyond the permissions it was given.

- [https://github.com/sn0x-sharma/CVE-2026-57850](https://github.com/sn0x-sharma/CVE-2026-57850) :  ![starts](https://img.shields.io/github/stars/sn0x-sharma/CVE-2026-57850.svg) ![forks](https://img.shields.io/github/forks/sn0x-sharma/CVE-2026-57850.svg)


## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/yanxinwu946/CVE-2026-46331](https://github.com/yanxinwu946/CVE-2026-46331) :  ![starts](https://img.shields.io/github/stars/yanxinwu946/CVE-2026-46331.svg) ![forks](https://img.shields.io/github/forks/yanxinwu946/CVE-2026-46331.svg)


## CVE-2026-46242
READ_ONCE(epi-dying) fast-path bailout stays.

- [https://github.com/Baba01hacker666/CVE-2026-46242](https://github.com/Baba01hacker666/CVE-2026-46242) :  ![starts](https://img.shields.io/github/stars/Baba01hacker666/CVE-2026-46242.svg) ![forks](https://img.shields.io/github/forks/Baba01hacker666/CVE-2026-46242.svg)


## CVE-2026-46215
v2: cleanups of error paths

- [https://github.com/bluedragonsecurity/CVE-2026-46215-EXPLOIT](https://github.com/bluedragonsecurity/CVE-2026-46215-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/bluedragonsecurity/CVE-2026-46215-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/bluedragonsecurity/CVE-2026-46215-EXPLOIT.svg)


## CVE-2026-43501
MAC header fits afterwards.

- [https://github.com/Anyone202/cybermeowfia-termux](https://github.com/Anyone202/cybermeowfia-termux) :  ![starts](https://img.shields.io/github/stars/Anyone202/cybermeowfia-termux.svg) ![forks](https://img.shields.io/github/forks/Anyone202/cybermeowfia-termux.svg)


## CVE-2026-42527
Users are recommended to upgrade to a version that contains the CAMEL-23372 fix once available: 4.21.0 for the 4.21.x line, 4.18.3 for the 4.18.x line, and 4.14.8 for the 4.14.x line. For deployments that cannot upgrade immediately, configure a JMS-provider-side allow-list (Apache ActiveMQ Artemis 'deserializationAllowList' / 'deserializationDenyList', Apache ActiveMQ Classic 'org.apache.activemq.SERIALIZABLE_PACKAGES') as the primary mitigation, and/or override the in-code default via the endpoint-level 'deserializationFilter' option or the JVM-wide '-Djdk.serialFilter' system property with an explicit deny: '!java.net.**;java.**;javax.**;org.apache.camel.**;!*' (or '!java.net.**;java.**;org.apache.camel.**;!*' for the aggregation-repository components, which do not include javax.**).

- [https://github.com/oscerd/CVE-2026-42527](https://github.com/oscerd/CVE-2026-42527) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-42527.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-42527.svg)


## CVE-2026-40887
 Vendure is an open-source headless commerce platform. Starting in version 1.7.4 and prior to versions 2.3.4, 3.5.7, and 3.6.2, an unauthenticated SQL injection vulnerability exists in the Vendure Shop API. A user-controlled query string parameter is interpolated directly into a raw SQL expression without parameterization or validation, allowing an attacker to execute arbitrary SQL against the database. This affects all supported database backends (PostgreSQL, MySQL/MariaDB, SQLite). The Admin API is also affected, though exploitation there requires authentication. Versions 2.3.4, 3.5.7, and 3.6.2 contain a patch. For those who are unable to upgrade immediately, Vendure has made a hotfix available that uses `RequestContextService.getLanguageCode` to validate the `languageCode` input at the boundary. This blocks injection payloads before they can reach any query. The hotfix replaces the existing `getLanguageCode` method in `packages/core/src/service/helpers/request-context/request-context.service.ts`. Invalid values are silently dropped and the channel's default language is used instead. The patched versions additionally convert the vulnerable SQL interpolation to a parameterized query as defense in depth.

- [https://github.com/thecodeb0ss/CVE-2026-40887](https://github.com/thecodeb0ss/CVE-2026-40887) :  ![starts](https://img.shields.io/github/stars/thecodeb0ss/CVE-2026-40887.svg) ![forks](https://img.shields.io/github/forks/thecodeb0ss/CVE-2026-40887.svg)


## CVE-2026-39938
 Cacti is an open source performance and fault management framework. Versions 1.2.30 and prior have unauthenticated LFI through graph_theme and rrdtool IPC serialization hardening. This issue has been resolved in version 1.2.31.

- [https://github.com/kx00007/CVE-2026-39938](https://github.com/kx00007/CVE-2026-39938) :  ![starts](https://img.shields.io/github/stars/kx00007/CVE-2026-39938.svg) ![forks](https://img.shields.io/github/forks/kx00007/CVE-2026-39938.svg)


## CVE-2026-38526
 An authenticated arbitrary file upload vulnerability in the /admin/tinymce/upload endpoint of Webkul Krayin CRM v2.2.x allows attackers to execute arbitrary code via uploading a crafted PHP file.

- [https://github.com/Resolvdd/CVE-2026-38526-PoC-htb-nexus](https://github.com/Resolvdd/CVE-2026-38526-PoC-htb-nexus) :  ![starts](https://img.shields.io/github/stars/Resolvdd/CVE-2026-38526-PoC-htb-nexus.svg) ![forks](https://img.shields.io/github/forks/Resolvdd/CVE-2026-38526-PoC-htb-nexus.svg)


## CVE-2026-29145
Users are recommended to upgrade to version Tomcat Native 1.3.7 or 2.0.14 and Tomcat 11.0.20, 10.1.53 and 9.0.116, which fix the issue.

- [https://github.com/gkdgkd123/CVE-2026-29145-Everything](https://github.com/gkdgkd123/CVE-2026-29145-Everything) :  ![starts](https://img.shields.io/github/stars/gkdgkd123/CVE-2026-29145-Everything.svg) ![forks](https://img.shields.io/github/forks/gkdgkd123/CVE-2026-29145-Everything.svg)


## CVE-2026-29116
resulting in a denial of service.

- [https://github.com/CrimsonfiedOfficial/CVE-2026-29116](https://github.com/CrimsonfiedOfficial/CVE-2026-29116) :  ![starts](https://img.shields.io/github/stars/CrimsonfiedOfficial/CVE-2026-29116.svg) ![forks](https://img.shields.io/github/forks/CrimsonfiedOfficial/CVE-2026-29116.svg)


## CVE-2026-29115
 A vulnerability has been found in some Dahua products could allow an authenticated remote attacker to send a specially crafted packet, triggering an exception that causes the system to reboot unexpectedly, resulting in a denial of service.

- [https://github.com/CrimsonfiedOfficial/CVE-2026-29115](https://github.com/CrimsonfiedOfficial/CVE-2026-29115) :  ![starts](https://img.shields.io/github/stars/CrimsonfiedOfficial/CVE-2026-29115.svg) ![forks](https://img.shields.io/github/forks/CrimsonfiedOfficial/CVE-2026-29115.svg)


## CVE-2026-29114
trusted by those clients and undermine the certificate trust chain.

- [https://github.com/CrimsonfiedOfficial/CVE-2026-29114](https://github.com/CrimsonfiedOfficial/CVE-2026-29114) :  ![starts](https://img.shields.io/github/stars/CrimsonfiedOfficial/CVE-2026-29114.svg) ![forks](https://img.shields.io/github/forks/CrimsonfiedOfficial/CVE-2026-29114.svg)


## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.

- [https://github.com/dua2z3rr/CVE-2026-29000-PoC](https://github.com/dua2z3rr/CVE-2026-29000-PoC) :  ![starts](https://img.shields.io/github/stars/dua2z3rr/CVE-2026-29000-PoC.svg) ![forks](https://img.shields.io/github/forks/dua2z3rr/CVE-2026-29000-PoC.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/ozcanpng/CVE-2026-23744](https://github.com/ozcanpng/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2026-23744.svg)


## CVE-2026-15282
 The Instant Appointment plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'insapp_upload_image_as_attachment' function in all versions up to, and including, 1.2. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/shinthink/CVE-2026-15282](https://github.com/shinthink/CVE-2026-15282) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-15282.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-15282.svg)


## CVE-2026-14894
 The Super Forms – Drag & Drop Form Builder plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 6.3.313 via the submit_form function. This is due to missing file type validation and the absence of any capability check on the submit_form nopriv AJAX handler, whose only barrier is a session nonce freely obtainable by unauthenticated visitors via a separate nopriv endpoint. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible. The nonce requirement is trivially bypassed because the super_create_nonce nopriv AJAX action allows any unauthenticated visitor to mint a valid sf_nonce and session cookie in a single prior request, reducing exploitation to two unauthenticated HTTP requests.

- [https://github.com/1beelze/CVE-2026-14894](https://github.com/1beelze/CVE-2026-14894) :  ![starts](https://img.shields.io/github/stars/1beelze/CVE-2026-14894.svg) ![forks](https://img.shields.io/github/forks/1beelze/CVE-2026-14894.svg)


## CVE-2026-13768
 Gardyn devices expose a privileged iothubowner key. Access to this key will allow a malicious user to invoke an IoTHub Registry Manager function which returns connection information for all Gardyn Home Kit and Studio devices. Access to this key also allows a malicious user to execute arbitrary commands on a specific connected device and may allow the malicious user to pivot to other devices on the user's network.

- [https://github.com/J4ck3LSyN-Gen2/CVE-2026-13768](https://github.com/J4ck3LSyN-Gen2/CVE-2026-13768) :  ![starts](https://img.shields.io/github/stars/J4ck3LSyN-Gen2/CVE-2026-13768.svg) ![forks](https://img.shields.io/github/forks/J4ck3LSyN-Gen2/CVE-2026-13768.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/MW-HF/Drupal-CVE-2026-9082](https://github.com/MW-HF/Drupal-CVE-2026-9082) :  ![starts](https://img.shields.io/github/stars/MW-HF/Drupal-CVE-2026-9082.svg) ![forks](https://img.shields.io/github/forks/MW-HF/Drupal-CVE-2026-9082.svg)


## CVE-2026-4257
 The Contact Form by Supsystic plugin for WordPress is vulnerable to Server-Side Template Injection (SSTI) leading to Remote Code Execution (RCE) in all versions up to, and including, 1.7.36. This is due to the plugin using the Twig `Twig_Loader_String` template engine without sandboxing, combined with the `cfsPreFill` prefill functionality that allows unauthenticated users to inject arbitrary Twig expressions into form field values via GET parameters. This makes it possible for unauthenticated attackers to execute arbitrary PHP functions and OS commands on the server by leveraging Twig's `registerUndefinedFilterCallback()` method to register arbitrary PHP callbacks.

- [https://github.com/dann3xplo1t/CVE-2026-4257](https://github.com/dann3xplo1t/CVE-2026-4257) :  ![starts](https://img.shields.io/github/stars/dann3xplo1t/CVE-2026-4257.svg) ![forks](https://img.shields.io/github/forks/dann3xplo1t/CVE-2026-4257.svg)


## CVE-2026-0740
 The Ninja Forms - File Uploads plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'NF_FU_AJAX_Controllers_Uploads::handle_upload' function in all versions up to, and including, 3.3.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: The vulnerability was partially patched in version 3.3.25 and fully patched in version 3.3.27.

- [https://github.com/ExDev994/CVE-2026-0740-mass](https://github.com/ExDev994/CVE-2026-0740-mass) :  ![starts](https://img.shields.io/github/stars/ExDev994/CVE-2026-0740-mass.svg) ![forks](https://img.shields.io/github/forks/ExDev994/CVE-2026-0740-mass.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-55319
 Ai command injection in Agentic AI and Visual Studio Code allows an unauthorized attacker to execute code over a network.

- [https://github.com/nephila016/CVE-2025-55319-PoC](https://github.com/nephila016/CVE-2025-55319-PoC) :  ![starts](https://img.shields.io/github/stars/nephila016/CVE-2025-55319-PoC.svg) ![forks](https://img.shields.io/github/forks/nephila016/CVE-2025-55319-PoC.svg)


## CVE-2025-46285
 An integer overflow was addressed by adopting 64-bit timestamps. This issue is fixed in iOS 18.7.3 and iPadOS 18.7.3, iOS 26.2 and iPadOS 26.2, macOS Sequoia 15.7.3, macOS Sonoma 14.8.3, macOS Tahoe 26.2, tvOS 26.2, visionOS 26.2, watchOS 26.2. An app may be able to gain root privileges.

- [https://github.com/Yankeelucas/OpenSovix](https://github.com/Yankeelucas/OpenSovix) :  ![starts](https://img.shields.io/github/stars/Yankeelucas/OpenSovix.svg) ![forks](https://img.shields.io/github/forks/Yankeelucas/OpenSovix.svg)


## CVE-2025-22457
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.6, Ivanti Policy Secure before version 22.7R1.4, and Ivanti ZTA Gateways before version 22.8R2.2 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/melisakumral/CVE-2025-22457](https://github.com/melisakumral/CVE-2025-22457) :  ![starts](https://img.shields.io/github/stars/melisakumral/CVE-2025-22457.svg) ![forks](https://img.shields.io/github/forks/melisakumral/CVE-2025-22457.svg)


## CVE-2024-13985
 A command injection vulnerability in Dahua EIMS versions prior to 2240008 allows unauthenticated remote attackers to execute arbitrary system commands via the capture_handle.action interface. The flaw stems from improper input validation in the captureCommand parameter, which is processed without sanitization or authentication. By sending crafted HTTP requests, attackers can inject OS-level commands that are executed on the server, leading to full system compromise. Exploitation evidence was first observed by the Shadowserver Foundation on 2024-04-06 UTC.

- [https://github.com/CrimsonfiedOfficial/CVE-2024-13985](https://github.com/CrimsonfiedOfficial/CVE-2024-13985) :  ![starts](https://img.shields.io/github/stars/CrimsonfiedOfficial/CVE-2024-13985.svg) ![forks](https://img.shields.io/github/forks/CrimsonfiedOfficial/CVE-2024-13985.svg)


## CVE-2022-29078
 The ejs (aka Embedded JavaScript templates) package 3.1.6 for Node.js allows server-side template injection in settings[view options][outputFunctionName]. This is parsed as an internal option, and overwrites the outputFunctionName option with an arbitrary OS command (which is executed upon template compilation).

- [https://github.com/taka3636/CVE-2022-29078](https://github.com/taka3636/CVE-2022-29078) :  ![starts](https://img.shields.io/github/stars/taka3636/CVE-2022-29078.svg) ![forks](https://img.shields.io/github/forks/taka3636/CVE-2022-29078.svg)


## CVE-2022-2024
 OS Command Injection in GitHub repository gogs/gogs prior to 0.12.11.

- [https://github.com/ShifaShaikh074/cve-vulnerability-trend-analyzer](https://github.com/ShifaShaikh074/cve-vulnerability-trend-analyzer) :  ![starts](https://img.shields.io/github/stars/ShifaShaikh074/cve-vulnerability-trend-analyzer.svg) ![forks](https://img.shields.io/github/forks/ShifaShaikh074/cve-vulnerability-trend-analyzer.svg)


## CVE-2021-40449
 Win32k Elevation of Privilege Vulnerability

- [https://github.com/Joe1sn/CVE_2021_40449](https://github.com/Joe1sn/CVE_2021_40449) :  ![starts](https://img.shields.io/github/stars/Joe1sn/CVE_2021_40449.svg) ![forks](https://img.shields.io/github/forks/Joe1sn/CVE_2021_40449.svg)


## CVE-2021-39312
 The True Ranker plugin = 2.2.2 for WordPress allows arbitrary files, including sensitive configuration files such as wp-config.php, to be accessed via the src parameter found in the ~/admin/vendor/datatables/examples/resources/examples.php file.

- [https://github.com/root-wav/wordpress-true-ranker-cve-2021-39312](https://github.com/root-wav/wordpress-true-ranker-cve-2021-39312) :  ![starts](https://img.shields.io/github/stars/root-wav/wordpress-true-ranker-cve-2021-39312.svg) ![forks](https://img.shields.io/github/forks/root-wav/wordpress-true-ranker-cve-2021-39312.svg)


## CVE-2021-25646
 Apache Druid includes the ability to execute user-provided JavaScript code embedded in various types of requests. This functionality is intended for use in high-trust environments, and is disabled by default. However, in Druid 0.20.0 and earlier, it is possible for an authenticated user to send a specially-crafted request that forces Druid to run user-provided JavaScript code for that request, regardless of server configuration. This can be leveraged to execute code on the target machine with the privileges of the Druid server process.

- [https://github.com/shahdawadfallah-sys/Cybersecurity-Capstone-Project](https://github.com/shahdawadfallah-sys/Cybersecurity-Capstone-Project) :  ![starts](https://img.shields.io/github/stars/shahdawadfallah-sys/Cybersecurity-Capstone-Project.svg) ![forks](https://img.shields.io/github/forks/shahdawadfallah-sys/Cybersecurity-Capstone-Project.svg)


## CVE-2019-1003030
 A sandbox bypass vulnerability exists in Jenkins Pipeline: Groovy Plugin 2.63 and earlier in pom.xml, src/main/java/org/jenkinsci/plugins/workflow/cps/CpsGroovyShell.java that allows attackers able to control pipeline scripts to execute arbitrary code on the Jenkins master JVM.

- [https://github.com/cyberbelly/PoC-CVE-2019-1003030](https://github.com/cyberbelly/PoC-CVE-2019-1003030) :  ![starts](https://img.shields.io/github/stars/cyberbelly/PoC-CVE-2019-1003030.svg) ![forks](https://img.shields.io/github/forks/cyberbelly/PoC-CVE-2019-1003030.svg)


## CVE-2019-15107
 An issue was discovered in Webmin =1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/jini135wii/CVE-2019-15107](https://github.com/jini135wii/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/jini135wii/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/jini135wii/CVE-2019-15107.svg)


## CVE-2019-0232
 When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache Tomcat 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 is vulnerable to Remote Code Execution due to a bug in the way the JRE passes command line arguments to Windows. The CGI Servlet is disabled by default. The CGI option enableCmdLineArguments is disable by default in Tomcat 9.0.x (and will be disabled by default in all versions in response to this vulnerability). For a detailed explanation of the JRE behaviour, see Markus Wulftange's blog (https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-windows.html) and this archived MSDN blog (https://web.archive.org/web/20161228144344/https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/).

- [https://github.com/luongchivi/Preproduce-CVE-2019-0232](https://github.com/luongchivi/Preproduce-CVE-2019-0232) :  ![starts](https://img.shields.io/github/stars/luongchivi/Preproduce-CVE-2019-0232.svg) ![forks](https://img.shields.io/github/forks/luongchivi/Preproduce-CVE-2019-0232.svg)


## CVE-2018-1000533
 klaussilveira GitList version = 0.6 contains a Passing incorrectly sanitized input to system function vulnerability in `searchTree` function that can result in Execute any code as PHP user. This attack appear to be exploitable via Send POST request using search form. This vulnerability appears to have been fixed in 0.7 after commit 87b8c26b023c3fc37f0796b14bb13710f397b322.

- [https://github.com/dddo0/CVE-2018-1000533](https://github.com/dddo0/CVE-2018-1000533) :  ![starts](https://img.shields.io/github/stars/dddo0/CVE-2018-1000533.svg) ![forks](https://img.shields.io/github/forks/dddo0/CVE-2018-1000533.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/TheRealCiscoo/shellshock-manual-exploitation](https://github.com/TheRealCiscoo/shellshock-manual-exploitation) :  ![starts](https://img.shields.io/github/stars/TheRealCiscoo/shellshock-manual-exploitation.svg) ![forks](https://img.shields.io/github/forks/TheRealCiscoo/shellshock-manual-exploitation.svg)
- [https://github.com/TheRealCiscoo/shellshock-poc](https://github.com/TheRealCiscoo/shellshock-poc) :  ![starts](https://img.shields.io/github/stars/TheRealCiscoo/shellshock-poc.svg) ![forks](https://img.shields.io/github/forks/TheRealCiscoo/shellshock-poc.svg)

