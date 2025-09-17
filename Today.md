# Update 2025-09-17
## CVE-2025-59377
 feiskyer mcp-kubernetes-server through 0.1.11 allows OS command injection, even in read-only mode, via /mcp/kubectl because shell=True is used. NOTE: this is unrelated to mcp-server-kubernetes and CVE-2025-53355.

- [https://github.com/william31212/CVE-Requests-1896609](https://github.com/william31212/CVE-Requests-1896609) :  ![starts](https://img.shields.io/github/stars/william31212/CVE-Requests-1896609.svg) ![forks](https://img.shields.io/github/forks/william31212/CVE-Requests-1896609.svg)


## CVE-2025-59376
 feiskyer mcp-kubernetes-server through 0.1.11 does not consider chained commands in the implementation of --disable-write and --disable-delete, e.g., it allows a "kubectl version; kubectl delete pod" command because the first word (i.e., "version") is not a write or delete operation.

- [https://github.com/william31212/CVE-Requests-1896609](https://github.com/william31212/CVE-Requests-1896609) :  ![starts](https://img.shields.io/github/stars/william31212/CVE-Requests-1896609.svg) ![forks](https://img.shields.io/github/forks/william31212/CVE-Requests-1896609.svg)


## CVE-2025-58444
 The MCP inspector is a developer tool for testing and debugging MCP servers. A cross-site scripting issue was reported in versions of the MCP Inspector local development tool prior to 0.16.6 when connecting to untrusted remote MCP servers with a malicious redirect URI. This could be leveraged to interact directly with the inspector proxy to trigger arbitrary command execution. Users are advised to update to 0.16.6 to resolve this issue.

- [https://github.com/intbjw/Inspector-xss-poc](https://github.com/intbjw/Inspector-xss-poc) :  ![starts](https://img.shields.io/github/stars/intbjw/Inspector-xss-poc.svg) ![forks](https://img.shields.io/github/forks/intbjw/Inspector-xss-poc.svg)


## CVE-2025-55234
Adopt appropriate SMB Server hardening measures.

- [https://github.com/mrk336/Patch-the-Path-CVE-2025-55234-Detection-Defense](https://github.com/mrk336/Patch-the-Path-CVE-2025-55234-Detection-Defense) :  ![starts](https://img.shields.io/github/stars/mrk336/Patch-the-Path-CVE-2025-55234-Detection-Defense.svg) ![forks](https://img.shields.io/github/forks/mrk336/Patch-the-Path-CVE-2025-55234-Detection-Defense.svg)


## CVE-2025-50944
 An issue was discovered in the method push.lite.avtech.com.MySSLSocketFactoryNew.checkServerTrusted in AVTECH EagleEyes 2.0.0. The custom X509TrustManager used in checkServerTrusted only checks the certificate's expiration date, skipping proper TLS chain validation.

- [https://github.com/shinyColumn/CVE-2025-50944](https://github.com/shinyColumn/CVE-2025-50944) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-50944.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-50944.svg)


## CVE-2025-50110
 An issue was discovered in the method push.lite.avtech.com.AvtechLib.GetHttpsResponse in AVTECH EagleEyes Lite 2.0.0, the GetHttpsResponse method transmits sensitive information - including internal server URLs, account IDs, passwords, and device tokens - as plaintext query parameters over HTTPS

- [https://github.com/shinyColumn/CVE-2025-50110](https://github.com/shinyColumn/CVE-2025-50110) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-50110.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-50110.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/Zen-kun04/CVE-2025-49132](https://github.com/Zen-kun04/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/Zen-kun04/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/Zen-kun04/CVE-2025-49132.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/s41r4j/CVE-2025-48384-submodule](https://github.com/s41r4j/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/s41r4j/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/s41r4j/CVE-2025-48384-submodule.svg)
- [https://github.com/s41r4j/CVE-2025-48384](https://github.com/s41r4j/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/s41r4j/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/s41r4j/CVE-2025-48384.svg)


## CVE-2025-46408
 An issue was discovered in the methods push.lite.avtech.com.AvtechLib.GetHttpsResponse and push.lite.avtech.com.Push_HttpService.getNewHttpClient in AVTECH EagleEyes 2.0.0. The methods set ALLOW_ALL_HOSTNAME_VERIFIER, bypassing domain validation.

- [https://github.com/shinyColumn/CVE-2025-46408](https://github.com/shinyColumn/CVE-2025-46408) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-46408.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-46408.svg)


## CVE-2025-38501
This patch limit repeated connections from clients with the same IP.

- [https://github.com/keymaker-arch/KSMBDrain](https://github.com/keymaker-arch/KSMBDrain) :  ![starts](https://img.shields.io/github/stars/keymaker-arch/KSMBDrain.svg) ![forks](https://img.shields.io/github/forks/keymaker-arch/KSMBDrain.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/acan0007/CVE-2025-31161](https://github.com/acan0007/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/acan0007/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/acan0007/CVE-2025-31161.svg)


## CVE-2025-30468
 This issue was addressed through improved state management. This issue is fixed in iOS 26 and iPadOS 26. Private Browsing tabs may be accessed without authentication.

- [https://github.com/richeeta/DEFCON33-Siriously-Leaky](https://github.com/richeeta/DEFCON33-Siriously-Leaky) :  ![starts](https://img.shields.io/github/stars/richeeta/DEFCON33-Siriously-Leaky.svg) ![forks](https://img.shields.io/github/forks/richeeta/DEFCON33-Siriously-Leaky.svg)


## CVE-2025-23165
* This vulnerability affects APIs relying on `ReadFileUtf8` on Node.js release lines: v20 and v22.

- [https://github.com/mrk336/ElkStack-Secured-From-Logs-to-CVEs](https://github.com/mrk336/ElkStack-Secured-From-Logs-to-CVEs) :  ![starts](https://img.shields.io/github/stars/mrk336/ElkStack-Secured-From-Logs-to-CVEs.svg) ![forks](https://img.shields.io/github/forks/mrk336/ElkStack-Secured-From-Logs-to-CVEs.svg)


## CVE-2025-21756
 entry_SYSCALL_64_after_hwframe+0x76/0x7e

- [https://github.com/khoatran107/cve-2025-21756](https://github.com/khoatran107/cve-2025-21756) :  ![starts](https://img.shields.io/github/stars/khoatran107/cve-2025-21756.svg) ![forks](https://img.shields.io/github/forks/khoatran107/cve-2025-21756.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/fortihack/CVE-2025-9074](https://github.com/fortihack/CVE-2025-9074) :  ![starts](https://img.shields.io/github/stars/fortihack/CVE-2025-9074.svg) ![forks](https://img.shields.io/github/forks/fortihack/CVE-2025-9074.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/guinea-offensive-security/CVE-2025-6019](https://github.com/guinea-offensive-security/CVE-2025-6019) :  ![starts](https://img.shields.io/github/stars/guinea-offensive-security/CVE-2025-6019.svg) ![forks](https://img.shields.io/github/forks/guinea-offensive-security/CVE-2025-6019.svg)


## CVE-2025-3639
 Liferay Portal 7.3.0 through 7.4.3.132, and Liferay DXP 2025.Q1 through 2025.Q1.6, 2024.Q4.0 through 2024.Q4.7, 2024.Q3.1 through 2024.Q3.13, 2024.Q2.0 through 2024.Q2.13, 2024.Q1.1 through 2024.Q1.15, 7.4 GA through update 92 and 7.3 GA through update 36 allows unauthenticated users with valid credentials to bypass the login process by changing the POST method to GET, once the site has MFA enabled.

- [https://github.com/6lj/CVE-2025-3639](https://github.com/6lj/CVE-2025-3639) :  ![starts](https://img.shields.io/github/stars/6lj/CVE-2025-3639.svg) ![forks](https://img.shields.io/github/forks/6lj/CVE-2025-3639.svg)


## CVE-2025-2945
This issue affects pgAdmin 4: before 9.2.

- [https://github.com/Cycloctane/cve-2025-2945-poc](https://github.com/Cycloctane/cve-2025-2945-poc) :  ![starts](https://img.shields.io/github/stars/Cycloctane/cve-2025-2945-poc.svg) ![forks](https://img.shields.io/github/forks/Cycloctane/cve-2025-2945-poc.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE](https://github.com/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE) :  ![starts](https://img.shields.io/github/stars/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE.svg) ![forks](https://img.shields.io/github/forks/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/amalpvatayam67/day03-jenkins-23897](https://github.com/amalpvatayam67/day03-jenkins-23897) :  ![starts](https://img.shields.io/github/stars/amalpvatayam67/day03-jenkins-23897.svg) ![forks](https://img.shields.io/github/forks/amalpvatayam67/day03-jenkins-23897.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/nishan0x1/CVE-2024-0044](https://github.com/nishan0x1/CVE-2024-0044) :  ![starts](https://img.shields.io/github/stars/nishan0x1/CVE-2024-0044.svg) ![forks](https://img.shields.io/github/forks/nishan0x1/CVE-2024-0044.svg)


## CVE-2019-10076
 A carefully crafted malicious attachment could trigger an XSS vulnerability on Apache JSPWiki 2.9.0 to 2.11.0.M3, which could lead to session hijacking.

- [https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10076_2_11_0_M4_fixed](https://github.com/shoucheng3/apache__jspwiki_CVE-2019-10076_2_11_0_M4_fixed) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__jspwiki_CVE-2019-10076_2_11_0_M4_fixed.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__jspwiki_CVE-2019-10076_2_11_0_M4_fixed.svg)


## CVE-2019-9978
 The social-warfare plugin before 3.5.3 for WordPress has stored XSS via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, as exploited in the wild in March 2019. This affects Social Warfare and Social Warfare Pro.

- [https://github.com/xxoprt/payloadCVE-2019-9978](https://github.com/xxoprt/payloadCVE-2019-9978) :  ![starts](https://img.shields.io/github/stars/xxoprt/payloadCVE-2019-9978.svg) ![forks](https://img.shields.io/github/forks/xxoprt/payloadCVE-2019-9978.svg)


## CVE-2019-3396
 The Widget Connector macro in Atlassian Confluence Server before version 6.6.12 (the fixed version for 6.6.x), from version 6.7.0 before 6.12.3 (the fixed version for 6.12.x), from version 6.13.0 before 6.13.3 (the fixed version for 6.13.x), and from version 6.14.0 before 6.14.2 (the fixed version for 6.14.x), allows remote attackers to achieve path traversal and remote code execution on a Confluence Server or Data Center instance via server-side template injection.

- [https://github.com/kh4sh3i/CVE-2019-3396](https://github.com/kh4sh3i/CVE-2019-3396) :  ![starts](https://img.shields.io/github/stars/kh4sh3i/CVE-2019-3396.svg) ![forks](https://img.shields.io/github/forks/kh4sh3i/CVE-2019-3396.svg)


## CVE-2019-0207
 Tapestry processes assets `/assets/ctx` using classes chain `StaticFilesFilter - AssetDispatcher - ContextResource`, which doesn't filter the character `\`, so attacker can perform a path traversal attack to read any files on Windows platform.

- [https://github.com/shoucheng3/asf__tapestry-5_CVE-2019-0207_5_4_5_fixed](https://github.com/shoucheng3/asf__tapestry-5_CVE-2019-0207_5_4_5_fixed) :  ![starts](https://img.shields.io/github/stars/shoucheng3/asf__tapestry-5_CVE-2019-0207_5_4_5_fixed.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/asf__tapestry-5_CVE-2019-0207_5_4_5_fixed.svg)


## CVE-2018-20062
 An issue was discovered in NoneCms V1.3. thinkphp/library/think/App.php allows remote attackers to execute arbitrary PHP code via crafted use of the filter parameter, as demonstrated by the s=index/\think\Request/input&filter=phpinfo&data=1 query string.

- [https://github.com/shenhui35/RedArrow](https://github.com/shenhui35/RedArrow) :  ![starts](https://img.shields.io/github/stars/shenhui35/RedArrow.svg) ![forks](https://img.shields.io/github/forks/shenhui35/RedArrow.svg)


## CVE-2017-12611
 In Apache Struts 2.0.0 through 2.3.33 and 2.5 through 2.5.10.1, using an unintentional expression in a Freemarker tag instead of string literals can lead to a RCE attack.

- [https://github.com/tcetin704/CVE-2017-12611](https://github.com/tcetin704/CVE-2017-12611) :  ![starts](https://img.shields.io/github/stars/tcetin704/CVE-2017-12611.svg) ![forks](https://img.shields.io/github/forks/tcetin704/CVE-2017-12611.svg)

