# Update 2026-06-10
## CVE-2026-50751
 A logic flow weakness in Remote Access and Mobile Access certificate validation in deprecated IKEv1 key exchange allows an unauthenticated remote attacker to bypass user authentication and establish a remote access VPN connection without a valid user password.

- [https://github.com/0xBlackash/CVE-2026-50751](https://github.com/0xBlackash/CVE-2026-50751) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-50751.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-50751.svg)
- [https://github.com/WadesWeaponShed/CVE-2026-50751-Mitigation-Scripts](https://github.com/WadesWeaponShed/CVE-2026-50751-Mitigation-Scripts) :  ![starts](https://img.shields.io/github/stars/WadesWeaponShed/CVE-2026-50751-Mitigation-Scripts.svg) ![forks](https://img.shields.io/github/forks/WadesWeaponShed/CVE-2026-50751-Mitigation-Scripts.svg)


## CVE-2026-49975
This issue affects Apache HTTP Server: from 2.4.17 through 2.4.67.

- [https://github.com/mrx-arafat/CVE-2026-49975-POC](https://github.com/mrx-arafat/CVE-2026-49975-POC) :  ![starts](https://img.shields.io/github/stars/mrx-arafat/CVE-2026-49975-POC.svg) ![forks](https://img.shields.io/github/forks/mrx-arafat/CVE-2026-49975-POC.svg)
- [https://github.com/fevar54/Proof-of-Concept-POC---CVE-2026-49975-HTTP-2-Bomb-](https://github.com/fevar54/Proof-of-Concept-POC---CVE-2026-49975-HTTP-2-Bomb-) :  ![starts](https://img.shields.io/github/stars/fevar54/Proof-of-Concept-POC---CVE-2026-49975-HTTP-2-Bomb-.svg) ![forks](https://img.shields.io/github/forks/fevar54/Proof-of-Concept-POC---CVE-2026-49975-HTTP-2-Bomb-.svg)
- [https://github.com/obrige/http2-bomb](https://github.com/obrige/http2-bomb) :  ![starts](https://img.shields.io/github/stars/obrige/http2-bomb.svg) ![forks](https://img.shields.io/github/forks/obrige/http2-bomb.svg)
- [https://github.com/renzi25031469/CVE-2026-49975-HTTP-2-Bomb](https://github.com/renzi25031469/CVE-2026-49975-HTTP-2-Bomb) :  ![starts](https://img.shields.io/github/stars/renzi25031469/CVE-2026-49975-HTTP-2-Bomb.svg) ![forks](https://img.shields.io/github/forks/renzi25031469/CVE-2026-49975-HTTP-2-Bomb.svg)


## CVE-2026-46275
   all paths to prevent permanently breaking user-space retry capabilities.

- [https://github.com/xxconi/CVE-2026-46275](https://github.com/xxconi/CVE-2026-46275) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-46275.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-46275.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/ChanderManiPandey2022/YellowKey-BitLocker-Bypass-CVE-2026-45585-Detect-Fix-Automatically-via-Microsoft-Intune](https://github.com/ChanderManiPandey2022/YellowKey-BitLocker-Bypass-CVE-2026-45585-Detect-Fix-Automatically-via-Microsoft-Intune) :  ![starts](https://img.shields.io/github/stars/ChanderManiPandey2022/YellowKey-BitLocker-Bypass-CVE-2026-45585-Detect-Fix-Automatically-via-Microsoft-Intune.svg) ![forks](https://img.shields.io/github/forks/ChanderManiPandey2022/YellowKey-BitLocker-Bypass-CVE-2026-45585-Detect-Fix-Automatically-via-Microsoft-Intune.svg)


## CVE-2026-43512
Users are recommended to upgrade to version 11.0.22, 10.1.55 or 9.0.118 which fix the issue.

- [https://github.com/covepseng/cve-2026-43512-poc](https://github.com/covepseng/cve-2026-43512-poc) :  ![starts](https://img.shields.io/github/stars/covepseng/cve-2026-43512-poc.svg) ![forks](https://img.shields.io/github/forks/covepseng/cve-2026-43512-poc.svg)


## CVE-2026-42588
Users are recommended to upgrade to version 5.19.7 or 6.2.6, which fixes the issue.

- [https://github.com/Catherines77/ActiveMQ-EXPtools](https://github.com/Catherines77/ActiveMQ-EXPtools) :  ![starts](https://img.shields.io/github/stars/Catherines77/ActiveMQ-EXPtools.svg) ![forks](https://img.shields.io/github/forks/Catherines77/ActiveMQ-EXPtools.svg)


## CVE-2026-42208
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.81.16 to before version 1.83.7, a database query used during proxy API key checks mixed the caller-supplied key value into the query text instead of passing it as a separate parameter. An unauthenticated attacker could send a specially crafted Authorization header to any LLM API route (for example POST /chat/completions) and reach this query through the proxy's error-handling path. An attacker could read data from the proxy's database and may be able to modify it, leading to unauthorised access to the proxy and the credentials it manages. This issue has been patched in version 1.83.7.

- [https://github.com/rootdirective-sec/CVE-2026-42208-Lab](https://github.com/rootdirective-sec/CVE-2026-42208-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-42208-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-42208-Lab.svg)


## CVE-2026-27886
 Strapi is an open source headless content management system. Strapi versions starting in 4.0.0 and prior to 5.37.0 did not sufficiently sanitize query parameters when filtering content via relational fields. An unauthenticated attacker could use the `where` query parameter on any publicly-accessible content-type with an `updatedBy` (or other admin-relation) field to perform a boolean-oracle attack against private fields on the joined `admin_users` table, including the `resetPasswordToken` field. Extracting an admin reset token via this oracle made full administrative account takeover possible without authentication. When a filter such as `where[updatedBy][resetPasswordToken][$startsWith]=a` was applied to a public Content API endpoint, the underlying query generation performed a `LEFT JOIN` against the `admin_users` table and emitted a `WHERE` clause referencing the joined column. The query parameter sanitization layer did not block operator chains that traversed into relational target schemas the caller had no read permission on, allowing the response count to be used as a one-bit oracle on any admin-table field. The patch in version 5.37.0 introduces explicit query-parameter sanitization at the controller and service boundary via three new primitives: `strictParam`, `addQueryParams`, and `addBodyParams`. Operator chains that traverse into restricted relational targets are now rejected before reaching the database.

- [https://github.com/thesw0rd/CVE-2026-27886-PoC-Account-Takeover](https://github.com/thesw0rd/CVE-2026-27886-PoC-Account-Takeover) :  ![starts](https://img.shields.io/github/stars/thesw0rd/CVE-2026-27886-PoC-Account-Takeover.svg) ![forks](https://img.shields.io/github/forks/thesw0rd/CVE-2026-27886-PoC-Account-Takeover.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/K3ysTr0K3R/CVE-2026-24061](https://github.com/K3ysTr0K3R/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-24061.svg)
- [https://github.com/achnouri/CVE-2026-24061-GNU-InetUtils-telnetd](https://github.com/achnouri/CVE-2026-24061-GNU-InetUtils-telnetd) :  ![starts](https://img.shields.io/github/stars/achnouri/CVE-2026-24061-GNU-InetUtils-telnetd.svg) ![forks](https://img.shields.io/github/forks/achnouri/CVE-2026-24061-GNU-InetUtils-telnetd.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/HORKimhab/CVE-2026-23111](https://github.com/HORKimhab/CVE-2026-23111) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-23111.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-23111.svg)


## CVE-2026-11518
 A vulnerability was identified in SourceCodester Inventory System 1.0. Affected is an unknown function of the file /users.php of the component User Management Page. The manipulation of the argument fullname/username leads to cross site scripting. The attack is possible to be carried out remotely. The exploit is publicly available and might be used.

- [https://github.com/Xmyronn/CVE-2026-11518-XSS](https://github.com/Xmyronn/CVE-2026-11518-XSS) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-11518-XSS.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-11518-XSS.svg)


## CVE-2026-11499
 A vulnerability was determined in Tenda HG7HG9 and HG10 300001138_en_xpon. This affects the function formDOMAINBLK of the file /boaform/formDOMAINBLK. Executing a manipulation of the argument blkDomain can lead to stack-based buffer overflow. The attack may be performed from remote.

- [https://github.com/0xBlackash/CVE-2026-11499](https://github.com/0xBlackash/CVE-2026-11499) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-11499.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-11499.svg)


## CVE-2026-8054
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in the Publish Audit API endpoints (/api/auditPublishing/get and /api/auditPublishing/getAll) in dotCMS Core 25.11.04-1 through 26.04.28-02 allows remote unauthenticated attackers to read, modify, or destroy arbitrary database content. The endpoints did not enforce authentication and accepted unsanitized input used in dynamically constructed SQL. The fix in dotCMS Core 26.04.28-03 requires an authenticated backend user with the publishing-queue portlet permission. LTS releases are not affected as the vulnerable code path was never backported.

- [https://github.com/Mr-xn/CVE-2026-8054](https://github.com/Mr-xn/CVE-2026-8054) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2026-8054.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2026-8054.svg)


## CVE-2026-7465
 The Spectra Gutenberg Blocks – Website Builder for the Block Editor plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 2.19.25. This makes it possible for authenticated attackers, with Contributor-level access and above, to execute code on the server. Exploitation requires a two-block payload embedded in post content: the first block registers a fake uagb/-prefixed block type with an attacker-specified render_callback, and the second block of the same fake type triggers invocation of that callback via call_user_func() during sequential block rendering in the same page request.

- [https://github.com/rootdirective-sec/CVE-2026-7465-Lab](https://github.com/rootdirective-sec/CVE-2026-7465-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-7465-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-7465-Lab.svg)


## CVE-2026-5718
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file upload in versions up to, and including, 1.3.9.7. This is due to insufficient file type validation that occurs when custom blacklist types are configured, which replaces the default dangerous extension denylist instead of merging with it, and the wpcf7_antiscript_file_name() sanitization function being bypassed for filenames containing non-ASCII characters. This makes it possible for unauthenticated attackers to upload arbitrary files, such as PHP files, to the server, which can be leveraged to achieve remote code execution. The vulnerability was originally reported by Leonid Semenenko (lsemenenko) and partially patched in version 1.3.9.7. A bypass for the patch was separately discovered and reported by Nguyen Hung (Mitchell).

- [https://github.com/rootdirective-sec/CVE-2026-5718-Lab](https://github.com/rootdirective-sec/CVE-2026-5718-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-5718-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-5718-Lab.svg)


## CVE-2026-4506
 A vulnerability was found in Mindinventory MindSQL up to 0.2.1. Impacted is the function ask_db of the file mindsql/core/mindsql_core.py. Performing a manipulation results in code injection. The attack can be initiated remotely. The exploit has been made public and could be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/HORKimhab/CVE-2026-45067](https://github.com/HORKimhab/CVE-2026-45067) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-45067.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-45067.svg)


## CVE-2026-4480
substitution character without escaping shell meta characters. A remote attacker could exploit this vulnerability by sending a specially crafted print job description that contains unescaped shell characters. This could lead to remote code execution on the affected system.

- [https://github.com/CarlosEduardoPM/CVE-2026-4480-POC](https://github.com/CarlosEduardoPM/CVE-2026-4480-POC) :  ![starts](https://img.shields.io/github/stars/CarlosEduardoPM/CVE-2026-4480-POC.svg) ![forks](https://img.shields.io/github/forks/CarlosEduardoPM/CVE-2026-4480-POC.svg)


## CVE-2026-3180
 The Contest Gallery – Upload & Vote Photos, Media, Sell with PayPal & Stripe plugin for WordPress is vulnerable to blind SQL Injection via the ‘cgLostPasswordEmail’ and the ’cgl_mail’ parameter in all versions up to, and including, 28.1.4 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database. The vulnerability's ’cgLostPasswordEmail’ parameter was patched in version 28.1.4, and the ’cgl_mail’ parameter was patched in version 28.1.5.

- [https://github.com/carlosalbertotuma/cve-2026-3180-poc](https://github.com/carlosalbertotuma/cve-2026-3180-poc) :  ![starts](https://img.shields.io/github/stars/carlosalbertotuma/cve-2026-3180-poc.svg) ![forks](https://img.shields.io/github/forks/carlosalbertotuma/cve-2026-3180-poc.svg)


## CVE-2026-1689
 A vulnerability was detected in Tenda HG10 US_HG7_HG9_HG10re_300001138_en_xpon. The impacted element is the function checkUserFromLanOrWan of the file /boaform/admin/formLogin of the component Login Interface. The manipulation of the argument Host results in command injection. The attack can be launched remotely. The exploit is now public and may be used.

- [https://github.com/e76f01z/tenda-hg10-rce](https://github.com/e76f01z/tenda-hg10-rce) :  ![starts](https://img.shields.io/github/stars/e76f01z/tenda-hg10-rce.svg) ![forks](https://img.shields.io/github/forks/e76f01z/tenda-hg10-rce.svg)


## CVE-2026-1555
 The WebStack theme for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the io_img_upload() function in all versions up to, and including, 1.2024. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/willygailo/WG-CVE-2026-1555-Linux](https://github.com/willygailo/WG-CVE-2026-1555-Linux) :  ![starts](https://img.shields.io/github/stars/willygailo/WG-CVE-2026-1555-Linux.svg) ![forks](https://img.shields.io/github/forks/willygailo/WG-CVE-2026-1555-Linux.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/Moon-Harvest/CVE-2025-59528](https://github.com/Moon-Harvest/CVE-2025-59528) :  ![starts](https://img.shields.io/github/stars/Moon-Harvest/CVE-2025-59528.svg) ![forks](https://img.shields.io/github/forks/Moon-Harvest/CVE-2025-59528.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/YuvrajSHAD/FreePBX-CVE-2025-57819](https://github.com/YuvrajSHAD/FreePBX-CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/YuvrajSHAD/FreePBX-CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/YuvrajSHAD/FreePBX-CVE-2025-57819.svg)


## CVE-2025-43537
 A path handling issue was addressed with improved validation. This issue is fixed in iOS 18.7.5 and iPadOS 18.7.5, iOS 26.2 and iPadOS 26.2. Restoring a maliciously crafted backup file may lead to modification of protected system files.

- [https://github.com/hawkeye-bd/CVE-2025-43537](https://github.com/hawkeye-bd/CVE-2025-43537) :  ![starts](https://img.shields.io/github/stars/hawkeye-bd/CVE-2025-43537.svg) ![forks](https://img.shields.io/github/forks/hawkeye-bd/CVE-2025-43537.svg)


## CVE-2025-43529
 A use-after-free issue was addressed with improved memory management. This issue is fixed in Safari 26.2, iOS 18.7.3 and iPadOS 18.7.3, iOS 26.2 and iPadOS 26.2, macOS Tahoe 26.2, tvOS 26.2, visionOS 26.2, watchOS 26.2. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 was also issued in response to this report.

- [https://github.com/junfuture1103/CVE-2025-43529-no-forked](https://github.com/junfuture1103/CVE-2025-43529-no-forked) :  ![starts](https://img.shields.io/github/stars/junfuture1103/CVE-2025-43529-no-forked.svg) ![forks](https://img.shields.io/github/forks/junfuture1103/CVE-2025-43529-no-forked.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/chuzouX/CVE-2025-32433-Exploit-edited](https://github.com/chuzouX/CVE-2025-32433-Exploit-edited) :  ![starts](https://img.shields.io/github/stars/chuzouX/CVE-2025-32433-Exploit-edited.svg) ![forks](https://img.shields.io/github/forks/chuzouX/CVE-2025-32433-Exploit-edited.svg)


## CVE-2025-15556
 Notepad++ versions prior to 8.8.9, when using the WinGUp updater, contain an update integrity verification vulnerability where downloaded update metadata and installers are not cryptographically verified. An attacker able to intercept or redirect update traffic can cause the updater to download and execute an attacker-controlled installer, resulting in arbitrary code execution with the privileges of the user.

- [https://github.com/neutronsharkpray/Notepad-Plus-Plus-v8.9.6-Unlocked](https://github.com/neutronsharkpray/Notepad-Plus-Plus-v8.9.6-Unlocked) :  ![starts](https://img.shields.io/github/stars/neutronsharkpray/Notepad-Plus-Plus-v8.9.6-Unlocked.svg) ![forks](https://img.shields.io/github/forks/neutronsharkpray/Notepad-Plus-Plus-v8.9.6-Unlocked.svg)


## CVE-2025-5878
 A vulnerability was found in ESAPI esapi-java-legacy and classified as problematic. This issue affects the interface Encoder.encodeForSQL of the SQL Injection Defense. An attack leads to an improper neutralization of special elements. The attack may be initiated remotely and an exploit has been disclosed to the public. The project was contacted early about this issue and handled it with an exceptional level of professionalism. Upgrading to version 2.7.0.0 is able to address this issue. Commit ID f75ac2c2647a81d2cfbdc9c899f8719c240ed512 is disabling the feature by default and any attempt to use it will trigger a warning. And commit ID e2322914304d9b1c52523ff24be495b7832f6a56 is updating the misleading Java class documentation to warn about the risks.

- [https://github.com/dickfu/ESAPI-SQLinjection-CVE-2025-5878-Exploit](https://github.com/dickfu/ESAPI-SQLinjection-CVE-2025-5878-Exploit) :  ![starts](https://img.shields.io/github/stars/dickfu/ESAPI-SQLinjection-CVE-2025-5878-Exploit.svg) ![forks](https://img.shields.io/github/forks/dickfu/ESAPI-SQLinjection-CVE-2025-5878-Exploit.svg)


## CVE-2024-52011
 launch-editor allows users to open files with line numbers in editor from Node.js. Prior to version 2.9.0, due to the insufficient sanitization of the `file` argument in the `launchEditor`, an attacker can execute arbitrary commands on Windows by supplying a filename that contains special characters. This issue has been fixed in the `launch-editor` version 2.9.0, corresponding to vite version 5.4.9.

- [https://github.com/HORKimhab/CVE-2024-52011](https://github.com/HORKimhab/CVE-2024-52011) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2024-52011.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2024-52011.svg)


## CVE-2024-38475
Substitutions in server context that use a backreferences or variables as the first segment of the substitution are affected.  Some unsafe RewiteRules will be broken by this change and the rewrite flag "UnsafePrefixStat" can be used to opt back in once ensuring the substitution is appropriately constrained.

- [https://github.com/syaifulandy/CVE-2024-38475](https://github.com/syaifulandy/CVE-2024-38475) :  ![starts](https://img.shields.io/github/stars/syaifulandy/CVE-2024-38475.svg) ![forks](https://img.shields.io/github/forks/syaifulandy/CVE-2024-38475.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/kmrlbhr/pwntilldawn-10.150.150.38](https://github.com/kmrlbhr/pwntilldawn-10.150.150.38) :  ![starts](https://img.shields.io/github/stars/kmrlbhr/pwntilldawn-10.150.150.38.svg) ![forks](https://img.shields.io/github/forks/kmrlbhr/pwntilldawn-10.150.150.38.svg)


## CVE-2024-3342
 The Timetable and Event Schedule by MotoPress plugin for WordPress is vulnerable to SQL Injection via the 'events' attribute of the 'mp-timetable' shortcode in all versions up to, and including, 2.4.11 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with contributor-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/sp624/CVE-2024-33421](https://github.com/sp624/CVE-2024-33421) :  ![starts](https://img.shields.io/github/stars/sp624/CVE-2024-33421.svg) ![forks](https://img.shields.io/github/forks/sp624/CVE-2024-33421.svg)


## CVE-2024-3150
 In mintplex-labs/anything-llm, a vulnerability exists in the thread update process that allows users with Default or Manager roles to escalate their privileges to Administrator. The issue arises from improper input validation when handling HTTP POST requests to the endpoint `/workspace/:slug/thread/:threadSlug/update`. Specifically, the application fails to validate or check user input before passing it to the `workspace_thread` Prisma model for execution. This oversight allows attackers to craft a Prisma relation query operation that manipulates the `users` model to change a user's role to admin. Successful exploitation grants attackers the highest level of user privileges, enabling them to see and perform all actions within the system.

- [https://github.com/sp624/CVE-2024-31508](https://github.com/sp624/CVE-2024-31508) :  ![starts](https://img.shields.io/github/stars/sp624/CVE-2024-31508.svg) ![forks](https://img.shields.io/github/forks/sp624/CVE-2024-31508.svg)
- [https://github.com/sp624/CVE-2024-31509](https://github.com/sp624/CVE-2024-31509) :  ![starts](https://img.shields.io/github/stars/sp624/CVE-2024-31509.svg) ![forks](https://img.shields.io/github/forks/sp624/CVE-2024-31509.svg)


## CVE-2024-0258
 The issue was addressed with improved memory handling. This issue is fixed in iOS 17.4 and iPadOS 17.4, macOS Sonoma 14.4, tvOS 17.4, watchOS 10.4. An app may be able to execute arbitrary code out of its sandbox or with certain elevated privileges.

- [https://github.com/aliyabuz25/CVE-2024-0258-Research](https://github.com/aliyabuz25/CVE-2024-0258-Research) :  ![starts](https://img.shields.io/github/stars/aliyabuz25/CVE-2024-0258-Research.svg) ![forks](https://img.shields.io/github/forks/aliyabuz25/CVE-2024-0258-Research.svg)


## CVE-2023-48795
 The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

- [https://github.com/Mr-Whiskerss/SSH-Terrapin-Prefix-Truncation-Weakness-CVE-2023-48795-Checker](https://github.com/Mr-Whiskerss/SSH-Terrapin-Prefix-Truncation-Weakness-CVE-2023-48795-Checker) :  ![starts](https://img.shields.io/github/stars/Mr-Whiskerss/SSH-Terrapin-Prefix-Truncation-Weakness-CVE-2023-48795-Checker.svg) ![forks](https://img.shields.io/github/forks/Mr-Whiskerss/SSH-Terrapin-Prefix-Truncation-Weakness-CVE-2023-48795-Checker.svg)


## CVE-2023-42793
 In JetBrains TeamCity before 2023.05.4 authentication bypass leading to RCE on TeamCity Server was possible

- [https://github.com/syaifulandy/Nuclei-Template-CVE-2023-42793.yaml](https://github.com/syaifulandy/Nuclei-Template-CVE-2023-42793.yaml) :  ![starts](https://img.shields.io/github/stars/syaifulandy/Nuclei-Template-CVE-2023-42793.yaml.svg) ![forks](https://img.shields.io/github/forks/syaifulandy/Nuclei-Template-CVE-2023-42793.yaml.svg)


## CVE-2023-21716
 Microsoft Word Remote Code Execution Vulnerability

- [https://github.com/REGGYRAIDER/CVE-2023-21716](https://github.com/REGGYRAIDER/CVE-2023-21716) :  ![starts](https://img.shields.io/github/stars/REGGYRAIDER/CVE-2023-21716.svg) ![forks](https://img.shields.io/github/forks/REGGYRAIDER/CVE-2023-21716.svg)


## CVE-2023-2714
 The Groundhogg plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'check_license' functions in versions up to, and including, 2.7.9.8. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to change the license key and support license key, but it can only be changed to a valid license key.

- [https://github.com/astrocombat1607/CVE-2023-27146-LocalPotato-Priviledge-Escalation](https://github.com/astrocombat1607/CVE-2023-27146-LocalPotato-Priviledge-Escalation) :  ![starts](https://img.shields.io/github/stars/astrocombat1607/CVE-2023-27146-LocalPotato-Priviledge-Escalation.svg) ![forks](https://img.shields.io/github/forks/astrocombat1607/CVE-2023-27146-LocalPotato-Priviledge-Escalation.svg)


## CVE-2022-39997
 A weak password requirement issue was discovered in Teldats Router RS123, RS123w allows a remote attacker to escalate privileges

- [https://github.com/uyhacked/Teldat-Router-CVE-2022-POC](https://github.com/uyhacked/Teldat-Router-CVE-2022-POC) :  ![starts](https://img.shields.io/github/stars/uyhacked/Teldat-Router-CVE-2022-POC.svg) ![forks](https://img.shields.io/github/forks/uyhacked/Teldat-Router-CVE-2022-POC.svg)


## CVE-2022-39996
 Cross Site Scripting vulnerability in Teldats Router RS123, RS123w allows attacker to execute arbitrary code via the cmdcookie parameter to the upgrade/query.php page.

- [https://github.com/uyhacked/Teldat-Router-CVE-2022-POC](https://github.com/uyhacked/Teldat-Router-CVE-2022-POC) :  ![starts](https://img.shields.io/github/stars/uyhacked/Teldat-Router-CVE-2022-POC.svg) ![forks](https://img.shields.io/github/forks/uyhacked/Teldat-Router-CVE-2022-POC.svg)


## CVE-2020-10567
 An issue was discovered in Responsive Filemanager through 9.14.0. In the ajax_calls.php file in the save_img action in the name parameter, there is no validation of what kind of extension is sent. This makes it possible to execute PHP code if a legitimate JPEG image contains this code in the EXIF data, and the .php extension is used in the name parameter. (A potential fast patch is to disable the save_img action in the config file.)

- [https://github.com/PierreAdams/CVE-2020-10567](https://github.com/PierreAdams/CVE-2020-10567) :  ![starts](https://img.shields.io/github/stars/PierreAdams/CVE-2020-10567.svg) ![forks](https://img.shields.io/github/forks/PierreAdams/CVE-2020-10567.svg)


## CVE-2017-2025
 DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: none.  Reason: This candidate was in a CNA pool that was not assigned to any issues during 2017.  Notes: none

- [https://github.com/Polosss/By-Poloss..-..CVE-2017-20251](https://github.com/Polosss/By-Poloss..-..CVE-2017-20251) :  ![starts](https://img.shields.io/github/stars/Polosss/By-Poloss..-..CVE-2017-20251.svg) ![forks](https://img.shields.io/github/forks/Polosss/By-Poloss..-..CVE-2017-20251.svg)

