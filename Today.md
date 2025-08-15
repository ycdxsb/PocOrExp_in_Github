# Update 2025-08-15
## CVE-2025-55668
Users are recommended to upgrade to version 11.0.8, 10.1.42 or 9.0.106, which fix the issue.

- [https://github.com/gregk4sec/CVE-2025-55668](https://github.com/gregk4sec/CVE-2025-55668) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-55668.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-55668.svg)


## CVE-2025-54887
 jwe is a Ruby implementation of the RFC 7516 JSON Web Encryption (JWE) standard. In versions 1.1.0 and below, authentication tags of encrypted JWEs can be brute forced, which may result in loss of confidentiality for those JWEs and provide ways to craft arbitrary JWEs. This puts users at risk because JWEs can be modified to decrypt to an arbitrary value, decrypted by observing parsing differences and the GCM internal GHASH key can be recovered. Users are affected by this vulnerability even if they do not use an AES-GCM encryption algorithm for their JWEs. As the GHASH key may have been leaked, users must rotate the encryption keys after upgrading. This issue is fixed in version 1.1.1.

- [https://github.com/shinigami-777/PoC_CVE-2025-54887](https://github.com/shinigami-777/PoC_CVE-2025-54887) :  ![starts](https://img.shields.io/github/stars/shinigami-777/PoC_CVE-2025-54887.svg) ![forks](https://img.shields.io/github/forks/shinigami-777/PoC_CVE-2025-54887.svg)


## CVE-2025-54135
 Cursor is a code editor built for programming with AI. Cursor allows writing in-workspace files with no user approval in versions below 1.3.9, If the file is a dotfile, editing it requires approval but creating a new one doesn't. Hence, if sensitive MCP files, such as the .cursor/mcp.json file don't already exist in the workspace, an attacker can chain a indirect prompt injection vulnerability to hijack the context to write to the settings file and trigger RCE on the victim without user approval. This is fixed in version 1.3.9.

- [https://github.com/anntsmart/CVE-2025-54135](https://github.com/anntsmart/CVE-2025-54135) :  ![starts](https://img.shields.io/github/stars/anntsmart/CVE-2025-54135.svg) ![forks](https://img.shields.io/github/forks/anntsmart/CVE-2025-54135.svg)


## CVE-2025-53773
 Improper neutralization of special elements used in a command ('command injection') in GitHub Copilot and Visual Studio allows an unauthorized attacker to execute code locally.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-53773](https://github.com/B1ack4sh/Blackash-CVE-2025-53773) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-53773.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-53773.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/CyprianAtsyor/ToolShell-CVE-2025-53770-SharePoint-Exploit-Lab-LetsDefend](https://github.com/CyprianAtsyor/ToolShell-CVE-2025-53770-SharePoint-Exploit-Lab-LetsDefend) :  ![starts](https://img.shields.io/github/stars/CyprianAtsyor/ToolShell-CVE-2025-53770-SharePoint-Exploit-Lab-LetsDefend.svg) ![forks](https://img.shields.io/github/forks/CyprianAtsyor/ToolShell-CVE-2025-53770-SharePoint-Exploit-Lab-LetsDefend.svg)


## CVE-2025-52385
 An issue in Studio 3T v.2025.1.0 and before allows a remote attacker to execute arbitrary code via a crafted payload to the child_process module

- [https://github.com/Kov404/CVE-2025-52385](https://github.com/Kov404/CVE-2025-52385) :  ![starts](https://img.shields.io/github/stars/Kov404/CVE-2025-52385.svg) ![forks](https://img.shields.io/github/forks/Kov404/CVE-2025-52385.svg)


## CVE-2025-50154
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/rubenformation/CVE-2025-50154](https://github.com/rubenformation/CVE-2025-50154) :  ![starts](https://img.shields.io/github/stars/rubenformation/CVE-2025-50154.svg) ![forks](https://img.shields.io/github/forks/rubenformation/CVE-2025-50154.svg)
- [https://github.com/zenzue/CVE-2025-50154](https://github.com/zenzue/CVE-2025-50154) :  ![starts](https://img.shields.io/github/stars/zenzue/CVE-2025-50154.svg) ![forks](https://img.shields.io/github/forks/zenzue/CVE-2025-50154.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/testtianmaaaa/CVE-2025-48384](https://github.com/testtianmaaaa/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/testtianmaaaa/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/testtianmaaaa/CVE-2025-48384.svg)


## CVE-2025-47533
 Cross-Site Request Forgery (CSRF) vulnerability in Iqonic Design Graphina allows PHP Local File Inclusion. This issue affects Graphina: from n/a through 3.0.4.

- [https://github.com/zs1n/CVE-2024-47533](https://github.com/zs1n/CVE-2024-47533) :  ![starts](https://img.shields.io/github/stars/zs1n/CVE-2024-47533.svg) ![forks](https://img.shields.io/github/forks/zs1n/CVE-2024-47533.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/NiteeshPujari/CVE-2025-32433-PoC](https://github.com/NiteeshPujari/CVE-2025-32433-PoC) :  ![starts](https://img.shields.io/github/stars/NiteeshPujari/CVE-2025-32433-PoC.svg) ![forks](https://img.shields.io/github/forks/NiteeshPujari/CVE-2025-32433-PoC.svg)


## CVE-2025-25256
 An improper neutralization of special elements used in an OS command ('OS Command Injection') vulnerability [CWE-78] in Fortinet FortiSIEM version 7.3.0 through 7.3.1, 7.2.0 through 7.2.5, 7.1.0 through 7.1.7, 7.0.0 through 7.0.3 and before 6.7.9 allows an unauthenticated attacker to execute unauthorized code or commands via crafted CLI requests.

- [https://github.com/barbaraeivyu/CVE-2025-25256](https://github.com/barbaraeivyu/CVE-2025-25256) :  ![starts](https://img.shields.io/github/stars/barbaraeivyu/CVE-2025-25256.svg) ![forks](https://img.shields.io/github/forks/barbaraeivyu/CVE-2025-25256.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/CMassa/CVE-2025-24893](https://github.com/CMassa/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/CMassa/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/CMassa/CVE-2025-24893.svg)


## CVE-2025-24054
 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/rubenformation/CVE-2025-50154](https://github.com/rubenformation/CVE-2025-50154) :  ![starts](https://img.shields.io/github/stars/rubenformation/CVE-2025-50154.svg) ![forks](https://img.shields.io/github/forks/rubenformation/CVE-2025-50154.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/sxyrxyy/CVE-2025-8088-WinRAR-Proof-of-Concept-PoC-Exploit-](https://github.com/sxyrxyy/CVE-2025-8088-WinRAR-Proof-of-Concept-PoC-Exploit-) :  ![starts](https://img.shields.io/github/stars/sxyrxyy/CVE-2025-8088-WinRAR-Proof-of-Concept-PoC-Exploit-.svg) ![forks](https://img.shields.io/github/forks/sxyrxyy/CVE-2025-8088-WinRAR-Proof-of-Concept-PoC-Exploit-.svg)
- [https://github.com/onlytoxi/CVE-2025-8088-Winrar-Tool](https://github.com/onlytoxi/CVE-2025-8088-Winrar-Tool) :  ![starts](https://img.shields.io/github/stars/onlytoxi/CVE-2025-8088-Winrar-Tool.svg) ![forks](https://img.shields.io/github/forks/onlytoxi/CVE-2025-8088-Winrar-Tool.svg)


## CVE-2025-5419
 Out of bounds read and write in V8 in Google Chrome prior to 137.0.7151.68 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/riemannj/CVE-2025-5419](https://github.com/riemannj/CVE-2025-5419) :  ![starts](https://img.shields.io/github/stars/riemannj/CVE-2025-5419.svg) ![forks](https://img.shields.io/github/forks/riemannj/CVE-2025-5419.svg)


## CVE-2025-5042
 A maliciously crafted RFA file, when parsed through Autodesk Revit, can force an Out-of-Bounds Read vulnerability. A malicious actor can leverage this vulnerability to cause a crash, read sensitive data, or execute arbitrary code in the context of the current process.

- [https://github.com/security-smarttecs/cve-2025-50428](https://github.com/security-smarttecs/cve-2025-50428) :  ![starts](https://img.shields.io/github/stars/security-smarttecs/cve-2025-50428.svg) ![forks](https://img.shields.io/github/forks/security-smarttecs/cve-2025-50428.svg)


## CVE-2025-5036
 A maliciously crafted RFA file, when linked or imported into Autodesk Revit, can force a Use-After-Free vulnerability. A malicious actor can leverage this vulnerability to cause a crash, read sensitive data, or execute arbitrary code in the context of the current process.

- [https://github.com/Ch1keen/CVE-2025-50361](https://github.com/Ch1keen/CVE-2025-50361) :  ![starts](https://img.shields.io/github/stars/Ch1keen/CVE-2025-50361.svg) ![forks](https://img.shields.io/github/forks/Ch1keen/CVE-2025-50361.svg)
- [https://github.com/Ch1keen/CVE-2025-50360](https://github.com/Ch1keen/CVE-2025-50360) :  ![starts](https://img.shields.io/github/stars/Ch1keen/CVE-2025-50360.svg) ![forks](https://img.shields.io/github/forks/Ch1keen/CVE-2025-50360.svg)


## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/Kento-Sec/CVE-2024-34102](https://github.com/Kento-Sec/CVE-2024-34102) :  ![starts](https://img.shields.io/github/stars/Kento-Sec/CVE-2024-34102.svg) ![forks](https://img.shields.io/github/forks/Kento-Sec/CVE-2024-34102.svg)


## CVE-2024-26009
 An authentication bypass using an alternate path or channel [CWE-288] vulnerability in Fortinet FortiOS version 6.4.0 through 6.4.15	and before 6.2.16, FortiProxy version 7.4.0 through 7.4.2, 7.2.0 through 7.2.8 and before 7.0.15 & FortiPAM before version 1.2.0 allows an unauthenticated attacker to seize control of a managed device via crafted FGFM requests, if the device is managed by a FortiManager, and if the attacker knows that FortiManager's serial number.

- [https://github.com/allinsthon/CVE-2024-26009](https://github.com/allinsthon/CVE-2024-26009) :  ![starts](https://img.shields.io/github/stars/allinsthon/CVE-2024-26009.svg) ![forks](https://img.shields.io/github/forks/allinsthon/CVE-2024-26009.svg)


## CVE-2023-32434
 An integer overflow was addressed with improved input validation. This issue is fixed in watchOS 9.5.2, macOS Big Sur 11.7.8, iOS 15.7.7 and iPadOS 15.7.7, macOS Monterey 12.6.7, watchOS 8.8.1, iOS 16.5.1 and iPadOS 16.5.1, macOS Ventura 13.4.1. An app may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS released before iOS 15.7.

- [https://github.com/rkrakesh524/oob_entry](https://github.com/rkrakesh524/oob_entry) :  ![starts](https://img.shields.io/github/stars/rkrakesh524/oob_entry.svg) ![forks](https://img.shields.io/github/forks/rkrakesh524/oob_entry.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/ar2o3/FollinaXploit](https://github.com/ar2o3/FollinaXploit) :  ![starts](https://img.shields.io/github/stars/ar2o3/FollinaXploit.svg) ![forks](https://img.shields.io/github/forks/ar2o3/FollinaXploit.svg)
- [https://github.com/seinab-ibrahim/Follina-Vulnerability-CVE-2022-30190-Exploit-Analysis](https://github.com/seinab-ibrahim/Follina-Vulnerability-CVE-2022-30190-Exploit-Analysis) :  ![starts](https://img.shields.io/github/stars/seinab-ibrahim/Follina-Vulnerability-CVE-2022-30190-Exploit-Analysis.svg) ![forks](https://img.shields.io/github/forks/seinab-ibrahim/Follina-Vulnerability-CVE-2022-30190-Exploit-Analysis.svg)


## CVE-2022-26766
 A certificate parsing issue was addressed with improved checks. This issue is fixed in tvOS 15.5, iOS 15.5 and iPadOS 15.5, Security Update 2022-004 Catalina, watchOS 8.6, macOS Big Sur 11.6.6, macOS Monterey 12.4. A malicious app may be able to bypass signature validation.

- [https://github.com/zhuowei/CoreTrustDemo](https://github.com/zhuowei/CoreTrustDemo) :  ![starts](https://img.shields.io/github/stars/zhuowei/CoreTrustDemo.svg) ![forks](https://img.shields.io/github/forks/zhuowei/CoreTrustDemo.svg)


## CVE-2022-26133
 SharedSecretClusterAuthenticator in Atlassian Bitbucket Data Center versions 5.14.0 and later before 7.6.14, 7.7.0 and later prior to 7.17.6, 7.18.0 and later prior to 7.18.4, 7.19.0 and later prior to 7.19.4, and 7.20.0 allow a remote, unauthenticated attacker to execute arbitrary code via Java deserialization.

- [https://github.com/ar2o3/CVE-2022-26133](https://github.com/ar2o3/CVE-2022-26133) :  ![starts](https://img.shields.io/github/stars/ar2o3/CVE-2022-26133.svg) ![forks](https://img.shields.io/github/forks/ar2o3/CVE-2022-26133.svg)


## CVE-2022-24124
 The query API in Casdoor before 1.13.1 has a SQL injection vulnerability related to the field and value parameters, as demonstrated by api/get-organizations.

- [https://github.com/ar2o3/CVE-2022-24124](https://github.com/ar2o3/CVE-2022-24124) :  ![starts](https://img.shields.io/github/stars/ar2o3/CVE-2022-24124.svg) ![forks](https://img.shields.io/github/forks/ar2o3/CVE-2022-24124.svg)


## CVE-2022-3213
 A heap buffer overflow issue was found in ImageMagick. When an application processes a malformed TIFF file, it could lead to undefined behavior or a crash causing a denial of service.

- [https://github.com/reewardius/CVE-2022-32132](https://github.com/reewardius/CVE-2022-32132) :  ![starts](https://img.shields.io/github/stars/reewardius/CVE-2022-32132.svg) ![forks](https://img.shields.io/github/forks/reewardius/CVE-2022-32132.svg)


## CVE-2021-46067
 In Vehicle Service Management System 1.0 an attacker can steal the cookies leading to Full Account Takeover.

- [https://github.com/plsanu/CVE-2021-46067](https://github.com/plsanu/CVE-2021-46067) :  ![starts](https://img.shields.io/github/stars/plsanu/CVE-2021-46067.svg) ![forks](https://img.shields.io/github/forks/plsanu/CVE-2021-46067.svg)
- [https://github.com/plsanu/Vehicle-Service-Management-System-Multiple-Cookie-Stealing-Leads-to-Full-Account-Takeover](https://github.com/plsanu/Vehicle-Service-Management-System-Multiple-Cookie-Stealing-Leads-to-Full-Account-Takeover) :  ![starts](https://img.shields.io/github/stars/plsanu/Vehicle-Service-Management-System-Multiple-Cookie-Stealing-Leads-to-Full-Account-Takeover.svg) ![forks](https://img.shields.io/github/forks/plsanu/Vehicle-Service-Management-System-Multiple-Cookie-Stealing-Leads-to-Full-Account-Takeover.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)


## CVE-2021-34527
pNote that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as “PrintNightmare”, documented in CVE-2021-34527./p

- [https://github.com/ArtAtrium/PrintNightmare](https://github.com/ArtAtrium/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/ArtAtrium/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/ArtAtrium/PrintNightmare.svg)


## CVE-2021-25076
 The WP User Frontend WordPress plugin before 3.5.26 does not validate and escape the status parameter before using it in a SQL statement in the Subscribers dashboard, leading to an SQL injection. Due to the lack of sanitisation and escaping, this could also lead to Reflected Cross-Site Scripting

- [https://github.com/ar2o3/CVE-2021-25076](https://github.com/ar2o3/CVE-2021-25076) :  ![starts](https://img.shields.io/github/stars/ar2o3/CVE-2021-25076.svg) ![forks](https://img.shields.io/github/forks/ar2o3/CVE-2021-25076.svg)


## CVE-2021-23369
 The package handlebars before 4.7.7 are vulnerable to Remote Code Execution (RCE) when selecting certain compiling options to compile templates coming from an untrusted source.

- [https://github.com/fazilbaig1/CVE-2021-23369](https://github.com/fazilbaig1/CVE-2021-23369) :  ![starts](https://img.shields.io/github/stars/fazilbaig1/CVE-2021-23369.svg) ![forks](https://img.shields.io/github/forks/fazilbaig1/CVE-2021-23369.svg)


## CVE-2021-2064
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). The supported version that is affected is 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/ArtAtrium/PrintNightmare](https://github.com/ArtAtrium/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/ArtAtrium/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/ArtAtrium/PrintNightmare.svg)


## CVE-2020-29607
 A file upload restriction bypass vulnerability in Pluck CMS before 4.7.13 allows an admin privileged user to gain access in the host through the "manage files" functionality, which may result in remote code execution.

- [https://github.com/ar2o3/CVE-2020-29607](https://github.com/ar2o3/CVE-2020-29607) :  ![starts](https://img.shields.io/github/stars/ar2o3/CVE-2020-29607.svg) ![forks](https://img.shields.io/github/forks/ar2o3/CVE-2020-29607.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/ar2o3/CVE-Exploit](https://github.com/ar2o3/CVE-Exploit) :  ![starts](https://img.shields.io/github/stars/ar2o3/CVE-Exploit.svg) ![forks](https://img.shields.io/github/forks/ar2o3/CVE-Exploit.svg)


## CVE-2018-0114
 A vulnerability in the Cisco node-jose open source library before 0.11.0 could allow an unauthenticated, remote attacker to re-sign tokens using a key that is embedded within the token. The vulnerability is due to node-jose following the JSON Web Signature (JWS) standard for JSON Web Tokens (JWTs). This standard specifies that a JSON Web Key (JWK) representing a public key can be embedded within the header of a JWS. This public key is then trusted for verification. An attacker could exploit this by forging valid JWS objects by removing the original signature, adding a new public key to the header, and then signing the object using the (attacker-owned) private key associated with the public key embedded in that JWS header.

- [https://github.com/n0m-d/CVE-2018-0114-Go](https://github.com/n0m-d/CVE-2018-0114-Go) :  ![starts](https://img.shields.io/github/stars/n0m-d/CVE-2018-0114-Go.svg) ![forks](https://img.shields.io/github/forks/n0m-d/CVE-2018-0114-Go.svg)


## CVE-2017-1002101
 In Kubernetes versions 1.3.x, 1.4.x, 1.5.x, 1.6.x and prior to versions 1.7.14, 1.8.9 and 1.9.4 containers using subpath volume mounts with any volume type (including non-privileged pods, subject to file permissions) can access files/directories outside of the volume, including the host's filesystem.

- [https://github.com/bgeesaman/subpath-exploit](https://github.com/bgeesaman/subpath-exploit) :  ![starts](https://img.shields.io/github/stars/bgeesaman/subpath-exploit.svg) ![forks](https://img.shields.io/github/forks/bgeesaman/subpath-exploit.svg)


## CVE-2017-1001004
 typed-function before 0.10.6 had an arbitrary code execution in the JavaScript engine. Creating a typed function with JavaScript code in the name could result arbitrary execution.

- [https://github.com/ossf-cve-benchmark/CVE-2017-1001004](https://github.com/ossf-cve-benchmark/CVE-2017-1001004) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1001004.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1001004.svg)


## CVE-2017-1000486
 Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution

- [https://github.com/pimps/CVE-2017-1000486](https://github.com/pimps/CVE-2017-1000486) :  ![starts](https://img.shields.io/github/stars/pimps/CVE-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/pimps/CVE-2017-1000486.svg)
- [https://github.com/000pp/pwnfaces](https://github.com/000pp/pwnfaces) :  ![starts](https://img.shields.io/github/stars/000pp/pwnfaces.svg) ![forks](https://img.shields.io/github/forks/000pp/pwnfaces.svg)
- [https://github.com/mogwailabs/CVE-2017-1000486](https://github.com/mogwailabs/CVE-2017-1000486) :  ![starts](https://img.shields.io/github/stars/mogwailabs/CVE-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/mogwailabs/CVE-2017-1000486.svg)
- [https://github.com/Pastea/CVE-2017-1000486](https://github.com/Pastea/CVE-2017-1000486) :  ![starts](https://img.shields.io/github/stars/Pastea/CVE-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/Pastea/CVE-2017-1000486.svg)
- [https://github.com/cved-sources/cve-2017-1000486](https://github.com/cved-sources/cve-2017-1000486) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-1000486.svg)
- [https://github.com/jam620/primefaces](https://github.com/jam620/primefaces) :  ![starts](https://img.shields.io/github/stars/jam620/primefaces.svg) ![forks](https://img.shields.io/github/forks/jam620/primefaces.svg)
- [https://github.com/LongWayHomie/CVE-2017-1000486](https://github.com/LongWayHomie/CVE-2017-1000486) :  ![starts](https://img.shields.io/github/stars/LongWayHomie/CVE-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/LongWayHomie/CVE-2017-1000486.svg)


## CVE-2017-1000475
 FreeSSHd 1.3.1 version is vulnerable to an Unquoted Path Service allowing local users to launch processes with elevated privileges.

- [https://github.com/lajarajorge/CVE-2017-1000475](https://github.com/lajarajorge/CVE-2017-1000475) :  ![starts](https://img.shields.io/github/stars/lajarajorge/CVE-2017-1000475.svg) ![forks](https://img.shields.io/github/forks/lajarajorge/CVE-2017-1000475.svg)


## CVE-2017-1000405
 The Linux Kernel versions 2.6.38 through 4.14 have a problematic use of pmd_mkdirty() in the touch_pmd() function inside the THP implementation. touch_pmd() can be reached by get_user_pages(). In such case, the pmd will become dirty. This scenario breaks the new can_follow_write_pmd()'s logic - pmd can become dirty without going through a COW cycle. This bug is not as severe as the original "Dirty cow" because an ext4 file (or any other regular file) cannot be mapped using THP. Nevertheless, it does allow us to overwrite read-only huge pages. For example, the zero huge page and sealed shmem files can be overwritten (since their mapping can be populated using THP). Note that after the first write page-fault to the zero page, it will be replaced with a new fresh (and zeroed) thp.

- [https://github.com/bindecy/HugeDirtyCowPOC](https://github.com/bindecy/HugeDirtyCowPOC) :  ![starts](https://img.shields.io/github/stars/bindecy/HugeDirtyCowPOC.svg) ![forks](https://img.shields.io/github/forks/bindecy/HugeDirtyCowPOC.svg)


## CVE-2017-1000371
 The offset2lib patch as used by the Linux Kernel contains a vulnerability, if RLIMIT_STACK is set to RLIM_INFINITY and 1 Gigabyte of memory is allocated (the maximum under the 1/4 restriction) then the stack will be grown down to 0x80000000, and as the PIE binary is mapped above 0x80000000 the minimum distance between the end of the PIE binary's read-write segment and the start of the stack becomes small enough that the stack guard page can be jumped over by an attacker. This affects Linux Kernel version 4.11.5. This is a different issue than CVE-2017-1000370 and CVE-2017-1000365. This issue appears to be limited to i386 based systems.

- [https://github.com/Trinadh465/linux-4.1.15_CVE-2017-1000371](https://github.com/Trinadh465/linux-4.1.15_CVE-2017-1000371) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.1.15_CVE-2017-1000371.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.1.15_CVE-2017-1000371.svg)


## CVE-2017-1000367
 Todd Miller's sudo version 1.8.20 and earlier is vulnerable to an input validation (embedded spaces) in the get_process_ttyname() function resulting in information disclosure and command execution.

- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)
- [https://github.com/c0d3z3r0/sudo-CVE-2017-1000367](https://github.com/c0d3z3r0/sudo-CVE-2017-1000367) :  ![starts](https://img.shields.io/github/stars/c0d3z3r0/sudo-CVE-2017-1000367.svg) ![forks](https://img.shields.io/github/forks/c0d3z3r0/sudo-CVE-2017-1000367.svg)
- [https://github.com/pucerpocok/sudo_exploit](https://github.com/pucerpocok/sudo_exploit) :  ![starts](https://img.shields.io/github/stars/pucerpocok/sudo_exploit.svg) ![forks](https://img.shields.io/github/forks/pucerpocok/sudo_exploit.svg)
- [https://github.com/homjxi0e/CVE-2017-1000367](https://github.com/homjxi0e/CVE-2017-1000367) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-1000367.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-1000367.svg)


## CVE-2017-1000251
 The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.

- [https://github.com/hayzamjs/Blueborne-CVE-2017-1000251](https://github.com/hayzamjs/Blueborne-CVE-2017-1000251) :  ![starts](https://img.shields.io/github/stars/hayzamjs/Blueborne-CVE-2017-1000251.svg) ![forks](https://img.shields.io/github/forks/hayzamjs/Blueborne-CVE-2017-1000251.svg)
- [https://github.com/CrackSoft900/Blue-Borne](https://github.com/CrackSoft900/Blue-Borne) :  ![starts](https://img.shields.io/github/stars/CrackSoft900/Blue-Borne.svg) ![forks](https://img.shields.io/github/forks/CrackSoft900/Blue-Borne.svg)
- [https://github.com/sgxgsx/blueborne-CVE-2017-1000251](https://github.com/sgxgsx/blueborne-CVE-2017-1000251) :  ![starts](https://img.shields.io/github/stars/sgxgsx/blueborne-CVE-2017-1000251.svg) ![forks](https://img.shields.io/github/forks/sgxgsx/blueborne-CVE-2017-1000251.svg)
- [https://github.com/own2pwn/blueborne-CVE-2017-1000251-POC](https://github.com/own2pwn/blueborne-CVE-2017-1000251-POC) :  ![starts](https://img.shields.io/github/stars/own2pwn/blueborne-CVE-2017-1000251-POC.svg) ![forks](https://img.shields.io/github/forks/own2pwn/blueborne-CVE-2017-1000251-POC.svg)
- [https://github.com/istanescu/CVE-2017-1000251_Exploit](https://github.com/istanescu/CVE-2017-1000251_Exploit) :  ![starts](https://img.shields.io/github/stars/istanescu/CVE-2017-1000251_Exploit.svg) ![forks](https://img.shields.io/github/forks/istanescu/CVE-2017-1000251_Exploit.svg)
- [https://github.com/tlatkdgus1/blueborne-CVE-2017-1000251](https://github.com/tlatkdgus1/blueborne-CVE-2017-1000251) :  ![starts](https://img.shields.io/github/stars/tlatkdgus1/blueborne-CVE-2017-1000251.svg) ![forks](https://img.shields.io/github/forks/tlatkdgus1/blueborne-CVE-2017-1000251.svg)


## CVE-2017-1000250
 All versions of the SDP server in BlueZ 5.46 and earlier are vulnerable to an information disclosure vulnerability which allows remote attackers to obtain sensitive information from the bluetoothd process memory. This vulnerability lies in the processing of SDP search attribute requests.

- [https://github.com/AxelRoudaut/THC_BlueBorne](https://github.com/AxelRoudaut/THC_BlueBorne) :  ![starts](https://img.shields.io/github/stars/AxelRoudaut/THC_BlueBorne.svg) ![forks](https://img.shields.io/github/forks/AxelRoudaut/THC_BlueBorne.svg)
- [https://github.com/olav-st/CVE-2017-1000250-PoC](https://github.com/olav-st/CVE-2017-1000250-PoC) :  ![starts](https://img.shields.io/github/stars/olav-st/CVE-2017-1000250-PoC.svg) ![forks](https://img.shields.io/github/forks/olav-st/CVE-2017-1000250-PoC.svg)


## CVE-2017-1000219
 npm/KyleRoss windows-cpu all versions vulnerable to command injection resulting in code execution as Node.js user

- [https://github.com/ossf-cve-benchmark/CVE-2017-1000219](https://github.com/ossf-cve-benchmark/CVE-2017-1000219) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1000219.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1000219.svg)


## CVE-2017-1000170
 jqueryFileTree 2.1.5 and older Directory Traversal

- [https://github.com/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal](https://github.com/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal) :  ![starts](https://img.shields.io/github/stars/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal.svg) ![forks](https://img.shields.io/github/forks/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal.svg)


## CVE-2017-1000117
 A malicious third-party can give a crafted "ssh://..." URL to an unsuspecting victim, and an attempt to visit the URL can result in any program that exists on the victim's machine being executed. Such a URL could be placed in the .gitmodules file of a malicious project, and an unsuspecting victim could be tricked into running "git clone --recurse-submodules" to trigger the vulnerability.

- [https://github.com/greymd/CVE-2017-1000117](https://github.com/greymd/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/greymd/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/greymd/CVE-2017-1000117.svg)
- [https://github.com/Manouchehri/CVE-2017-1000117](https://github.com/Manouchehri/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/Manouchehri/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/Manouchehri/CVE-2017-1000117.svg)
- [https://github.com/timwr/CVE-2017-1000117](https://github.com/timwr/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/timwr/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/timwr/CVE-2017-1000117.svg)
- [https://github.com/ieee0824/CVE-2017-1000117](https://github.com/ieee0824/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/ieee0824/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/ieee0824/CVE-2017-1000117.svg)
- [https://github.com/VulApps/CVE-2017-1000117](https://github.com/VulApps/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/VulApps/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/VulApps/CVE-2017-1000117.svg)
- [https://github.com/AnonymKing/CVE-2017-1000117](https://github.com/AnonymKing/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/AnonymKing/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/AnonymKing/CVE-2017-1000117.svg)
- [https://github.com/nkoneko/CVE-2017-1000117](https://github.com/nkoneko/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/nkoneko/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/nkoneko/CVE-2017-1000117.svg)
- [https://github.com/leezp/CVE-2017-1000117](https://github.com/leezp/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/leezp/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/leezp/CVE-2017-1000117.svg)
- [https://github.com/sasairc/CVE-2017-1000117_wasawasa](https://github.com/sasairc/CVE-2017-1000117_wasawasa) :  ![starts](https://img.shields.io/github/stars/sasairc/CVE-2017-1000117_wasawasa.svg) ![forks](https://img.shields.io/github/forks/sasairc/CVE-2017-1000117_wasawasa.svg)
- [https://github.com/rootclay/CVE-2017-1000117](https://github.com/rootclay/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/rootclay/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/rootclay/CVE-2017-1000117.svg)
- [https://github.com/cved-sources/cve-2017-1000117](https://github.com/cved-sources/cve-2017-1000117) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-1000117.svg)
- [https://github.com/chenzhuo0618/test](https://github.com/chenzhuo0618/test) :  ![starts](https://img.shields.io/github/stars/chenzhuo0618/test.svg) ![forks](https://img.shields.io/github/forks/chenzhuo0618/test.svg)
- [https://github.com/ieee0824/CVE-2017-1000117-sl](https://github.com/ieee0824/CVE-2017-1000117-sl) :  ![starts](https://img.shields.io/github/stars/ieee0824/CVE-2017-1000117-sl.svg) ![forks](https://img.shields.io/github/forks/ieee0824/CVE-2017-1000117-sl.svg)
- [https://github.com/alilangtest/CVE-2017-1000117](https://github.com/alilangtest/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/alilangtest/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/alilangtest/CVE-2017-1000117.svg)
- [https://github.com/takehaya/CVE-2017-1000117](https://github.com/takehaya/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/takehaya/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/takehaya/CVE-2017-1000117.svg)
- [https://github.com/Q2h1Cg/CVE-2017-1000117](https://github.com/Q2h1Cg/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/Q2h1Cg/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/Q2h1Cg/CVE-2017-1000117.svg)
- [https://github.com/Jerry-zhuang/CVE-2017-1000117](https://github.com/Jerry-zhuang/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/Jerry-zhuang/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/Jerry-zhuang/CVE-2017-1000117.svg)
- [https://github.com/Shadow5523/CVE-2017-1000117-test](https://github.com/Shadow5523/CVE-2017-1000117-test) :  ![starts](https://img.shields.io/github/stars/Shadow5523/CVE-2017-1000117-test.svg) ![forks](https://img.shields.io/github/forks/Shadow5523/CVE-2017-1000117-test.svg)
- [https://github.com/thelastbyte/CVE-2017-1000117](https://github.com/thelastbyte/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/thelastbyte/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/thelastbyte/CVE-2017-1000117.svg)
- [https://github.com/siling2017/CVE-2017-1000117](https://github.com/siling2017/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/siling2017/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/siling2017/CVE-2017-1000117.svg)
- [https://github.com/ikmski/CVE-2017-1000117](https://github.com/ikmski/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/ikmski/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/ikmski/CVE-2017-1000117.svg)
- [https://github.com/shogo82148/Fix-CVE-2017-1000117](https://github.com/shogo82148/Fix-CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/shogo82148/Fix-CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/shogo82148/Fix-CVE-2017-1000117.svg)


## CVE-2017-1000112
 Linux kernel: Exploitable memory corruption due to UFO to non-UFO path switch. When building a UFO packet with MSG_MORE __ip_append_data() calls ip_ufo_append_data() to append. However in between two send() calls, the append path can be switched from UFO to non-UFO one, which leads to a memory corruption. In case UFO packet lengths exceeds MTU, copy = maxfraglen - skb-len becomes negative on the non-UFO path and the branch to allocate new skb is taken. This triggers fragmentation and computation of fraggap = skb_prev-len - maxfraglen. Fraggap can exceed MTU, causing copy = datalen - transhdrlen - fraggap to become negative. Subsequently skb_copy_and_csum_bits() writes out-of-bounds. A similar issue is present in IPv6 code. The bug was introduced in e89e9cf539a2 ("[IPv4/IPv6]: UFO Scatter-gather approach") on Oct 18 2005.

- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)
- [https://github.com/ol0273st-s/CVE-2017-1000112-Adpated](https://github.com/ol0273st-s/CVE-2017-1000112-Adpated) :  ![starts](https://img.shields.io/github/stars/ol0273st-s/CVE-2017-1000112-Adpated.svg) ![forks](https://img.shields.io/github/forks/ol0273st-s/CVE-2017-1000112-Adpated.svg)
- [https://github.com/IT19083124/SNP-Assignment](https://github.com/IT19083124/SNP-Assignment) :  ![starts](https://img.shields.io/github/stars/IT19083124/SNP-Assignment.svg) ![forks](https://img.shields.io/github/forks/IT19083124/SNP-Assignment.svg)
- [https://github.com/hikame/docker_escape_pwn](https://github.com/hikame/docker_escape_pwn) :  ![starts](https://img.shields.io/github/stars/hikame/docker_escape_pwn.svg) ![forks](https://img.shields.io/github/forks/hikame/docker_escape_pwn.svg)


## CVE-2017-1000083
 backend/comics/comics-document.c (aka the comic book backend) in GNOME Evince before 3.24.1 allows remote attackers to execute arbitrary commands via a .cbt file that is a TAR archive containing a filename beginning with a "--" command-line option substring, as demonstrated by a --checkpoint-action=exec=bash at the beginning of the filename.

- [https://github.com/matlink/evince-cve-2017-1000083](https://github.com/matlink/evince-cve-2017-1000083) :  ![starts](https://img.shields.io/github/stars/matlink/evince-cve-2017-1000083.svg) ![forks](https://img.shields.io/github/forks/matlink/evince-cve-2017-1000083.svg)
- [https://github.com/matlink/cve-2017-1000083-atril-nautilus](https://github.com/matlink/cve-2017-1000083-atril-nautilus) :  ![starts](https://img.shields.io/github/stars/matlink/cve-2017-1000083-atril-nautilus.svg) ![forks](https://img.shields.io/github/forks/matlink/cve-2017-1000083-atril-nautilus.svg)


## CVE-2017-1000000
 DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: none.  Reason: This candidate was withdrawn by its CNA.  This issue lacks details and  cannot be determined if it is a security issue or not.  Notes: none

- [https://github.com/smythtech/DWF-CVE-2017-1000000](https://github.com/smythtech/DWF-CVE-2017-1000000) :  ![starts](https://img.shields.io/github/stars/smythtech/DWF-CVE-2017-1000000.svg) ![forks](https://img.shields.io/github/forks/smythtech/DWF-CVE-2017-1000000.svg)


## CVE-2017-20165
 A vulnerability classified as problematic has been found in debug-js debug up to 3.0.x. This affects the function useColors of the file src/node.js. The manipulation of the argument str leads to inefficient regular expression complexity. Upgrading to version 3.1.0 is able to address this issue. The identifier of the patch is c38a0166c266a679c8de012d4eaccec3f944e685. It is recommended to upgrade the affected component. The identifier VDB-217665 was assigned to this vulnerability.

- [https://github.com/fastify/send](https://github.com/fastify/send) :  ![starts](https://img.shields.io/github/stars/fastify/send.svg) ![forks](https://img.shields.io/github/forks/fastify/send.svg)


## CVE-2017-18486
 Jitbit Helpdesk before 9.0.3 allows remote attackers to escalate privileges because of mishandling of the User/AutoLogin userHash parameter. By inspecting the token value provided in a password reset link, a user can leverage a weak PRNG to recover the shared secret used by the server for remote authentication. The shared secret can be used to escalate privileges by forging new tokens for any user. These tokens can be used to automatically log in as the affected user.

- [https://github.com/Kc57/JitBit_Helpdesk_Auth_Bypass](https://github.com/Kc57/JitBit_Helpdesk_Auth_Bypass) :  ![starts](https://img.shields.io/github/stars/Kc57/JitBit_Helpdesk_Auth_Bypass.svg) ![forks](https://img.shields.io/github/forks/Kc57/JitBit_Helpdesk_Auth_Bypass.svg)


## CVE-2017-18362
 ConnectWise ManagedITSync integration through 2017 for Kaseya VSA is vulnerable to unauthenticated remote commands that allow full direct access to the Kaseya VSA database. In February 2019, attackers have actively exploited this in the wild to download and execute ransomware payloads on all endpoints managed by the VSA server. If the ManagedIT.asmx page is available via the Kaseya VSA web interface, anyone with access to the page is able to run arbitrary SQL queries, both read and write, without authentication.

- [https://github.com/yawningmoney/CVE-2017-18362-LAB](https://github.com/yawningmoney/CVE-2017-18362-LAB) :  ![starts](https://img.shields.io/github/stars/yawningmoney/CVE-2017-18362-LAB.svg) ![forks](https://img.shields.io/github/forks/yawningmoney/CVE-2017-18362-LAB.svg)


## CVE-2017-18355
 Installed packages are exposed by node_modules in Rendertron 1.0.0, allowing remote attackers to read absolute paths on the server by examining the "_where" attribute of package.json files.

- [https://github.com/ossf-cve-benchmark/CVE-2017-18355](https://github.com/ossf-cve-benchmark/CVE-2017-18355) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18355.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18355.svg)


## CVE-2017-18354
 Rendertron 1.0.0 allows for alternative protocols such as 'file://' introducing a Local File Inclusion (LFI) bug where arbitrary files can be read by a remote attacker.

- [https://github.com/ossf-cve-benchmark/CVE-2017-18354](https://github.com/ossf-cve-benchmark/CVE-2017-18354) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18354.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18354.svg)


## CVE-2017-18353
 Rendertron 1.0.0 includes an _ah/stop route to shutdown the Chrome instance responsible for serving render requests to all users. Visiting this route with a GET request allows any unauthorized remote attacker to disable the core service of the application.

- [https://github.com/ossf-cve-benchmark/CVE-2017-18353](https://github.com/ossf-cve-benchmark/CVE-2017-18353) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18353.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18353.svg)


## CVE-2017-18352
 Error reporting within Rendertron 1.0.0 allows reflected Cross Site Scripting (XSS) from invalid URLs.

- [https://github.com/ossf-cve-benchmark/CVE-2017-18352](https://github.com/ossf-cve-benchmark/CVE-2017-18352) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18352.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18352.svg)


## CVE-2017-18349
 parseObject in Fastjson before 1.2.25, as used in FastjsonEngine in Pippo 1.11.0 and other products, allows remote attackers to execute arbitrary code via a crafted JSON request, as demonstrated by a crafted rmi:// URI in the dataSourceName field of HTTP POST data to the Pippo /json URI, which is mishandled in AjaxApplication.java.

- [https://github.com/h0cksr/Fastjson--CVE-2017-18349-](https://github.com/h0cksr/Fastjson--CVE-2017-18349-) :  ![starts](https://img.shields.io/github/stars/h0cksr/Fastjson--CVE-2017-18349-.svg) ![forks](https://img.shields.io/github/forks/h0cksr/Fastjson--CVE-2017-18349-.svg)


## CVE-2017-18345
 The Joomanager component through 2.0.0 for Joomla! has an arbitrary file download issue, resulting in exposing the credentials of the database via an index.php?option=com_joomanager&controller=details&task=download&path=configuration.php request.

- [https://github.com/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD](https://github.com/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD) :  ![starts](https://img.shields.io/github/stars/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD.svg) ![forks](https://img.shields.io/github/forks/Luth1er/CVE-2017-18345-COM_JOOMANAGER-ARBITRARY-FILE-DOWNLOAD.svg)


## CVE-2017-18344
 The timer_create syscall implementation in kernel/time/posix-timers.c in the Linux kernel before 4.14.8 doesn't properly validate the sigevent-sigev_notify field, which leads to out-of-bounds access in the show_timer function (called when /proc/$PID/timers is read). This allows userspace applications to read arbitrary kernel memory (on a kernel built with CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE).

- [https://github.com/echo-devim/exploit_linux_kernel4.13](https://github.com/echo-devim/exploit_linux_kernel4.13) :  ![starts](https://img.shields.io/github/stars/echo-devim/exploit_linux_kernel4.13.svg) ![forks](https://img.shields.io/github/forks/echo-devim/exploit_linux_kernel4.13.svg)
- [https://github.com/hikame/docker_escape_pwn](https://github.com/hikame/docker_escape_pwn) :  ![starts](https://img.shields.io/github/stars/hikame/docker_escape_pwn.svg) ![forks](https://img.shields.io/github/forks/hikame/docker_escape_pwn.svg)


## CVE-2017-18077
 index.js in brace-expansion before 1.1.7 is vulnerable to Regular Expression Denial of Service (ReDoS) attacks, as demonstrated by an expand argument containing many comma characters.

- [https://github.com/ossf-cve-benchmark/CVE-2017-18077](https://github.com/ossf-cve-benchmark/CVE-2017-18077) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-18077.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-18077.svg)


## CVE-2017-18047
 Buffer Overflow in the FTP client in LabF nfsAxe 3.7 allows remote FTP servers to execute arbitrary code via a long reply.

- [https://github.com/wetw0rk/Exploit-Development](https://github.com/wetw0rk/Exploit-Development) :  ![starts](https://img.shields.io/github/stars/wetw0rk/Exploit-Development.svg) ![forks](https://img.shields.io/github/forks/wetw0rk/Exploit-Development.svg)


## CVE-2017-18044
 A Command Injection issue was discovered in ContentStore/Base/CVDataPipe.dll in Commvault before v11 SP6. A certain message parsing function inside the Commvault service does not properly validate the input of an incoming string before passing it to CreateProcess. As a result, a specially crafted message can inject commands that will be executed on the target operating system. Exploitation of this vulnerability does not require authentication and can lead to SYSTEM level privilege on any system running the cvd daemon. This is a different vulnerability than CVE-2017-3195.

- [https://github.com/securifera/CVE-2017-18044-Exploit](https://github.com/securifera/CVE-2017-18044-Exploit) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2017-18044-Exploit.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2017-18044-Exploit.svg)


## CVE-2017-18019
 In K7 Total Security before 15.1.0.305, user-controlled input to the K7Sentry device is not sufficiently sanitized: the user-controlled input can be used to compare an arbitrary memory address with a fixed value, which in turn can be used to read the contents of arbitrary memory. Similarly, the product crashes upon a \\.\K7Sentry DeviceIoControl call with an invalid kernel pointer.

- [https://github.com/SpiralBL0CK/CVE-2017-18019](https://github.com/SpiralBL0CK/CVE-2017-18019) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2017-18019.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2017-18019.svg)


## CVE-2017-17917
 SQL injection vulnerability in the 'where' method in Ruby on Rails 5.1.4 and earlier allows remote attackers to execute arbitrary SQL commands via the 'id' parameter. NOTE: The vendor disputes this issue because the documentation states that this method is not intended for use with untrusted input

- [https://github.com/matiasarenhard/rails-cve-2017-17917](https://github.com/matiasarenhard/rails-cve-2017-17917) :  ![starts](https://img.shields.io/github/stars/matiasarenhard/rails-cve-2017-17917.svg) ![forks](https://img.shields.io/github/forks/matiasarenhard/rails-cve-2017-17917.svg)


## CVE-2017-17761
 An issue was discovered on Ichano AtHome IP Camera devices. The device runs the "noodles" binary - a service on port 1300 that allows a remote (LAN) unauthenticated user to run arbitrary commands. This binary requires the "system" XML element for specifying the command. For example, a systemid/system command results in a system_ackok/system_ack response.

- [https://github.com/mirellesilvajs/iot-vuln-lab-cve-2017-17761](https://github.com/mirellesilvajs/iot-vuln-lab-cve-2017-17761) :  ![starts](https://img.shields.io/github/stars/mirellesilvajs/iot-vuln-lab-cve-2017-17761.svg) ![forks](https://img.shields.io/github/forks/mirellesilvajs/iot-vuln-lab-cve-2017-17761.svg)


## CVE-2017-17736
 Kentico 9.0 before 9.0.51 and 10.0 before 10.0.48 allows remote attackers to obtain Global Administrator access by visiting CMSInstall/install.aspx and then navigating to the CMS Administration Dashboard.

- [https://github.com/0xSojalSec/Nuclei-TemplatesNuclei-Templates-CVE-2017-17736](https://github.com/0xSojalSec/Nuclei-TemplatesNuclei-Templates-CVE-2017-17736) :  ![starts](https://img.shields.io/github/stars/0xSojalSec/Nuclei-TemplatesNuclei-Templates-CVE-2017-17736.svg) ![forks](https://img.shields.io/github/forks/0xSojalSec/Nuclei-TemplatesNuclei-Templates-CVE-2017-17736.svg)


## CVE-2017-17692
 Samsung Internet Browser 5.4.02.3 allows remote attackers to bypass the Same Origin Policy and obtain sensitive information via crafted JavaScript code that redirects to a child tab and rewrites the innerHTML property.

- [https://github.com/specloli/CVE-2017-17692](https://github.com/specloli/CVE-2017-17692) :  ![starts](https://img.shields.io/github/stars/specloli/CVE-2017-17692.svg) ![forks](https://img.shields.io/github/forks/specloli/CVE-2017-17692.svg)


## CVE-2017-17485
 FasterXML jackson-databind through 2.8.10 and 2.9.x through 2.9.3 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the Spring libraries are available in the classpath.

- [https://github.com/Al1ex/CVE-2017-17485](https://github.com/Al1ex/CVE-2017-17485) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-17485.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-17485.svg)
- [https://github.com/x7iaob/cve-2017-17485](https://github.com/x7iaob/cve-2017-17485) :  ![starts](https://img.shields.io/github/stars/x7iaob/cve-2017-17485.svg) ![forks](https://img.shields.io/github/forks/x7iaob/cve-2017-17485.svg)
- [https://github.com/tafamace/CVE-2017-17485](https://github.com/tafamace/CVE-2017-17485) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2017-17485.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2017-17485.svg)


## CVE-2017-17461
 DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: none.  Reason: This candidate was withdrawn by its CNA.  Further investigation showed that it was not a security issue.  Notes: none

- [https://github.com/ossf-cve-benchmark/CVE-2017-17461](https://github.com/ossf-cve-benchmark/CVE-2017-17461) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-17461.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-17461.svg)


## CVE-2017-17309
 Huawei HG255s-10 V100R001C163B025SP02 has a path traversal vulnerability due to insufficient validation of the received HTTP requests, a remote attacker may access the local files on the device without authentication.

- [https://github.com/exploit-labs/huawei_hg255s_exploit](https://github.com/exploit-labs/huawei_hg255s_exploit) :  ![starts](https://img.shields.io/github/stars/exploit-labs/huawei_hg255s_exploit.svg) ![forks](https://img.shields.io/github/forks/exploit-labs/huawei_hg255s_exploit.svg)


## CVE-2017-17275
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who requested this candidate did not associate it with any vulnerability during 2017. Notes: none

- [https://github.com/kd992102/CVE-2017-17275](https://github.com/kd992102/CVE-2017-17275) :  ![starts](https://img.shields.io/github/stars/kd992102/CVE-2017-17275.svg) ![forks](https://img.shields.io/github/forks/kd992102/CVE-2017-17275.svg)


## CVE-2017-17215
 Huawei HG532 with some customized versions has a remote code execution vulnerability. An authenticated attacker could send malicious packets to port 37215 to launch attacks. Successful exploit could lead to the remote execution of arbitrary code.

- [https://github.com/1337g/CVE-2017-17215](https://github.com/1337g/CVE-2017-17215) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-17215.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-17215.svg)
- [https://github.com/wilfred-wulbou/HG532d-RCE-Exploit](https://github.com/wilfred-wulbou/HG532d-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/wilfred-wulbou/HG532d-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/wilfred-wulbou/HG532d-RCE-Exploit.svg)
- [https://github.com/ltfafei/HuaWei_Route_HG532_RCE_CVE-2017-17215](https://github.com/ltfafei/HuaWei_Route_HG532_RCE_CVE-2017-17215) :  ![starts](https://img.shields.io/github/stars/ltfafei/HuaWei_Route_HG532_RCE_CVE-2017-17215.svg) ![forks](https://img.shields.io/github/forks/ltfafei/HuaWei_Route_HG532_RCE_CVE-2017-17215.svg)
- [https://github.com/kd992102/CVE-2017-17275](https://github.com/kd992102/CVE-2017-17275) :  ![starts](https://img.shields.io/github/stars/kd992102/CVE-2017-17275.svg) ![forks](https://img.shields.io/github/forks/kd992102/CVE-2017-17275.svg)


## CVE-2017-17058
 The WooCommerce plugin through 3.x for WordPress has a Directory Traversal Vulnerability via a /wp-content/plugins/woocommerce/templates/emails/plain/ URI, which accesses a parent directory. NOTE: a software maintainer indicates that Directory Traversal is not possible because all of the template files have "if (!defined('ABSPATH')) {exit;}" code

- [https://github.com/fu2x2000/CVE-2017-17058-woo_exploit](https://github.com/fu2x2000/CVE-2017-17058-woo_exploit) :  ![starts](https://img.shields.io/github/stars/fu2x2000/CVE-2017-17058-woo_exploit.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/CVE-2017-17058-woo_exploit.svg)


## CVE-2017-16997
 elf/dl-load.c in the GNU C Library (aka glibc or libc6) 2.19 through 2.26 mishandles RPATH and RUNPATH containing $ORIGIN for a privileged (setuid or AT_SECURE) program, which allows local users to gain privileges via a Trojan horse library in the current working directory, related to the fillin_rpath and decompose_rpath functions. This is associated with misinterpretion of an empty RPATH/RUNPATH token as the "./" directory. NOTE: this configuration of RPATH/RUNPATH for a privileged program is apparently very uncommon; most likely, no such program is shipped with any common Linux distribution.

- [https://github.com/Xiami2012/CVE-2017-16997-poc](https://github.com/Xiami2012/CVE-2017-16997-poc) :  ![starts](https://img.shields.io/github/stars/Xiami2012/CVE-2017-16997-poc.svg) ![forks](https://img.shields.io/github/forks/Xiami2012/CVE-2017-16997-poc.svg)


## CVE-2017-16995
 The check_alu_op function in kernel/bpf/verifier.c in the Linux kernel through 4.4 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging incorrect sign extension.

- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)
- [https://github.com/Al1ex/CVE-2017-16995](https://github.com/Al1ex/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-16995.svg)
- [https://github.com/dangokyo/CVE_2017_16995](https://github.com/dangokyo/CVE_2017_16995) :  ![starts](https://img.shields.io/github/stars/dangokyo/CVE_2017_16995.svg) ![forks](https://img.shields.io/github/forks/dangokyo/CVE_2017_16995.svg)
- [https://github.com/ph4ntonn/CVE-2017-16995](https://github.com/ph4ntonn/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/ph4ntonn/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/ph4ntonn/CVE-2017-16995.svg)
- [https://github.com/gugronnier/CVE-2017-16995](https://github.com/gugronnier/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/gugronnier/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/gugronnier/CVE-2017-16995.svg)
- [https://github.com/senyuuri/cve-2017-16995](https://github.com/senyuuri/cve-2017-16995) :  ![starts](https://img.shields.io/github/stars/senyuuri/cve-2017-16995.svg) ![forks](https://img.shields.io/github/forks/senyuuri/cve-2017-16995.svg)
- [https://github.com/littlebin404/CVE-2017-16995](https://github.com/littlebin404/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/littlebin404/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/littlebin404/CVE-2017-16995.svg)
- [https://github.com/vnik5287/CVE-2017-16995](https://github.com/vnik5287/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/vnik5287/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/vnik5287/CVE-2017-16995.svg)
- [https://github.com/C0dak/CVE-2017-16995](https://github.com/C0dak/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/C0dak/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/C0dak/CVE-2017-16995.svg)
- [https://github.com/anldori/CVE-2017-16995](https://github.com/anldori/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/anldori/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/anldori/CVE-2017-16995.svg)
- [https://github.com/xxxTectationxxx/CVE-2017-16995](https://github.com/xxxTectationxxx/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/xxxTectationxxx/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/xxxTectationxxx/CVE-2017-16995.svg)
- [https://github.com/fei9747/CVE-2017-16995](https://github.com/fei9747/CVE-2017-16995) :  ![starts](https://img.shields.io/github/stars/fei9747/CVE-2017-16995.svg) ![forks](https://img.shields.io/github/forks/fei9747/CVE-2017-16995.svg)
- [https://github.com/mareks1007/cve-2017-16995](https://github.com/mareks1007/cve-2017-16995) :  ![starts](https://img.shields.io/github/stars/mareks1007/cve-2017-16995.svg) ![forks](https://img.shields.io/github/forks/mareks1007/cve-2017-16995.svg)
- [https://github.com/ZhiQiAnSecFork/cve-2017-16995](https://github.com/ZhiQiAnSecFork/cve-2017-16995) :  ![starts](https://img.shields.io/github/stars/ZhiQiAnSecFork/cve-2017-16995.svg) ![forks](https://img.shields.io/github/forks/ZhiQiAnSecFork/cve-2017-16995.svg)
- [https://github.com/ivilpez/cve-2017-16995.c](https://github.com/ivilpez/cve-2017-16995.c) :  ![starts](https://img.shields.io/github/stars/ivilpez/cve-2017-16995.c.svg) ![forks](https://img.shields.io/github/forks/ivilpez/cve-2017-16995.c.svg)
- [https://github.com/Lumindu/CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-](https://github.com/Lumindu/CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-) :  ![starts](https://img.shields.io/github/stars/Lumindu/CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-.svg) ![forks](https://img.shields.io/github/forks/Lumindu/CVE-2017-16995-Linux-Kernel---BPF-Sign-Extension-Local-Privilege-Escalation-.svg)


## CVE-2017-16994
 The walk_hugetlb_range function in mm/pagewalk.c in the Linux kernel before 4.14.2 mishandles holes in hugetlb ranges, which allows local users to obtain sensitive information from uninitialized kernel memory via crafted use of the mincore() system call.

- [https://github.com/jedai47/CVE-2017-16994](https://github.com/jedai47/CVE-2017-16994) :  ![starts](https://img.shields.io/github/stars/jedai47/CVE-2017-16994.svg) ![forks](https://img.shields.io/github/forks/jedai47/CVE-2017-16994.svg)


## CVE-2017-16929
 The remote management interface on the Claymore Dual GPU miner 10.1 is vulnerable to an authenticated directory traversal vulnerability exploited by issuing a specially crafted request, allowing a remote attacker to read/write arbitrary files. This can be exploited via ../ sequences in the pathname to miner_file or miner_getfile.

- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)


## CVE-2017-16921
 In OTRS 6.0.x up to and including 6.0.1, OTRS 5.0.x up to and including 5.0.24, and OTRS 4.0.x up to and including 4.0.26, an attacker who is logged into OTRS as an agent can manipulate form parameters (related to PGP) and execute arbitrary shell commands with the permissions of the OTRS or web server user.

- [https://github.com/Smarttfoxx/OTRS-4.0.1-6.0.1-Remote-Command-Execution](https://github.com/Smarttfoxx/OTRS-4.0.1-6.0.1-Remote-Command-Execution) :  ![starts](https://img.shields.io/github/stars/Smarttfoxx/OTRS-4.0.1-6.0.1-Remote-Command-Execution.svg) ![forks](https://img.shields.io/github/forks/Smarttfoxx/OTRS-4.0.1-6.0.1-Remote-Command-Execution.svg)


## CVE-2017-16894
 In Laravel framework through 5.5.21, remote attackers can obtain sensitive information (such as externally usable passwords) via a direct request for the /.env URI. NOTE: this CVE is only about Laravel framework's writeNewEnvironmentFileWith function in src/Illuminate/Foundation/Console/KeyGenerateCommand.php, which uses file_put_contents without restricting the .env permissions. The .env filename is not used exclusively by Laravel framework.

- [https://github.com/ibnurusdianto/CVE-2017-16894](https://github.com/ibnurusdianto/CVE-2017-16894) :  ![starts](https://img.shields.io/github/stars/ibnurusdianto/CVE-2017-16894.svg) ![forks](https://img.shields.io/github/forks/ibnurusdianto/CVE-2017-16894.svg)
- [https://github.com/H3dI/ENV-Mass-Exploit](https://github.com/H3dI/ENV-Mass-Exploit) :  ![starts](https://img.shields.io/github/stars/H3dI/ENV-Mass-Exploit.svg) ![forks](https://img.shields.io/github/forks/H3dI/ENV-Mass-Exploit.svg)
- [https://github.com/LuanDevecchi/CVE201716894](https://github.com/LuanDevecchi/CVE201716894) :  ![starts](https://img.shields.io/github/stars/LuanDevecchi/CVE201716894.svg) ![forks](https://img.shields.io/github/forks/LuanDevecchi/CVE201716894.svg)


## CVE-2017-16877
 ZEIT Next.js before 2.4.1 has directory traversal under the /_next and /static request namespace, allowing attackers to obtain sensitive information.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16877](https://github.com/ossf-cve-benchmark/CVE-2017-16877) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16877.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16877.svg)


## CVE-2017-16778
 An access control weakness in the DTMF tone receiver of Fermax Outdoor Panel allows physical attackers to inject a Dual-Tone-Multi-Frequency (DTMF) tone to invoke an access grant that would allow physical access to a restricted floor/level. By design, only a residential unit owner may allow such an access grant. However, due to incorrect access control, an attacker could inject it via the speaker unit to perform an access grant to gain unauthorized access, as demonstrated by a loud DTMF tone representing '1' and a long '#' (697 Hz and 1209 Hz, followed by 941 Hz and 1477 Hz).

- [https://github.com/breaktoprotect/CVE-2017-16778-Intercom-DTMF-Injection](https://github.com/breaktoprotect/CVE-2017-16778-Intercom-DTMF-Injection) :  ![starts](https://img.shields.io/github/stars/breaktoprotect/CVE-2017-16778-Intercom-DTMF-Injection.svg) ![forks](https://img.shields.io/github/forks/breaktoprotect/CVE-2017-16778-Intercom-DTMF-Injection.svg)


## CVE-2017-16748
 An attacker can log into the local Niagara platform (Niagara AX Framework Versions 3.8 and prior or Niagara 4 Framework Versions 4.4 and prior) using a disabled account name and a blank password, granting the attacker administrator access to the Niagara system.

- [https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara](https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara) :  ![starts](https://img.shields.io/github/stars/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg) ![forks](https://img.shields.io/github/forks/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg)


## CVE-2017-16744
 A path traversal vulnerability in Tridium Niagara AX Versions 3.8 and prior and Niagara 4 systems Versions 4.4 and prior installed on Microsoft Windows Systems can be exploited by leveraging valid platform (administrator) credentials.

- [https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara](https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara) :  ![starts](https://img.shields.io/github/stars/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg) ![forks](https://img.shields.io/github/forks/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg)


## CVE-2017-16720
 A Path Traversal issue was discovered in WebAccess versions 8.3.2 and earlier. An attacker has access to files within the directory structure of the target device.

- [https://github.com/CN016/WebAccess-CVE-2017-16720-](https://github.com/CN016/WebAccess-CVE-2017-16720-) :  ![starts](https://img.shields.io/github/stars/CN016/WebAccess-CVE-2017-16720-.svg) ![forks](https://img.shields.io/github/forks/CN016/WebAccess-CVE-2017-16720-.svg)


## CVE-2017-16651
 Roundcube Webmail before 1.1.10, 1.2.x before 1.2.7, and 1.3.x before 1.3.3 allows unauthorized access to arbitrary files on the host's filesystem, including configuration files, as exploited in the wild in November 2017. The attacker must be able to authenticate at the target system with a valid username/password as the attack requires an active session. The issue is related to file-based attachment plugins and _task=settings&_action=upload-display&_from=timezone requests.

- [https://github.com/starnightcyber/Exploit-Database-For-Webmail](https://github.com/starnightcyber/Exploit-Database-For-Webmail) :  ![starts](https://img.shields.io/github/stars/starnightcyber/Exploit-Database-For-Webmail.svg) ![forks](https://img.shields.io/github/forks/starnightcyber/Exploit-Database-For-Webmail.svg)
- [https://github.com/ropbear/CVE-2017-16651](https://github.com/ropbear/CVE-2017-16651) :  ![starts](https://img.shields.io/github/stars/ropbear/CVE-2017-16651.svg) ![forks](https://img.shields.io/github/forks/ropbear/CVE-2017-16651.svg)


## CVE-2017-16568
 Persistent Cross-Site Scripting (XSS) vulnerability in Logitech Media Server 7.9.0, affecting the "Radio" functionality. This vulnerability allows attackers to inject malicious JavaScript payloads, which become permanently stored on the server and execute when a user plays the compromised radio stream. Exploitation of this vulnerability can lead to Session hijacking and unauthorized access, Persistent manipulation of web content within the application, and Phishing or malicious redirects to external domains. This vulnerability can be exploited to manipulate media server behavior in enterprise and home network environments.

- [https://github.com/dewankpant/CVE-2017-16568](https://github.com/dewankpant/CVE-2017-16568) :  ![starts](https://img.shields.io/github/stars/dewankpant/CVE-2017-16568.svg) ![forks](https://img.shields.io/github/forks/dewankpant/CVE-2017-16568.svg)


## CVE-2017-16567
 Persistent Cross-Site Scripting (XSS) vulnerability in Logitech Media Server 7.9.0, affecting the "Favorites" feature. This vulnerability allows remote attackers to inject and permanently store malicious JavaScript payloads, which are executed when users access the affected functionality. Exploitation of this vulnerability can lead to Session Hijacking and Credential Theft, Execution of unauthorized actions on behalf of users, and Exfiltration of sensitive data. This vulnerability presents a potential risk for widespread exploitation in connected IoT environments.

- [https://github.com/dewankpant/CVE-2017-16567](https://github.com/dewankpant/CVE-2017-16567) :  ![starts](https://img.shields.io/github/stars/dewankpant/CVE-2017-16567.svg) ![forks](https://img.shields.io/github/forks/dewankpant/CVE-2017-16567.svg)


## CVE-2017-16541
 Tor Browser before 7.0.9 on macOS and Linux allows remote attackers to bypass the intended anonymity feature and discover a client IP address via vectors involving a crafted web site that leverages file:// mishandling in Firefox, aka TorMoil. NOTE: Tails is unaffected.

- [https://github.com/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541](https://github.com/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541) :  ![starts](https://img.shields.io/github/stars/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541.svg) ![forks](https://img.shields.io/github/forks/Ethan-Chen-uwo/A-breif-introduction-of-CVE-2017-16541.svg)


## CVE-2017-16226
 The static-eval module is intended to evaluate statically-analyzable expressions. In affected versions, untrusted user input is able to access the global function constructor, effectively allowing arbitrary code execution.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16226](https://github.com/ossf-cve-benchmark/CVE-2017-16226) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16226.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16226.svg)


## CVE-2017-16224
 st is a module for serving static files. An attacker is able to craft a request that results in an HTTP 301 (redirect) to an entirely different domain. A request for: http://some.server.com//nodesecurity.org/%2e%2e would result in a 301 to //nodesecurity.org/%2e%2e which most browsers treat as a proper redirect as // is translated into the current schema being used. Mitigating factor: In order for this to work, st must be serving from the root of a server (/) rather than the typical sub directory (/static/) and the redirect URL will end with some form of URL encoded .. ("%2e%2e", "%2e.", ".%2e").

- [https://github.com/ossf-cve-benchmark/CVE-2017-16224](https://github.com/ossf-cve-benchmark/CVE-2017-16224) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16224.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16224.svg)


## CVE-2017-16138
 The mime module  1.4.1, 2.0.1, 2.0.2 is vulnerable to regular expression denial of service when a mime lookup is performed on untrusted user input.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16138](https://github.com/ossf-cve-benchmark/CVE-2017-16138) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16138.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16138.svg)


## CVE-2017-16136
 method-override is a module used by the Express.js framework to let you use HTTP verbs such as PUT or DELETE in places where the client doesn't support it. method-override is vulnerable to a regular expression denial of service vulnerability when specially crafted input is passed in to be parsed via the X-HTTP-Method-Override header.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16136](https://github.com/ossf-cve-benchmark/CVE-2017-16136) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16136.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16136.svg)


## CVE-2017-16119
 Fresh is a module used by the Express.js framework for HTTP response freshness testing. It is vulnerable to a regular expression denial of service when it is passed specially crafted input to parse. This causes the event loop to be blocked causing a denial of service condition.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16119](https://github.com/ossf-cve-benchmark/CVE-2017-16119) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16119.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16119.svg)


## CVE-2017-16118
 The forwarded module is used by the Express.js framework to handle the X-Forwarded-For header. It is vulnerable to a regular expression denial of service when it's passed specially crafted input to parse. This causes the event loop to be blocked causing a denial of service condition.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16118](https://github.com/ossf-cve-benchmark/CVE-2017-16118) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16118.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16118.svg)


## CVE-2017-16117
 slug is a module to slugify strings, even if they contain unicode. slug is vulnerable to regular expression denial of service is specially crafted untrusted input is passed as input. About 50k characters can block the event loop for 2 seconds.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16117](https://github.com/ossf-cve-benchmark/CVE-2017-16117) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16117.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16117.svg)


## CVE-2017-16100
 dns-sync is a sync/blocking dns resolver. If untrusted user input is allowed into the resolve() method then command injection is possible.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16100](https://github.com/ossf-cve-benchmark/CVE-2017-16100) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16100.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16100.svg)


## CVE-2017-16088
 The safe-eval module describes itself as a safer version of eval. By accessing the object constructors, un-sanitized user input can access the entire standard library and effectively break out of the sandbox.

- [https://github.com/Flyy-yu/CVE-2017-16088](https://github.com/Flyy-yu/CVE-2017-16088) :  ![starts](https://img.shields.io/github/stars/Flyy-yu/CVE-2017-16088.svg) ![forks](https://img.shields.io/github/forks/Flyy-yu/CVE-2017-16088.svg)


## CVE-2017-16084
 list-n-stream is a server for static files to list and stream local videos. list-n-stream v0.0.10 or lower is vulnerable to a directory traversal issue, giving an attacker access to the filesystem by placing "../" in the url.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16084](https://github.com/ossf-cve-benchmark/CVE-2017-16084) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16084.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16084.svg)


## CVE-2017-16083
 node-simple-router is a minimalistic router for Node. node-simple-router is vulnerable to a directory traversal issue, giving an attacker access to the filesystem by placing "../" in the URL.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16083](https://github.com/ossf-cve-benchmark/CVE-2017-16083) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16083.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16083.svg)


## CVE-2017-16031
 Socket.io is a realtime application framework that provides communication via websockets. Because socket.io 0.9.6 and earlier depends on `Math.random()` to create socket IDs, the IDs are predictable. An attacker is able to guess the socket ID and gain access to socket.io servers, potentially obtaining sensitive information.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16031](https://github.com/ossf-cve-benchmark/CVE-2017-16031) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16031.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16031.svg)


## CVE-2017-16030
 Useragent is used to parse useragent headers. It uses several regular expressions to accomplish this. An attacker could edit their own headers, creating an arbitrarily long useragent string, causing the event loop and server to block. This affects Useragent 2.1.12 and earlier.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16030](https://github.com/ossf-cve-benchmark/CVE-2017-16030) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16030.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16030.svg)


## CVE-2017-16029
 hostr is a simple web server that serves up the contents of the current directory. There is a directory traversal vulnerability in hostr 2.3.5 and earlier that allows an attacker to read files outside the current directory by sending `../` in the url path for GET requests.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16029](https://github.com/ossf-cve-benchmark/CVE-2017-16029) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16029.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16029.svg)


## CVE-2017-16028
 react-native-meteor-oauth is a library for Oauth2 login to a Meteor server in React Native. The oauth Random Token is generated using a non-cryptographically strong RNG (Math.random()).

- [https://github.com/ossf-cve-benchmark/CVE-2017-16028](https://github.com/ossf-cve-benchmark/CVE-2017-16028) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16028.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16028.svg)


## CVE-2017-16026
 Request is an http client. If a request is made using ```multipart```, and the body type is a ```number```, then the specified number of non-zero memory is passed in the body. This affects Request =2.2.6 2.47.0 || 2.51.0 =2.67.0.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16026](https://github.com/ossf-cve-benchmark/CVE-2017-16026) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16026.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16026.svg)


## CVE-2017-16023
 Decamelize is used to convert a dash/dot/underscore/space separated string to camelCase. Decamelize 1.1.0 through 1.1.1 uses regular expressions to evaluate a string and takes unescaped separator values, which can be used to create a denial of service attack.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16023](https://github.com/ossf-cve-benchmark/CVE-2017-16023) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16023.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16023.svg)


## CVE-2017-16018
 Restify is a framework for building REST APIs. Restify =2.0.0 =4.0.4 using URL encoded script tags in a non-existent URL, an attacker can get script to run in some browsers.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16018](https://github.com/ossf-cve-benchmark/CVE-2017-16018) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16018.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16018.svg)


## CVE-2017-16003
 windows-build-tools is a module for installing C++ Build Tools for Windows using npm. windows-build-tools versions below 1.0.0 download resources over HTTP, which leaves it vulnerable to MITM attacks. It may be possible to cause remote code execution (RCE) by swapping out the requested resources with an attacker controlled copy if the attacker is on the network or positioned in between the user and the remote server.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16003](https://github.com/ossf-cve-benchmark/CVE-2017-16003) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16003.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16003.svg)


## CVE-2017-15950
 Flexense SyncBreeze Enterprise version 10.1.16 is vulnerable to a buffer overflow that can be exploited for arbitrary code execution. The flaw is triggered by providing a long input into the "Destination directory" field, either within an XML document or through use of passive mode.

- [https://github.com/rnnsz/CVE-2017-15950](https://github.com/rnnsz/CVE-2017-15950) :  ![starts](https://img.shields.io/github/stars/rnnsz/CVE-2017-15950.svg) ![forks](https://img.shields.io/github/forks/rnnsz/CVE-2017-15950.svg)


## CVE-2017-15944
 Palo Alto Networks PAN-OS before 6.1.19, 7.0.x before 7.0.19, 7.1.x before 7.1.14, and 8.0.x before 8.0.6 allows remote attackers to execute arbitrary code via vectors involving the management interface.

- [https://github.com/surajraghuvanshi/PaloAltoRceDetectionAndExploit](https://github.com/surajraghuvanshi/PaloAltoRceDetectionAndExploit) :  ![starts](https://img.shields.io/github/stars/surajraghuvanshi/PaloAltoRceDetectionAndExploit.svg) ![forks](https://img.shields.io/github/forks/surajraghuvanshi/PaloAltoRceDetectionAndExploit.svg)
- [https://github.com/xxnbyy/CVE-2017-15944-POC](https://github.com/xxnbyy/CVE-2017-15944-POC) :  ![starts](https://img.shields.io/github/stars/xxnbyy/CVE-2017-15944-POC.svg) ![forks](https://img.shields.io/github/forks/xxnbyy/CVE-2017-15944-POC.svg)
- [https://github.com/AiK1d/PaloAlto_EXP](https://github.com/AiK1d/PaloAlto_EXP) :  ![starts](https://img.shields.io/github/stars/AiK1d/PaloAlto_EXP.svg) ![forks](https://img.shields.io/github/forks/AiK1d/PaloAlto_EXP.svg)
- [https://github.com/yukar1z0e/CVE-2017-15944](https://github.com/yukar1z0e/CVE-2017-15944) :  ![starts](https://img.shields.io/github/stars/yukar1z0e/CVE-2017-15944.svg) ![forks](https://img.shields.io/github/forks/yukar1z0e/CVE-2017-15944.svg)


## CVE-2017-15715
 In Apache httpd 2.4.0 to 2.4.29, the expression specified in FilesMatch could match '$' to a newline character in a malicious filename, rather than matching only the end of the filename. This could be exploited in environments where uploads of some files are are externally blocked, but only by matching the trailing portion of the filename.

- [https://github.com/whisp1830/CVE-2017-15715](https://github.com/whisp1830/CVE-2017-15715) :  ![starts](https://img.shields.io/github/stars/whisp1830/CVE-2017-15715.svg) ![forks](https://img.shields.io/github/forks/whisp1830/CVE-2017-15715.svg)


## CVE-2017-15708
 In Apache Synapse, by default no authentication is required for Java Remote Method Invocation (RMI). So Apache Synapse 3.0.1 or all previous releases (3.0.0, 2.1.0, 2.0.0, 1.2, 1.1.2, 1.1.1) allows remote code execution attacks that can be performed by injecting specially crafted serialized objects. And the presence of Apache Commons Collections 3.2.1 (commons-collections-3.2.1.jar) or previous versions in Synapse distribution makes this exploitable. To mitigate the issue, we need to limit RMI access to trusted users only. Further upgrading to 3.0.1 version will eliminate the risk of having said Commons Collection version. In Synapse 3.0.1, Commons Collection has been updated to 3.2.2 version.

- [https://github.com/HuSoul/CVE-2017-15708](https://github.com/HuSoul/CVE-2017-15708) :  ![starts](https://img.shields.io/github/stars/HuSoul/CVE-2017-15708.svg) ![forks](https://img.shields.io/github/forks/HuSoul/CVE-2017-15708.svg)


## CVE-2017-15428
 Insufficient data validation in V8 builtins string generator could lead to out of bounds read and write access in V8 in Google Chrome prior to 62.0.3202.94 and allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.

- [https://github.com/w1ldb1t/CVE-2017-15428](https://github.com/w1ldb1t/CVE-2017-15428) :  ![starts](https://img.shields.io/github/stars/w1ldb1t/CVE-2017-15428.svg) ![forks](https://img.shields.io/github/forks/w1ldb1t/CVE-2017-15428.svg)


## CVE-2017-15394
 Insufficient Policy Enforcement in Extensions in Google Chrome prior to 62.0.3202.62 allowed a remote attacker to perform domain spoofing in permission dialogs via IDN homographs in a crafted Chrome Extension.

- [https://github.com/sudosammy/CVE-2017-15394](https://github.com/sudosammy/CVE-2017-15394) :  ![starts](https://img.shields.io/github/stars/sudosammy/CVE-2017-15394.svg) ![forks](https://img.shields.io/github/forks/sudosammy/CVE-2017-15394.svg)


## CVE-2017-15361
 The Infineon RSA library 1.02.013 in Infineon Trusted Platform Module (TPM) firmware, such as versions before 0000000000000422 - 4.34, before 000000000000062b - 6.43, and before 0000000000008521 - 133.33, mishandles RSA key generation, which makes it easier for attackers to defeat various cryptographic protection mechanisms via targeted attacks, aka ROCA. Examples of affected technologies include BitLocker with TPM 1.2, YubiKey 4 (before 4.3.5) PGP key generation, and the Cached User Data encryption feature in Chrome OS.

- [https://github.com/nsacyber/Detect-CVE-2017-15361-TPM](https://github.com/nsacyber/Detect-CVE-2017-15361-TPM) :  ![starts](https://img.shields.io/github/stars/nsacyber/Detect-CVE-2017-15361-TPM.svg) ![forks](https://img.shields.io/github/forks/nsacyber/Detect-CVE-2017-15361-TPM.svg)
- [https://github.com/brunoproduit/roca](https://github.com/brunoproduit/roca) :  ![starts](https://img.shields.io/github/stars/brunoproduit/roca.svg) ![forks](https://img.shields.io/github/forks/brunoproduit/roca.svg)
- [https://github.com/titanous/rocacheck](https://github.com/titanous/rocacheck) :  ![starts](https://img.shields.io/github/stars/titanous/rocacheck.svg) ![forks](https://img.shields.io/github/forks/titanous/rocacheck.svg)
- [https://github.com/0xxon/zeek-plugin-roca](https://github.com/0xxon/zeek-plugin-roca) :  ![starts](https://img.shields.io/github/stars/0xxon/zeek-plugin-roca.svg) ![forks](https://img.shields.io/github/forks/0xxon/zeek-plugin-roca.svg)
- [https://github.com/lva/Infineon-CVE-2017-15361](https://github.com/lva/Infineon-CVE-2017-15361) :  ![starts](https://img.shields.io/github/stars/lva/Infineon-CVE-2017-15361.svg) ![forks](https://img.shields.io/github/forks/lva/Infineon-CVE-2017-15361.svg)
- [https://github.com/Elbarbons/ROCA-attack-on-vulnerability-CVE-2017-15361](https://github.com/Elbarbons/ROCA-attack-on-vulnerability-CVE-2017-15361) :  ![starts](https://img.shields.io/github/stars/Elbarbons/ROCA-attack-on-vulnerability-CVE-2017-15361.svg) ![forks](https://img.shields.io/github/forks/Elbarbons/ROCA-attack-on-vulnerability-CVE-2017-15361.svg)
- [https://github.com/0xxon/roca](https://github.com/0xxon/roca) :  ![starts](https://img.shields.io/github/stars/0xxon/roca.svg) ![forks](https://img.shields.io/github/forks/0xxon/roca.svg)


## CVE-2017-15303
 In CPUID CPU-Z before 1.43, there is an arbitrary memory write that results directly in elevation of privileges, because any program running on the local machine (while CPU-Z is running) can issue an ioctl 0x9C402430 call to the kernel-mode driver (e.g., cpuz141_x64.sys for version 1.41).

- [https://github.com/hfiref0x/Stryker](https://github.com/hfiref0x/Stryker) :  ![starts](https://img.shields.io/github/stars/hfiref0x/Stryker.svg) ![forks](https://img.shields.io/github/forks/hfiref0x/Stryker.svg)


## CVE-2017-15277
 ReadGIFImage in coders/gif.c in ImageMagick 7.0.6-1 and GraphicsMagick 1.3.26 leaves the palette uninitialized when processing a GIF file that has neither a global nor local palette. If the affected product is used as a library loaded into a process that operates on interesting data, this data sometimes can be leaked via the uninitialized palette.

- [https://github.com/hexrom/ImageMagick-CVE-2017-15277](https://github.com/hexrom/ImageMagick-CVE-2017-15277) :  ![starts](https://img.shields.io/github/stars/hexrom/ImageMagick-CVE-2017-15277.svg) ![forks](https://img.shields.io/github/forks/hexrom/ImageMagick-CVE-2017-15277.svg)


## CVE-2017-15099
 INSERT ... ON CONFLICT DO UPDATE commands in PostgreSQL 10.x before 10.1, 9.6.x before 9.6.6, and 9.5.x before 9.5.10 disclose table contents that the invoker lacks privilege to read. These exploits affect only tables where the attacker lacks full read access but has both INSERT and UPDATE privileges. Exploits bypass row level security policies and lack of SELECT privilege.

- [https://github.com/ToontjeM/CVE-2017-15099](https://github.com/ToontjeM/CVE-2017-15099) :  ![starts](https://img.shields.io/github/stars/ToontjeM/CVE-2017-15099.svg) ![forks](https://img.shields.io/github/forks/ToontjeM/CVE-2017-15099.svg)


## CVE-2017-15095
 A deserialization flaw was discovered in the jackson-databind in versions before 2.8.10 and 2.9.1, which could allow an unauthenticated user to perform code execution by sending the maliciously crafted input to the readValue method of the ObjectMapper. This issue extends the previous flaw CVE-2017-7525 by blacklisting more classes that could be used maliciously.

- [https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095](https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095) :  ![starts](https://img.shields.io/github/stars/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095.svg) ![forks](https://img.shields.io/github/forks/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095.svg)


## CVE-2017-14980
 Buffer overflow in Sync Breeze Enterprise 10.0.28 allows remote attackers to have unspecified impact via a long username parameter to /login.

- [https://github.com/LipeOzyy/CVE-2017-14980_syncbreeze_10.0.28_bof](https://github.com/LipeOzyy/CVE-2017-14980_syncbreeze_10.0.28_bof) :  ![starts](https://img.shields.io/github/stars/LipeOzyy/CVE-2017-14980_syncbreeze_10.0.28_bof.svg) ![forks](https://img.shields.io/github/forks/LipeOzyy/CVE-2017-14980_syncbreeze_10.0.28_bof.svg)
- [https://github.com/TheDarthMole/CVE-2017-14980](https://github.com/TheDarthMole/CVE-2017-14980) :  ![starts](https://img.shields.io/github/stars/TheDarthMole/CVE-2017-14980.svg) ![forks](https://img.shields.io/github/forks/TheDarthMole/CVE-2017-14980.svg)
- [https://github.com/xn0kkx/Exploit_Sync_Breeze_v10.0.28_CVE-2017-14980](https://github.com/xn0kkx/Exploit_Sync_Breeze_v10.0.28_CVE-2017-14980) :  ![starts](https://img.shields.io/github/stars/xn0kkx/Exploit_Sync_Breeze_v10.0.28_CVE-2017-14980.svg) ![forks](https://img.shields.io/github/forks/xn0kkx/Exploit_Sync_Breeze_v10.0.28_CVE-2017-14980.svg)


## CVE-2017-14954
 The waitid implementation in kernel/exit.c in the Linux kernel through 4.13.4 accesses rusage data structures in unintended cases, which allows local users to obtain sensitive information, and bypass the KASLR protection mechanism, via a crafted system call.

- [https://github.com/echo-devim/exploit_linux_kernel4.13](https://github.com/echo-devim/exploit_linux_kernel4.13) :  ![starts](https://img.shields.io/github/stars/echo-devim/exploit_linux_kernel4.13.svg) ![forks](https://img.shields.io/github/forks/echo-devim/exploit_linux_kernel4.13.svg)


## CVE-2017-14948
 Certain D-Link products are affected by: Buffer Overflow. This affects DIR-880L 1.08B04 and DIR-895 L/R 1.13b03. The impact is: execute arbitrary code (remote). The component is: htdocs/fileaccess.cgi. The attack vector is: A crafted HTTP request handled by fileacces.cgi could allow an attacker to mount a ROP attack: if the HTTP header field CONTENT_TYPE starts with ''boundary=' followed by more than 256 characters, a buffer overflow would be triggered, potentially causing code execution.

- [https://github.com/badnack/d_link_880_bug](https://github.com/badnack/d_link_880_bug) :  ![starts](https://img.shields.io/github/stars/badnack/d_link_880_bug.svg) ![forks](https://img.shields.io/github/forks/badnack/d_link_880_bug.svg)


## CVE-2017-14494
 dnsmasq before 2.78, when configured as a relay, allows remote attackers to obtain sensitive memory information via vectors involving handling DHCPv6 forwarded requests.

- [https://github.com/raw-packet/raw-packet](https://github.com/raw-packet/raw-packet) :  ![starts](https://img.shields.io/github/stars/raw-packet/raw-packet.svg) ![forks](https://img.shields.io/github/forks/raw-packet/raw-packet.svg)


## CVE-2017-14493
 Stack-based buffer overflow in dnsmasq before 2.78 allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted DHCPv6 request.

- [https://github.com/raw-packet/raw-packet](https://github.com/raw-packet/raw-packet) :  ![starts](https://img.shields.io/github/stars/raw-packet/raw-packet.svg) ![forks](https://img.shields.io/github/forks/raw-packet/raw-packet.svg)
- [https://github.com/pupiles/bof-dnsmasq-cve-2017-14493](https://github.com/pupiles/bof-dnsmasq-cve-2017-14493) :  ![starts](https://img.shields.io/github/stars/pupiles/bof-dnsmasq-cve-2017-14493.svg) ![forks](https://img.shields.io/github/forks/pupiles/bof-dnsmasq-cve-2017-14493.svg)


## CVE-2017-14491
 Heap-based buffer overflow in dnsmasq before 2.78 allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted DNS response.

- [https://github.com/skyformat99/dnsmasq-2.4.1-fix-CVE-2017-14491](https://github.com/skyformat99/dnsmasq-2.4.1-fix-CVE-2017-14491) :  ![starts](https://img.shields.io/github/stars/skyformat99/dnsmasq-2.4.1-fix-CVE-2017-14491.svg) ![forks](https://img.shields.io/github/forks/skyformat99/dnsmasq-2.4.1-fix-CVE-2017-14491.svg)


## CVE-2017-14322
 The function in charge to check whether the user is already logged in init.php in Interspire Email Marketer (IEM) prior to 6.1.6 allows remote attackers to bypass authentication and obtain administrative access by using the IEM_CookieLogin cookie with a specially crafted value.

- [https://github.com/joesmithjaffa/CVE-2017-14322](https://github.com/joesmithjaffa/CVE-2017-14322) :  ![starts](https://img.shields.io/github/stars/joesmithjaffa/CVE-2017-14322.svg) ![forks](https://img.shields.io/github/forks/joesmithjaffa/CVE-2017-14322.svg)


## CVE-2017-14263
 Honeywell NVR devices allow remote attackers to create a user account in the admin group by leveraging access to a guest account to obtain a session ID, and then sending that session ID in a userManager.addUser request to the /RPC2 URI. The attacker can login to the device with that new user account to fully control the device.

- [https://github.com/zzz66686/CVE-2017-14263](https://github.com/zzz66686/CVE-2017-14263) :  ![starts](https://img.shields.io/github/stars/zzz66686/CVE-2017-14263.svg) ![forks](https://img.shields.io/github/forks/zzz66686/CVE-2017-14263.svg)


## CVE-2017-14262
 On Samsung NVR devices, remote attackers can read the MD5 password hash of the 'admin' account via certain szUserName JSON data to cgi-bin/main-cgi, and login to the device with that hash in the szUserPasswd parameter.

- [https://github.com/zzz66686/CVE-2017-14262](https://github.com/zzz66686/CVE-2017-14262) :  ![starts](https://img.shields.io/github/stars/zzz66686/CVE-2017-14262.svg) ![forks](https://img.shields.io/github/forks/zzz66686/CVE-2017-14262.svg)


## CVE-2017-14244
 An authentication bypass vulnerability on iBall Baton ADSL2+ Home Router FW_iB-LR7011A_1.0.2 devices potentially allows attackers to directly access administrative router settings by crafting URLs with a .cgi extension, as demonstrated by /info.cgi and /password.cgi.

- [https://github.com/GemGeorge/iBall-UTStar-CVEChecker](https://github.com/GemGeorge/iBall-UTStar-CVEChecker) :  ![starts](https://img.shields.io/github/stars/GemGeorge/iBall-UTStar-CVEChecker.svg) ![forks](https://img.shields.io/github/forks/GemGeorge/iBall-UTStar-CVEChecker.svg)


## CVE-2017-14243
 An authentication bypass vulnerability on UTStar WA3002G4 ADSL Broadband Modem WA3002G4-0021.01 devices allows attackers to directly access administrative settings and obtain cleartext credentials from HTML source, as demonstrated by info.cgi, upload.cgi, backupsettings.cgi, pppoe.cgi, resetrouter.cgi, and password.cgi.

- [https://github.com/GemGeorge/iBall-UTStar-CVEChecker](https://github.com/GemGeorge/iBall-UTStar-CVEChecker) :  ![starts](https://img.shields.io/github/stars/GemGeorge/iBall-UTStar-CVEChecker.svg) ![forks](https://img.shields.io/github/forks/GemGeorge/iBall-UTStar-CVEChecker.svg)


## CVE-2017-13672
 QEMU (aka Quick Emulator), when built with the VGA display emulator support, allows local guest OS privileged users to cause a denial of service (out-of-bounds read and QEMU process crash) via vectors involving display update.

- [https://github.com/DavidBuchanan314/CVE-2017-13672](https://github.com/DavidBuchanan314/CVE-2017-13672) :  ![starts](https://img.shields.io/github/stars/DavidBuchanan314/CVE-2017-13672.svg) ![forks](https://img.shields.io/github/forks/DavidBuchanan314/CVE-2017-13672.svg)


## CVE-2017-13253
 In CryptoPlugin::decrypt of CryptoPlugin.cpp, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation. Product: Android. Versions: 8.0, 8.1. Android ID: A-71389378.

- [https://github.com/tamirzb/CVE-2017-13253](https://github.com/tamirzb/CVE-2017-13253) :  ![starts](https://img.shields.io/github/stars/tamirzb/CVE-2017-13253.svg) ![forks](https://img.shields.io/github/forks/tamirzb/CVE-2017-13253.svg)


## CVE-2017-13208
 In receive_packet of libnetutils/packet.c, there is a possible out-of-bounds write due to a missing bounds check on the DHCP response. This could lead to remote code execution as a privileged process with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0, 8.1. Android ID: A-67474440.

- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)
- [https://github.com/idanshechter/CVE-2017-13208-Scanner](https://github.com/idanshechter/CVE-2017-13208-Scanner) :  ![starts](https://img.shields.io/github/stars/idanshechter/CVE-2017-13208-Scanner.svg) ![forks](https://img.shields.io/github/forks/idanshechter/CVE-2017-13208-Scanner.svg)


## CVE-2017-13156
 An elevation of privilege vulnerability in the Android system (art). Product: Android. Versions: 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID A-64211847.

- [https://github.com/xyzAsian/Janus-CVE-2017-13156](https://github.com/xyzAsian/Janus-CVE-2017-13156) :  ![starts](https://img.shields.io/github/stars/xyzAsian/Janus-CVE-2017-13156.svg) ![forks](https://img.shields.io/github/forks/xyzAsian/Janus-CVE-2017-13156.svg)
- [https://github.com/tea9/CVE-2017-13156-Janus](https://github.com/tea9/CVE-2017-13156-Janus) :  ![starts](https://img.shields.io/github/stars/tea9/CVE-2017-13156-Janus.svg) ![forks](https://img.shields.io/github/forks/tea9/CVE-2017-13156-Janus.svg)
- [https://github.com/giacomoferretti/janus-toolkit](https://github.com/giacomoferretti/janus-toolkit) :  ![starts](https://img.shields.io/github/stars/giacomoferretti/janus-toolkit.svg) ![forks](https://img.shields.io/github/forks/giacomoferretti/janus-toolkit.svg)
- [https://github.com/ppapadatis/python-janus-vulnerability-scan](https://github.com/ppapadatis/python-janus-vulnerability-scan) :  ![starts](https://img.shields.io/github/stars/ppapadatis/python-janus-vulnerability-scan.svg) ![forks](https://img.shields.io/github/forks/ppapadatis/python-janus-vulnerability-scan.svg)
- [https://github.com/M507/CVE-2017-13156](https://github.com/M507/CVE-2017-13156) :  ![starts](https://img.shields.io/github/stars/M507/CVE-2017-13156.svg) ![forks](https://img.shields.io/github/forks/M507/CVE-2017-13156.svg)
- [https://github.com/nahid0x1/Janus-Vulnerability-CVE-2017-13156-Exploit](https://github.com/nahid0x1/Janus-Vulnerability-CVE-2017-13156-Exploit) :  ![starts](https://img.shields.io/github/stars/nahid0x1/Janus-Vulnerability-CVE-2017-13156-Exploit.svg) ![forks](https://img.shields.io/github/forks/nahid0x1/Janus-Vulnerability-CVE-2017-13156-Exploit.svg)
- [https://github.com/entediado97/rosa_dex_injetor](https://github.com/entediado97/rosa_dex_injetor) :  ![starts](https://img.shields.io/github/stars/entediado97/rosa_dex_injetor.svg) ![forks](https://img.shields.io/github/forks/entediado97/rosa_dex_injetor.svg)
- [https://github.com/caxmd/CVE-2017-13156](https://github.com/caxmd/CVE-2017-13156) :  ![starts](https://img.shields.io/github/stars/caxmd/CVE-2017-13156.svg) ![forks](https://img.shields.io/github/forks/caxmd/CVE-2017-13156.svg)
- [https://github.com/nictjh/threatDemos](https://github.com/nictjh/threatDemos) :  ![starts](https://img.shields.io/github/stars/nictjh/threatDemos.svg) ![forks](https://img.shields.io/github/forks/nictjh/threatDemos.svg)


## CVE-2017-13089
 The http.c:skip_short_body() function is called in some circumstances, such as when processing redirects. When the response is sent chunked in wget before 1.19.2, the chunk parser uses strtol() to read each chunk's length, but doesn't check that the chunk length is a non-negative number. The code then tries to skip the chunk in pieces of 512 bytes by using the MIN() macro, but ends up passing the negative chunk length to connect.c:fd_read(). As fd_read() takes an int argument, the high 32 bits of the chunk length are discarded, leaving fd_read() with a completely attacker controlled length argument.

- [https://github.com/mzeyong/CVE-2017-13089](https://github.com/mzeyong/CVE-2017-13089) :  ![starts](https://img.shields.io/github/stars/mzeyong/CVE-2017-13089.svg) ![forks](https://img.shields.io/github/forks/mzeyong/CVE-2017-13089.svg)
- [https://github.com/r1b/CVE-2017-13089](https://github.com/r1b/CVE-2017-13089) :  ![starts](https://img.shields.io/github/stars/r1b/CVE-2017-13089.svg) ![forks](https://img.shields.io/github/forks/r1b/CVE-2017-13089.svg)


## CVE-2017-12852
 The numpy.pad function in Numpy 1.13.1 and older versions is missing input validation. An empty list or ndarray will stick into an infinite loop, which can allow attackers to cause a DoS attack.

- [https://github.com/BT123/numpy-1.13.1](https://github.com/BT123/numpy-1.13.1) :  ![starts](https://img.shields.io/github/stars/BT123/numpy-1.13.1.svg) ![forks](https://img.shields.io/github/forks/BT123/numpy-1.13.1.svg)


## CVE-2017-12717
 An Uncontrolled Search Path Element issue was discovered in Advantech WebAccess versions prior to V8.2_20170817. A maliciously crafted dll file placed earlier in the search path may allow an attacker to execute code within the context of the application.

- [https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717](https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717) :  ![starts](https://img.shields.io/github/stars/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg) ![forks](https://img.shields.io/github/forks/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg)


## CVE-2017-12637
 Directory traversal vulnerability in scheduler/ui/js/ffffffffbca41eb4/UIUtilJavaScriptJS in SAP NetWeaver Application Server Java 7.5 allows remote attackers to read arbitrary files via a .. (dot dot) in the query string, as exploited in the wild in August 2017, aka SAP Security Note 2486657.

- [https://github.com/abrewer251/CVE-2017-12637_SAP-NetWeaver-URL-Traversal](https://github.com/abrewer251/CVE-2017-12637_SAP-NetWeaver-URL-Traversal) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2017-12637_SAP-NetWeaver-URL-Traversal.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2017-12637_SAP-NetWeaver-URL-Traversal.svg)


## CVE-2017-12636
 CouchDB administrative users can configure the database server via HTTP(S). Some of the configuration options include paths for operating system-level binaries that are subsequently launched by CouchDB. This allows an admin user in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to execute arbitrary shell commands as the CouchDB user, including downloading and executing scripts from the public internet.

- [https://github.com/XTeam-Wing/CVE-2017-12636](https://github.com/XTeam-Wing/CVE-2017-12636) :  ![starts](https://img.shields.io/github/stars/XTeam-Wing/CVE-2017-12636.svg) ![forks](https://img.shields.io/github/forks/XTeam-Wing/CVE-2017-12636.svg)
- [https://github.com/moayadalmalat/CVE-2017-12636](https://github.com/moayadalmalat/CVE-2017-12636) :  ![starts](https://img.shields.io/github/stars/moayadalmalat/CVE-2017-12636.svg) ![forks](https://img.shields.io/github/forks/moayadalmalat/CVE-2017-12636.svg)


## CVE-2017-12635
 Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit _users documents with duplicate keys for 'roles' used for access control within the database, including the special case '_admin' role, that denotes administrative users. In combination with CVE-2017-12636 (Remote Code Execution), this can be used to give non-admin users access to arbitrary shell commands on the server as the database system user. The JSON parser differences result in behaviour that if two 'roles' keys are available in the JSON, the second one will be used for authorising the document write, but the first 'roles' key is used for subsequent authorization for the newly created user. By design, users can not assign themselves roles. The vulnerability allows non-admin users to give themselves admin privileges.

- [https://github.com/assalielmehdi/CVE-2017-12635](https://github.com/assalielmehdi/CVE-2017-12635) :  ![starts](https://img.shields.io/github/stars/assalielmehdi/CVE-2017-12635.svg) ![forks](https://img.shields.io/github/forks/assalielmehdi/CVE-2017-12635.svg)
- [https://github.com/cyberharsh/Apache-couchdb-CVE-2017-12635](https://github.com/cyberharsh/Apache-couchdb-CVE-2017-12635) :  ![starts](https://img.shields.io/github/stars/cyberharsh/Apache-couchdb-CVE-2017-12635.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/Apache-couchdb-CVE-2017-12635.svg)


## CVE-2017-12624
 Apache CXF supports sending and receiving attachments via either the JAX-WS or JAX-RS specifications. It is possible to craft a message attachment header that could lead to a Denial of Service (DoS) attack on a CXF web service provider. Both JAX-WS and JAX-RS services are vulnerable to this attack. From Apache CXF 3.2.1 and 3.1.14, message attachment headers that are greater than 300 characters will be rejected by default. This value is configurable via the property "attachment-max-header-size".

- [https://github.com/tafamace/CVE-2017-12624](https://github.com/tafamace/CVE-2017-12624) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2017-12624.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2017-12624.svg)


## CVE-2017-12617
 When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/cyberheartmi9/CVE-2017-12617](https://github.com/cyberheartmi9/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/cyberheartmi9/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/cyberheartmi9/CVE-2017-12617.svg)
- [https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717](https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717) :  ![starts](https://img.shields.io/github/stars/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg) ![forks](https://img.shields.io/github/forks/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg)
- [https://github.com/LongWayHomie/CVE-2017-12617](https://github.com/LongWayHomie/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/LongWayHomie/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/LongWayHomie/CVE-2017-12617.svg)
- [https://github.com/ygouzerh/CVE-2017-12617](https://github.com/ygouzerh/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/ygouzerh/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/ygouzerh/CVE-2017-12617.svg)
- [https://github.com/TheRealCiscoo/Tomcat_CVE201712617](https://github.com/TheRealCiscoo/Tomcat_CVE201712617) :  ![starts](https://img.shields.io/github/stars/TheRealCiscoo/Tomcat_CVE201712617.svg) ![forks](https://img.shields.io/github/forks/TheRealCiscoo/Tomcat_CVE201712617.svg)
- [https://github.com/jptr218/tc_hack](https://github.com/jptr218/tc_hack) :  ![starts](https://img.shields.io/github/stars/jptr218/tc_hack.svg) ![forks](https://img.shields.io/github/forks/jptr218/tc_hack.svg)
- [https://github.com/tyranteye666/tomcat-cve-2017-12617](https://github.com/tyranteye666/tomcat-cve-2017-12617) :  ![starts](https://img.shields.io/github/stars/tyranteye666/tomcat-cve-2017-12617.svg) ![forks](https://img.shields.io/github/forks/tyranteye666/tomcat-cve-2017-12617.svg)
- [https://github.com/yZee00/CVE-2017-12617](https://github.com/yZee00/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/yZee00/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/yZee00/CVE-2017-12617.svg)
- [https://github.com/qiantu88/CVE-2017-12617](https://github.com/qiantu88/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/qiantu88/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/qiantu88/CVE-2017-12617.svg)
- [https://github.com/devcoinfet/CVE-2017-12617](https://github.com/devcoinfet/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/devcoinfet/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/devcoinfet/CVE-2017-12617.svg)
- [https://github.com/scirusvulgaris/CVE-2017-12617](https://github.com/scirusvulgaris/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/scirusvulgaris/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/scirusvulgaris/CVE-2017-12617.svg)
- [https://github.com/DevaDJ/CVE-2017-12617](https://github.com/DevaDJ/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/DevaDJ/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/DevaDJ/CVE-2017-12617.svg)
- [https://github.com/K3ysTr0K3R/CVE-2017-12617-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-12617-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-12617-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-12617-EXPLOIT.svg)


## CVE-2017-12561
 A remote code execution vulnerability in HPE intelligent Management Center (iMC) PLAT version Plat 7.3 E0504P4 and earlier was found.

- [https://github.com/Everdoh/CVE-2017-12561](https://github.com/Everdoh/CVE-2017-12561) :  ![starts](https://img.shields.io/github/stars/Everdoh/CVE-2017-12561.svg) ![forks](https://img.shields.io/github/forks/Everdoh/CVE-2017-12561.svg)


## CVE-2017-12426
 GitLab Community Edition (CE) and Enterprise Edition (EE) before 8.17.8, 9.0.x before 9.0.13, 9.1.x before 9.1.10, 9.2.x before 9.2.10, 9.3.x before 9.3.10, and 9.4.x before 9.4.4 might allow remote attackers to execute arbitrary code via a crafted SSH URL in a project import.

- [https://github.com/sm-paul-schuette/CVE-2017-12426](https://github.com/sm-paul-schuette/CVE-2017-12426) :  ![starts](https://img.shields.io/github/stars/sm-paul-schuette/CVE-2017-12426.svg) ![forks](https://img.shields.io/github/forks/sm-paul-schuette/CVE-2017-12426.svg)


## CVE-2017-12149
 In Jboss Application Server as shipped with Red Hat Enterprise Application Platform 5.2, it was found that the doFilter method in the ReadOnlyAccessFilter of the HTTP Invoker does not restrict classes for which it performs deserialization and thus allowing an attacker to execute arbitrary code via crafted serialized data.

- [https://github.com/yunxu1/jboss-_CVE-2017-12149](https://github.com/yunxu1/jboss-_CVE-2017-12149) :  ![starts](https://img.shields.io/github/stars/yunxu1/jboss-_CVE-2017-12149.svg) ![forks](https://img.shields.io/github/forks/yunxu1/jboss-_CVE-2017-12149.svg)
- [https://github.com/sevck/CVE-2017-12149](https://github.com/sevck/CVE-2017-12149) :  ![starts](https://img.shields.io/github/stars/sevck/CVE-2017-12149.svg) ![forks](https://img.shields.io/github/forks/sevck/CVE-2017-12149.svg)
- [https://github.com/1337g/CVE-2017-12149](https://github.com/1337g/CVE-2017-12149) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-12149.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-12149.svg)
- [https://github.com/jreppiks/CVE-2017-12149](https://github.com/jreppiks/CVE-2017-12149) :  ![starts](https://img.shields.io/github/stars/jreppiks/CVE-2017-12149.svg) ![forks](https://img.shields.io/github/forks/jreppiks/CVE-2017-12149.svg)
- [https://github.com/zesnd/cve-2017-12149](https://github.com/zesnd/cve-2017-12149) :  ![starts](https://img.shields.io/github/stars/zesnd/cve-2017-12149.svg) ![forks](https://img.shields.io/github/forks/zesnd/cve-2017-12149.svg)
- [https://github.com/JesseClarkND/CVE-2017-12149](https://github.com/JesseClarkND/CVE-2017-12149) :  ![starts](https://img.shields.io/github/stars/JesseClarkND/CVE-2017-12149.svg) ![forks](https://img.shields.io/github/forks/JesseClarkND/CVE-2017-12149.svg)
- [https://github.com/VVeakee/CVE-2017-12149](https://github.com/VVeakee/CVE-2017-12149) :  ![starts](https://img.shields.io/github/stars/VVeakee/CVE-2017-12149.svg) ![forks](https://img.shields.io/github/forks/VVeakee/CVE-2017-12149.svg)
- [https://github.com/MrE-Fog/jboss-_CVE-2017-12149](https://github.com/MrE-Fog/jboss-_CVE-2017-12149) :  ![starts](https://img.shields.io/github/stars/MrE-Fog/jboss-_CVE-2017-12149.svg) ![forks](https://img.shields.io/github/forks/MrE-Fog/jboss-_CVE-2017-12149.svg)
- [https://github.com/Xcatolin/jboss-deserialization](https://github.com/Xcatolin/jboss-deserialization) :  ![starts](https://img.shields.io/github/stars/Xcatolin/jboss-deserialization.svg) ![forks](https://img.shields.io/github/forks/Xcatolin/jboss-deserialization.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka "Microsoft Office Memory Corruption Vulnerability". This CVE ID is unique from CVE-2017-11884.

- [https://github.com/Ridter/CVE-2017-11882](https://github.com/Ridter/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/Ridter/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/Ridter/CVE-2017-11882.svg)
- [https://github.com/embedi/CVE-2017-11882](https://github.com/embedi/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/embedi/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/embedi/CVE-2017-11882.svg)
- [https://github.com/rip1s/CVE-2017-11882](https://github.com/rip1s/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/rip1s/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/rip1s/CVE-2017-11882.svg)
- [https://github.com/rxwx/CVE-2018-0802](https://github.com/rxwx/CVE-2018-0802) :  ![starts](https://img.shields.io/github/stars/rxwx/CVE-2018-0802.svg) ![forks](https://img.shields.io/github/forks/rxwx/CVE-2018-0802.svg)
- [https://github.com/Ridter/RTF_11882_0802](https://github.com/Ridter/RTF_11882_0802) :  ![starts](https://img.shields.io/github/stars/Ridter/RTF_11882_0802.svg) ![forks](https://img.shields.io/github/forks/Ridter/RTF_11882_0802.svg)
- [https://github.com/0x09AL/CVE-2017-11882-metasploit](https://github.com/0x09AL/CVE-2017-11882-metasploit) :  ![starts](https://img.shields.io/github/stars/0x09AL/CVE-2017-11882-metasploit.svg) ![forks](https://img.shields.io/github/forks/0x09AL/CVE-2017-11882-metasploit.svg)
- [https://github.com/starnightcyber/CVE-2017-11882](https://github.com/starnightcyber/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/starnightcyber/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/starnightcyber/CVE-2017-11882.svg)
- [https://github.com/BlackMathIT/2017-11882_Generator](https://github.com/BlackMathIT/2017-11882_Generator) :  ![starts](https://img.shields.io/github/stars/BlackMathIT/2017-11882_Generator.svg) ![forks](https://img.shields.io/github/forks/BlackMathIT/2017-11882_Generator.svg)
- [https://github.com/likekabin/CVE-2018-0802_CVE-2017-11882](https://github.com/likekabin/CVE-2018-0802_CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2018-0802_CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2018-0802_CVE-2017-11882.svg)
- [https://github.com/Retr0-code/SignHere](https://github.com/Retr0-code/SignHere) :  ![starts](https://img.shields.io/github/stars/Retr0-code/SignHere.svg) ![forks](https://img.shields.io/github/forks/Retr0-code/SignHere.svg)
- [https://github.com/littlebin404/CVE-2017-11882](https://github.com/littlebin404/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/littlebin404/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/littlebin404/CVE-2017-11882.svg)
- [https://github.com/zhouat/cve-2017-11882](https://github.com/zhouat/cve-2017-11882) :  ![starts](https://img.shields.io/github/stars/zhouat/cve-2017-11882.svg) ![forks](https://img.shields.io/github/forks/zhouat/cve-2017-11882.svg)
- [https://github.com/ChaitanyaHaritash/CVE-2017-11882](https://github.com/ChaitanyaHaritash/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/ChaitanyaHaritash/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/ChaitanyaHaritash/CVE-2017-11882.svg)
- [https://github.com/Shadowshusky/CVE-2017-11882-](https://github.com/Shadowshusky/CVE-2017-11882-) :  ![starts](https://img.shields.io/github/stars/Shadowshusky/CVE-2017-11882-.svg) ![forks](https://img.shields.io/github/forks/Shadowshusky/CVE-2017-11882-.svg)
- [https://github.com/ekgg/Overflow-Demo-CVE-2017-11882](https://github.com/ekgg/Overflow-Demo-CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/ekgg/Overflow-Demo-CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/ekgg/Overflow-Demo-CVE-2017-11882.svg)
- [https://github.com/tzwlhack/CVE-2017-11882](https://github.com/tzwlhack/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/tzwlhack/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/tzwlhack/CVE-2017-11882.svg)
- [https://github.com/Sunqiz/CVE-2017-11882-reproduction](https://github.com/Sunqiz/CVE-2017-11882-reproduction) :  ![starts](https://img.shields.io/github/stars/Sunqiz/CVE-2017-11882-reproduction.svg) ![forks](https://img.shields.io/github/forks/Sunqiz/CVE-2017-11882-reproduction.svg)
- [https://github.com/Abdibimantara/Maldoc-Analysis](https://github.com/Abdibimantara/Maldoc-Analysis) :  ![starts](https://img.shields.io/github/stars/Abdibimantara/Maldoc-Analysis.svg) ![forks](https://img.shields.io/github/forks/Abdibimantara/Maldoc-Analysis.svg)
- [https://github.com/letiencong96/CVE_2017_11882](https://github.com/letiencong96/CVE_2017_11882) :  ![starts](https://img.shields.io/github/stars/letiencong96/CVE_2017_11882.svg) ![forks](https://img.shields.io/github/forks/letiencong96/CVE_2017_11882.svg)
- [https://github.com/HZachev/ABC](https://github.com/HZachev/ABC) :  ![starts](https://img.shields.io/github/stars/HZachev/ABC.svg) ![forks](https://img.shields.io/github/forks/HZachev/ABC.svg)
- [https://github.com/CSC-pentest/cve-2017-11882](https://github.com/CSC-pentest/cve-2017-11882) :  ![starts](https://img.shields.io/github/stars/CSC-pentest/cve-2017-11882.svg) ![forks](https://img.shields.io/github/forks/CSC-pentest/cve-2017-11882.svg)
- [https://github.com/imkidz0/CVE-2017-11882](https://github.com/imkidz0/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/imkidz0/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/imkidz0/CVE-2017-11882.svg)
- [https://github.com/likekabin/CVE-2017-11882](https://github.com/likekabin/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2017-11882.svg)
- [https://github.com/j0lama/CVE-2017-11882](https://github.com/j0lama/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/j0lama/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/j0lama/CVE-2017-11882.svg)
- [https://github.com/HaoJame/CVE-2017-11882](https://github.com/HaoJame/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/HaoJame/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/HaoJame/CVE-2017-11882.svg)
- [https://github.com/nhuynhuy/cve-2017-11882](https://github.com/nhuynhuy/cve-2017-11882) :  ![starts](https://img.shields.io/github/stars/nhuynhuy/cve-2017-11882.svg) ![forks](https://img.shields.io/github/forks/nhuynhuy/cve-2017-11882.svg)
- [https://github.com/ActorExpose/CVE-2017-11882](https://github.com/ActorExpose/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/ActorExpose/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/ActorExpose/CVE-2017-11882.svg)
- [https://github.com/chanbin/CVE-2017-11882](https://github.com/chanbin/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/chanbin/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/chanbin/CVE-2017-11882.svg)
- [https://github.com/yaseenibnakhtar/001-Malware-Analysis-CVE-2017-11882](https://github.com/yaseenibnakhtar/001-Malware-Analysis-CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/yaseenibnakhtar/001-Malware-Analysis-CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/yaseenibnakhtar/001-Malware-Analysis-CVE-2017-11882.svg)
- [https://github.com/Grey-Li/CVE-2017-11882](https://github.com/Grey-Li/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/Grey-Li/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/Grey-Li/CVE-2017-11882.svg)
- [https://github.com/lisinan988/CVE-2017-11882-exp](https://github.com/lisinan988/CVE-2017-11882-exp) :  ![starts](https://img.shields.io/github/stars/lisinan988/CVE-2017-11882-exp.svg) ![forks](https://img.shields.io/github/forks/lisinan988/CVE-2017-11882-exp.svg)
- [https://github.com/xdrake1010/CVE-2017-11882-Preventer](https://github.com/xdrake1010/CVE-2017-11882-Preventer) :  ![starts](https://img.shields.io/github/stars/xdrake1010/CVE-2017-11882-Preventer.svg) ![forks](https://img.shields.io/github/forks/xdrake1010/CVE-2017-11882-Preventer.svg)
- [https://github.com/n18dcat053-luuvannga/DetectPacket-CVE-2017-11882](https://github.com/n18dcat053-luuvannga/DetectPacket-CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/n18dcat053-luuvannga/DetectPacket-CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/n18dcat053-luuvannga/DetectPacket-CVE-2017-11882.svg)
- [https://github.com/legendsec/CVE-2017-11882-for-Kali](https://github.com/legendsec/CVE-2017-11882-for-Kali) :  ![starts](https://img.shields.io/github/stars/legendsec/CVE-2017-11882-for-Kali.svg) ![forks](https://img.shields.io/github/forks/legendsec/CVE-2017-11882-for-Kali.svg)
- [https://github.com/herbiezimmerman/CVE-2017-11882-Possible-Remcos-Malspam](https://github.com/herbiezimmerman/CVE-2017-11882-Possible-Remcos-Malspam) :  ![starts](https://img.shields.io/github/stars/herbiezimmerman/CVE-2017-11882-Possible-Remcos-Malspam.svg) ![forks](https://img.shields.io/github/forks/herbiezimmerman/CVE-2017-11882-Possible-Remcos-Malspam.svg)
- [https://github.com/qy1202/https-github.com-Ridter-CVE-2017-11882-](https://github.com/qy1202/https-github.com-Ridter-CVE-2017-11882-) :  ![starts](https://img.shields.io/github/stars/qy1202/https-github.com-Ridter-CVE-2017-11882-.svg) ![forks](https://img.shields.io/github/forks/qy1202/https-github.com-Ridter-CVE-2017-11882-.svg)
- [https://github.com/davidforis/exp-2024-1213](https://github.com/davidforis/exp-2024-1213) :  ![starts](https://img.shields.io/github/stars/davidforis/exp-2024-1213.svg) ![forks](https://img.shields.io/github/forks/davidforis/exp-2024-1213.svg)
- [https://github.com/jadeapar/Dragonfish-s-Malware-Cyber-Analysis](https://github.com/jadeapar/Dragonfish-s-Malware-Cyber-Analysis) :  ![starts](https://img.shields.io/github/stars/jadeapar/Dragonfish-s-Malware-Cyber-Analysis.svg) ![forks](https://img.shields.io/github/forks/jadeapar/Dragonfish-s-Malware-Cyber-Analysis.svg)


## CVE-2017-11826
 Microsoft Office 2010, SharePoint Enterprise Server 2010, SharePoint Server 2010, Web Applications, Office Web Apps Server 2010 and 2013, Word Viewer, Word 2007, 2010, 2013 and 2016, Word Automation Services, and Office Online Server allow remote code execution when the software fails to properly handle objects in memory.

- [https://github.com/thatskriptkid/CVE-2017-11826](https://github.com/thatskriptkid/CVE-2017-11826) :  ![starts](https://img.shields.io/github/stars/thatskriptkid/CVE-2017-11826.svg) ![forks](https://img.shields.io/github/forks/thatskriptkid/CVE-2017-11826.svg)
- [https://github.com/9aylas/DDE-MS_WORD-Exploit_Detector](https://github.com/9aylas/DDE-MS_WORD-Exploit_Detector) :  ![starts](https://img.shields.io/github/stars/9aylas/DDE-MS_WORD-Exploit_Detector.svg) ![forks](https://img.shields.io/github/forks/9aylas/DDE-MS_WORD-Exploit_Detector.svg)


## CVE-2017-11783
 Microsoft Windows 8.1, Windows Server 2012 R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation of privilege vulnerability in the way it handles calls to Advanced Local Procedure Call (ALPC), aka "Windows Elevation of Privilege Vulnerability".

- [https://github.com/Sheisback/CVE-2017-11783](https://github.com/Sheisback/CVE-2017-11783) :  ![starts](https://img.shields.io/github/stars/Sheisback/CVE-2017-11783.svg) ![forks](https://img.shields.io/github/forks/Sheisback/CVE-2017-11783.svg)


## CVE-2017-11774
 Microsoft Outlook 2010 SP2, Outlook 2013 SP1 and RT SP1, and Outlook 2016 allow an attacker to execute arbitrary commands, due to how Microsoft Office handles objects in memory, aka "Microsoft Outlook Security Feature Bypass Vulnerability."

- [https://github.com/devcoinfet/SniperRoost](https://github.com/devcoinfet/SniperRoost) :  ![starts](https://img.shields.io/github/stars/devcoinfet/SniperRoost.svg) ![forks](https://img.shields.io/github/forks/devcoinfet/SniperRoost.svg)


## CVE-2017-11611
 Wolf CMS 0.8.3.1 allows Cross-Site Scripting (XSS) attacks. The vulnerability exists due to insufficient sanitization of the file name in a "create-file-popup" action, and the directory name in a "create-directory-popup" action, in the HTTP POST method to the "/plugin/file_manager/" script (aka an /admin/plugin/file_manager/browse// URI).

- [https://github.com/faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc](https://github.com/faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc) :  ![starts](https://img.shields.io/github/stars/faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc.svg) ![forks](https://img.shields.io/github/forks/faizzaidi/Wolfcms-v0.8.3.1-xss-POC-by-Provensec-llc.svg)


## CVE-2017-11610
 The XML-RPC server in supervisor before 3.0.1, 3.1.x before 3.1.4, 3.2.x before 3.2.4, and 3.3.x before 3.3.3 allows remote authenticated users to execute arbitrary commands via a crafted XML-RPC request, related to nested supervisord namespace lookups.

- [https://github.com/yaunsky/CVE-2017-11610](https://github.com/yaunsky/CVE-2017-11610) :  ![starts](https://img.shields.io/github/stars/yaunsky/CVE-2017-11610.svg) ![forks](https://img.shields.io/github/forks/yaunsky/CVE-2017-11610.svg)
- [https://github.com/ivanitlearning/CVE-2017-11610](https://github.com/ivanitlearning/CVE-2017-11610) :  ![starts](https://img.shields.io/github/stars/ivanitlearning/CVE-2017-11610.svg) ![forks](https://img.shields.io/github/forks/ivanitlearning/CVE-2017-11610.svg)


## CVE-2017-11427
 OneLogin PythonSAML 2.3.0 and earlier may incorrectly utilize the results of XML DOM traversal and canonicalization APIs in such a way that an attacker may be able to manipulate the SAML data without invalidating the cryptographic signature, allowing the attack to potentially bypass authentication to SAML service providers.

- [https://github.com/CHYbeta/CVE-2017-11427-DEMO](https://github.com/CHYbeta/CVE-2017-11427-DEMO) :  ![starts](https://img.shields.io/github/stars/CHYbeta/CVE-2017-11427-DEMO.svg) ![forks](https://img.shields.io/github/forks/CHYbeta/CVE-2017-11427-DEMO.svg)


## CVE-2017-11357
 Progress Telerik UI for ASP.NET AJAX before R2 2017 SP2 does not properly restrict user input to RadAsyncUpload, which allows remote attackers to perform arbitrary file uploads or execute arbitrary code.

- [https://github.com/bao7uo/RAU_crypto](https://github.com/bao7uo/RAU_crypto) :  ![starts](https://img.shields.io/github/stars/bao7uo/RAU_crypto.svg) ![forks](https://img.shields.io/github/forks/bao7uo/RAU_crypto.svg)


## CVE-2017-11317
 Telerik.Web.UI in Progress Telerik UI for ASP.NET AJAX before R1 2017 and R2 before R2 2017 SP2 uses weak RadAsyncUpload encryption, which allows remote attackers to perform arbitrary file uploads or execute arbitrary code.

- [https://github.com/bao7uo/RAU_crypto](https://github.com/bao7uo/RAU_crypto) :  ![starts](https://img.shields.io/github/stars/bao7uo/RAU_crypto.svg) ![forks](https://img.shields.io/github/forks/bao7uo/RAU_crypto.svg)
- [https://github.com/KasunPriyashan/Unrestricted-File-Upload-by-Weak-Encryption-affected-versions-CVE-2017-11317-Remote-Code-Execut](https://github.com/KasunPriyashan/Unrestricted-File-Upload-by-Weak-Encryption-affected-versions-CVE-2017-11317-Remote-Code-Execut) :  ![starts](https://img.shields.io/github/stars/KasunPriyashan/Unrestricted-File-Upload-by-Weak-Encryption-affected-versions-CVE-2017-11317-Remote-Code-Execut.svg) ![forks](https://img.shields.io/github/forks/KasunPriyashan/Unrestricted-File-Upload-by-Weak-Encryption-affected-versions-CVE-2017-11317-Remote-Code-Execut.svg)
- [https://github.com/KasunPriyashan/Telerik-UI-ASP.NET-AJAX-Exploitation](https://github.com/KasunPriyashan/Telerik-UI-ASP.NET-AJAX-Exploitation) :  ![starts](https://img.shields.io/github/stars/KasunPriyashan/Telerik-UI-ASP.NET-AJAX-Exploitation.svg) ![forks](https://img.shields.io/github/forks/KasunPriyashan/Telerik-UI-ASP.NET-AJAX-Exploitation.svg)


## CVE-2017-10952
 This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Foxit Reader 8.2.0.2051. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the saveAs JavaScript function. The issue results from the lack of proper validation of user-supplied data, which can lead to writing arbitrary files into attacker controlled locations. An attacker can leverage this vulnerability to execute code under the context of the current process. Was ZDI-CAN-4518.

- [https://github.com/afbase/CVE-2017-10952](https://github.com/afbase/CVE-2017-10952) :  ![starts](https://img.shields.io/github/stars/afbase/CVE-2017-10952.svg) ![forks](https://img.shields.io/github/forks/afbase/CVE-2017-10952.svg)


## CVE-2017-10910
 MQTT.js 2.x.x prior to 2.15.0 issue in handling PUBLISH tickets may lead to an attacker causing a denial-of-service condition.

- [https://github.com/ossf-cve-benchmark/CVE-2017-10910](https://github.com/ossf-cve-benchmark/CVE-2017-10910) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-10910.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-10910.svg)


## CVE-2017-10661
 Race condition in fs/timerfd.c in the Linux kernel before 4.10.15 allows local users to gain privileges or cause a denial of service (list corruption or use-after-free) via simultaneous file-descriptor operations that leverage improper might_cancel queueing.

- [https://github.com/GeneBlue/CVE-2017-10661_POC](https://github.com/GeneBlue/CVE-2017-10661_POC) :  ![starts](https://img.shields.io/github/stars/GeneBlue/CVE-2017-10661_POC.svg) ![forks](https://img.shields.io/github/forks/GeneBlue/CVE-2017-10661_POC.svg)


## CVE-2017-10616
 The ifmap service that comes bundled with Juniper Networks Contrail releases uses hard coded credentials. Affected releases are Contrail releases 2.2 prior to 2.21.4; 3.0 prior to 3.0.3.4; 3.1 prior to 3.1.4.0; 3.2 prior to 3.2.5.0. CVE-2017-10616 and CVE-2017-10617 can be chained together and have a combined CVSSv3 score of 5.8 (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N).

- [https://github.com/gteissier/CVE-2017-10617](https://github.com/gteissier/CVE-2017-10617) :  ![starts](https://img.shields.io/github/stars/gteissier/CVE-2017-10617.svg) ![forks](https://img.shields.io/github/forks/gteissier/CVE-2017-10617.svg)


## CVE-2017-10415
 Vulnerability in the Oracle iSupport component of Oracle E-Business Suite (subcomponent: Others). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iSupport. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle iSupport, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle iSupport accessible data as well as unauthorized update, insert or delete access to some of Oracle iSupport accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)


## CVE-2017-10414
 Vulnerability in the Oracle iStore component of Oracle E-Business Suite (subcomponent: Checkout and Order Placement). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iStore. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle iStore, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle iStore accessible data as well as unauthorized update, insert or delete access to some of Oracle iStore accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)


## CVE-2017-10413
 Vulnerability in the Oracle Mobile Field Service component of Oracle E-Business Suite (subcomponent: Multiplatform Based on HTML5). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Mobile Field Service. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Mobile Field Service, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Mobile Field Service accessible data as well as unauthorized update, insert or delete access to some of Oracle Mobile Field Service accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)


## CVE-2017-10412
 Vulnerability in the Oracle Knowledge Management component of Oracle E-Business Suite (subcomponent: User Interface). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Knowledge Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Knowledge Management accessible data as well as unauthorized update, insert or delete access to some of Oracle Knowledge Management accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)


## CVE-2017-10411
 Vulnerability in the Oracle Knowledge Management component of Oracle E-Business Suite (subcomponent: User Interface). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Knowledge Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Knowledge Management accessible data as well as unauthorized update, insert or delete access to some of Oracle Knowledge Management accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)


## CVE-2017-10410
 Vulnerability in the Oracle Knowledge Management component of Oracle E-Business Suite (subcomponent: Search). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Knowledge Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Knowledge Management accessible data as well as unauthorized update, insert or delete access to some of Oracle Knowledge Management accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)


## CVE-2017-10409
 Vulnerability in the Oracle iStore component of Oracle E-Business Suite (subcomponent: Merchant UI). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iStore. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle iStore, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle iStore accessible data as well as unauthorized update, insert or delete access to some of Oracle iStore accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)


## CVE-2017-10366
 Vulnerability in the PeopleSoft Enterprise PT PeopleTools component of Oracle PeopleSoft Products (subcomponent: Performance Monitor). Supported versions that are affected are 8.54, 8.55 and 8.56. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PT PeopleTools. Successful attacks of this vulnerability can result in takeover of PeopleSoft Enterprise PT PeopleTools. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)
- [https://github.com/blazeinfosec/CVE-2017-10366_peoplesoft](https://github.com/blazeinfosec/CVE-2017-10366_peoplesoft) :  ![starts](https://img.shields.io/github/stars/blazeinfosec/CVE-2017-10366_peoplesoft.svg) ![forks](https://img.shields.io/github/forks/blazeinfosec/CVE-2017-10366_peoplesoft.svg)


## CVE-2017-10352
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS - Web Services). The supported version that is affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0, 12.2.1.2.0 and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server as well as unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data and unauthorized read access to a subset of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 9.9 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H).

- [https://github.com/bigsizeme/weblogic-XMLDecoder](https://github.com/bigsizeme/weblogic-XMLDecoder) :  ![starts](https://img.shields.io/github/stars/bigsizeme/weblogic-XMLDecoder.svg) ![forks](https://img.shields.io/github/forks/bigsizeme/weblogic-XMLDecoder.svg)


## CVE-2017-10235
 Vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core). The supported version that is affected is Prior to 5.1.24. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox as well as unauthorized update, insert or delete access to some of Oracle VM VirtualBox accessible data. CVSS 3.0 Base Score 6.7 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H).

- [https://github.com/fundacion-sadosky/vbox_cve_2017_10235](https://github.com/fundacion-sadosky/vbox_cve_2017_10235) :  ![starts](https://img.shields.io/github/stars/fundacion-sadosky/vbox_cve_2017_10235.svg) ![forks](https://img.shields.io/github/forks/fundacion-sadosky/vbox_cve_2017_10235.svg)


## CVE-2017-10148
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.1 and 12.2.1.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 5.8 (Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N). NOTE: the previous information is from the July 2017 CPU. Oracle has not commented on third-party claims that this issue allows remote attackers to inject special data into log files via a crafted T3 request.

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)


## CVE-2017-10147
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.1 and 12.2.1.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server. CVSS 3.0 Base Score 8.6 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H). NOTE: the previous information is from the July 2017 CPU. Oracle has not commented on third-party claims that this issue exists in the migrate functionality in the WebLogic/cluster/singleton/ServerMigrationCoordinator class and allows remote attackers to shutdown the server via a crafted T3 request.

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)


## CVE-2017-9999
 DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: none.  Reason: This candidate was used as an example and was not assigned for a  security issue.  Notes: none

- [https://github.com/homjxi0e/CVE-2017-9999_bypassing_General_Firefox](https://github.com/homjxi0e/CVE-2017-9999_bypassing_General_Firefox) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-9999_bypassing_General_Firefox.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-9999_bypassing_General_Firefox.svg)


## CVE-2017-9947
 A vulnerability has been identified in Siemens APOGEE PXC and TALON TC BACnet Automation Controllers in all versions V3.5. A directory traversal vulnerability could allow a remote attacker with network access to the integrated web server (80/tcp and 443/tcp) to obtain information on the structure of the file system of the affected devices.

- [https://github.com/RoseSecurity/APOLOGEE](https://github.com/RoseSecurity/APOLOGEE) :  ![starts](https://img.shields.io/github/stars/RoseSecurity/APOLOGEE.svg) ![forks](https://img.shields.io/github/forks/RoseSecurity/APOLOGEE.svg)


## CVE-2017-9934
 Missing CSRF token checks and improper input validation in Joomla! CMS 1.7.3 through 3.7.2 lead to an XSS vulnerability.

- [https://github.com/xyringe/CVE-2017-9934](https://github.com/xyringe/CVE-2017-9934) :  ![starts](https://img.shields.io/github/stars/xyringe/CVE-2017-9934.svg) ![forks](https://img.shields.io/github/forks/xyringe/CVE-2017-9934.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/RandomRobbieBF/phpunit-brute](https://github.com/RandomRobbieBF/phpunit-brute) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/phpunit-brute.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/phpunit-brute.svg)
- [https://github.com/incogbyte/laravel-phpunit-rce-masscaner](https://github.com/incogbyte/laravel-phpunit-rce-masscaner) :  ![starts](https://img.shields.io/github/stars/incogbyte/laravel-phpunit-rce-masscaner.svg) ![forks](https://img.shields.io/github/forks/incogbyte/laravel-phpunit-rce-masscaner.svg)
- [https://github.com/ludy-dev/PHPUnit_eval-stdin_RCE](https://github.com/ludy-dev/PHPUnit_eval-stdin_RCE) :  ![starts](https://img.shields.io/github/stars/ludy-dev/PHPUnit_eval-stdin_RCE.svg) ![forks](https://img.shields.io/github/forks/ludy-dev/PHPUnit_eval-stdin_RCE.svg)
- [https://github.com/MadExploits/PHPunit-Exploit](https://github.com/MadExploits/PHPunit-Exploit) :  ![starts](https://img.shields.io/github/stars/MadExploits/PHPunit-Exploit.svg) ![forks](https://img.shields.io/github/forks/MadExploits/PHPunit-Exploit.svg)
- [https://github.com/Chocapikk/CVE-2017-9841](https://github.com/Chocapikk/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2017-9841.svg)
- [https://github.com/MrG3P5/CVE-2017-9841](https://github.com/MrG3P5/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/MrG3P5/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/MrG3P5/CVE-2017-9841.svg)
- [https://github.com/akr3ch/CVE-2017-9841](https://github.com/akr3ch/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/akr3ch/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/akr3ch/CVE-2017-9841.svg)
- [https://github.com/p1ckzi/CVE-2017-9841](https://github.com/p1ckzi/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/p1ckzi/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/p1ckzi/CVE-2017-9841.svg)
- [https://github.com/K3ysTr0K3R/CVE-2017-9841-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-9841-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-9841-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-9841-EXPLOIT.svg)
- [https://github.com/dream434/CVE-2017-9841](https://github.com/dream434/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/dream434/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/dream434/CVE-2017-9841.svg)
- [https://github.com/mbrasile/CVE-2017-9841](https://github.com/mbrasile/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/mbrasile/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/mbrasile/CVE-2017-9841.svg)
- [https://github.com/jax7sec/CVE-2017-9841](https://github.com/jax7sec/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/jax7sec/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/jax7sec/CVE-2017-9841.svg)
- [https://github.com/cyberharsh/Php-unit-CVE-2017-9841](https://github.com/cyberharsh/Php-unit-CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/cyberharsh/Php-unit-CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/Php-unit-CVE-2017-9841.svg)
- [https://github.com/mileticluka1/eval-stdin](https://github.com/mileticluka1/eval-stdin) :  ![starts](https://img.shields.io/github/stars/mileticluka1/eval-stdin.svg) ![forks](https://img.shields.io/github/forks/mileticluka1/eval-stdin.svg)
- [https://github.com/joelindra/Argus](https://github.com/joelindra/Argus) :  ![starts](https://img.shields.io/github/stars/joelindra/Argus.svg) ![forks](https://img.shields.io/github/forks/joelindra/Argus.svg)


## CVE-2017-9833
 /cgi-bin/wapopen in Boa 0.94.14rc21 allows the injection of "../.." using the FILECAMERA variable (sent by GET) to read files with root privileges. NOTE: multiple third parties report that this is a system-integrator issue (e.g., a vulnerability on one type of camera) because Boa does not include any wapopen program or any code to read a FILECAMERA variable.

- [https://github.com/anldori/CVE-2017-9833](https://github.com/anldori/CVE-2017-9833) :  ![starts](https://img.shields.io/github/stars/anldori/CVE-2017-9833.svg) ![forks](https://img.shields.io/github/forks/anldori/CVE-2017-9833.svg)


## CVE-2017-9822
 DNN (aka DotNetNuke) before 9.1.1 has Remote Code Execution via a cookie, aka "2017-08 (Critical) Possible remote code execution on DNN sites."

- [https://github.com/murataydemir/CVE-2017-9822](https://github.com/murataydemir/CVE-2017-9822) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2017-9822.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2017-9822.svg)


## CVE-2017-9805
 The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.

- [https://github.com/mazen160/struts-pwn_CVE-2017-9805](https://github.com/mazen160/struts-pwn_CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/mazen160/struts-pwn_CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/mazen160/struts-pwn_CVE-2017-9805.svg)
- [https://github.com/luc10/struts-rce-cve-2017-9805](https://github.com/luc10/struts-rce-cve-2017-9805) :  ![starts](https://img.shields.io/github/stars/luc10/struts-rce-cve-2017-9805.svg) ![forks](https://img.shields.io/github/forks/luc10/struts-rce-cve-2017-9805.svg)
- [https://github.com/chrisjd20/cve-2017-9805.py](https://github.com/chrisjd20/cve-2017-9805.py) :  ![starts](https://img.shields.io/github/stars/chrisjd20/cve-2017-9805.py.svg) ![forks](https://img.shields.io/github/forks/chrisjd20/cve-2017-9805.py.svg)
- [https://github.com/0x00-0x00/-CVE-2017-9805](https://github.com/0x00-0x00/-CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/-CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/-CVE-2017-9805.svg)
- [https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805](https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/Lone-Ranger/apache-struts-pwn_CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/Lone-Ranger/apache-struts-pwn_CVE-2017-9805.svg)
- [https://github.com/hahwul/struts2-rce-cve-2017-9805-ruby](https://github.com/hahwul/struts2-rce-cve-2017-9805-ruby) :  ![starts](https://img.shields.io/github/stars/hahwul/struts2-rce-cve-2017-9805-ruby.svg) ![forks](https://img.shields.io/github/forks/hahwul/struts2-rce-cve-2017-9805-ruby.svg)
- [https://github.com/Shakun8/CVE-2017-9805](https://github.com/Shakun8/CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/Shakun8/CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/Shakun8/CVE-2017-9805.svg)
- [https://github.com/0xd3vil/CVE-2017-9805-Exploit](https://github.com/0xd3vil/CVE-2017-9805-Exploit) :  ![starts](https://img.shields.io/github/stars/0xd3vil/CVE-2017-9805-Exploit.svg) ![forks](https://img.shields.io/github/forks/0xd3vil/CVE-2017-9805-Exploit.svg)
- [https://github.com/BeyondCy/S2-052](https://github.com/BeyondCy/S2-052) :  ![starts](https://img.shields.io/github/stars/BeyondCy/S2-052.svg) ![forks](https://img.shields.io/github/forks/BeyondCy/S2-052.svg)
- [https://github.com/jongmartinez/-CVE-2017-9805-](https://github.com/jongmartinez/-CVE-2017-9805-) :  ![starts](https://img.shields.io/github/stars/jongmartinez/-CVE-2017-9805-.svg) ![forks](https://img.shields.io/github/forks/jongmartinez/-CVE-2017-9805-.svg)
- [https://github.com/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-](https://github.com/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-) :  ![starts](https://img.shields.io/github/stars/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-.svg) ![forks](https://img.shields.io/github/forks/UbuntuStrike/struts_rest_rce_fuzz-CVE-2017-9805-.svg)
- [https://github.com/z3bd/CVE-2017-9805](https://github.com/z3bd/CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/z3bd/CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/z3bd/CVE-2017-9805.svg)
- [https://github.com/wifido/CVE-2017-9805-Exploit](https://github.com/wifido/CVE-2017-9805-Exploit) :  ![starts](https://img.shields.io/github/stars/wifido/CVE-2017-9805-Exploit.svg) ![forks](https://img.shields.io/github/forks/wifido/CVE-2017-9805-Exploit.svg)
- [https://github.com/rvermeulen/apache-struts-cve-2017-9805](https://github.com/rvermeulen/apache-struts-cve-2017-9805) :  ![starts](https://img.shields.io/github/stars/rvermeulen/apache-struts-cve-2017-9805.svg) ![forks](https://img.shields.io/github/forks/rvermeulen/apache-struts-cve-2017-9805.svg)
- [https://github.com/sujithvaddi/apache_struts_cve_2017_9805](https://github.com/sujithvaddi/apache_struts_cve_2017_9805) :  ![starts](https://img.shields.io/github/stars/sujithvaddi/apache_struts_cve_2017_9805.svg) ![forks](https://img.shields.io/github/forks/sujithvaddi/apache_struts_cve_2017_9805.svg)
- [https://github.com/AvishkaSenadheera/CVE-2017-9805---Documentation---IT19143378](https://github.com/AvishkaSenadheera/CVE-2017-9805---Documentation---IT19143378) :  ![starts](https://img.shields.io/github/stars/AvishkaSenadheera/CVE-2017-9805---Documentation---IT19143378.svg) ![forks](https://img.shields.io/github/forks/AvishkaSenadheera/CVE-2017-9805---Documentation---IT19143378.svg)
- [https://github.com/UbuntuStrike/CVE-2017-9805-Apache-Struts-Fuzz-N-Sploit](https://github.com/UbuntuStrike/CVE-2017-9805-Apache-Struts-Fuzz-N-Sploit) :  ![starts](https://img.shields.io/github/stars/UbuntuStrike/CVE-2017-9805-Apache-Struts-Fuzz-N-Sploit.svg) ![forks](https://img.shields.io/github/forks/UbuntuStrike/CVE-2017-9805-Apache-Struts-Fuzz-N-Sploit.svg)


## CVE-2017-9798
 Apache httpd allows remote attackers to read secret data from process memory if the Limit directive can be set in a user's .htaccess file, or if httpd.conf has certain misconfigurations, aka Optionsbleed. This affects the Apache HTTP Server through 2.2.34 and 2.4.x through 2.4.27. The attacker sends an unauthenticated OPTIONS HTTP request when attempting to read secret data. This is a use-after-free issue and thus secret data is not always sent, and the specific data depends on many factors including configuration. Exploitation with .htaccess can be blocked with a patch to the ap_limit_section function in server/core.c.

- [https://github.com/brokensound77/OptionsBleed-POC-Scanner](https://github.com/brokensound77/OptionsBleed-POC-Scanner) :  ![starts](https://img.shields.io/github/stars/brokensound77/OptionsBleed-POC-Scanner.svg) ![forks](https://img.shields.io/github/forks/brokensound77/OptionsBleed-POC-Scanner.svg)
- [https://github.com/nitrado/CVE-2017-9798](https://github.com/nitrado/CVE-2017-9798) :  ![starts](https://img.shields.io/github/stars/nitrado/CVE-2017-9798.svg) ![forks](https://img.shields.io/github/forks/nitrado/CVE-2017-9798.svg)
- [https://github.com/pabloec20/optionsbleed](https://github.com/pabloec20/optionsbleed) :  ![starts](https://img.shields.io/github/stars/pabloec20/optionsbleed.svg) ![forks](https://img.shields.io/github/forks/pabloec20/optionsbleed.svg)
- [https://github.com/l0n3rs/CVE-2017-9798](https://github.com/l0n3rs/CVE-2017-9798) :  ![starts](https://img.shields.io/github/stars/l0n3rs/CVE-2017-9798.svg) ![forks](https://img.shields.io/github/forks/l0n3rs/CVE-2017-9798.svg)


## CVE-2017-9791
 The Struts 1 plugin in Apache Struts 2.1.x and 2.3.x might allow remote code execution via a malicious field value passed in a raw message to the ActionMessage.

- [https://github.com/dragoneeg/Struts2-048](https://github.com/dragoneeg/Struts2-048) :  ![starts](https://img.shields.io/github/stars/dragoneeg/Struts2-048.svg) ![forks](https://img.shields.io/github/forks/dragoneeg/Struts2-048.svg)
- [https://github.com/IanSmith123/s2-048](https://github.com/IanSmith123/s2-048) :  ![starts](https://img.shields.io/github/stars/IanSmith123/s2-048.svg) ![forks](https://img.shields.io/github/forks/IanSmith123/s2-048.svg)
- [https://github.com/gh0st27/Struts2Scanner](https://github.com/gh0st27/Struts2Scanner) :  ![starts](https://img.shields.io/github/stars/gh0st27/Struts2Scanner.svg) ![forks](https://img.shields.io/github/forks/gh0st27/Struts2Scanner.svg)
- [https://github.com/xfer0/CVE-2017-9791](https://github.com/xfer0/CVE-2017-9791) :  ![starts](https://img.shields.io/github/stars/xfer0/CVE-2017-9791.svg) ![forks](https://img.shields.io/github/forks/xfer0/CVE-2017-9791.svg)


## CVE-2017-9779
 OCaml compiler allows attackers to have unspecified impact via unknown vectors, a similar issue to CVE-2017-9772 "but with much less impact."

- [https://github.com/homjxi0e/CVE-2017-9779](https://github.com/homjxi0e/CVE-2017-9779) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-9779.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-9779.svg)


## CVE-2017-9769
 A specially crafted IOCTL can be issued to the rzpnk.sys driver in Razer Synapse 2.20.15.1104 that is forwarded to ZwOpenProcess allowing a handle to be opened to an arbitrary process.

- [https://github.com/kkent030315/CVE-2017-9769](https://github.com/kkent030315/CVE-2017-9769) :  ![starts](https://img.shields.io/github/stars/kkent030315/CVE-2017-9769.svg) ![forks](https://img.shields.io/github/forks/kkent030315/CVE-2017-9769.svg)


## CVE-2017-9757
 IPFire 2.19 has a Remote Command Injection vulnerability in ids.cgi via the OINKCODE parameter, which is mishandled by a shell. This can be exploited directly by authenticated users, or through CSRF.

- [https://github.com/peterleiva/CVE-2017-9757](https://github.com/peterleiva/CVE-2017-9757) :  ![starts](https://img.shields.io/github/stars/peterleiva/CVE-2017-9757.svg) ![forks](https://img.shields.io/github/forks/peterleiva/CVE-2017-9757.svg)


## CVE-2017-9631
 A Null Pointer Dereference issue was discovered in Schneider Electric Wonderware ArchestrA Logger, versions 2017.426.2307.1 and prior. The null pointer dereference vulnerability could allow an attacker to crash the logger process, causing a denial of service for logging and log-viewing (applications that use the Wonderware ArchestrA Logger continue to run when the Wonderware ArchestrA Logger service is unavailable).

- [https://github.com/USSCltd/aaLogger](https://github.com/USSCltd/aaLogger) :  ![starts](https://img.shields.io/github/stars/USSCltd/aaLogger.svg) ![forks](https://img.shields.io/github/forks/USSCltd/aaLogger.svg)


## CVE-2017-9629
 A Stack-Based Buffer Overflow issue was discovered in Schneider Electric Wonderware ArchestrA Logger, versions 2017.426.2307.1 and prior. The stack-based buffer overflow vulnerability has been identified, which may allow a remote attacker to execute arbitrary code in the context of a highly privileged account.

- [https://github.com/USSCltd/aaLogger](https://github.com/USSCltd/aaLogger) :  ![starts](https://img.shields.io/github/stars/USSCltd/aaLogger.svg) ![forks](https://img.shields.io/github/forks/USSCltd/aaLogger.svg)


## CVE-2017-9608
 The dnxhd decoder in FFmpeg before 3.2.6, and 3.3.x before 3.3.3 allows remote attackers to cause a denial of service (NULL pointer dereference) via a crafted mov file.

- [https://github.com/LaCinquette/practice-22-23](https://github.com/LaCinquette/practice-22-23) :  ![starts](https://img.shields.io/github/stars/LaCinquette/practice-22-23.svg) ![forks](https://img.shields.io/github/forks/LaCinquette/practice-22-23.svg)


## CVE-2017-9606
 Infotecs ViPNet Client and Coordinator before 4.3.2-42442 allow local users to gain privileges by placing a Trojan horse ViPNet update file in the update folder. The attack succeeds because of incorrect folder permissions in conjunction with a lack of integrity and authenticity checks.

- [https://github.com/Houl777/CVE-2017-9606](https://github.com/Houl777/CVE-2017-9606) :  ![starts](https://img.shields.io/github/stars/Houl777/CVE-2017-9606.svg) ![forks](https://img.shields.io/github/forks/Houl777/CVE-2017-9606.svg)


## CVE-2017-9554
 An information exposure vulnerability in forget_passwd.cgi in Synology DiskStation Manager (DSM) before 6.1.3-15152 allows remote attackers to enumerate valid usernames via unspecified vectors.

- [https://github.com/rfcl/Synology-DiskStation-User-Enumeration-CVE-2017-9554-](https://github.com/rfcl/Synology-DiskStation-User-Enumeration-CVE-2017-9554-) :  ![starts](https://img.shields.io/github/stars/rfcl/Synology-DiskStation-User-Enumeration-CVE-2017-9554-.svg) ![forks](https://img.shields.io/github/forks/rfcl/Synology-DiskStation-User-Enumeration-CVE-2017-9554-.svg)
- [https://github.com/Ez0-yf/CVE-2017-9554-Exploit-Tool](https://github.com/Ez0-yf/CVE-2017-9554-Exploit-Tool) :  ![starts](https://img.shields.io/github/stars/Ez0-yf/CVE-2017-9554-Exploit-Tool.svg) ![forks](https://img.shields.io/github/forks/Ez0-yf/CVE-2017-9554-Exploit-Tool.svg)


## CVE-2017-9544
 There is a remote stack-based buffer overflow (SEH) in register.ghp in EFS Software Easy Chat Server versions 2.0 to 3.1. By sending an overly long username string to registresult.htm for registering the user, an attacker may be able to execute arbitrary code.

- [https://github.com/adenkiewicz/CVE-2017-9544](https://github.com/adenkiewicz/CVE-2017-9544) :  ![starts](https://img.shields.io/github/stars/adenkiewicz/CVE-2017-9544.svg) ![forks](https://img.shields.io/github/forks/adenkiewicz/CVE-2017-9544.svg)


## CVE-2017-9506
 The IconUriServlet of the Atlassian OAuth Plugin from version 1.3.0 before version 1.9.12 and from version 2.0.0 before version 2.0.4 allows remote attackers to access the content of internal network resources and/or perform an XSS attack via Server Side Request Forgery (SSRF).

- [https://github.com/random-robbie/Jira-Scan](https://github.com/random-robbie/Jira-Scan) :  ![starts](https://img.shields.io/github/stars/random-robbie/Jira-Scan.svg) ![forks](https://img.shields.io/github/forks/random-robbie/Jira-Scan.svg)
- [https://github.com/labsbots/CVE-2017-9506](https://github.com/labsbots/CVE-2017-9506) :  ![starts](https://img.shields.io/github/stars/labsbots/CVE-2017-9506.svg) ![forks](https://img.shields.io/github/forks/labsbots/CVE-2017-9506.svg)
- [https://github.com/pwn1sher/jira-ssrf](https://github.com/pwn1sher/jira-ssrf) :  ![starts](https://img.shields.io/github/stars/pwn1sher/jira-ssrf.svg) ![forks](https://img.shields.io/github/forks/pwn1sher/jira-ssrf.svg)


## CVE-2017-9476
 The Comcast firmware on Cisco DPC3939 (firmware version dpc3939-P20-18-v303r20421733-160420a-CMCST); Cisco DPC3939 (firmware version dpc3939-P20-18-v303r20421746-170221a-CMCST); and Arris TG1682G (eMTA&DOCSIS version 10.0.132.SIP.PC20.CT, software version TG1682_2.2p7s2_PROD_sey) devices makes it easy for remote attackers to determine the hidden SSID and passphrase for a Home Security Wi-Fi network.

- [https://github.com/wiire-a/CVE-2017-9476](https://github.com/wiire-a/CVE-2017-9476) :  ![starts](https://img.shields.io/github/stars/wiire-a/CVE-2017-9476.svg) ![forks](https://img.shields.io/github/forks/wiire-a/CVE-2017-9476.svg)


## CVE-2017-9430
 Stack-based buffer overflow in dnstracer through 1.9 allows attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a command line with a long name argument that is mishandled in a strcpy call for argv[0]. An example threat model is a web application that launches dnstracer with an untrusted name string.

- [https://github.com/j0lama/Dnstracer-1.9-Fix](https://github.com/j0lama/Dnstracer-1.9-Fix) :  ![starts](https://img.shields.io/github/stars/j0lama/Dnstracer-1.9-Fix.svg) ![forks](https://img.shields.io/github/forks/j0lama/Dnstracer-1.9-Fix.svg)
- [https://github.com/homjxi0e/CVE-2017-9430](https://github.com/homjxi0e/CVE-2017-9430) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-9430.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-9430.svg)


## CVE-2017-9417
 Broadcom BCM43xx Wi-Fi chips allow remote attackers to execute arbitrary code via unspecified vectors, aka the "Broadpwn" issue.

- [https://github.com/mailinneberg/Broadpwn](https://github.com/mailinneberg/Broadpwn) :  ![starts](https://img.shields.io/github/stars/mailinneberg/Broadpwn.svg) ![forks](https://img.shields.io/github/forks/mailinneberg/Broadpwn.svg)


## CVE-2017-9248
 Telerik.Web.UI.dll in Progress Telerik UI for ASP.NET AJAX before R2 2017 SP1 and Sitefinity before 10.0.6412.0 does not properly protect Telerik.Web.UI.DialogParametersEncryptionKey or the MachineKey, which makes it easier for remote attackers to defeat cryptographic protection mechanisms, leading to a MachineKey leak, arbitrary file uploads or downloads, XSS, or ASP.NET ViewState compromise.

- [https://github.com/bao7uo/dp_crypto](https://github.com/bao7uo/dp_crypto) :  ![starts](https://img.shields.io/github/stars/bao7uo/dp_crypto.svg) ![forks](https://img.shields.io/github/forks/bao7uo/dp_crypto.svg)
- [https://github.com/capt-meelo/Telewreck](https://github.com/capt-meelo/Telewreck) :  ![starts](https://img.shields.io/github/stars/capt-meelo/Telewreck.svg) ![forks](https://img.shields.io/github/forks/capt-meelo/Telewreck.svg)
- [https://github.com/blacklanternsecurity/dp_cryptomg](https://github.com/blacklanternsecurity/dp_cryptomg) :  ![starts](https://img.shields.io/github/stars/blacklanternsecurity/dp_cryptomg.svg) ![forks](https://img.shields.io/github/forks/blacklanternsecurity/dp_cryptomg.svg)
- [https://github.com/0xsharz/telerik-scanner-cve-2017-9248](https://github.com/0xsharz/telerik-scanner-cve-2017-9248) :  ![starts](https://img.shields.io/github/stars/0xsharz/telerik-scanner-cve-2017-9248.svg) ![forks](https://img.shields.io/github/forks/0xsharz/telerik-scanner-cve-2017-9248.svg)
- [https://github.com/ictnamanh/CVE-2017-9248](https://github.com/ictnamanh/CVE-2017-9248) :  ![starts](https://img.shields.io/github/stars/ictnamanh/CVE-2017-9248.svg) ![forks](https://img.shields.io/github/forks/ictnamanh/CVE-2017-9248.svg)
- [https://github.com/cehamod/UI_CVE-2017-9248](https://github.com/cehamod/UI_CVE-2017-9248) :  ![starts](https://img.shields.io/github/stars/cehamod/UI_CVE-2017-9248.svg) ![forks](https://img.shields.io/github/forks/cehamod/UI_CVE-2017-9248.svg)
- [https://github.com/oldboysonnt/dp](https://github.com/oldboysonnt/dp) :  ![starts](https://img.shields.io/github/stars/oldboysonnt/dp.svg) ![forks](https://img.shields.io/github/forks/oldboysonnt/dp.svg)


## CVE-2017-9101
 import.php (aka the Phonebook import feature) in PlaySMS 1.4 allows remote code execution via vectors involving the User-Agent HTTP header and PHP code in the name of a file.

- [https://github.com/jasperla/CVE-2017-9101](https://github.com/jasperla/CVE-2017-9101) :  ![starts](https://img.shields.io/github/stars/jasperla/CVE-2017-9101.svg) ![forks](https://img.shields.io/github/forks/jasperla/CVE-2017-9101.svg)


## CVE-2017-9096
 The XML parsers in iText before 5.5.12 and 7.x before 7.0.3 do not disable external entities, which might allow remote attackers to conduct XML external entity (XXE) attacks via a crafted PDF.

- [https://github.com/jakabakos/CVE-2017-9096-iText-XXE](https://github.com/jakabakos/CVE-2017-9096-iText-XXE) :  ![starts](https://img.shields.io/github/stars/jakabakos/CVE-2017-9096-iText-XXE.svg) ![forks](https://img.shields.io/github/forks/jakabakos/CVE-2017-9096-iText-XXE.svg)


## CVE-2017-8890
 The inet_csk_clone_lock function in net/ipv4/inet_connection_sock.c in the Linux kernel through 4.10.15 allows attackers to cause a denial of service (double free) or possibly have unspecified other impact by leveraging use of the accept system call.

- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)
- [https://github.com/thinkycx/CVE-2017-8890](https://github.com/thinkycx/CVE-2017-8890) :  ![starts](https://img.shields.io/github/stars/thinkycx/CVE-2017-8890.svg) ![forks](https://img.shields.io/github/forks/thinkycx/CVE-2017-8890.svg)
- [https://github.com/beraphin/CVE-2017-8890](https://github.com/beraphin/CVE-2017-8890) :  ![starts](https://img.shields.io/github/stars/beraphin/CVE-2017-8890.svg) ![forks](https://img.shields.io/github/forks/beraphin/CVE-2017-8890.svg)
- [https://github.com/7043mcgeep/cve-2017-8890-msf](https://github.com/7043mcgeep/cve-2017-8890-msf) :  ![starts](https://img.shields.io/github/stars/7043mcgeep/cve-2017-8890-msf.svg) ![forks](https://img.shields.io/github/forks/7043mcgeep/cve-2017-8890-msf.svg)


## CVE-2017-8869
 Buffer overflow in MediaCoder 0.8.48.5888 allows remote attackers to execute arbitrary code via a crafted .m3u file.

- [https://github.com/tankist0x01/CVE-2017-8869](https://github.com/tankist0x01/CVE-2017-8869) :  ![starts](https://img.shields.io/github/stars/tankist0x01/CVE-2017-8869.svg) ![forks](https://img.shields.io/github/forks/tankist0x01/CVE-2017-8869.svg)


## CVE-2017-8779
 rpcbind through 0.2.4, LIBTIRPC through 1.0.1 and 1.0.2-rc through 1.0.2-rc3, and NTIRPC through 1.4.3 do not consider the maximum RPC data size during memory allocation for XDR strings, which allows remote attackers to cause a denial of service (memory consumption with no subsequent free) via a crafted UDP packet to port 111, aka rpcbomb.

- [https://github.com/drbothen/GO-RPCBOMB](https://github.com/drbothen/GO-RPCBOMB) :  ![starts](https://img.shields.io/github/stars/drbothen/GO-RPCBOMB.svg) ![forks](https://img.shields.io/github/forks/drbothen/GO-RPCBOMB.svg)


## CVE-2017-8760
 An issue was discovered on Accellion FTA devices before FTA_9_12_180. There is XSS in courier/1000@/index.html with the auth_params parameter. The device tries to use internal WAF filters to stop specific XSS Vulnerabilities. However, these can be bypassed by using some modifications to the payloads, e.g., URL encoding.

- [https://github.com/Voraka/cve-2017-8760](https://github.com/Voraka/cve-2017-8760) :  ![starts](https://img.shields.io/github/stars/Voraka/cve-2017-8760.svg) ![forks](https://img.shields.io/github/forks/Voraka/cve-2017-8760.svg)


## CVE-2017-8641
 Microsoft browsers in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allow an attacker to execute arbitrary code in the context of the current user due to the way that Microsoft browser JavaScript engines render when handling objects in memory, aka "Scripting Engine Memory Corruption Vulnerability". This CVE ID is unique from CVE-2017-8634, CVE-2017-8635, CVE-2017-8636, CVE-2017-8638, CVE-2017-8639, CVE-2017-8640, CVE-2017-8645, CVE-2017-8646, CVE-2017-8647, CVE-2017-8655, CVE-2017-8656, CVE-2017-8657, CVE-2017-8670, CVE-2017-8671, CVE-2017-8672, and CVE-2017-8674.

- [https://github.com/homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject](https://github.com/homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-8641_chakra_Js_GlobalObject.svg)


## CVE-2017-8625
 Internet Explorer in Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows an attacker to bypass Device Guard User Mode Code Integrity (UMCI) policies due to Internet Explorer failing to validate UMCI policies, aka "Internet Explorer Security Feature Bypass Vulnerability".

- [https://github.com/homjxi0e/CVE-2017-8625_Bypass_UMCI](https://github.com/homjxi0e/CVE-2017-8625_Bypass_UMCI) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-8625_Bypass_UMCI.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-8625_Bypass_UMCI.svg)


## CVE-2017-8529
 Internet Explorer in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8.1 and Windows RT 8.1, and Windows Server 2012 and R2 allow an attacker to detect specific files on the user's computer when affected Microsoft scripting engines do not properly handle objects in memory, aka "Microsoft Browser Information Disclosure Vulnerability".

- [https://github.com/sfitpro/cve-2017-8529](https://github.com/sfitpro/cve-2017-8529) :  ![starts](https://img.shields.io/github/stars/sfitpro/cve-2017-8529.svg) ![forks](https://img.shields.io/github/forks/sfitpro/cve-2017-8529.svg)
- [https://github.com/kaddirov/windows2016fixCVE-2017-8529](https://github.com/kaddirov/windows2016fixCVE-2017-8529) :  ![starts](https://img.shields.io/github/stars/kaddirov/windows2016fixCVE-2017-8529.svg) ![forks](https://img.shields.io/github/forks/kaddirov/windows2016fixCVE-2017-8529.svg)


## CVE-2017-8465
 Microsoft Windows 8.1 and Windows RT 8.1, Windows Server 2012 R2, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allow an attacker to run processes in an elevated context when the Windows kernel improperly handles objects in memory, aka "Win32k Elevation of Privilege Vulnerability." This CVE ID is unique from CVE-2017-8468.

- [https://github.com/nghiadt1098/CVE-2017-8465](https://github.com/nghiadt1098/CVE-2017-8465) :  ![starts](https://img.shields.io/github/stars/nghiadt1098/CVE-2017-8465.svg) ![forks](https://img.shields.io/github/forks/nghiadt1098/CVE-2017-8465.svg)


## CVE-2017-8382
 admidio 3.2.8 has CSRF in adm_program/modules/members/members_function.php with an impact of deleting arbitrary user accounts.

- [https://github.com/faizzaidi/Admidio-3.2.8-CSRF-POC-by-Provensec-llc](https://github.com/faizzaidi/Admidio-3.2.8-CSRF-POC-by-Provensec-llc) :  ![starts](https://img.shields.io/github/stars/faizzaidi/Admidio-3.2.8-CSRF-POC-by-Provensec-llc.svg) ![forks](https://img.shields.io/github/forks/faizzaidi/Admidio-3.2.8-CSRF-POC-by-Provensec-llc.svg)


## CVE-2017-8367
 Buffer overflow in Ether Software Easy MOV Converter 1.4.24, Easy DVD Creator, Easy MPEG/AVI/DIVX/WMV/RM to DVD, Easy Avi/Divx/Xvid to DVD Burner, Easy MPEG to DVD Burner, Easy WMV/ASF/ASX to DVD Burner, Easy RM RMVB to DVD Burner, Easy CD DVD Copy, MP3/AVI/MPEG/WMV/RM to Audio CD Burner, MP3/WAV/OGG/WMA/AC3 to CD Burner, MP3 WAV to CD Burner, My Video Converter, Easy AVI DivX Converter, Easy Video to iPod Converter, Easy Video to PSP Converter, Easy Video to 3GP Converter, Easy Video to MP4 Converter, and Easy Video to iPod/MP4/PSP/3GP Converter allows local attackers to cause a denial of service (SEH overwrite) or possibly have unspecified other impact via a long username.

- [https://github.com/rnnsz/CVE-2017-8367](https://github.com/rnnsz/CVE-2017-8367) :  ![starts](https://img.shields.io/github/stars/rnnsz/CVE-2017-8367.svg) ![forks](https://img.shields.io/github/forks/rnnsz/CVE-2017-8367.svg)


## CVE-2017-8295
 WordPress through 4.7.4 relies on the Host HTTP header for a password-reset e-mail message, which makes it easier for remote attackers to reset arbitrary passwords by making a crafted wp-login.php?action=lostpassword request and then arranging for this message to bounce or be resent, leading to transmission of the reset key to a mailbox on an attacker-controlled SMTP server. This is related to problematic use of the SERVER_NAME variable in wp-includes/pluggable.php in conjunction with the PHP mail function. Exploitation is not achievable in all cases because it requires at least one of the following: (1) the attacker can prevent the victim from receiving any e-mail messages for an extended period of time (such as 5 days), (2) the victim's e-mail system sends an autoresponse containing the original message, or (3) the victim manually composes a reply containing the original message.

- [https://github.com/cyberheartmi9/CVE-2017-8295](https://github.com/cyberheartmi9/CVE-2017-8295) :  ![starts](https://img.shields.io/github/stars/cyberheartmi9/CVE-2017-8295.svg) ![forks](https://img.shields.io/github/forks/cyberheartmi9/CVE-2017-8295.svg)
- [https://github.com/alash3al/wp-allowed-hosts](https://github.com/alash3al/wp-allowed-hosts) :  ![starts](https://img.shields.io/github/stars/alash3al/wp-allowed-hosts.svg) ![forks](https://img.shields.io/github/forks/alash3al/wp-allowed-hosts.svg)
- [https://github.com/homjxi0e/CVE-2017-8295-WordPress-4.7.4---Unauthorized-Password-Reset](https://github.com/homjxi0e/CVE-2017-8295-WordPress-4.7.4---Unauthorized-Password-Reset) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-8295-WordPress-4.7.4---Unauthorized-Password-Reset.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-8295-WordPress-4.7.4---Unauthorized-Password-Reset.svg)


## CVE-2017-8291
 Artifex Ghostscript through 2017-04-26 allows -dSAFER bypass and remote command execution via .rsdparams type confusion with a "/OutputFile (%pipe%" substring in a crafted .eps document that is an input to the gs program, as exploited in the wild in April 2017.

- [https://github.com/shun1403/CVE-2017-8291](https://github.com/shun1403/CVE-2017-8291) :  ![starts](https://img.shields.io/github/stars/shun1403/CVE-2017-8291.svg) ![forks](https://img.shields.io/github/forks/shun1403/CVE-2017-8291.svg)
- [https://github.com/hkcfs/PIL-CVE-2017-8291](https://github.com/hkcfs/PIL-CVE-2017-8291) :  ![starts](https://img.shields.io/github/stars/hkcfs/PIL-CVE-2017-8291.svg) ![forks](https://img.shields.io/github/forks/hkcfs/PIL-CVE-2017-8291.svg)
- [https://github.com/shun1403/PIL-CVE-2017-8291-study](https://github.com/shun1403/PIL-CVE-2017-8291-study) :  ![starts](https://img.shields.io/github/stars/shun1403/PIL-CVE-2017-8291-study.svg) ![forks](https://img.shields.io/github/forks/shun1403/PIL-CVE-2017-8291-study.svg)


## CVE-2017-8225
 On Wireless IP Camera (P2P) WIFICAM devices, access to .ini files (containing credentials) is not correctly checked. An attacker can bypass authentication by providing an empty loginuse parameter and an empty loginpas parameter in the URI.

- [https://github.com/K3ysTr0K3R/CVE-2017-8225-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-8225-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-8225-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-8225-EXPLOIT.svg)
- [https://github.com/kienquoc102/CVE-2017-8225](https://github.com/kienquoc102/CVE-2017-8225) :  ![starts](https://img.shields.io/github/stars/kienquoc102/CVE-2017-8225.svg) ![forks](https://img.shields.io/github/forks/kienquoc102/CVE-2017-8225.svg)


## CVE-2017-8046
 Malicious PATCH requests submitted to servers using Spring Data REST versions prior to 2.6.9 (Ingalls SR9), versions prior to 3.0.1 (Kay SR1) and Spring Boot versions prior to 1.5.9, 2.0 M6 can use specially crafted JSON data to run arbitrary Java code.

- [https://github.com/m3ssap0/spring-break_cve-2017-8046](https://github.com/m3ssap0/spring-break_cve-2017-8046) :  ![starts](https://img.shields.io/github/stars/m3ssap0/spring-break_cve-2017-8046.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/spring-break_cve-2017-8046.svg)
- [https://github.com/m3ssap0/SpringBreakVulnerableApp](https://github.com/m3ssap0/SpringBreakVulnerableApp) :  ![starts](https://img.shields.io/github/stars/m3ssap0/SpringBreakVulnerableApp.svg) ![forks](https://img.shields.io/github/forks/m3ssap0/SpringBreakVulnerableApp.svg)
- [https://github.com/Soontao/CVE-2017-8046-DEMO](https://github.com/Soontao/CVE-2017-8046-DEMO) :  ![starts](https://img.shields.io/github/stars/Soontao/CVE-2017-8046-DEMO.svg) ![forks](https://img.shields.io/github/forks/Soontao/CVE-2017-8046-DEMO.svg)
- [https://github.com/cved-sources/cve-2017-8046](https://github.com/cved-sources/cve-2017-8046) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-8046.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-8046.svg)
- [https://github.com/FixYourFace/SpringBreakPoC](https://github.com/FixYourFace/SpringBreakPoC) :  ![starts](https://img.shields.io/github/stars/FixYourFace/SpringBreakPoC.svg) ![forks](https://img.shields.io/github/forks/FixYourFace/SpringBreakPoC.svg)
- [https://github.com/jkutner/spring-break-cve-2017-8046](https://github.com/jkutner/spring-break-cve-2017-8046) :  ![starts](https://img.shields.io/github/stars/jkutner/spring-break-cve-2017-8046.svg) ![forks](https://img.shields.io/github/forks/jkutner/spring-break-cve-2017-8046.svg)
- [https://github.com/sj/spring-data-rest-CVE-2017-8046](https://github.com/sj/spring-data-rest-CVE-2017-8046) :  ![starts](https://img.shields.io/github/stars/sj/spring-data-rest-CVE-2017-8046.svg) ![forks](https://img.shields.io/github/forks/sj/spring-data-rest-CVE-2017-8046.svg)
- [https://github.com/guanjivip/CVE-2017-8046](https://github.com/guanjivip/CVE-2017-8046) :  ![starts](https://img.shields.io/github/stars/guanjivip/CVE-2017-8046.svg) ![forks](https://img.shields.io/github/forks/guanjivip/CVE-2017-8046.svg)
- [https://github.com/bkhablenko/CVE-2017-8046](https://github.com/bkhablenko/CVE-2017-8046) :  ![starts](https://img.shields.io/github/stars/bkhablenko/CVE-2017-8046.svg) ![forks](https://img.shields.io/github/forks/bkhablenko/CVE-2017-8046.svg)
- [https://github.com/jsotiro/VulnerableSpringDataRest](https://github.com/jsotiro/VulnerableSpringDataRest) :  ![starts](https://img.shields.io/github/stars/jsotiro/VulnerableSpringDataRest.svg) ![forks](https://img.shields.io/github/forks/jsotiro/VulnerableSpringDataRest.svg)


## CVE-2017-7998
 Multiple cross-site scripting (XSS) vulnerabilities in Gespage before 7.4.9 allow remote attackers to inject arbitrary web script or HTML via the (1) printer name when adding a printer in the admin panel or (2) username parameter to webapp/users/user_reg.jsp.

- [https://github.com/homjxi0e/CVE-2017-7998](https://github.com/homjxi0e/CVE-2017-7998) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7998.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7998.svg)


## CVE-2017-7912
 Hanwha Techwin SRN-4000, SRN-4000 firmware versions prior to SRN4000_v2.16_170401, A specially crafted http request and response could allow an attacker to gain access to the device management page with admin privileges without proper authentication.

- [https://github.com/homjxi0e/CVE-2017-7912_Sneak](https://github.com/homjxi0e/CVE-2017-7912_Sneak) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7912_Sneak.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7912_Sneak.svg)


## CVE-2017-7679
 In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can read one byte past the end of a buffer when sending a malicious Content-Type response header.

- [https://github.com/snknritr/CVE-2017-7679-in-python](https://github.com/snknritr/CVE-2017-7679-in-python) :  ![starts](https://img.shields.io/github/stars/snknritr/CVE-2017-7679-in-python.svg) ![forks](https://img.shields.io/github/forks/snknritr/CVE-2017-7679-in-python.svg)


## CVE-2017-7651
 In Eclipse Mosquitto 1.4.14, a user can shutdown the Mosquitto server simply by filling the RAM memory with a lot of connections with large payload. This can be done without authentications if occur in connection phase of MQTT protocol.

- [https://github.com/mukkul007/MqttAttack](https://github.com/mukkul007/MqttAttack) :  ![starts](https://img.shields.io/github/stars/mukkul007/MqttAttack.svg) ![forks](https://img.shields.io/github/forks/mukkul007/MqttAttack.svg)
- [https://github.com/St3v3nsS/CVE-2017-7651](https://github.com/St3v3nsS/CVE-2017-7651) :  ![starts](https://img.shields.io/github/stars/St3v3nsS/CVE-2017-7651.svg) ![forks](https://img.shields.io/github/forks/St3v3nsS/CVE-2017-7651.svg)


## CVE-2017-7648
 Foscam networked devices use the same hardcoded SSL private key across different customers' installations, which allows remote attackers to defeat cryptographic protection mechanisms by leveraging knowledge of this key from another installation.

- [https://github.com/notmot/CVE-2017-7648.](https://github.com/notmot/CVE-2017-7648.) :  ![starts](https://img.shields.io/github/stars/notmot/CVE-2017-7648..svg) ![forks](https://img.shields.io/github/forks/notmot/CVE-2017-7648..svg)


## CVE-2017-7533
 Race condition in the fsnotify implementation in the Linux kernel through 4.12.4 allows local users to gain privileges or cause a denial of service (memory corruption) via a crafted application that leverages simultaneous execution of the inotify_handle_event and vfs_rename functions.

- [https://github.com/jltxgcy/CVE_2017_7533_EXP](https://github.com/jltxgcy/CVE_2017_7533_EXP) :  ![starts](https://img.shields.io/github/stars/jltxgcy/CVE_2017_7533_EXP.svg) ![forks](https://img.shields.io/github/forks/jltxgcy/CVE_2017_7533_EXP.svg)


## CVE-2017-7525
 A deserialization flaw was discovered in the jackson-databind, versions before 2.6.7.1, 2.7.9.1 and 2.8.9, which could allow an unauthenticated user to perform code execution by sending the maliciously crafted input to the readValue method of the ObjectMapper.

- [https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095](https://github.com/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095) :  ![starts](https://img.shields.io/github/stars/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095.svg) ![forks](https://img.shields.io/github/forks/SecureSkyTechnology/study-struts2-s2-054_055-jackson-cve-2017-7525_cve-2017-15095.svg)
- [https://github.com/JavanXD/Demo-Exploit-Jackson-RCE](https://github.com/JavanXD/Demo-Exploit-Jackson-RCE) :  ![starts](https://img.shields.io/github/stars/JavanXD/Demo-Exploit-Jackson-RCE.svg) ![forks](https://img.shields.io/github/forks/JavanXD/Demo-Exploit-Jackson-RCE.svg)
- [https://github.com/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab](https://github.com/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab) :  ![starts](https://img.shields.io/github/stars/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab.svg) ![forks](https://img.shields.io/github/forks/Ingenuity-Fainting-Goats/CVE-2017-7525-Jackson-Deserialization-Lab.svg)
- [https://github.com/Dannners/jackson-deserialization-2017-7525](https://github.com/Dannners/jackson-deserialization-2017-7525) :  ![starts](https://img.shields.io/github/stars/Dannners/jackson-deserialization-2017-7525.svg) ![forks](https://img.shields.io/github/forks/Dannners/jackson-deserialization-2017-7525.svg)
- [https://github.com/Nazicc/S2-055](https://github.com/Nazicc/S2-055) :  ![starts](https://img.shields.io/github/stars/Nazicc/S2-055.svg) ![forks](https://img.shields.io/github/forks/Nazicc/S2-055.svg)


## CVE-2017-7504
 HTTPServerILServlet.java in JMS over HTTP Invocation Layer of the JbossMQ implementation, which is enabled by default in Red Hat Jboss Application Server = Jboss 4.X does not restrict the classes for which it performs deserialization, which allows remote attackers to execute arbitrary code via crafted serialized data.

- [https://github.com/wudidwo/CVE-2017-7504-poc](https://github.com/wudidwo/CVE-2017-7504-poc) :  ![starts](https://img.shields.io/github/stars/wudidwo/CVE-2017-7504-poc.svg) ![forks](https://img.shields.io/github/forks/wudidwo/CVE-2017-7504-poc.svg)


## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.

- [https://github.com/opsxcq/exploit-CVE-2017-7494](https://github.com/opsxcq/exploit-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/opsxcq/exploit-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/opsxcq/exploit-CVE-2017-7494.svg)
- [https://github.com/joxeankoret/CVE-2017-7494](https://github.com/joxeankoret/CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/joxeankoret/CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/joxeankoret/CVE-2017-7494.svg)
- [https://github.com/betab0t/cve-2017-7494](https://github.com/betab0t/cve-2017-7494) :  ![starts](https://img.shields.io/github/stars/betab0t/cve-2017-7494.svg) ![forks](https://img.shields.io/github/forks/betab0t/cve-2017-7494.svg)
- [https://github.com/Waffles-2/SambaCry](https://github.com/Waffles-2/SambaCry) :  ![starts](https://img.shields.io/github/stars/Waffles-2/SambaCry.svg) ![forks](https://img.shields.io/github/forks/Waffles-2/SambaCry.svg)
- [https://github.com/brianwrf/SambaHunter](https://github.com/brianwrf/SambaHunter) :  ![starts](https://img.shields.io/github/stars/brianwrf/SambaHunter.svg) ![forks](https://img.shields.io/github/forks/brianwrf/SambaHunter.svg)
- [https://github.com/d3fudd/CVE-2017-7494_SambaCry](https://github.com/d3fudd/CVE-2017-7494_SambaCry) :  ![starts](https://img.shields.io/github/stars/d3fudd/CVE-2017-7494_SambaCry.svg) ![forks](https://img.shields.io/github/forks/d3fudd/CVE-2017-7494_SambaCry.svg)
- [https://github.com/0xm4ud/noSAMBAnoCRY-CVE-2017-7494](https://github.com/0xm4ud/noSAMBAnoCRY-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/0xm4ud/noSAMBAnoCRY-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/0xm4ud/noSAMBAnoCRY-CVE-2017-7494.svg)
- [https://github.com/I-Rinka/BIT-EternalBlue-for-macOS_Linux](https://github.com/I-Rinka/BIT-EternalBlue-for-macOS_Linux) :  ![starts](https://img.shields.io/github/stars/I-Rinka/BIT-EternalBlue-for-macOS_Linux.svg) ![forks](https://img.shields.io/github/forks/I-Rinka/BIT-EternalBlue-for-macOS_Linux.svg)
- [https://github.com/00mjk/exploit-CVE-2017-7494](https://github.com/00mjk/exploit-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/00mjk/exploit-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/00mjk/exploit-CVE-2017-7494.svg)
- [https://github.com/Zer0d0y/Samba-CVE-2017-7494](https://github.com/Zer0d0y/Samba-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/Zer0d0y/Samba-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/Zer0d0y/Samba-CVE-2017-7494.svg)
- [https://github.com/homjxi0e/CVE-2017-7494](https://github.com/homjxi0e/CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7494.svg)
- [https://github.com/gunsan92/CVE2017-7494_quicktest](https://github.com/gunsan92/CVE2017-7494_quicktest) :  ![starts](https://img.shields.io/github/stars/gunsan92/CVE2017-7494_quicktest.svg) ![forks](https://img.shields.io/github/forks/gunsan92/CVE2017-7494_quicktest.svg)
- [https://github.com/cved-sources/cve-2017-7494](https://github.com/cved-sources/cve-2017-7494) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-7494.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-7494.svg)
- [https://github.com/incredible1yu/CVE-2017-7494](https://github.com/incredible1yu/CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/incredible1yu/CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/incredible1yu/CVE-2017-7494.svg)
- [https://github.com/NhutMinh2801/CVE_2017_7494](https://github.com/NhutMinh2801/CVE_2017_7494) :  ![starts](https://img.shields.io/github/stars/NhutMinh2801/CVE_2017_7494.svg) ![forks](https://img.shields.io/github/forks/NhutMinh2801/CVE_2017_7494.svg)
- [https://github.com/john-80/cve-2017-7494](https://github.com/john-80/cve-2017-7494) :  ![starts](https://img.shields.io/github/stars/john-80/cve-2017-7494.svg) ![forks](https://img.shields.io/github/forks/john-80/cve-2017-7494.svg)
- [https://github.com/Hansindu-M/CVE-2017-7494_IT19115344](https://github.com/Hansindu-M/CVE-2017-7494_IT19115344) :  ![starts](https://img.shields.io/github/stars/Hansindu-M/CVE-2017-7494_IT19115344.svg) ![forks](https://img.shields.io/github/forks/Hansindu-M/CVE-2017-7494_IT19115344.svg)
- [https://github.com/adjaliya/-CVE-2017-7494-Samba-Exploit-POC](https://github.com/adjaliya/-CVE-2017-7494-Samba-Exploit-POC) :  ![starts](https://img.shields.io/github/stars/adjaliya/-CVE-2017-7494-Samba-Exploit-POC.svg) ![forks](https://img.shields.io/github/forks/adjaliya/-CVE-2017-7494-Samba-Exploit-POC.svg)


## CVE-2017-7472
 The KEYS subsystem in the Linux kernel before 4.10.13 allows local users to cause a denial of service (memory consumption) via a series of KEY_REQKEY_DEFL_THREAD_KEYRING keyctl_set_reqkey_keyring calls.

- [https://github.com/homjxi0e/CVE-2017-7472](https://github.com/homjxi0e/CVE-2017-7472) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7472.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7472.svg)


## CVE-2017-7410
 Multiple SQL injection vulnerabilities in account/signup.php and account/signup2.php in WebsiteBaker 2.10.0 and earlier allow remote attackers to execute arbitrary SQL commands via the (1) username, (2) display_name parameter.

- [https://github.com/ashangp923/CVE-2017-7410](https://github.com/ashangp923/CVE-2017-7410) :  ![starts](https://img.shields.io/github/stars/ashangp923/CVE-2017-7410.svg) ![forks](https://img.shields.io/github/forks/ashangp923/CVE-2017-7410.svg)


## CVE-2017-7308
 The packet_set_ring function in net/packet/af_packet.c in the Linux kernel through 4.10.6 does not properly validate certain block-size data, which allows local users to cause a denial of service (integer signedness error and out-of-bounds write), or gain privileges (if the CAP_NET_RAW capability is held), via crafted system calls.

- [https://github.com/anldori/CVE-2017-7308](https://github.com/anldori/CVE-2017-7308) :  ![starts](https://img.shields.io/github/stars/anldori/CVE-2017-7308.svg) ![forks](https://img.shields.io/github/forks/anldori/CVE-2017-7308.svg)


## CVE-2017-7269
 Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with "If: http://" in a PROPFIND request, as exploited in the wild in July or August 2016.

- [https://github.com/zcgonvh/cve-2017-7269](https://github.com/zcgonvh/cve-2017-7269) :  ![starts](https://img.shields.io/github/stars/zcgonvh/cve-2017-7269.svg) ![forks](https://img.shields.io/github/forks/zcgonvh/cve-2017-7269.svg)
- [https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/g0rx/iis6-exploit-2017-CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/g0rx/iis6-exploit-2017-CVE-2017-7269.svg)
- [https://github.com/lcatro/CVE-2017-7269-Echo-PoC](https://github.com/lcatro/CVE-2017-7269-Echo-PoC) :  ![starts](https://img.shields.io/github/stars/lcatro/CVE-2017-7269-Echo-PoC.svg) ![forks](https://img.shields.io/github/forks/lcatro/CVE-2017-7269-Echo-PoC.svg)
- [https://github.com/zcgonvh/cve-2017-7269-tool](https://github.com/zcgonvh/cve-2017-7269-tool) :  ![starts](https://img.shields.io/github/stars/zcgonvh/cve-2017-7269-tool.svg) ![forks](https://img.shields.io/github/forks/zcgonvh/cve-2017-7269-tool.svg)
- [https://github.com/eliuha/webdav_exploit](https://github.com/eliuha/webdav_exploit) :  ![starts](https://img.shields.io/github/stars/eliuha/webdav_exploit.svg) ![forks](https://img.shields.io/github/forks/eliuha/webdav_exploit.svg)
- [https://github.com/Al1ex/CVE-2017-7269](https://github.com/Al1ex/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-7269.svg)
- [https://github.com/slimpagey/IIS_6.0_WebDAV_Ruby](https://github.com/slimpagey/IIS_6.0_WebDAV_Ruby) :  ![starts](https://img.shields.io/github/stars/slimpagey/IIS_6.0_WebDAV_Ruby.svg) ![forks](https://img.shields.io/github/forks/slimpagey/IIS_6.0_WebDAV_Ruby.svg)
- [https://github.com/h3x0v3rl0rd/CVE-2017-7269](https://github.com/h3x0v3rl0rd/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/h3x0v3rl0rd/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/h3x0v3rl0rd/CVE-2017-7269.svg)
- [https://github.com/geniuszly/CVE-2017-7269](https://github.com/geniuszly/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/geniuszly/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/geniuszly/CVE-2017-7269.svg)
- [https://github.com/caicai1355/CVE-2017-7269-exploit](https://github.com/caicai1355/CVE-2017-7269-exploit) :  ![starts](https://img.shields.io/github/stars/caicai1355/CVE-2017-7269-exploit.svg) ![forks](https://img.shields.io/github/forks/caicai1355/CVE-2017-7269-exploit.svg)
- [https://github.com/xiaovpn/CVE-2017-7269](https://github.com/xiaovpn/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/xiaovpn/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/xiaovpn/CVE-2017-7269.svg)
- [https://github.com/denchief1/CVE-2017-7269](https://github.com/denchief1/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/denchief1/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/denchief1/CVE-2017-7269.svg)
- [https://github.com/mirrorblack/CVE-2017-7269](https://github.com/mirrorblack/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/mirrorblack/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/mirrorblack/CVE-2017-7269.svg)
- [https://github.com/denchief1/CVE-2017-7269_Python3](https://github.com/denchief1/CVE-2017-7269_Python3) :  ![starts](https://img.shields.io/github/stars/denchief1/CVE-2017-7269_Python3.svg) ![forks](https://img.shields.io/github/forks/denchief1/CVE-2017-7269_Python3.svg)
- [https://github.com/M1a0rz/CVE-2017-7269](https://github.com/M1a0rz/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/M1a0rz/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/M1a0rz/CVE-2017-7269.svg)
- [https://github.com/Cappricio-Securities/CVE-2017-7269](https://github.com/Cappricio-Securities/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2017-7269.svg)
- [https://github.com/VanishedPeople/CVE-2017-7269](https://github.com/VanishedPeople/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/VanishedPeople/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/VanishedPeople/CVE-2017-7269.svg)
- [https://github.com/homjxi0e/cve-2017-7269](https://github.com/homjxi0e/cve-2017-7269) :  ![starts](https://img.shields.io/github/stars/homjxi0e/cve-2017-7269.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/cve-2017-7269.svg)
- [https://github.com/ThanHuuTuan/CVE-2017-7269](https://github.com/ThanHuuTuan/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/ThanHuuTuan/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/ThanHuuTuan/CVE-2017-7269.svg)
- [https://github.com/whiteHat001/cve-2017-7269picture](https://github.com/whiteHat001/cve-2017-7269picture) :  ![starts](https://img.shields.io/github/stars/whiteHat001/cve-2017-7269picture.svg) ![forks](https://img.shields.io/github/forks/whiteHat001/cve-2017-7269picture.svg)


## CVE-2017-7188
 Zurmo 3.1.1 Stable allows a Cross-Site Scripting (XSS) attack with a base64-encoded SCRIPT element within a data: URL in the returnUrl parameter to default/toggleCollapse.

- [https://github.com/faizzaidi/Zurmo-Stable-3.1.1-XSS-By-Provensec-LLC](https://github.com/faizzaidi/Zurmo-Stable-3.1.1-XSS-By-Provensec-LLC) :  ![starts](https://img.shields.io/github/stars/faizzaidi/Zurmo-Stable-3.1.1-XSS-By-Provensec-LLC.svg) ![forks](https://img.shields.io/github/forks/faizzaidi/Zurmo-Stable-3.1.1-XSS-By-Provensec-LLC.svg)


## CVE-2017-7184
 The xfrm_replay_verify_len function in net/xfrm/xfrm_user.c in the Linux kernel through 4.10.6 does not validate certain size data after an XFRM_MSG_NEWAE update, which allows local users to obtain root privileges or cause a denial of service (heap-based out-of-bounds access) by leveraging the CAP_NET_ADMIN capability, as demonstrated during a Pwn2Own competition at CanSecWest 2017 for the Ubuntu 16.10 linux-image-* package 4.8.0.41.52.

- [https://github.com/b1nhack/CVE-2017-7184](https://github.com/b1nhack/CVE-2017-7184) :  ![starts](https://img.shields.io/github/stars/b1nhack/CVE-2017-7184.svg) ![forks](https://img.shields.io/github/forks/b1nhack/CVE-2017-7184.svg)
- [https://github.com/rockl/cve-2017-7184](https://github.com/rockl/cve-2017-7184) :  ![starts](https://img.shields.io/github/stars/rockl/cve-2017-7184.svg) ![forks](https://img.shields.io/github/forks/rockl/cve-2017-7184.svg)
- [https://github.com/rockl/cve-2017-7184-bak](https://github.com/rockl/cve-2017-7184-bak) :  ![starts](https://img.shields.io/github/stars/rockl/cve-2017-7184-bak.svg) ![forks](https://img.shields.io/github/forks/rockl/cve-2017-7184-bak.svg)


## CVE-2017-7173
 An issue was discovered in certain Apple products. macOS before 10.13.2 is affected. The issue involves the "Kernel" component. It allows attackers to bypass intended memory-read restrictions via a crafted app.

- [https://github.com/bazad/sysctl_coalition_get_pid_list-dos](https://github.com/bazad/sysctl_coalition_get_pid_list-dos) :  ![starts](https://img.shields.io/github/stars/bazad/sysctl_coalition_get_pid_list-dos.svg) ![forks](https://img.shields.io/github/forks/bazad/sysctl_coalition_get_pid_list-dos.svg)


## CVE-2017-7117
 An issue was discovered in certain Apple products. iOS before 11 is affected. Safari before 11 is affected. iCloud before 7.0 on Windows is affected. iTunes before 12.7 on Windows is affected. tvOS before 11 is affected. The issue involves the "WebKit" component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.

- [https://github.com/rebelle3/cve-2017-7117](https://github.com/rebelle3/cve-2017-7117) :  ![starts](https://img.shields.io/github/stars/rebelle3/cve-2017-7117.svg) ![forks](https://img.shields.io/github/forks/rebelle3/cve-2017-7117.svg)


## CVE-2017-7092
 An issue was discovered in certain Apple products. iOS before 11 is affected. Safari before 11 is affected. iCloud before 7.0 on Windows is affected. iTunes before 12.7 on Windows is affected. tvOS before 11 is affected. The issue involves the "WebKit" component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.

- [https://github.com/xuechiyaobai/CVE-2017-7092-PoC](https://github.com/xuechiyaobai/CVE-2017-7092-PoC) :  ![starts](https://img.shields.io/github/stars/xuechiyaobai/CVE-2017-7092-PoC.svg) ![forks](https://img.shields.io/github/forks/xuechiyaobai/CVE-2017-7092-PoC.svg)


## CVE-2017-7089
 An issue was discovered in certain Apple products. iOS before 11 is affected. Safari before 11 is affected. iCloud before 7.0 on Windows is affected. The issue involves the "WebKit" component. It allows remote attackers to conduct Universal XSS (UXSS) attacks via a crafted web site that is mishandled during parent-tab processing.

- [https://github.com/Bo0oM/CVE-2017-7089](https://github.com/Bo0oM/CVE-2017-7089) :  ![starts](https://img.shields.io/github/stars/Bo0oM/CVE-2017-7089.svg) ![forks](https://img.shields.io/github/forks/Bo0oM/CVE-2017-7089.svg)
- [https://github.com/aymankhalfatni/Safari_Mac](https://github.com/aymankhalfatni/Safari_Mac) :  ![starts](https://img.shields.io/github/stars/aymankhalfatni/Safari_Mac.svg) ![forks](https://img.shields.io/github/forks/aymankhalfatni/Safari_Mac.svg)


## CVE-2017-7047
 An issue was discovered in certain Apple products. iOS before 10.3.3 is affected. macOS before 10.12.6 is affected. tvOS before 10.2.2 is affected. watchOS before 3.2.3 is affected. The issue involves the "libxpc" component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.

- [https://github.com/JosephShenton/Triple_Fetch-Kernel-Creds](https://github.com/JosephShenton/Triple_Fetch-Kernel-Creds) :  ![starts](https://img.shields.io/github/stars/JosephShenton/Triple_Fetch-Kernel-Creds.svg) ![forks](https://img.shields.io/github/forks/JosephShenton/Triple_Fetch-Kernel-Creds.svg)
- [https://github.com/q1f3/Triple_fetch](https://github.com/q1f3/Triple_fetch) :  ![starts](https://img.shields.io/github/stars/q1f3/Triple_fetch.svg) ![forks](https://img.shields.io/github/forks/q1f3/Triple_fetch.svg)


## CVE-2017-6971
 AlienVault USM and OSSIM before 5.3.7 and NfSen before 1.3.8 allow remote authenticated users to execute arbitrary commands in a privileged context, or launch a reverse shell, via vectors involving the PHP session ID and the NfSen PHP code, aka AlienVault ID ENG-104862.

- [https://github.com/patrickfreed/nfsen-exploit](https://github.com/patrickfreed/nfsen-exploit) :  ![starts](https://img.shields.io/github/stars/patrickfreed/nfsen-exploit.svg) ![forks](https://img.shields.io/github/forks/patrickfreed/nfsen-exploit.svg)
- [https://github.com/KeyStrOke95/nfsen_1.3.7_CVE-2017-6971](https://github.com/KeyStrOke95/nfsen_1.3.7_CVE-2017-6971) :  ![starts](https://img.shields.io/github/stars/KeyStrOke95/nfsen_1.3.7_CVE-2017-6971.svg) ![forks](https://img.shields.io/github/forks/KeyStrOke95/nfsen_1.3.7_CVE-2017-6971.svg)


## CVE-2017-6640
 A vulnerability in Cisco Prime Data Center Network Manager (DCNM) Software could allow an unauthenticated, remote attacker to log in to the administrative console of a DCNM server by using an account that has a default, static password. The account could be granted root- or system-level privileges. The vulnerability exists because the affected software has a default user account that has a default, static password. The user account is created automatically when the software is installed. An attacker could exploit this vulnerability by connecting remotely to an affected system and logging in to the affected software by using the credentials for this default user account. A successful exploit could allow the attacker to use this default user account to log in to the affected software and gain access to the administrative console of a DCNM server. This vulnerability affects Cisco Prime Data Center Network Manager (DCNM) Software releases prior to Release 10.2(1) for Microsoft Windows, Linux, and Virtual Appliance platforms. Cisco Bug IDs: CSCvd95346.

- [https://github.com/hemp3l/CVE-2017-6640-POC](https://github.com/hemp3l/CVE-2017-6640-POC) :  ![starts](https://img.shields.io/github/stars/hemp3l/CVE-2017-6640-POC.svg) ![forks](https://img.shields.io/github/forks/hemp3l/CVE-2017-6640-POC.svg)


## CVE-2017-6516
 A Local Privilege Escalation Vulnerability in MagniComp's Sysinfo before 10-H64 for Linux and UNIX platforms could allow a local attacker to gain elevated privileges. Parts of SysInfo require setuid-to-root access in order to access restricted system files and make restricted kernel calls. This access could be exploited by a local attacker to gain a root shell prompt using the right combination of environment variables and command line arguments.

- [https://github.com/Rubytox/CVE-2017-6516-mcsiwrapper-](https://github.com/Rubytox/CVE-2017-6516-mcsiwrapper-) :  ![starts](https://img.shields.io/github/stars/Rubytox/CVE-2017-6516-mcsiwrapper-.svg) ![forks](https://img.shields.io/github/forks/Rubytox/CVE-2017-6516-mcsiwrapper-.svg)


## CVE-2017-6370
 TYPO3 7.6.15 sends an http request to an index.php?loginProvider URI in cases with an https Referer, which allows remote attackers to obtain sensitive cleartext information by sniffing the network and reading the userident and username fields.

- [https://github.com/faizzaidi/TYPO3-v7.6.15-Unencrypted-Login-Request](https://github.com/faizzaidi/TYPO3-v7.6.15-Unencrypted-Login-Request) :  ![starts](https://img.shields.io/github/stars/faizzaidi/TYPO3-v7.6.15-Unencrypted-Login-Request.svg) ![forks](https://img.shields.io/github/forks/faizzaidi/TYPO3-v7.6.15-Unencrypted-Login-Request.svg)


## CVE-2017-6206
 D-Link DGS-1510-28XMP, DGS-1510-28X, DGS-1510-52X, DGS-1510-52, DGS-1510-28P, DGS-1510-28, and DGS-1510-20 Websmart devices with firmware before 1.31.B003 allow attackers to conduct Unauthenticated Information Disclosure attacks via unspecified vectors.

- [https://github.com/varangamin/CVE-2017-6206](https://github.com/varangamin/CVE-2017-6206) :  ![starts](https://img.shields.io/github/stars/varangamin/CVE-2017-6206.svg) ![forks](https://img.shields.io/github/forks/varangamin/CVE-2017-6206.svg)


## CVE-2017-6090
 Unrestricted file upload vulnerability in clients/editclient.php in PhpCollab 2.5.1 and earlier allows remote authenticated users to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in logos_clients/.

- [https://github.com/jlk/exploit-CVE-2017-6090](https://github.com/jlk/exploit-CVE-2017-6090) :  ![starts](https://img.shields.io/github/stars/jlk/exploit-CVE-2017-6090.svg) ![forks](https://img.shields.io/github/forks/jlk/exploit-CVE-2017-6090.svg)


## CVE-2017-6079
 The HTTP web-management application on Edgewater Networks Edgemarc appliances has a hidden page that allows for user-defined commands such as specific iptables routes, etc., to be set. You can use this page as a web shell essentially to execute commands, though you get no feedback client-side from the web application: if the command is valid, it executes. An example is the wget command. The page that allows this has been confirmed in firmware as old as 2006.

- [https://github.com/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit](https://github.com/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit) :  ![starts](https://img.shields.io/github/stars/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit.svg) ![forks](https://img.shields.io/github/forks/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit.svg)


## CVE-2017-6074
 The dccp_rcv_state_process function in net/dccp/input.c in the Linux kernel through 4.9.11 mishandles DCCP_PKT_REQUEST packet data structures in the LISTEN state, which allows local users to obtain root privileges or cause a denial of service (double free) via an application that makes an IPV6_RECVPKTINFO setsockopt system call.

- [https://github.com/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074](https://github.com/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074) :  ![starts](https://img.shields.io/github/stars/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074.svg) ![forks](https://img.shields.io/github/forks/BimsaraMalinda/Linux-Kernel-4.4.0-Ubuntu---DCCP-Double-Free-Privilege-Escalation-CVE-2017-6074.svg)
- [https://github.com/toanthang1842002/CVE-2017-6074](https://github.com/toanthang1842002/CVE-2017-6074) :  ![starts](https://img.shields.io/github/stars/toanthang1842002/CVE-2017-6074.svg) ![forks](https://img.shields.io/github/forks/toanthang1842002/CVE-2017-6074.svg)


## CVE-2017-6008
 A kernel pool overflow in the driver hitmanpro37.sys in Sophos SurfRight HitmanPro before 3.7.20 Build 286 (included in the HitmanPro.Alert solution and Sophos Clean) allows local users to escalate privileges via a malformed IOCTL call.

- [https://github.com/cbayet/Exploit-CVE-2017-6008](https://github.com/cbayet/Exploit-CVE-2017-6008) :  ![starts](https://img.shields.io/github/stars/cbayet/Exploit-CVE-2017-6008.svg) ![forks](https://img.shields.io/github/forks/cbayet/Exploit-CVE-2017-6008.svg)


## CVE-2017-5954
 An issue was discovered in the serialize-to-js package 0.5.0 for Node.js. Untrusted data passed into the deserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/ossf-cve-benchmark/CVE-2017-5954](https://github.com/ossf-cve-benchmark/CVE-2017-5954) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-5954.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-5954.svg)


## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/rodolfomarianocy/nodeserial](https://github.com/rodolfomarianocy/nodeserial) :  ![starts](https://img.shields.io/github/stars/rodolfomarianocy/nodeserial.svg) ![forks](https://img.shields.io/github/forks/rodolfomarianocy/nodeserial.svg)
- [https://github.com/uartu0/nodejshell](https://github.com/uartu0/nodejshell) :  ![starts](https://img.shields.io/github/stars/uartu0/nodejshell.svg) ![forks](https://img.shields.io/github/forks/uartu0/nodejshell.svg)
- [https://github.com/Cr4zyD14m0nd137/Lab-for-cve-2018-15133](https://github.com/Cr4zyD14m0nd137/Lab-for-cve-2018-15133) :  ![starts](https://img.shields.io/github/stars/Cr4zyD14m0nd137/Lab-for-cve-2018-15133.svg) ![forks](https://img.shields.io/github/forks/Cr4zyD14m0nd137/Lab-for-cve-2018-15133.svg)
- [https://github.com/turnernator1/Node.js-CVE-2017-5941](https://github.com/turnernator1/Node.js-CVE-2017-5941) :  ![starts](https://img.shields.io/github/stars/turnernator1/Node.js-CVE-2017-5941.svg) ![forks](https://img.shields.io/github/forks/turnernator1/Node.js-CVE-2017-5941.svg)
- [https://github.com/Frivolous-scholar/CVE-2017-5941-NodeJS-RCE](https://github.com/Frivolous-scholar/CVE-2017-5941-NodeJS-RCE) :  ![starts](https://img.shields.io/github/stars/Frivolous-scholar/CVE-2017-5941-NodeJS-RCE.svg) ![forks](https://img.shields.io/github/forks/Frivolous-scholar/CVE-2017-5941-NodeJS-RCE.svg)
- [https://github.com/kylew1004/cve-2017-5941-poc-docker-lab](https://github.com/kylew1004/cve-2017-5941-poc-docker-lab) :  ![starts](https://img.shields.io/github/stars/kylew1004/cve-2017-5941-poc-docker-lab.svg) ![forks](https://img.shields.io/github/forks/kylew1004/cve-2017-5941-poc-docker-lab.svg)


## CVE-2017-5754
 Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis of the data cache.

- [https://github.com/speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) :  ![starts](https://img.shields.io/github/stars/speed47/spectre-meltdown-checker.svg) ![forks](https://img.shields.io/github/forks/speed47/spectre-meltdown-checker.svg)
- [https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) :  ![starts](https://img.shields.io/github/stars/nsacyber/Hardware-and-Firmware-Security-Guidance.svg) ![forks](https://img.shields.io/github/forks/nsacyber/Hardware-and-Firmware-Security-Guidance.svg)
- [https://github.com/ionescu007/SpecuCheck](https://github.com/ionescu007/SpecuCheck) :  ![starts](https://img.shields.io/github/stars/ionescu007/SpecuCheck.svg) ![forks](https://img.shields.io/github/forks/ionescu007/SpecuCheck.svg)
- [https://github.com/raphaelsc/Am-I-affected-by-Meltdown](https://github.com/raphaelsc/Am-I-affected-by-Meltdown) :  ![starts](https://img.shields.io/github/stars/raphaelsc/Am-I-affected-by-Meltdown.svg) ![forks](https://img.shields.io/github/forks/raphaelsc/Am-I-affected-by-Meltdown.svg)
- [https://github.com/Viralmaniar/In-Spectre-Meltdown](https://github.com/Viralmaniar/In-Spectre-Meltdown) :  ![starts](https://img.shields.io/github/stars/Viralmaniar/In-Spectre-Meltdown.svg) ![forks](https://img.shields.io/github/forks/Viralmaniar/In-Spectre-Meltdown.svg)
- [https://github.com/mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) :  ![starts](https://img.shields.io/github/stars/mathse/meltdown-spectre-bios-list.svg) ![forks](https://img.shields.io/github/forks/mathse/meltdown-spectre-bios-list.svg)
- [https://github.com/neuhalje/presentation_meltdown_spectre](https://github.com/neuhalje/presentation_meltdown_spectre) :  ![starts](https://img.shields.io/github/stars/neuhalje/presentation_meltdown_spectre.svg) ![forks](https://img.shields.io/github/forks/neuhalje/presentation_meltdown_spectre.svg)
- [https://github.com/jarmouz/spectre_meltdown](https://github.com/jarmouz/spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/jarmouz/spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/jarmouz/spectre_meltdown.svg)
- [https://github.com/gonoph/ansible-meltdown-spectre](https://github.com/gonoph/ansible-meltdown-spectre) :  ![starts](https://img.shields.io/github/stars/gonoph/ansible-meltdown-spectre.svg) ![forks](https://img.shields.io/github/forks/gonoph/ansible-meltdown-spectre.svg)
- [https://github.com/miglen/Awesome-Meltdown-Spectre](https://github.com/miglen/Awesome-Meltdown-Spectre) :  ![starts](https://img.shields.io/github/stars/miglen/Awesome-Meltdown-Spectre.svg) ![forks](https://img.shields.io/github/forks/miglen/Awesome-Meltdown-Spectre.svg)
- [https://github.com/zzado/Meltdown](https://github.com/zzado/Meltdown) :  ![starts](https://img.shields.io/github/stars/zzado/Meltdown.svg) ![forks](https://img.shields.io/github/forks/zzado/Meltdown.svg)
- [https://github.com/jdmulloy/meltdown-aws-scanner](https://github.com/jdmulloy/meltdown-aws-scanner) :  ![starts](https://img.shields.io/github/stars/jdmulloy/meltdown-aws-scanner.svg) ![forks](https://img.shields.io/github/forks/jdmulloy/meltdown-aws-scanner.svg)
- [https://github.com/speecyy/Am-I-affected-by-Meltdown](https://github.com/speecyy/Am-I-affected-by-Meltdown) :  ![starts](https://img.shields.io/github/stars/speecyy/Am-I-affected-by-Meltdown.svg) ![forks](https://img.shields.io/github/forks/speecyy/Am-I-affected-by-Meltdown.svg)
- [https://github.com/GregAskew/SpeculativeExecutionAssessment](https://github.com/GregAskew/SpeculativeExecutionAssessment) :  ![starts](https://img.shields.io/github/stars/GregAskew/SpeculativeExecutionAssessment.svg) ![forks](https://img.shields.io/github/forks/GregAskew/SpeculativeExecutionAssessment.svg)
- [https://github.com/kevincoakley/puppet-spectre_meltdown](https://github.com/kevincoakley/puppet-spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/kevincoakley/puppet-spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/kevincoakley/puppet-spectre_meltdown.svg)


## CVE-2017-5721
 Insufficient input validation in system firmware for Intel NUC7i3BNK, NUC7i3BNH, NUC7i5BNK, NUC7i5BNH, NUC7i7BNH versions BN0049 and below allows local attackers to execute arbitrary code via manipulation of memory.

- [https://github.com/embedi/smm_usbrt_poc](https://github.com/embedi/smm_usbrt_poc) :  ![starts](https://img.shields.io/github/stars/embedi/smm_usbrt_poc.svg) ![forks](https://img.shields.io/github/forks/embedi/smm_usbrt_poc.svg)


## CVE-2017-5715
 Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.

- [https://github.com/speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) :  ![starts](https://img.shields.io/github/stars/speed47/spectre-meltdown-checker.svg) ![forks](https://img.shields.io/github/forks/speed47/spectre-meltdown-checker.svg)
- [https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance](https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance) :  ![starts](https://img.shields.io/github/stars/nsacyber/Hardware-and-Firmware-Security-Guidance.svg) ![forks](https://img.shields.io/github/forks/nsacyber/Hardware-and-Firmware-Security-Guidance.svg)
- [https://github.com/Eugnis/spectre-attack](https://github.com/Eugnis/spectre-attack) :  ![starts](https://img.shields.io/github/stars/Eugnis/spectre-attack.svg) ![forks](https://img.shields.io/github/forks/Eugnis/spectre-attack.svg)
- [https://github.com/ionescu007/SpecuCheck](https://github.com/ionescu007/SpecuCheck) :  ![starts](https://img.shields.io/github/stars/ionescu007/SpecuCheck.svg) ![forks](https://img.shields.io/github/forks/ionescu007/SpecuCheck.svg)
- [https://github.com/Viralmaniar/In-Spectre-Meltdown](https://github.com/Viralmaniar/In-Spectre-Meltdown) :  ![starts](https://img.shields.io/github/stars/Viralmaniar/In-Spectre-Meltdown.svg) ![forks](https://img.shields.io/github/forks/Viralmaniar/In-Spectre-Meltdown.svg)
- [https://github.com/opsxcq/exploit-cve-2017-5715](https://github.com/opsxcq/exploit-cve-2017-5715) :  ![starts](https://img.shields.io/github/stars/opsxcq/exploit-cve-2017-5715.svg) ![forks](https://img.shields.io/github/forks/opsxcq/exploit-cve-2017-5715.svg)
- [https://github.com/mathse/meltdown-spectre-bios-list](https://github.com/mathse/meltdown-spectre-bios-list) :  ![starts](https://img.shields.io/github/stars/mathse/meltdown-spectre-bios-list.svg) ![forks](https://img.shields.io/github/forks/mathse/meltdown-spectre-bios-list.svg)
- [https://github.com/00052/spectre-attack-example](https://github.com/00052/spectre-attack-example) :  ![starts](https://img.shields.io/github/stars/00052/spectre-attack-example.svg) ![forks](https://img.shields.io/github/forks/00052/spectre-attack-example.svg)
- [https://github.com/neuhalje/presentation_meltdown_spectre](https://github.com/neuhalje/presentation_meltdown_spectre) :  ![starts](https://img.shields.io/github/stars/neuhalje/presentation_meltdown_spectre.svg) ![forks](https://img.shields.io/github/forks/neuhalje/presentation_meltdown_spectre.svg)
- [https://github.com/ixtal23/spectreScope](https://github.com/ixtal23/spectreScope) :  ![starts](https://img.shields.io/github/stars/ixtal23/spectreScope.svg) ![forks](https://img.shields.io/github/forks/ixtal23/spectreScope.svg)
- [https://github.com/jarmouz/spectre_meltdown](https://github.com/jarmouz/spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/jarmouz/spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/jarmouz/spectre_meltdown.svg)
- [https://github.com/garnetsunset/CiscoSpectreTakeover](https://github.com/garnetsunset/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/garnetsunset/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/garnetsunset/CiscoSpectreTakeover.svg)
- [https://github.com/EdwardOwusuAdjei/Spectre-PoC](https://github.com/EdwardOwusuAdjei/Spectre-PoC) :  ![starts](https://img.shields.io/github/stars/EdwardOwusuAdjei/Spectre-PoC.svg) ![forks](https://img.shields.io/github/forks/EdwardOwusuAdjei/Spectre-PoC.svg)
- [https://github.com/gonoph/ansible-meltdown-spectre](https://github.com/gonoph/ansible-meltdown-spectre) :  ![starts](https://img.shields.io/github/stars/gonoph/ansible-meltdown-spectre.svg) ![forks](https://img.shields.io/github/forks/gonoph/ansible-meltdown-spectre.svg)
- [https://github.com/miglen/Awesome-Meltdown-Spectre](https://github.com/miglen/Awesome-Meltdown-Spectre) :  ![starts](https://img.shields.io/github/stars/miglen/Awesome-Meltdown-Spectre.svg) ![forks](https://img.shields.io/github/forks/miglen/Awesome-Meltdown-Spectre.svg)
- [https://github.com/pedrolucasoliva/spectre-attack-demo](https://github.com/pedrolucasoliva/spectre-attack-demo) :  ![starts](https://img.shields.io/github/stars/pedrolucasoliva/spectre-attack-demo.svg) ![forks](https://img.shields.io/github/forks/pedrolucasoliva/spectre-attack-demo.svg)
- [https://github.com/GalloLuigi/Analisi-CVE-2017-5715](https://github.com/GalloLuigi/Analisi-CVE-2017-5715) :  ![starts](https://img.shields.io/github/stars/GalloLuigi/Analisi-CVE-2017-5715.svg) ![forks](https://img.shields.io/github/forks/GalloLuigi/Analisi-CVE-2017-5715.svg)
- [https://github.com/dmo2118/retpoline-audit](https://github.com/dmo2118/retpoline-audit) :  ![starts](https://img.shields.io/github/stars/dmo2118/retpoline-audit.svg) ![forks](https://img.shields.io/github/forks/dmo2118/retpoline-audit.svg)
- [https://github.com/GregAskew/SpeculativeExecutionAssessment](https://github.com/GregAskew/SpeculativeExecutionAssessment) :  ![starts](https://img.shields.io/github/stars/GregAskew/SpeculativeExecutionAssessment.svg) ![forks](https://img.shields.io/github/forks/GregAskew/SpeculativeExecutionAssessment.svg)
- [https://github.com/kevincoakley/puppet-spectre_meltdown](https://github.com/kevincoakley/puppet-spectre_meltdown) :  ![starts](https://img.shields.io/github/stars/kevincoakley/puppet-spectre_meltdown.svg) ![forks](https://img.shields.io/github/forks/kevincoakley/puppet-spectre_meltdown.svg)


## CVE-2017-5693
 Firmware in the Intel Puma 5, 6, and 7 Series might experience resource depletion or timeout, which allows a network attacker to create a denial of service via crafted network traffic.

- [https://github.com/LunNova/Puma6Fail](https://github.com/LunNova/Puma6Fail) :  ![starts](https://img.shields.io/github/stars/LunNova/Puma6Fail.svg) ![forks](https://img.shields.io/github/forks/LunNova/Puma6Fail.svg)


## CVE-2017-5689
 An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).

- [https://github.com/bartblaze/Disable-Intel-AMT](https://github.com/bartblaze/Disable-Intel-AMT) :  ![starts](https://img.shields.io/github/stars/bartblaze/Disable-Intel-AMT.svg) ![forks](https://img.shields.io/github/forks/bartblaze/Disable-Intel-AMT.svg)
- [https://github.com/embedi/amt_auth_bypass_poc](https://github.com/embedi/amt_auth_bypass_poc) :  ![starts](https://img.shields.io/github/stars/embedi/amt_auth_bypass_poc.svg) ![forks](https://img.shields.io/github/forks/embedi/amt_auth_bypass_poc.svg)
- [https://github.com/CerberusSecurity/CVE-2017-5689](https://github.com/CerberusSecurity/CVE-2017-5689) :  ![starts](https://img.shields.io/github/stars/CerberusSecurity/CVE-2017-5689.svg) ![forks](https://img.shields.io/github/forks/CerberusSecurity/CVE-2017-5689.svg)
- [https://github.com/Bijaye/intel_amt_bypass](https://github.com/Bijaye/intel_amt_bypass) :  ![starts](https://img.shields.io/github/stars/Bijaye/intel_amt_bypass.svg) ![forks](https://img.shields.io/github/forks/Bijaye/intel_amt_bypass.svg)
- [https://github.com/MlSebrell/amthoneypot](https://github.com/MlSebrell/amthoneypot) :  ![starts](https://img.shields.io/github/stars/MlSebrell/amthoneypot.svg) ![forks](https://img.shields.io/github/forks/MlSebrell/amthoneypot.svg)
- [https://github.com/baonq-me/cve2017-5689](https://github.com/baonq-me/cve2017-5689) :  ![starts](https://img.shields.io/github/stars/baonq-me/cve2017-5689.svg) ![forks](https://img.shields.io/github/forks/baonq-me/cve2017-5689.svg)
- [https://github.com/TheWay-hue/CVE-2017-5689-Checker](https://github.com/TheWay-hue/CVE-2017-5689-Checker) :  ![starts](https://img.shields.io/github/stars/TheWay-hue/CVE-2017-5689-Checker.svg) ![forks](https://img.shields.io/github/forks/TheWay-hue/CVE-2017-5689-Checker.svg)


## CVE-2017-5645
 In Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.

- [https://github.com/pimps/CVE-2017-5645](https://github.com/pimps/CVE-2017-5645) :  ![starts](https://img.shields.io/github/stars/pimps/CVE-2017-5645.svg) ![forks](https://img.shields.io/github/forks/pimps/CVE-2017-5645.svg)
- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)


## CVE-2017-5633
 Multiple cross-site request forgery (CSRF) vulnerabilities on the D-Link DI-524 Wireless Router with firmware 9.01 allow remote attackers to (1) change the admin password, (2) reboot the device, or (3) possibly have unspecified other impact via crafted requests to CGI programs.

- [https://github.com/cardangi/Exploit-CVE-2017-5633](https://github.com/cardangi/Exploit-CVE-2017-5633) :  ![starts](https://img.shields.io/github/stars/cardangi/Exploit-CVE-2017-5633.svg) ![forks](https://img.shields.io/github/forks/cardangi/Exploit-CVE-2017-5633.svg)


## CVE-2017-5487
 wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php in the REST API implementation in WordPress 4.7 before 4.7.1 does not properly restrict listings of post authors, which allows remote attackers to obtain sensitive information via a wp-json/wp/v2/users request.

- [https://github.com/K3ysTr0K3R/CVE-2017-5487-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-5487-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-5487-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-5487-EXPLOIT.svg)
- [https://github.com/anx0ing/Wordpress_Brute](https://github.com/anx0ing/Wordpress_Brute) :  ![starts](https://img.shields.io/github/stars/anx0ing/Wordpress_Brute.svg) ![forks](https://img.shields.io/github/forks/anx0ing/Wordpress_Brute.svg)
- [https://github.com/patilkr/wp-CVE-2017-5487-exploit](https://github.com/patilkr/wp-CVE-2017-5487-exploit) :  ![starts](https://img.shields.io/github/stars/patilkr/wp-CVE-2017-5487-exploit.svg) ![forks](https://img.shields.io/github/forks/patilkr/wp-CVE-2017-5487-exploit.svg)
- [https://github.com/GeunSam2/CVE-2017-5487](https://github.com/GeunSam2/CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/GeunSam2/CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/GeunSam2/CVE-2017-5487.svg)
- [https://github.com/R3K1NG/wpUsersScan](https://github.com/R3K1NG/wpUsersScan) :  ![starts](https://img.shields.io/github/stars/R3K1NG/wpUsersScan.svg) ![forks](https://img.shields.io/github/forks/R3K1NG/wpUsersScan.svg)
- [https://github.com/teambugsbunny/wpUsersScan](https://github.com/teambugsbunny/wpUsersScan) :  ![starts](https://img.shields.io/github/stars/teambugsbunny/wpUsersScan.svg) ![forks](https://img.shields.io/github/forks/teambugsbunny/wpUsersScan.svg)
- [https://github.com/ndr-repo/CVE-2017-5487](https://github.com/ndr-repo/CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/ndr-repo/CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/ndr-repo/CVE-2017-5487.svg)
- [https://github.com/SeasonLeague/CVE-2017-5487](https://github.com/SeasonLeague/CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/SeasonLeague/CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/SeasonLeague/CVE-2017-5487.svg)
- [https://github.com/tpdlshdmlrkfmcla/cve-2017-5487](https://github.com/tpdlshdmlrkfmcla/cve-2017-5487) :  ![starts](https://img.shields.io/github/stars/tpdlshdmlrkfmcla/cve-2017-5487.svg) ![forks](https://img.shields.io/github/forks/tpdlshdmlrkfmcla/cve-2017-5487.svg)
- [https://github.com/dream434/CVE-2017-5487](https://github.com/dream434/CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/dream434/CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/dream434/CVE-2017-5487.svg)
- [https://github.com/zkhalidul/GrabberWP-CVE-2017-5487](https://github.com/zkhalidul/GrabberWP-CVE-2017-5487) :  ![starts](https://img.shields.io/github/stars/zkhalidul/GrabberWP-CVE-2017-5487.svg) ![forks](https://img.shields.io/github/forks/zkhalidul/GrabberWP-CVE-2017-5487.svg)
- [https://github.com/Ravindu-Priyankara/CVE-2017-5487-vulnerability-on-NSBM](https://github.com/Ravindu-Priyankara/CVE-2017-5487-vulnerability-on-NSBM) :  ![starts](https://img.shields.io/github/stars/Ravindu-Priyankara/CVE-2017-5487-vulnerability-on-NSBM.svg) ![forks](https://img.shields.io/github/forks/Ravindu-Priyankara/CVE-2017-5487-vulnerability-on-NSBM.svg)


## CVE-2017-5415
 An attack can use a blob URL and script to spoof an arbitrary addressbar URL prefaced by "blob:" as the protocol, leading to user confusion and further spoofing attacks. This vulnerability affects Firefox  52.

- [https://github.com/649/CVE-2017-5415](https://github.com/649/CVE-2017-5415) :  ![starts](https://img.shields.io/github/stars/649/CVE-2017-5415.svg) ![forks](https://img.shields.io/github/forks/649/CVE-2017-5415.svg)


## CVE-2017-5223
 An issue was discovered in PHPMailer before 5.2.22. PHPMailer's msgHTML method applies transformations to an HTML document to make it usable as an email message body. One of the transformations is to convert relative image URLs into attachments using a script-provided base directory. If no base directory is provided, it resolves to /, meaning that relative image URLs get treated as absolute local file paths and added as attachments. To form a remote vulnerability, the msgHTML method must be called, passed an unfiltered, user-supplied HTML document, and must not set a base directory.

- [https://github.com/cscli/CVE-2017-5223](https://github.com/cscli/CVE-2017-5223) :  ![starts](https://img.shields.io/github/stars/cscli/CVE-2017-5223.svg) ![forks](https://img.shields.io/github/forks/cscli/CVE-2017-5223.svg)


## CVE-2017-5124
 Incorrect application of sandboxing in Blink in Google Chrome prior to 62.0.3202.62 allowed a remote attacker to inject arbitrary scripts or HTML (UXSS) via a crafted MHTML page.

- [https://github.com/Bo0oM/CVE-2017-5124](https://github.com/Bo0oM/CVE-2017-5124) :  ![starts](https://img.shields.io/github/stars/Bo0oM/CVE-2017-5124.svg) ![forks](https://img.shields.io/github/forks/Bo0oM/CVE-2017-5124.svg)


## CVE-2017-5123
 Insufficient data validation in waitid allowed an user to escape sandboxes on Linux.

- [https://github.com/c3r34lk1ll3r/CVE-2017-5123](https://github.com/c3r34lk1ll3r/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/c3r34lk1ll3r/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/c3r34lk1ll3r/CVE-2017-5123.svg)
- [https://github.com/0x5068656e6f6c/CVE-2017-5123](https://github.com/0x5068656e6f6c/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/0x5068656e6f6c/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/0x5068656e6f6c/CVE-2017-5123.svg)
- [https://github.com/Synacktiv-contrib/exploiting-cve-2017-5123](https://github.com/Synacktiv-contrib/exploiting-cve-2017-5123) :  ![starts](https://img.shields.io/github/stars/Synacktiv-contrib/exploiting-cve-2017-5123.svg) ![forks](https://img.shields.io/github/forks/Synacktiv-contrib/exploiting-cve-2017-5123.svg)
- [https://github.com/FloatingGuy/CVE-2017-5123](https://github.com/FloatingGuy/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/FloatingGuy/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/FloatingGuy/CVE-2017-5123.svg)
- [https://github.com/echo-devim/exploit_linux_kernel4.13](https://github.com/echo-devim/exploit_linux_kernel4.13) :  ![starts](https://img.shields.io/github/stars/echo-devim/exploit_linux_kernel4.13.svg) ![forks](https://img.shields.io/github/forks/echo-devim/exploit_linux_kernel4.13.svg)
- [https://github.com/teawater/CVE-2017-5123](https://github.com/teawater/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/teawater/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/teawater/CVE-2017-5123.svg)
- [https://github.com/h1bAna/CVE-2017-5123](https://github.com/h1bAna/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/h1bAna/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/h1bAna/CVE-2017-5123.svg)


## CVE-2017-5007
 Blink in Google Chrome prior to 56.0.2924.76 for Linux, Windows and Mac, and 56.0.2924.87 for Android, incorrectly handled the sequence of events when closing a page, which allowed a remote attacker to inject arbitrary scripts or HTML (UXSS) via a crafted HTML page.

- [https://github.com/Ang-YC/CVE-2017-5007](https://github.com/Ang-YC/CVE-2017-5007) :  ![starts](https://img.shields.io/github/stars/Ang-YC/CVE-2017-5007.svg) ![forks](https://img.shields.io/github/forks/Ang-YC/CVE-2017-5007.svg)


## CVE-2017-4971
 An issue was discovered in Pivotal Spring Web Flow through 2.4.4. Applications that do not change the value of the MvcViewFactoryCreator useSpringBinding property which is disabled by default (i.e., set to 'false') can be vulnerable to malicious EL expressions in view states that process form submissions but do not have a sub-element to declare explicit data binding property mappings.

- [https://github.com/cved-sources/cve-2017-4971](https://github.com/cved-sources/cve-2017-4971) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-4971.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-4971.svg)


## CVE-2017-4878
 DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: none.  Reason: This candidate was in a CNA pool that was not assigned to any issues during 2017.  Notes: none

- [https://github.com/brianwrf/CVE-2017-4878-Samples](https://github.com/brianwrf/CVE-2017-4878-Samples) :  ![starts](https://img.shields.io/github/stars/brianwrf/CVE-2017-4878-Samples.svg) ![forks](https://img.shields.io/github/forks/brianwrf/CVE-2017-4878-Samples.svg)


## CVE-2017-4490
 DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: none.  Reason: This candidate was in a CNA pool that was not assigned to any issues during 2017.  Notes: none

- [https://github.com/homjxi0e/CVE-2017-4490-](https://github.com/homjxi0e/CVE-2017-4490-) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-4490-.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-4490-.svg)
- [https://github.com/homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-](https://github.com/homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-4490-install-Script-Python-in-Terminal-.svg)


## CVE-2017-3881
 A vulnerability in the Cisco Cluster Management Protocol (CMP) processing code in Cisco IOS and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a reload of an affected device or remotely execute code with elevated privileges. The Cluster Management Protocol utilizes Telnet internally as a signaling and command protocol between cluster members. The vulnerability is due to the combination of two factors: (1) the failure to restrict the use of CMP-specific Telnet options only to internal, local communications between cluster members and instead accept and process such options over any Telnet connection to an affected device; and (2) the incorrect processing of malformed CMP-specific Telnet options. An attacker could exploit this vulnerability by sending malformed CMP-specific Telnet options while establishing a Telnet session with an affected Cisco device configured to accept Telnet connections. An exploit could allow an attacker to execute arbitrary code and obtain full control of the device or cause a reload of the affected device. This affects Catalyst switches, Embedded Service 2020 switches, Enhanced Layer 2 EtherSwitch Service Module, Enhanced Layer 2/3 EtherSwitch Service Module, Gigabit Ethernet Switch Module (CGESM) for HP, IE Industrial Ethernet switches, ME 4924-10GE switch, RF Gateway 10, and SM-X Layer 2/3 EtherSwitch Service Module. Cisco Bug IDs: CSCvd48893.

- [https://github.com/artkond/cisco-rce](https://github.com/artkond/cisco-rce) :  ![starts](https://img.shields.io/github/stars/artkond/cisco-rce.svg) ![forks](https://img.shields.io/github/forks/artkond/cisco-rce.svg)
- [https://github.com/homjxi0e/CVE-2017-3881-exploit-cisco-](https://github.com/homjxi0e/CVE-2017-3881-exploit-cisco-) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-3881-exploit-cisco-.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-3881-exploit-cisco-.svg)
- [https://github.com/1337g/CVE-2017-3881](https://github.com/1337g/CVE-2017-3881) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-3881.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-3881.svg)
- [https://github.com/mzakyz666/PoC-CVE-2017-3881](https://github.com/mzakyz666/PoC-CVE-2017-3881) :  ![starts](https://img.shields.io/github/stars/mzakyz666/PoC-CVE-2017-3881.svg) ![forks](https://img.shields.io/github/forks/mzakyz666/PoC-CVE-2017-3881.svg)
- [https://github.com/homjxi0e/CVE-2017-3881-Cisco](https://github.com/homjxi0e/CVE-2017-3881-Cisco) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-3881-Cisco.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-3881-Cisco.svg)


## CVE-2017-3730
 In OpenSSL 1.1.0 before 1.1.0d, if a malicious server supplies bad parameters for a DHE or ECDHE key exchange then this can result in the client attempting to dereference a NULL pointer leading to a client crash. This could be exploited in a Denial of Service attack.

- [https://github.com/olivierh59500/CVE-2017-3730](https://github.com/olivierh59500/CVE-2017-3730) :  ![starts](https://img.shields.io/github/stars/olivierh59500/CVE-2017-3730.svg) ![forks](https://img.shields.io/github/forks/olivierh59500/CVE-2017-3730.svg)


## CVE-2017-3599
 Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Pluggable Auth). Supported versions that are affected are 5.6.35 and earlier and 5.7.17 and earlier. Easily "exploitable" vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H). NOTE: the previous information is from the April 2017 CPU. Oracle has not commented on third-party claims that this issue is an integer overflow in sql/auth/sql_authentication.cc which allows remote attackers to cause a denial of service via a crafted authentication packet.

- [https://github.com/SECFORCE/CVE-2017-3599](https://github.com/SECFORCE/CVE-2017-3599) :  ![starts](https://img.shields.io/github/stars/SECFORCE/CVE-2017-3599.svg) ![forks](https://img.shields.io/github/forks/SECFORCE/CVE-2017-3599.svg)
- [https://github.com/jptr218/mysql_dos](https://github.com/jptr218/mysql_dos) :  ![starts](https://img.shields.io/github/stars/jptr218/mysql_dos.svg) ![forks](https://img.shields.io/github/forks/jptr218/mysql_dos.svg)


## CVE-2017-3506
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.0, 12.2.1.1 and 12.2.1.2. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle WebLogic Server accessible data as well as unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 7.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N).

- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)
- [https://github.com/Al1ex/CVE-2017-3506](https://github.com/Al1ex/CVE-2017-3506) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-3506.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-3506.svg)
- [https://github.com/ianxtianxt/CVE-2017-3506](https://github.com/ianxtianxt/CVE-2017-3506) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2017-3506.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2017-3506.svg)


## CVE-2017-3241
 Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: RMI). Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111; JRockit: R28.3.12. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. While the vulnerability is in Java SE, Java SE Embedded, JRockit, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Java SE, Java SE Embedded, JRockit. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS v3.0 Base Score 9.0 (Confidentiality, Integrity and Availability impacts).

- [https://github.com/xfei3/CVE-2017-3241-POC](https://github.com/xfei3/CVE-2017-3241-POC) :  ![starts](https://img.shields.io/github/stars/xfei3/CVE-2017-3241-POC.svg) ![forks](https://img.shields.io/github/forks/xfei3/CVE-2017-3241-POC.svg)
- [https://github.com/scopion/CVE-2017-3241](https://github.com/scopion/CVE-2017-3241) :  ![starts](https://img.shields.io/github/stars/scopion/CVE-2017-3241.svg) ![forks](https://img.shields.io/github/forks/scopion/CVE-2017-3241.svg)


## CVE-2017-3164
 Server Side Request Forgery in Apache Solr, versions 1.3 until 7.6 (inclusive). Since the "shards" parameter does not have a corresponding whitelist mechanism, a remote attacker with access to the server could make Solr perform an HTTP GET request to any reachable URL.

- [https://github.com/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262](https://github.com/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262) :  ![starts](https://img.shields.io/github/stars/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262.svg) ![forks](https://img.shields.io/github/forks/tdwyer/PoC_CVE-2017-3164_CVE-2017-1262.svg)


## CVE-2017-3143
 An attacker who is able to send and receive messages to an authoritative DNS server and who has knowledge of a valid TSIG key name for the zone and service being targeted may be able to manipulate BIND into accepting an unauthorized dynamic update. Affects BIND 9.4.0-9.8.8, 9.9.0-9.9.10-P1, 9.10.0-9.10.5-P1, 9.11.0-9.11.1-P1, 9.9.3-S1-9.9.10-S2, 9.10.5-S1-9.10.5-S2.

- [https://github.com/saaph/CVE-2017-3143](https://github.com/saaph/CVE-2017-3143) :  ![starts](https://img.shields.io/github/stars/saaph/CVE-2017-3143.svg) ![forks](https://img.shields.io/github/forks/saaph/CVE-2017-3143.svg)


## CVE-2017-3078
 Adobe Flash Player versions 25.0.0.171 and earlier have an exploitable memory corruption vulnerability in the Adobe Texture Format (ATF) module. Successful exploitation could lead to arbitrary code execution.

- [https://github.com/homjxi0e/CVE-2017-3078](https://github.com/homjxi0e/CVE-2017-3078) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-3078.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-3078.svg)


## CVE-2017-3066
 Adobe ColdFusion 2016 Update 3 and earlier, ColdFusion 11 update 11 and earlier, ColdFusion 10 Update 22 and earlier have a Java deserialization vulnerability in the Apache BlazeDS library. Successful exploitation could lead to arbitrary code execution.

- [https://github.com/codewhitesec/ColdFusionPwn](https://github.com/codewhitesec/ColdFusionPwn) :  ![starts](https://img.shields.io/github/stars/codewhitesec/ColdFusionPwn.svg) ![forks](https://img.shields.io/github/forks/codewhitesec/ColdFusionPwn.svg)
- [https://github.com/cucadili/CVE-2017-3066](https://github.com/cucadili/CVE-2017-3066) :  ![starts](https://img.shields.io/github/stars/cucadili/CVE-2017-3066.svg) ![forks](https://img.shields.io/github/forks/cucadili/CVE-2017-3066.svg)


## CVE-2017-3000
 Adobe Flash Player versions 24.0.0.221 and earlier have a vulnerability in the random number generator used for constant blinding. Successful exploitation could lead to information disclosure.

- [https://github.com/dangokyo/CVE-2017-3000](https://github.com/dangokyo/CVE-2017-3000) :  ![starts](https://img.shields.io/github/stars/dangokyo/CVE-2017-3000.svg) ![forks](https://img.shields.io/github/forks/dangokyo/CVE-2017-3000.svg)


## CVE-2017-2903
 An exploitable integer overflow exists in the DPX loading functionality of the Blender open-source 3d creation suite version 2.78c. A specially crafted '.cin' file can cause an integer overflow resulting in a buffer overflow which can allow for code execution under the context of the application. An attacker can convince a user to use the file as an asset via the sequencer in order to trigger this vulnerability.

- [https://github.com/SpiralBL0CK/dpx_work_CVE-2017-2903](https://github.com/SpiralBL0CK/dpx_work_CVE-2017-2903) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/dpx_work_CVE-2017-2903.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/dpx_work_CVE-2017-2903.svg)


## CVE-2017-2824
 An exploitable code execution vulnerability exists in the trapper command functionality of Zabbix Server 2.4.X. A specially crafted set of packets can cause a command injection resulting in remote code execution. An attacker can make requests from an active Zabbix Proxy to trigger this vulnerability.

- [https://github.com/listenquiet/cve-2017-2824-reverse-shell](https://github.com/listenquiet/cve-2017-2824-reverse-shell) :  ![starts](https://img.shields.io/github/stars/listenquiet/cve-2017-2824-reverse-shell.svg) ![forks](https://img.shields.io/github/forks/listenquiet/cve-2017-2824-reverse-shell.svg)


## CVE-2017-2793
 An exploitable heap corruption vulnerability exists in the UnCompressUnicode functionality of Antenna House DMC HTMLFilter used by MarkLogic 8.0-6. A specially crafted xls file can cause a heap corruption resulting in arbitrary code execution. An attacker can send/provide malicious XLS file to trigger this vulnerability.

- [https://github.com/sUbc0ol/Detection-for-CVE-2017-2793](https://github.com/sUbc0ol/Detection-for-CVE-2017-2793) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/Detection-for-CVE-2017-2793.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/Detection-for-CVE-2017-2793.svg)


## CVE-2017-2751
 A BIOS password extraction vulnerability has been reported on certain consumer notebooks with firmware F.22 and others. The BIOS password was stored in CMOS in a way that allowed it to be extracted. This applies to consumer notebooks launched in early 2014.

- [https://github.com/BaderSZ/CVE-2017-2751](https://github.com/BaderSZ/CVE-2017-2751) :  ![starts](https://img.shields.io/github/stars/BaderSZ/CVE-2017-2751.svg) ![forks](https://img.shields.io/github/forks/BaderSZ/CVE-2017-2751.svg)


## CVE-2017-2741
 A potential security vulnerability has been identified with HP PageWide Printers, HP OfficeJet Pro Printers, with firmware before 1708D. This vulnerability could potentially be exploited to execute arbitrary code.

- [https://github.com/dopheide-esnet/zeek-jetdirect](https://github.com/dopheide-esnet/zeek-jetdirect) :  ![starts](https://img.shields.io/github/stars/dopheide-esnet/zeek-jetdirect.svg) ![forks](https://img.shields.io/github/forks/dopheide-esnet/zeek-jetdirect.svg)


## CVE-2017-2671
 The ping_unhash function in net/ipv4/ping.c in the Linux kernel through 4.10.8 is too late in obtaining a certain lock and consequently cannot ensure that disconnect function calls are safe, which allows local users to cause a denial of service (panic) by leveraging access to the protocol value of IPPROTO_ICMP in a socket system call.

- [https://github.com/homjxi0e/CVE-2017-2671](https://github.com/homjxi0e/CVE-2017-2671) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-2671.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-2671.svg)


## CVE-2017-2666
 It was discovered in Undertow that the code that parsed the HTTP request line permitted invalid characters. This could be exploited, in conjunction with a proxy that also permitted the invalid characters but with a different interpretation, to inject data into the HTTP response. By manipulating the HTTP response the attacker could poison a web-cache, perform an XSS attack, or obtain sensitive information from requests other than their own.

- [https://github.com/tafamace/CVE-2017-2666](https://github.com/tafamace/CVE-2017-2666) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2017-2666.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2017-2666.svg)


## CVE-2017-2636
 Race condition in drivers/tty/n_hdlc.c in the Linux kernel through 4.10.1 allows local users to gain privileges or cause a denial of service (double free) by setting the HDLC line discipline.

- [https://github.com/alexzorin/cve-2017-2636-el](https://github.com/alexzorin/cve-2017-2636-el) :  ![starts](https://img.shields.io/github/stars/alexzorin/cve-2017-2636-el.svg) ![forks](https://img.shields.io/github/forks/alexzorin/cve-2017-2636-el.svg)


## CVE-2017-2370
 An issue was discovered in certain Apple products. iOS before 10.2.1 is affected. macOS before 10.12.3 is affected. tvOS before 10.1.1 is affected. watchOS before 3.1.3 is affected. The issue involves the "Kernel" component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (buffer overflow) via a crafted app.

- [https://github.com/Peterpan0927/CVE-2017-2370](https://github.com/Peterpan0927/CVE-2017-2370) :  ![starts](https://img.shields.io/github/stars/Peterpan0927/CVE-2017-2370.svg) ![forks](https://img.shields.io/github/forks/Peterpan0927/CVE-2017-2370.svg)
- [https://github.com/Rootkitsmm-zz/extra_recipe-iOS-10.2](https://github.com/Rootkitsmm-zz/extra_recipe-iOS-10.2) :  ![starts](https://img.shields.io/github/stars/Rootkitsmm-zz/extra_recipe-iOS-10.2.svg) ![forks](https://img.shields.io/github/forks/Rootkitsmm-zz/extra_recipe-iOS-10.2.svg)
- [https://github.com/ldebug/extra_recipe](https://github.com/ldebug/extra_recipe) :  ![starts](https://img.shields.io/github/stars/ldebug/extra_recipe.svg) ![forks](https://img.shields.io/github/forks/ldebug/extra_recipe.svg)
- [https://github.com/maximehip/extra_recipe](https://github.com/maximehip/extra_recipe) :  ![starts](https://img.shields.io/github/stars/maximehip/extra_recipe.svg) ![forks](https://img.shields.io/github/forks/maximehip/extra_recipe.svg)


## CVE-2017-2368
 An issue was discovered in certain Apple products. iOS before 10.2.1 is affected. The issue involves the "Contacts" component. It allows remote attackers to cause a denial of service (application crash) via a crafted contact card.

- [https://github.com/vincedes3/CVE-2017-2368](https://github.com/vincedes3/CVE-2017-2368) :  ![starts](https://img.shields.io/github/stars/vincedes3/CVE-2017-2368.svg) ![forks](https://img.shields.io/github/forks/vincedes3/CVE-2017-2368.svg)


## CVE-2017-2027
 DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: none.  Reason: This candidate was in a CNA pool that was not assigned to any issues during 2017.  Notes: none

- [https://github.com/ghhubin/weblogic_cve2017-20271](https://github.com/ghhubin/weblogic_cve2017-20271) :  ![starts](https://img.shields.io/github/stars/ghhubin/weblogic_cve2017-20271.svg) ![forks](https://img.shields.io/github/forks/ghhubin/weblogic_cve2017-20271.svg)


## CVE-2017-1635
 IBM Tivoli Monitoring V6 6.2.2.x could allow a remote attacker to execute arbitrary code on the system, caused by a use-after-free error. A remote attacker could exploit this vulnerability to execute arbitrary code on the system or cause the application to crash. IBM X-Force ID: 133243.

- [https://github.com/emcalv/tivoli-poc](https://github.com/emcalv/tivoli-poc) :  ![starts](https://img.shields.io/github/stars/emcalv/tivoli-poc.svg) ![forks](https://img.shields.io/github/forks/emcalv/tivoli-poc.svg)
- [https://github.com/bcdannyboy/cve-2017-1635-PoC](https://github.com/bcdannyboy/cve-2017-1635-PoC) :  ![starts](https://img.shields.io/github/stars/bcdannyboy/cve-2017-1635-PoC.svg) ![forks](https://img.shields.io/github/forks/bcdannyboy/cve-2017-1635-PoC.svg)


## CVE-2017-1624
 IBM QRadar 7.3 and 7.3.1 specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors. IBM X-Force ID: 133122.

- [https://github.com/AOCorsaire/CVE-2017-16245](https://github.com/AOCorsaire/CVE-2017-16245) :  ![starts](https://img.shields.io/github/stars/AOCorsaire/CVE-2017-16245.svg) ![forks](https://img.shields.io/github/forks/AOCorsaire/CVE-2017-16245.svg)


## CVE-2017-1608
 IBM Rational Quality Manager and IBM Rational Collaborative Lifecycle Management 5.0 through 5.0.2 and 6.0 through 6.0.5 are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 132928.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16087](https://github.com/ossf-cve-benchmark/CVE-2017-16087) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16087.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16087.svg)


## CVE-2017-1235
 IBM WebSphere MQ 8.0 could allow an authenticated user to cause a premature termination of a client application thread which could potentially cause denial of service. IBM X-Force ID: 123914.

- [https://github.com/11k4r/CVE-2017-1235_exploit](https://github.com/11k4r/CVE-2017-1235_exploit) :  ![starts](https://img.shields.io/github/stars/11k4r/CVE-2017-1235_exploit.svg) ![forks](https://img.shields.io/github/forks/11k4r/CVE-2017-1235_exploit.svg)


## CVE-2017-1182
 IBM Tivoli Monitoring Portal v6 could allow a local (network adjacent) attacker to execute arbitrary commands on the system, when default client-server default communications, HTTP, are being used. IBM X-Force ID: 123493.

- [https://github.com/Morfeen01/cve-2017-1182-TN](https://github.com/Morfeen01/cve-2017-1182-TN) :  ![starts](https://img.shields.io/github/stars/Morfeen01/cve-2017-1182-TN.svg) ![forks](https://img.shields.io/github/forks/Morfeen01/cve-2017-1182-TN.svg)


## CVE-2017-1079
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2017. Notes: none

- [https://github.com/n4xh4ck5/CVE-2017-10797](https://github.com/n4xh4ck5/CVE-2017-10797) :  ![starts](https://img.shields.io/github/stars/n4xh4ck5/CVE-2017-10797.svg) ![forks](https://img.shields.io/github/forks/n4xh4ck5/CVE-2017-10797.svg)


## CVE-2017-0931
 html-janitor node module suffers from a Cross-Site Scripting (XSS) vulnerability via clean() accepting user-controlled values.

- [https://github.com/ossf-cve-benchmark/CVE-2017-0931](https://github.com/ossf-cve-benchmark/CVE-2017-0931) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-0931.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-0931.svg)


## CVE-2017-0806
 An elevation of privilege vulnerability in the Android framework (gatekeeperresponse). Product: Android. Versions: 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-62998805.

- [https://github.com/michalbednarski/ReparcelBug](https://github.com/michalbednarski/ReparcelBug) :  ![starts](https://img.shields.io/github/stars/michalbednarski/ReparcelBug.svg) ![forks](https://img.shields.io/github/forks/michalbednarski/ReparcelBug.svg)


## CVE-2017-0554
 An elevation of privilege vulnerability in the Telephony component could enable a local malicious application to access capabilities outside of its permission levels. This issue is rated as Moderate because it could be used to gain access to elevated capabilities, which are not normally accessible to a third-party application. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-33815946.

- [https://github.com/lanrat/tethr](https://github.com/lanrat/tethr) :  ![starts](https://img.shields.io/github/stars/lanrat/tethr.svg) ![forks](https://img.shields.io/github/forks/lanrat/tethr.svg)


## CVE-2017-0541
 A remote code execution vulnerability in sonivox in Mediaserver could enable an attacker using a specially crafted file to cause memory corruption during media file and data processing. This issue is rated as Critical due to the possibility of remote code execution within the context of the Mediaserver process. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-34031018.

- [https://github.com/C0dak/CVE-2017-0541](https://github.com/C0dak/CVE-2017-0541) :  ![starts](https://img.shields.io/github/stars/C0dak/CVE-2017-0541.svg) ![forks](https://img.shields.io/github/forks/C0dak/CVE-2017-0541.svg)
- [https://github.com/likekabin/CVE-2017-0541](https://github.com/likekabin/CVE-2017-0541) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2017-0541.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2017-0541.svg)


## CVE-2017-0505
 An elevation of privilege vulnerability in MediaTek components, including the M4U driver, sound driver, touchscreen driver, GPU driver, and Command Queue driver, could enable a local malicious application to execute arbitrary code within the context of the kernel. This issue is rated as Critical due to the possibility of a local permanent device compromise, which may require reflashing the operating system to repair the device. Product: Android. Versions: N/A. Android ID: A-31822282. References: M-ALPS02992041.

- [https://github.com/R0rt1z2/CVE-2017-0505-mtk](https://github.com/R0rt1z2/CVE-2017-0505-mtk) :  ![starts](https://img.shields.io/github/stars/R0rt1z2/CVE-2017-0505-mtk.svg) ![forks](https://img.shields.io/github/forks/R0rt1z2/CVE-2017-0505-mtk.svg)


## CVE-2017-0478
 A remote code execution vulnerability in the Framesequence library could enable an attacker using a specially crafted file to execute arbitrary code in the context of an unprivileged process. This issue is rated as High due to the possibility of remote code execution in an application that uses the Framesequence library. Product: Android. Versions: 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-33718716.

- [https://github.com/bingghost/CVE-2017-0478](https://github.com/bingghost/CVE-2017-0478) :  ![starts](https://img.shields.io/github/stars/bingghost/CVE-2017-0478.svg) ![forks](https://img.shields.io/github/forks/bingghost/CVE-2017-0478.svg)
- [https://github.com/likekabin/CVE-2017-0478](https://github.com/likekabin/CVE-2017-0478) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2017-0478.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2017-0478.svg)


## CVE-2017-0411
 An elevation of privilege vulnerability in the Framework APIs could enable a local malicious application to execute arbitrary code within the context of a privileged process. This issue is rated as High because it could be used to gain local access to elevated capabilities, which are not normally accessible to a third-party application. Product: Android. Versions: 7.0, 7.1.1. Android ID: A-33042690.

- [https://github.com/lulusudoku/PoC](https://github.com/lulusudoku/PoC) :  ![starts](https://img.shields.io/github/stars/lulusudoku/PoC.svg) ![forks](https://img.shields.io/github/forks/lulusudoku/PoC.svg)


## CVE-2017-0290
 The Microsoft Malware Protection Engine running on Microsoft Forefront and Microsoft Defender on Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 does not properly scan a specially crafted file leading to memory corruption, aka "Microsoft Malware Protection Engine Remote Code Execution Vulnerability."

- [https://github.com/homjxi0e/CVE-2017-0290-](https://github.com/homjxi0e/CVE-2017-0290-) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-0290-.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-0290-.svg)


## CVE-2017-0263
 The kernel-mode drivers in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allow local users to gain privileges via a crafted application, aka "Win32k Elevation of Privilege Vulnerability."

- [https://github.com/R06otMD5/cve-2017-0263-poc](https://github.com/R06otMD5/cve-2017-0263-poc) :  ![starts](https://img.shields.io/github/stars/R06otMD5/cve-2017-0263-poc.svg) ![forks](https://img.shields.io/github/forks/R06otMD5/cve-2017-0263-poc.svg)


## CVE-2017-0261
 Microsoft Office 2010 SP2, Office 2013 SP1, and Office 2016 allow a remote code execution vulnerability when the software fails to properly handle objects in memory, aka "Office Remote Code Execution Vulnerability". This CVE ID is unique from CVE-2017-0262 and CVE-2017-0281.

- [https://github.com/kcufId/eps-CVE-2017-0261](https://github.com/kcufId/eps-CVE-2017-0261) :  ![starts](https://img.shields.io/github/stars/kcufId/eps-CVE-2017-0261.svg) ![forks](https://img.shields.io/github/forks/kcufId/eps-CVE-2017-0261.svg)
- [https://github.com/erfze/CVE-2017-0261](https://github.com/erfze/CVE-2017-0261) :  ![starts](https://img.shields.io/github/stars/erfze/CVE-2017-0261.svg) ![forks](https://img.shields.io/github/forks/erfze/CVE-2017-0261.svg)


## CVE-2017-0248
 Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to bypass Enhanced Security Usage taggings when they present a certificate that is invalid for a specific use, aka ".NET Security Feature Bypass Vulnerability."

- [https://github.com/rubenmamo/CVE-2017-0248-Test](https://github.com/rubenmamo/CVE-2017-0248-Test) :  ![starts](https://img.shields.io/github/stars/rubenmamo/CVE-2017-0248-Test.svg) ![forks](https://img.shields.io/github/forks/rubenmamo/CVE-2017-0248-Test.svg)


## CVE-2017-0214
 Windows COM in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation privilege vulnerability when Windows fails to properly validate input before loading type libraries, aka "Windows COM Elevation of Privilege Vulnerability". This CVE ID is unique from CVE-2017-0213.

- [https://github.com/Anonymous-Family/CVE-2017-0213](https://github.com/Anonymous-Family/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/CVE-2017-0213.svg)


## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka "Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API."

- [https://github.com/bhdresh/CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/bhdresh/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/bhdresh/CVE-2017-0199.svg)
- [https://github.com/haibara3839/CVE-2017-0199-master](https://github.com/haibara3839/CVE-2017-0199-master) :  ![starts](https://img.shields.io/github/stars/haibara3839/CVE-2017-0199-master.svg) ![forks](https://img.shields.io/github/forks/haibara3839/CVE-2017-0199-master.svg)
- [https://github.com/NotAwful/CVE-2017-0199-Fix](https://github.com/NotAwful/CVE-2017-0199-Fix) :  ![starts](https://img.shields.io/github/stars/NotAwful/CVE-2017-0199-Fix.svg) ![forks](https://img.shields.io/github/forks/NotAwful/CVE-2017-0199-Fix.svg)
- [https://github.com/SyFi/cve-2017-0199](https://github.com/SyFi/cve-2017-0199) :  ![starts](https://img.shields.io/github/stars/SyFi/cve-2017-0199.svg) ![forks](https://img.shields.io/github/forks/SyFi/cve-2017-0199.svg)
- [https://github.com/Exploit-install/CVE-2017-0199](https://github.com/Exploit-install/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/Exploit-install/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/Exploit-install/CVE-2017-0199.svg)
- [https://github.com/SwordSheath/CVE-2017-8570](https://github.com/SwordSheath/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/SwordSheath/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/SwordSheath/CVE-2017-8570.svg)
- [https://github.com/nicpenning/RTF-Cleaner](https://github.com/nicpenning/RTF-Cleaner) :  ![starts](https://img.shields.io/github/stars/nicpenning/RTF-Cleaner.svg) ![forks](https://img.shields.io/github/forks/nicpenning/RTF-Cleaner.svg)
- [https://github.com/jacobsoo/RTF-Cleaner](https://github.com/jacobsoo/RTF-Cleaner) :  ![starts](https://img.shields.io/github/stars/jacobsoo/RTF-Cleaner.svg) ![forks](https://img.shields.io/github/forks/jacobsoo/RTF-Cleaner.svg)
- [https://github.com/n1shant-sinha/CVE-2017-0199](https://github.com/n1shant-sinha/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/n1shant-sinha/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/n1shant-sinha/CVE-2017-0199.svg)
- [https://github.com/Sunqiz/CVE-2017-0199-reprofuction](https://github.com/Sunqiz/CVE-2017-0199-reprofuction) :  ![starts](https://img.shields.io/github/stars/Sunqiz/CVE-2017-0199-reprofuction.svg) ![forks](https://img.shields.io/github/forks/Sunqiz/CVE-2017-0199-reprofuction.svg)
- [https://github.com/herbiezimmerman/2017-11-17-Maldoc-Using-CVE-2017-0199](https://github.com/herbiezimmerman/2017-11-17-Maldoc-Using-CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/herbiezimmerman/2017-11-17-Maldoc-Using-CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/herbiezimmerman/2017-11-17-Maldoc-Using-CVE-2017-0199.svg)
- [https://github.com/kn0wm4d/htattack](https://github.com/kn0wm4d/htattack) :  ![starts](https://img.shields.io/github/stars/kn0wm4d/htattack.svg) ![forks](https://img.shields.io/github/forks/kn0wm4d/htattack.svg)
- [https://github.com/mzakyz666/PoC-CVE-2017-0199](https://github.com/mzakyz666/PoC-CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/mzakyz666/PoC-CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/mzakyz666/PoC-CVE-2017-0199.svg)
- [https://github.com/Phantomlancer123/CVE-2017-0199](https://github.com/Phantomlancer123/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/Phantomlancer123/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/Phantomlancer123/CVE-2017-0199.svg)
- [https://github.com/sUbc0ol/Microsoft-Word-CVE-2017-0199-](https://github.com/sUbc0ol/Microsoft-Word-CVE-2017-0199-) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/Microsoft-Word-CVE-2017-0199-.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/Microsoft-Word-CVE-2017-0199-.svg)
- [https://github.com/joke998/Cve-2017-0199-](https://github.com/joke998/Cve-2017-0199-) :  ![starts](https://img.shields.io/github/stars/joke998/Cve-2017-0199-.svg) ![forks](https://img.shields.io/github/forks/joke998/Cve-2017-0199-.svg)
- [https://github.com/Nacromencer/cve2017-0199-in-python](https://github.com/Nacromencer/cve2017-0199-in-python) :  ![starts](https://img.shields.io/github/stars/Nacromencer/cve2017-0199-in-python.svg) ![forks](https://img.shields.io/github/forks/Nacromencer/cve2017-0199-in-python.svg)
- [https://github.com/likekabin/CVE-2017-0199](https://github.com/likekabin/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2017-0199.svg)
- [https://github.com/joke998/Cve-2017-0199](https://github.com/joke998/Cve-2017-0199) :  ![starts](https://img.shields.io/github/stars/joke998/Cve-2017-0199.svg) ![forks](https://img.shields.io/github/forks/joke998/Cve-2017-0199.svg)
- [https://github.com/viethdgit/CVE-2017-0199](https://github.com/viethdgit/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/viethdgit/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/viethdgit/CVE-2017-0199.svg)
- [https://github.com/ryhanson/CVE-2017-0199](https://github.com/ryhanson/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/ryhanson/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/ryhanson/CVE-2017-0199.svg)
- [https://github.com/kash-123/CVE-2017-0199](https://github.com/kash-123/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/kash-123/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/kash-123/CVE-2017-0199.svg)
- [https://github.com/BRAINIAC22/CVE-2017-0199](https://github.com/BRAINIAC22/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/BRAINIAC22/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/BRAINIAC22/CVE-2017-0199.svg)
- [https://github.com/Winter3un/cve_2017_0199](https://github.com/Winter3un/cve_2017_0199) :  ![starts](https://img.shields.io/github/stars/Winter3un/cve_2017_0199.svg) ![forks](https://img.shields.io/github/forks/Winter3un/cve_2017_0199.svg)
- [https://github.com/stealth-ronin/CVE-2017-0199-PY-KIT](https://github.com/stealth-ronin/CVE-2017-0199-PY-KIT) :  ![starts](https://img.shields.io/github/stars/stealth-ronin/CVE-2017-0199-PY-KIT.svg) ![forks](https://img.shields.io/github/forks/stealth-ronin/CVE-2017-0199-PY-KIT.svg)
- [https://github.com/TheCyberWatchers/CVE-2017-0199-v5.0](https://github.com/TheCyberWatchers/CVE-2017-0199-v5.0) :  ![starts](https://img.shields.io/github/stars/TheCyberWatchers/CVE-2017-0199-v5.0.svg) ![forks](https://img.shields.io/github/forks/TheCyberWatchers/CVE-2017-0199-v5.0.svg)


## CVE-2017-0145
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0144, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/peterpt/eternal_scanner](https://github.com/peterpt/eternal_scanner) :  ![starts](https://img.shields.io/github/stars/peterpt/eternal_scanner.svg) ![forks](https://img.shields.io/github/forks/peterpt/eternal_scanner.svg)
- [https://github.com/MelonSmasher/chef_tissues](https://github.com/MelonSmasher/chef_tissues) :  ![starts](https://img.shields.io/github/stars/MelonSmasher/chef_tissues.svg) ![forks](https://img.shields.io/github/forks/MelonSmasher/chef_tissues.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/peterpt/eternal_scanner](https://github.com/peterpt/eternal_scanner) :  ![starts](https://img.shields.io/github/stars/peterpt/eternal_scanner.svg) ![forks](https://img.shields.io/github/forks/peterpt/eternal_scanner.svg)
- [https://github.com/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution](https://github.com/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution.svg)
- [https://github.com/AdityaBhatt3010/VAPT-Report-on-SMB-Exploitation-in-Windows-10-Finance-Endpoint](https://github.com/AdityaBhatt3010/VAPT-Report-on-SMB-Exploitation-in-Windows-10-Finance-Endpoint) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/VAPT-Report-on-SMB-Exploitation-in-Windows-10-Finance-Endpoint.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/VAPT-Report-on-SMB-Exploitation-in-Windows-10-Finance-Endpoint.svg)
- [https://github.com/AtithKhawas/autoblue](https://github.com/AtithKhawas/autoblue) :  ![starts](https://img.shields.io/github/stars/AtithKhawas/autoblue.svg) ![forks](https://img.shields.io/github/forks/AtithKhawas/autoblue.svg)
- [https://github.com/sethwhy/BlueDoor](https://github.com/sethwhy/BlueDoor) :  ![starts](https://img.shields.io/github/stars/sethwhy/BlueDoor.svg) ![forks](https://img.shields.io/github/forks/sethwhy/BlueDoor.svg)
- [https://github.com/kimocoder/eternalblue](https://github.com/kimocoder/eternalblue) :  ![starts](https://img.shields.io/github/stars/kimocoder/eternalblue.svg) ![forks](https://img.shields.io/github/forks/kimocoder/eternalblue.svg)
- [https://github.com/quynhold/Detect-CVE-2017-0144-attack](https://github.com/quynhold/Detect-CVE-2017-0144-attack) :  ![starts](https://img.shields.io/github/stars/quynhold/Detect-CVE-2017-0144-attack.svg) ![forks](https://img.shields.io/github/forks/quynhold/Detect-CVE-2017-0144-attack.svg)
- [https://github.com/ducanh2oo3/Vulnerability-Research-CVE-2017-0144](https://github.com/ducanh2oo3/Vulnerability-Research-CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/ducanh2oo3/Vulnerability-Research-CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/ducanh2oo3/Vulnerability-Research-CVE-2017-0144.svg)
- [https://github.com/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144](https://github.com/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/luckyman2907/SMB-Protocol-Vulnerability_CVE-2017-0144.svg)
- [https://github.com/AnugiArrawwala/CVE-Research](https://github.com/AnugiArrawwala/CVE-Research) :  ![starts](https://img.shields.io/github/stars/AnugiArrawwala/CVE-Research.svg) ![forks](https://img.shields.io/github/forks/AnugiArrawwala/CVE-Research.svg)
- [https://github.com/DenuwanJayasekara/CVE-Exploitation-Reports](https://github.com/DenuwanJayasekara/CVE-Exploitation-Reports) :  ![starts](https://img.shields.io/github/stars/DenuwanJayasekara/CVE-Exploitation-Reports.svg) ![forks](https://img.shields.io/github/forks/DenuwanJayasekara/CVE-Exploitation-Reports.svg)
- [https://github.com/MedX267/EternalBlue-Vulnerability-Scanner](https://github.com/MedX267/EternalBlue-Vulnerability-Scanner) :  ![starts](https://img.shields.io/github/stars/MedX267/EternalBlue-Vulnerability-Scanner.svg) ![forks](https://img.shields.io/github/forks/MedX267/EternalBlue-Vulnerability-Scanner.svg)
- [https://github.com/pelagornisandersi/WIndows-7-automated-exploitation-using-metasploit-framework-](https://github.com/pelagornisandersi/WIndows-7-automated-exploitation-using-metasploit-framework-) :  ![starts](https://img.shields.io/github/stars/pelagornisandersi/WIndows-7-automated-exploitation-using-metasploit-framework-.svg) ![forks](https://img.shields.io/github/forks/pelagornisandersi/WIndows-7-automated-exploitation-using-metasploit-framework-.svg)


## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/h3x0v3rl0rd/MS17-010_CVE-2017-0143](https://github.com/h3x0v3rl0rd/MS17-010_CVE-2017-0143) :  ![starts](https://img.shields.io/github/stars/h3x0v3rl0rd/MS17-010_CVE-2017-0143.svg) ![forks](https://img.shields.io/github/forks/h3x0v3rl0rd/MS17-010_CVE-2017-0143.svg)
- [https://github.com/NatteeSetobol/Etern-blue-Windows-7-Checker](https://github.com/NatteeSetobol/Etern-blue-Windows-7-Checker) :  ![starts](https://img.shields.io/github/stars/NatteeSetobol/Etern-blue-Windows-7-Checker.svg) ![forks](https://img.shields.io/github/forks/NatteeSetobol/Etern-blue-Windows-7-Checker.svg)
- [https://github.com/valarauco/wannafind](https://github.com/valarauco/wannafind) :  ![starts](https://img.shields.io/github/stars/valarauco/wannafind.svg) ![forks](https://img.shields.io/github/forks/valarauco/wannafind.svg)
- [https://github.com/h3x0v3rl0rd/MS17-010](https://github.com/h3x0v3rl0rd/MS17-010) :  ![starts](https://img.shields.io/github/stars/h3x0v3rl0rd/MS17-010.svg) ![forks](https://img.shields.io/github/forks/h3x0v3rl0rd/MS17-010.svg)
- [https://github.com/benguelmas/cve-2017-0143](https://github.com/benguelmas/cve-2017-0143) :  ![starts](https://img.shields.io/github/stars/benguelmas/cve-2017-0143.svg) ![forks](https://img.shields.io/github/forks/benguelmas/cve-2017-0143.svg)
- [https://github.com/Cedric-Martz/EthernalBlue_report](https://github.com/Cedric-Martz/EthernalBlue_report) :  ![starts](https://img.shields.io/github/stars/Cedric-Martz/EthernalBlue_report.svg) ![forks](https://img.shields.io/github/forks/Cedric-Martz/EthernalBlue_report.svg)
- [https://github.com/SampatDhakal/Metasploit-Attack-Report](https://github.com/SampatDhakal/Metasploit-Attack-Report) :  ![starts](https://img.shields.io/github/stars/SampatDhakal/Metasploit-Attack-Report.svg) ![forks](https://img.shields.io/github/forks/SampatDhakal/Metasploit-Attack-Report.svg)
- [https://github.com/Mafiosohack/offensive-security-lab-1](https://github.com/Mafiosohack/offensive-security-lab-1) :  ![starts](https://img.shields.io/github/stars/Mafiosohack/offensive-security-lab-1.svg) ![forks](https://img.shields.io/github/forks/Mafiosohack/offensive-security-lab-1.svg)
- [https://github.com/basimnawaz6/EternalBlue-Lab](https://github.com/basimnawaz6/EternalBlue-Lab) :  ![starts](https://img.shields.io/github/stars/basimnawaz6/EternalBlue-Lab.svg) ![forks](https://img.shields.io/github/forks/basimnawaz6/EternalBlue-Lab.svg)
- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)


## CVE-2017-0108
 The Windows Graphics Component in Microsoft Office 2007 SP3; 2010 SP2; and Word Viewer; Skype for Business 2016; Lync 2013 SP1; Lync 2010; Live Meeting 2007; Silverlight 5; Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; and Windows 7 SP1 allows remote attackers to execute arbitrary code via a crafted web site, aka "Graphics Component Remote Code Execution Vulnerability." This vulnerability is different from that described in CVE-2017-0014.

- [https://github.com/homjxi0e/CVE-2017-0108](https://github.com/homjxi0e/CVE-2017-0108) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-0108.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-0108.svg)


## CVE-2017-0106
 Microsoft Excel 2007 SP3, Microsoft Outlook 2010 SP2, Microsoft Outlook 2013 SP1, and Microsoft Outlook 2016 allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted document, aka "Microsoft Office Memory Corruption Vulnerability."

- [https://github.com/ryhanson/CVE-2017-0106](https://github.com/ryhanson/CVE-2017-0106) :  ![starts](https://img.shields.io/github/stars/ryhanson/CVE-2017-0106.svg) ![forks](https://img.shields.io/github/forks/ryhanson/CVE-2017-0106.svg)


## CVE-2017-0100
 A DCOM object in Helppane.exe in Microsoft Windows 7 SP1; Windows Server 2008 R2; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows local users to gain privileges via a crafted application, aka "Windows HelpPane Elevation of Privilege Vulnerability."

- [https://github.com/cssxn/CVE-2017-0100](https://github.com/cssxn/CVE-2017-0100) :  ![starts](https://img.shields.io/github/stars/cssxn/CVE-2017-0100.svg) ![forks](https://img.shields.io/github/forks/cssxn/CVE-2017-0100.svg)


## CVE-2017-0075
 Hyper-V in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows guest OS users to execute arbitrary code on the host OS via a crafted application, aka "Hyper-V Remote Code Execution Vulnerability." This vulnerability is different from that described in CVE-2017-0109.

- [https://github.com/4B5F5F4B/HyperV](https://github.com/4B5F5F4B/HyperV) :  ![starts](https://img.shields.io/github/stars/4B5F5F4B/HyperV.svg) ![forks](https://img.shields.io/github/forks/4B5F5F4B/HyperV.svg)
- [https://github.com/belyakovvitagmailt/4B5F5F4Bp](https://github.com/belyakovvitagmailt/4B5F5F4Bp) :  ![starts](https://img.shields.io/github/stars/belyakovvitagmailt/4B5F5F4Bp.svg) ![forks](https://img.shields.io/github/forks/belyakovvitagmailt/4B5F5F4Bp.svg)
- [https://github.com/MarkusCarelli1/4B5F5F4Bp](https://github.com/MarkusCarelli1/4B5F5F4Bp) :  ![starts](https://img.shields.io/github/stars/MarkusCarelli1/4B5F5F4Bp.svg) ![forks](https://img.shields.io/github/forks/MarkusCarelli1/4B5F5F4Bp.svg)


## CVE-2017-0065
 Microsoft Edge allows remote attackers to obtain sensitive information from process memory via a crafted web site, aka "Microsoft Browser Information Disclosure Vulnerability." This vulnerability is different from those described in CVE-2017-0009, CVE-2017-0011, CVE-2017-0017, and CVE-2017-0068.

- [https://github.com/Dankirk/cve-2017-0065](https://github.com/Dankirk/cve-2017-0065) :  ![starts](https://img.shields.io/github/stars/Dankirk/cve-2017-0065.svg) ![forks](https://img.shields.io/github/forks/Dankirk/cve-2017-0065.svg)


## CVE-2017-0055
 Microsoft Internet Information Server (IIS) in Windows Vista SP2; Windows Server 2008 SP2 and R2; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to perform cross-site scripting and run script with local user privileges via a crafted request, aka "Microsoft IIS Server XSS Elevation of Privilege Vulnerability."

- [https://github.com/NetJBS/CVE-2017-0055-PoC](https://github.com/NetJBS/CVE-2017-0055-PoC) :  ![starts](https://img.shields.io/github/stars/NetJBS/CVE-2017-0055-PoC.svg) ![forks](https://img.shields.io/github/forks/NetJBS/CVE-2017-0055-PoC.svg)


## CVE-2017-0005
 The Graphics Device Interface (GDI) in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607 allows local users to gain privileges via a crafted application, aka "Windows GDI Elevation of Privilege Vulnerability." This vulnerability is different from those described in CVE-2017-0001, CVE-2017-0025, and CVE-2017-0047.

- [https://github.com/sheri31/0005poc](https://github.com/sheri31/0005poc) :  ![starts](https://img.shields.io/github/stars/sheri31/0005poc.svg) ![forks](https://img.shields.io/github/forks/sheri31/0005poc.svg)


## CVE-2016-10956
 The mail-masta plugin 1.0 for WordPress has local file inclusion in count_of_send.php and csvexport.php.

- [https://github.com/p0dalirius/CVE-2016-10956-mail-masta](https://github.com/p0dalirius/CVE-2016-10956-mail-masta) :  ![starts](https://img.shields.io/github/stars/p0dalirius/CVE-2016-10956-mail-masta.svg) ![forks](https://img.shields.io/github/forks/p0dalirius/CVE-2016-10956-mail-masta.svg)
- [https://github.com/Hackhoven/wp-mail-masta-exploit](https://github.com/Hackhoven/wp-mail-masta-exploit) :  ![starts](https://img.shields.io/github/stars/Hackhoven/wp-mail-masta-exploit.svg) ![forks](https://img.shields.io/github/forks/Hackhoven/wp-mail-masta-exploit.svg)


## CVE-2016-10761
 Logitech Unifying devices before 2016-02-26 allow keystroke injection, bypassing encryption, aka MouseJack.

- [https://github.com/ISSAPolska/CVE-2016-10761](https://github.com/ISSAPolska/CVE-2016-10761) :  ![starts](https://img.shields.io/github/stars/ISSAPolska/CVE-2016-10761.svg) ![forks](https://img.shields.io/github/forks/ISSAPolska/CVE-2016-10761.svg)


## CVE-2016-10277
 An elevation of privilege vulnerability in the Motorola bootloader could enable a local malicious application to execute arbitrary code within the context of the bootloader. This issue is rated as Critical due to the possibility of a local permanent device compromise, which may require reflashing the operating system to repair the device. Product: Android. Versions: Kernel-3.10, Kernel-3.18. Android ID: A-33840490.

- [https://github.com/alephsecurity/initroot](https://github.com/alephsecurity/initroot) :  ![starts](https://img.shields.io/github/stars/alephsecurity/initroot.svg) ![forks](https://img.shields.io/github/forks/alephsecurity/initroot.svg)
- [https://github.com/leosol/initroot](https://github.com/leosol/initroot) :  ![starts](https://img.shields.io/github/stars/leosol/initroot.svg) ![forks](https://img.shields.io/github/forks/leosol/initroot.svg)


## CVE-2016-9192
 A vulnerability in Cisco AnyConnect Secure Mobility Client for Windows could allow an authenticated, local attacker to install and execute an arbitrary executable file with privileges equivalent to the Microsoft Windows operating system SYSTEM account. More Information: CSCvb68043. Known Affected Releases: 4.3(2039) 4.3(748). Known Fixed Releases: 4.3(4019) 4.4(225).

- [https://github.com/serializingme/cve-2016-9192](https://github.com/serializingme/cve-2016-9192) :  ![starts](https://img.shields.io/github/stars/serializingme/cve-2016-9192.svg) ![forks](https://img.shields.io/github/forks/serializingme/cve-2016-9192.svg)


## CVE-2016-8863
 Heap-based buffer overflow in the create_url_list function in gena/gena_device.c in Portable UPnP SDK (aka libupnp) before 1.6.21 allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a valid URI followed by an invalid one in the CALLBACK header of an SUBSCRIBE request.

- [https://github.com/mephi42/CVE-2016-8863](https://github.com/mephi42/CVE-2016-8863) :  ![starts](https://img.shields.io/github/stars/mephi42/CVE-2016-8863.svg) ![forks](https://img.shields.io/github/forks/mephi42/CVE-2016-8863.svg)


## CVE-2016-8776
 Huawei P9 phones with software EVA-AL10C00,EVA-CL10C00,EVA-DL10C00,EVA-TL10C00 and P9 Lite phones with software VNS-L21C185 allow attackers to bypass the factory reset protection (FRP) to enter some functional modules without authorization and perform operations to update the Google account.

- [https://github.com/akzedevops/CVE-2016-8776](https://github.com/akzedevops/CVE-2016-8776) :  ![starts](https://img.shields.io/github/stars/akzedevops/CVE-2016-8776.svg) ![forks](https://img.shields.io/github/forks/akzedevops/CVE-2016-8776.svg)


## CVE-2016-8022
 Authentication bypass by spoofing vulnerability in Intel Security VirusScan Enterprise Linux (VSEL) 2.0.3 (and earlier) allows remote unauthenticated attacker to execute arbitrary code or cause a denial of service via a crafted authentication cookie.

- [https://github.com/opsxcq/exploit-CVE-2016-8016-25](https://github.com/opsxcq/exploit-CVE-2016-8016-25) :  ![starts](https://img.shields.io/github/stars/opsxcq/exploit-CVE-2016-8016-25.svg) ![forks](https://img.shields.io/github/forks/opsxcq/exploit-CVE-2016-8016-25.svg)


## CVE-2016-6801
 Cross-site request forgery (CSRF) vulnerability in the CSRF content-type check in Jackrabbit-Webdav in Apache Jackrabbit 2.4.x before 2.4.6, 2.6.x before 2.6.6, 2.8.x before 2.8.3, 2.10.x before 2.10.4, 2.12.x before 2.12.4, and 2.13.x before 2.13.3 allows remote attackers to hijack the authentication of unspecified victims for requests that create a resource via an HTTP POST request with a (1) missing or (2) crafted Content-Type header.

- [https://github.com/TSNGL21/CVE-2016-6801](https://github.com/TSNGL21/CVE-2016-6801) :  ![starts](https://img.shields.io/github/stars/TSNGL21/CVE-2016-6801.svg) ![forks](https://img.shields.io/github/forks/TSNGL21/CVE-2016-6801.svg)


## CVE-2016-5983
 IBM WebSphere Application Server (WAS) 7.0 before 7.0.0.43, 8.0 before 8.0.0.13, 8.5 before 8.5.5.11, 9.0 before 9.0.0.2, and Liberty before 16.0.0.4 allows remote authenticated users to execute arbitrary Java code via a crafted serialized object.

- [https://github.com/BitWrecker/CVE-2016-5983](https://github.com/BitWrecker/CVE-2016-5983) :  ![starts](https://img.shields.io/github/stars/BitWrecker/CVE-2016-5983.svg) ![forks](https://img.shields.io/github/forks/BitWrecker/CVE-2016-5983.svg)


## CVE-2016-4861
 The (1) order and (2) group methods in Zend_Db_Select in the Zend Framework before 1.12.20 might allow remote attackers to conduct SQL injection attacks by leveraging failure to remove comments from an SQL statement before validation.

- [https://github.com/KosukeShimofuji/CVE-2016-4861](https://github.com/KosukeShimofuji/CVE-2016-4861) :  ![starts](https://img.shields.io/github/stars/KosukeShimofuji/CVE-2016-4861.svg) ![forks](https://img.shields.io/github/forks/KosukeShimofuji/CVE-2016-4861.svg)


## CVE-2016-4845
 Cross-site request forgery (CSRF) vulnerability on I-O DATA DEVICE HVL-A2.0, HVL-A3.0, HVL-A4.0, HVL-AT1.0S, HVL-AT2.0, HVL-AT3.0, HVL-AT4.0, HVL-AT2.0A, HVL-AT3.0A, and HVL-AT4.0A devices with firmware before 2.04 allows remote attackers to hijack the authentication of arbitrary users for requests that delete content.

- [https://github.com/kaito834/cve-2016-4845_csrf](https://github.com/kaito834/cve-2016-4845_csrf) :  ![starts](https://img.shields.io/github/stars/kaito834/cve-2016-4845_csrf.svg) ![forks](https://img.shields.io/github/forks/kaito834/cve-2016-4845_csrf.svg)


## CVE-2016-4655
 The kernel in Apple iOS before 9.3.5 allows attackers to obtain sensitive information from memory via a crafted app.

- [https://github.com/jndok/PegasusX](https://github.com/jndok/PegasusX) :  ![starts](https://img.shields.io/github/stars/jndok/PegasusX.svg) ![forks](https://img.shields.io/github/forks/jndok/PegasusX.svg)
- [https://github.com/tomitokics/br0ke](https://github.com/tomitokics/br0ke) :  ![starts](https://img.shields.io/github/stars/tomitokics/br0ke.svg) ![forks](https://img.shields.io/github/forks/tomitokics/br0ke.svg)
- [https://github.com/Cryptiiiic/skybreak](https://github.com/Cryptiiiic/skybreak) :  ![starts](https://img.shields.io/github/stars/Cryptiiiic/skybreak.svg) ![forks](https://img.shields.io/github/forks/Cryptiiiic/skybreak.svg)
- [https://github.com/liangle1986126z/jndok](https://github.com/liangle1986126z/jndok) :  ![starts](https://img.shields.io/github/stars/liangle1986126z/jndok.svg) ![forks](https://img.shields.io/github/forks/liangle1986126z/jndok.svg)


## CVE-2016-4468
 SQL injection vulnerability in Pivotal Cloud Foundry (PCF) before 238; UAA 2.x before 2.7.4.4, 3.x before 3.3.0.2, and 3.4.x before 3.4.1; UAA BOSH before 11.2 and 12.x before 12.2; Elastic Runtime before 1.6.29 and 1.7.x before 1.7.7; and Ops Manager 1.7.x before 1.7.8 allows remote authenticated users to execute arbitrary SQL commands via unspecified vectors.

- [https://github.com/shanika04/cloudfoundry_uaa](https://github.com/shanika04/cloudfoundry_uaa) :  ![starts](https://img.shields.io/github/stars/shanika04/cloudfoundry_uaa.svg) ![forks](https://img.shields.io/github/forks/shanika04/cloudfoundry_uaa.svg)


## CVE-2016-4438
 The REST plugin in Apache Struts 2 2.3.19 through 2.3.28.1 allows remote attackers to execute arbitrary code via a crafted expression.

- [https://github.com/jason3e7/CVE-2016-4438](https://github.com/jason3e7/CVE-2016-4438) :  ![starts](https://img.shields.io/github/stars/jason3e7/CVE-2016-4438.svg) ![forks](https://img.shields.io/github/forks/jason3e7/CVE-2016-4438.svg)
- [https://github.com/tafamace/CVE-2016-4438](https://github.com/tafamace/CVE-2016-4438) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2016-4438.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2016-4438.svg)


## CVE-2016-2776
 buffer.c in named in ISC BIND 9 before 9.9.9-P3, 9.10.x before 9.10.4-P3, and 9.11.x before 9.11.0rc3 does not properly construct responses, which allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a crafted query.

- [https://github.com/infobyte/CVE-2016-2776](https://github.com/infobyte/CVE-2016-2776) :  ![starts](https://img.shields.io/github/stars/infobyte/CVE-2016-2776.svg) ![forks](https://img.shields.io/github/forks/infobyte/CVE-2016-2776.svg)
- [https://github.com/KosukeShimofuji/CVE-2016-2776](https://github.com/KosukeShimofuji/CVE-2016-2776) :  ![starts](https://img.shields.io/github/stars/KosukeShimofuji/CVE-2016-2776.svg) ![forks](https://img.shields.io/github/forks/KosukeShimofuji/CVE-2016-2776.svg)


## CVE-2016-2118
 The MS-SAMR and MS-LSAD protocol implementations in Samba 3.x and 4.x before 4.2.11, 4.3.x before 4.3.8, and 4.4.x before 4.4.2 mishandle DCERPC connections, which allows man-in-the-middle attackers to perform protocol-downgrade attacks and impersonate users by modifying the client-server data stream, aka "BADLOCK."

- [https://github.com/nickanderson/cfengine-CVE-2016-2118](https://github.com/nickanderson/cfengine-CVE-2016-2118) :  ![starts](https://img.shields.io/github/stars/nickanderson/cfengine-CVE-2016-2118.svg) ![forks](https://img.shields.io/github/forks/nickanderson/cfengine-CVE-2016-2118.svg)


## CVE-2016-0793
 Incomplete blacklist vulnerability in the servlet filter restriction mechanism in WildFly (formerly JBoss Application Server) before 10.0.0.Final on Windows allows remote attackers to read the sensitive files in the (1) WEB-INF or (2) META-INF directory via a request that contains (a) lowercase or (b) "meaningless" characters.

- [https://github.com/tafamace/CVE-2016-0793](https://github.com/tafamace/CVE-2016-0793) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2016-0793.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2016-0793.svg)


## CVE-2015-10034
 A vulnerability has been found in j-nowak workout-organizer and classified as critical. This vulnerability affects unknown code. The manipulation leads to sql injection. The patch is identified as 13cd6c3d1210640bfdb39872b2bb3597aa991279. It is recommended to apply a patch to fix this issue. VDB-217714 is the identifier assigned to this vulnerability.

- [https://github.com/andrenasx/CVE-2015-10034](https://github.com/andrenasx/CVE-2015-10034) :  ![starts](https://img.shields.io/github/stars/andrenasx/CVE-2015-10034.svg) ![forks](https://img.shields.io/github/forks/andrenasx/CVE-2015-10034.svg)


## CVE-2015-7756
 The encryption implementation in Juniper ScreenOS 6.2.0r15 through 6.2.0r18, 6.3.0r12 before 6.3.0r12b, 6.3.0r13 before 6.3.0r13b, 6.3.0r14 before 6.3.0r14b, 6.3.0r15 before 6.3.0r15b, 6.3.0r16 before 6.3.0r16b, 6.3.0r17 before 6.3.0r17b, 6.3.0r18 before 6.3.0r18b, 6.3.0r19 before 6.3.0r19b, and 6.3.0r20 before 6.3.0r21 makes it easier for remote attackers to discover the plaintext content of VPN sessions by sniffing the network for ciphertext data and conducting an unspecified decryption attack.

- [https://github.com/hdm/juniper-cve-2015-7755](https://github.com/hdm/juniper-cve-2015-7755) :  ![starts](https://img.shields.io/github/stars/hdm/juniper-cve-2015-7755.svg) ![forks](https://img.shields.io/github/forks/hdm/juniper-cve-2015-7755.svg)


## CVE-2015-7755
 Juniper ScreenOS 6.2.0r15 through 6.2.0r18, 6.3.0r12 before 6.3.0r12b, 6.3.0r13 before 6.3.0r13b, 6.3.0r14 before 6.3.0r14b, 6.3.0r15 before 6.3.0r15b, 6.3.0r16 before 6.3.0r16b, 6.3.0r17 before 6.3.0r17b, 6.3.0r18 before 6.3.0r18b, 6.3.0r19 before 6.3.0r19b, and 6.3.0r20 before 6.3.0r21 allows remote attackers to obtain administrative access by entering an unspecified password during a (1) SSH or (2) TELNET session.

- [https://github.com/hdm/juniper-cve-2015-7755](https://github.com/hdm/juniper-cve-2015-7755) :  ![starts](https://img.shields.io/github/stars/hdm/juniper-cve-2015-7755.svg) ![forks](https://img.shields.io/github/forks/hdm/juniper-cve-2015-7755.svg)
- [https://github.com/cinno/CVE-2015-7755-POC](https://github.com/cinno/CVE-2015-7755-POC) :  ![starts](https://img.shields.io/github/stars/cinno/CVE-2015-7755-POC.svg) ![forks](https://img.shields.io/github/forks/cinno/CVE-2015-7755-POC.svg)


## CVE-2015-6748
 Cross-site scripting (XSS) vulnerability in jsoup before 1.8.3.

- [https://github.com/epicosy/VUL4J-59](https://github.com/epicosy/VUL4J-59) :  ![starts](https://img.shields.io/github/stars/epicosy/VUL4J-59.svg) ![forks](https://img.shields.io/github/forks/epicosy/VUL4J-59.svg)


## CVE-2015-6640
 The prctl_set_vma_anon_name function in kernel/sys.c in Android before 5.1.1 LMY49F and 6.0 before 2016-01-01 does not ensure that only one vma is accessed in a certain update action, which allows attackers to gain privileges or cause a denial of service (vma list corruption) via a crafted application, aka internal bug 20017123.

- [https://github.com/betalphafai/CVE-2015-6640](https://github.com/betalphafai/CVE-2015-6640) :  ![starts](https://img.shields.io/github/stars/betalphafai/CVE-2015-6640.svg) ![forks](https://img.shields.io/github/forks/betalphafai/CVE-2015-6640.svg)


## CVE-2015-6606
 The Secure Element Evaluation Kit (aka SEEK or SmartCard API) plugin in Android before 5.1.1 LMY48T allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bug 22301786.

- [https://github.com/michaelroland/omapi-cve-2015-6606-exploit](https://github.com/michaelroland/omapi-cve-2015-6606-exploit) :  ![starts](https://img.shields.io/github/stars/michaelroland/omapi-cve-2015-6606-exploit.svg) ![forks](https://img.shields.io/github/forks/michaelroland/omapi-cve-2015-6606-exploit.svg)


## CVE-2015-5995
 Mediabridge Medialink MWN-WAPR300N devices with firmware 5.07.50 and Tenda N3 Wireless N150 devices allow remote attackers to obtain administrative access via a certain admin substring in an HTTP Cookie header.

- [https://github.com/shaheemirza/TendaSpill](https://github.com/shaheemirza/TendaSpill) :  ![starts](https://img.shields.io/github/stars/shaheemirza/TendaSpill.svg) ![forks](https://img.shields.io/github/forks/shaheemirza/TendaSpill.svg)


## CVE-2015-3864
 Integer underflow in the MPEG4Extractor::parseChunk function in MPEG4Extractor.cpp in libstagefright in mediaserver in Android before 5.1.1 LMY48M allows remote attackers to execute arbitrary code via crafted MPEG-4 data, aka internal bug 23034759.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-3824.

- [https://github.com/eudemonics/scaredycat](https://github.com/eudemonics/scaredycat) :  ![starts](https://img.shields.io/github/stars/eudemonics/scaredycat.svg) ![forks](https://img.shields.io/github/forks/eudemonics/scaredycat.svg)
- [https://github.com/pwnaccelerator/stagefright-cve-2015-3864](https://github.com/pwnaccelerator/stagefright-cve-2015-3864) :  ![starts](https://img.shields.io/github/stars/pwnaccelerator/stagefright-cve-2015-3864.svg) ![forks](https://img.shields.io/github/forks/pwnaccelerator/stagefright-cve-2015-3864.svg)
- [https://github.com/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864](https://github.com/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864) :  ![starts](https://img.shields.io/github/stars/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864.svg) ![forks](https://img.shields.io/github/forks/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864.svg)
- [https://github.com/HenryVHuang/CVE-2015-3864](https://github.com/HenryVHuang/CVE-2015-3864) :  ![starts](https://img.shields.io/github/stars/HenryVHuang/CVE-2015-3864.svg) ![forks](https://img.shields.io/github/forks/HenryVHuang/CVE-2015-3864.svg)
- [https://github.com/Cmadhushanka/CVE-2015-3864-Exploitation](https://github.com/Cmadhushanka/CVE-2015-3864-Exploitation) :  ![starts](https://img.shields.io/github/stars/Cmadhushanka/CVE-2015-3864-Exploitation.svg) ![forks](https://img.shields.io/github/forks/Cmadhushanka/CVE-2015-3864-Exploitation.svg)


## CVE-2015-3224
 request.rb in Web Console before 2.1.3, as used with Ruby on Rails 3.x and 4.x, does not properly restrict the use of X-Forwarded-For headers in determining a client's IP address, which allows remote attackers to bypass the whitelisted_ips protection mechanism via a crafted request.

- [https://github.com/0xEval/cve-2015-3224](https://github.com/0xEval/cve-2015-3224) :  ![starts](https://img.shields.io/github/stars/0xEval/cve-2015-3224.svg) ![forks](https://img.shields.io/github/forks/0xEval/cve-2015-3224.svg)
- [https://github.com/0x00-0x00/CVE-2015-3224](https://github.com/0x00-0x00/CVE-2015-3224) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/CVE-2015-3224.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/CVE-2015-3224.svg)
- [https://github.com/n000xy/CVE-2015-3224-](https://github.com/n000xy/CVE-2015-3224-) :  ![starts](https://img.shields.io/github/stars/n000xy/CVE-2015-3224-.svg) ![forks](https://img.shields.io/github/forks/n000xy/CVE-2015-3224-.svg)
- [https://github.com/Sic4rio/CVE-2015-3224](https://github.com/Sic4rio/CVE-2015-3224) :  ![starts](https://img.shields.io/github/stars/Sic4rio/CVE-2015-3224.svg) ![forks](https://img.shields.io/github/forks/Sic4rio/CVE-2015-3224.svg)


## CVE-2015-3197
 ssl/s2_srvr.c in OpenSSL 1.0.1 before 1.0.1r and 1.0.2 before 1.0.2f does not prevent use of disabled ciphers, which makes it easier for man-in-the-middle attackers to defeat cryptographic protection mechanisms by performing computations on SSLv2 traffic, related to the get_client_master_key and get_client_hello functions.

- [https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3197](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3197) :  ![starts](https://img.shields.io/github/stars/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3197.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3197.svg)


## CVE-2015-3145
 The sanitize_cookie_path function in cURL and libcurl 7.31.0 through 7.41.0 does not properly calculate an index, which allows remote attackers to cause a denial of service (out-of-bounds write and crash) or possibly have other unspecified impact via a cookie path containing only a double-quote character.

- [https://github.com/serz999/CVE-2015-3145](https://github.com/serz999/CVE-2015-3145) :  ![starts](https://img.shields.io/github/stars/serz999/CVE-2015-3145.svg) ![forks](https://img.shields.io/github/forks/serz999/CVE-2015-3145.svg)


## CVE-2015-3090
 Adobe Flash Player before 13.0.0.289 and 14.x through 17.x before 17.0.0.188 on Windows and OS X and before 11.2.202.460 on Linux, Adobe AIR before 17.0.0.172, Adobe AIR SDK before 17.0.0.172, and Adobe AIR SDK & Compiler before 17.0.0.172 allow attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2015-3078, CVE-2015-3089, and CVE-2015-3093.

- [https://github.com/Xattam1/Adobe-Flash-Exploits_17-18](https://github.com/Xattam1/Adobe-Flash-Exploits_17-18) :  ![starts](https://img.shields.io/github/stars/Xattam1/Adobe-Flash-Exploits_17-18.svg) ![forks](https://img.shields.io/github/forks/Xattam1/Adobe-Flash-Exploits_17-18.svg)


## CVE-2015-2794
 The installation wizard in DotNetNuke (DNN) before 7.4.1 allows remote attackers to reinstall the application and gain SuperUser access via a direct request to Install/InstallWizard.aspx.

- [https://github.com/styx00/DNN_CVE-2015-2794](https://github.com/styx00/DNN_CVE-2015-2794) :  ![starts](https://img.shields.io/github/stars/styx00/DNN_CVE-2015-2794.svg) ![forks](https://img.shields.io/github/forks/styx00/DNN_CVE-2015-2794.svg)
- [https://github.com/wilsc0w/CVE-2015-2794-finder](https://github.com/wilsc0w/CVE-2015-2794-finder) :  ![starts](https://img.shields.io/github/stars/wilsc0w/CVE-2015-2794-finder.svg) ![forks](https://img.shields.io/github/forks/wilsc0w/CVE-2015-2794-finder.svg)


## CVE-2015-2546
 The kernel-mode driver in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT Gold and 8.1, and Windows 10 allows local users to gain privileges via a crafted application, aka "Win32k Memory Corruption Elevation of Privilege Vulnerability," a different vulnerability than CVE-2015-2511, CVE-2015-2517, and CVE-2015-2518.

- [https://github.com/k0keoyo/CVE-2015-2546-Exploit](https://github.com/k0keoyo/CVE-2015-2546-Exploit) :  ![starts](https://img.shields.io/github/stars/k0keoyo/CVE-2015-2546-Exploit.svg) ![forks](https://img.shields.io/github/forks/k0keoyo/CVE-2015-2546-Exploit.svg)


## CVE-2015-1561
 The escape_command function in include/Administration/corePerformance/getStats.php in Centreon (formerly Merethis Centreon) 2.5.4 and earlier (fixed in Centreon 19.10.0) uses an incorrect regular expression, which allows remote authenticated users to execute arbitrary commands via shell metacharacters in the ns_id parameter.

- [https://github.com/Iansus/Centreon-CVE-2015-1560_1561](https://github.com/Iansus/Centreon-CVE-2015-1560_1561) :  ![starts](https://img.shields.io/github/stars/Iansus/Centreon-CVE-2015-1560_1561.svg) ![forks](https://img.shields.io/github/forks/Iansus/Centreon-CVE-2015-1560_1561.svg)


## CVE-2015-1130
 The XPC implementation in Admin Framework in Apple OS X before 10.10.3 allows local users to bypass authentication and obtain admin privileges via unspecified vectors.

- [https://github.com/sideeffect42/RootPipeTester](https://github.com/sideeffect42/RootPipeTester) :  ![starts](https://img.shields.io/github/stars/sideeffect42/RootPipeTester.svg) ![forks](https://img.shields.io/github/forks/sideeffect42/RootPipeTester.svg)
- [https://github.com/Shmoopi/RootPipe-Demo](https://github.com/Shmoopi/RootPipe-Demo) :  ![starts](https://img.shields.io/github/stars/Shmoopi/RootPipe-Demo.svg) ![forks](https://img.shields.io/github/forks/Shmoopi/RootPipe-Demo.svg)


## CVE-2015-0345
 Cross-site scripting (XSS) vulnerability in Adobe ColdFusion 10 before Update 16 and 11 before Update 5 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.

- [https://github.com/BishopFox/coldfusion-10-11-xss](https://github.com/BishopFox/coldfusion-10-11-xss) :  ![starts](https://img.shields.io/github/stars/BishopFox/coldfusion-10-11-xss.svg) ![forks](https://img.shields.io/github/forks/BishopFox/coldfusion-10-11-xss.svg)


## CVE-2015-0205
 The ssl3_get_cert_verify function in s3_srvr.c in OpenSSL 1.0.0 before 1.0.0p and 1.0.1 before 1.0.1k accepts client authentication with a Diffie-Hellman (DH) certificate without requiring a CertificateVerify message, which allows remote attackers to obtain access without knowledge of a private key via crafted TLS Handshake Protocol traffic to a server that recognizes a Certification Authority with DH support.

- [https://github.com/saurabh2088/OpenSSL_1_0_1g_CVE-2015-0205](https://github.com/saurabh2088/OpenSSL_1_0_1g_CVE-2015-0205) :  ![starts](https://img.shields.io/github/stars/saurabh2088/OpenSSL_1_0_1g_CVE-2015-0205.svg) ![forks](https://img.shields.io/github/forks/saurabh2088/OpenSSL_1_0_1g_CVE-2015-0205.svg)


## CVE-2014-6721
 The Pharmaguideline (aka com.pharmaguideline) application 1.2.0 for Android does not verify X.509 certificates from SSL servers, which allows man-in-the-middle attackers to spoof servers and obtain sensitive information via a crafted certificate.

- [https://github.com/sagisar1/CVE-2014-6721-exploit-Shellshock](https://github.com/sagisar1/CVE-2014-6721-exploit-Shellshock) :  ![starts](https://img.shields.io/github/stars/sagisar1/CVE-2014-6721-exploit-Shellshock.svg) ![forks](https://img.shields.io/github/forks/sagisar1/CVE-2014-6721-exploit-Shellshock.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/opsxcq/exploit-CVE-2014-6271](https://github.com/opsxcq/exploit-CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/opsxcq/exploit-CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/opsxcq/exploit-CVE-2014-6271.svg)
- [https://github.com/capture0x/XSHOCK](https://github.com/capture0x/XSHOCK) :  ![starts](https://img.shields.io/github/stars/capture0x/XSHOCK.svg) ![forks](https://img.shields.io/github/forks/capture0x/XSHOCK.svg)
- [https://github.com/scottjpack/shellshock_scanner](https://github.com/scottjpack/shellshock_scanner) :  ![starts](https://img.shields.io/github/stars/scottjpack/shellshock_scanner.svg) ![forks](https://img.shields.io/github/forks/scottjpack/shellshock_scanner.svg)
- [https://github.com/hmlio/vaas-cve-2014-6271](https://github.com/hmlio/vaas-cve-2014-6271) :  ![starts](https://img.shields.io/github/stars/hmlio/vaas-cve-2014-6271.svg) ![forks](https://img.shields.io/github/forks/hmlio/vaas-cve-2014-6271.svg)
- [https://github.com/b4keSn4ke/CVE-2014-6271](https://github.com/b4keSn4ke/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/b4keSn4ke/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/b4keSn4ke/CVE-2014-6271.svg)
- [https://github.com/cj1324/CGIShell](https://github.com/cj1324/CGIShell) :  ![starts](https://img.shields.io/github/stars/cj1324/CGIShell.svg) ![forks](https://img.shields.io/github/forks/cj1324/CGIShell.svg)
- [https://github.com/francisck/shellshock-cgi](https://github.com/francisck/shellshock-cgi) :  ![starts](https://img.shields.io/github/stars/francisck/shellshock-cgi.svg) ![forks](https://img.shields.io/github/forks/francisck/shellshock-cgi.svg)
- [https://github.com/indiandragon/Shellshock-Vulnerability-Scan](https://github.com/indiandragon/Shellshock-Vulnerability-Scan) :  ![starts](https://img.shields.io/github/stars/indiandragon/Shellshock-Vulnerability-Scan.svg) ![forks](https://img.shields.io/github/forks/indiandragon/Shellshock-Vulnerability-Scan.svg)
- [https://github.com/npm/ansible-bashpocalypse](https://github.com/npm/ansible-bashpocalypse) :  ![starts](https://img.shields.io/github/stars/npm/ansible-bashpocalypse.svg) ![forks](https://img.shields.io/github/forks/npm/ansible-bashpocalypse.svg)
- [https://github.com/P0cL4bs/ShellShock-CGI-Scan](https://github.com/P0cL4bs/ShellShock-CGI-Scan) :  ![starts](https://img.shields.io/github/stars/P0cL4bs/ShellShock-CGI-Scan.svg) ![forks](https://img.shields.io/github/forks/P0cL4bs/ShellShock-CGI-Scan.svg)
- [https://github.com/zalalov/CVE-2014-6271](https://github.com/zalalov/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/zalalov/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/zalalov/CVE-2014-6271.svg)
- [https://github.com/ksang/shellshock](https://github.com/ksang/shellshock) :  ![starts](https://img.shields.io/github/stars/ksang/shellshock.svg) ![forks](https://img.shields.io/github/forks/ksang/shellshock.svg)
- [https://github.com/securusglobal/BadBash](https://github.com/securusglobal/BadBash) :  ![starts](https://img.shields.io/github/stars/securusglobal/BadBash.svg) ![forks](https://img.shields.io/github/forks/securusglobal/BadBash.svg)
- [https://github.com/akr3ch/CVE-2014-6271](https://github.com/akr3ch/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/akr3ch/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/akr3ch/CVE-2014-6271.svg)
- [https://github.com/0x00-0x00/CVE-2014-6271](https://github.com/0x00-0x00/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/CVE-2014-6271.svg)
- [https://github.com/Jsmoreira02/CVE-2014-6271](https://github.com/Jsmoreira02/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/Jsmoreira02/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/Jsmoreira02/CVE-2014-6271.svg)
- [https://github.com/sch3m4/RIS](https://github.com/sch3m4/RIS) :  ![starts](https://img.shields.io/github/stars/sch3m4/RIS.svg) ![forks](https://img.shields.io/github/forks/sch3m4/RIS.svg)
- [https://github.com/akiraaisha/shellshocker-python](https://github.com/akiraaisha/shellshocker-python) :  ![starts](https://img.shields.io/github/stars/akiraaisha/shellshocker-python.svg) ![forks](https://img.shields.io/github/forks/akiraaisha/shellshocker-python.svg)
- [https://github.com/RainMak3r/Rainstorm](https://github.com/RainMak3r/Rainstorm) :  ![starts](https://img.shields.io/github/stars/RainMak3r/Rainstorm.svg) ![forks](https://img.shields.io/github/forks/RainMak3r/Rainstorm.svg)
- [https://github.com/K3ysTr0K3R/CVE-2014-6271-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2014-6271-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2014-6271-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2014-6271-EXPLOIT.svg)
- [https://github.com/r4z0r5/SwissArmyShellshocker](https://github.com/r4z0r5/SwissArmyShellshocker) :  ![starts](https://img.shields.io/github/stars/r4z0r5/SwissArmyShellshocker.svg) ![forks](https://img.shields.io/github/forks/r4z0r5/SwissArmyShellshocker.svg)
- [https://github.com/ramnes/pyshellshock](https://github.com/ramnes/pyshellshock) :  ![starts](https://img.shields.io/github/stars/ramnes/pyshellshock.svg) ![forks](https://img.shields.io/github/forks/ramnes/pyshellshock.svg)
- [https://github.com/Anklebiter87/Cgi-bin_bash_Reverse](https://github.com/Anklebiter87/Cgi-bin_bash_Reverse) :  ![starts](https://img.shields.io/github/stars/Anklebiter87/Cgi-bin_bash_Reverse.svg) ![forks](https://img.shields.io/github/forks/Anklebiter87/Cgi-bin_bash_Reverse.svg)
- [https://github.com/proclnas/ShellShock-CGI-Scan](https://github.com/proclnas/ShellShock-CGI-Scan) :  ![starts](https://img.shields.io/github/stars/proclnas/ShellShock-CGI-Scan.svg) ![forks](https://img.shields.io/github/forks/proclnas/ShellShock-CGI-Scan.svg)
- [https://github.com/0xN7y/CVE-2014-6271](https://github.com/0xN7y/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/0xN7y/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/0xN7y/CVE-2014-6271.svg)
- [https://github.com/Any3ite/CVE-2014-6271](https://github.com/Any3ite/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/Any3ite/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/Any3ite/CVE-2014-6271.svg)
- [https://github.com/mochizuki875/CVE-2014-6271-Apache-Debian](https://github.com/mochizuki875/CVE-2014-6271-Apache-Debian) :  ![starts](https://img.shields.io/github/stars/mochizuki875/CVE-2014-6271-Apache-Debian.svg) ![forks](https://img.shields.io/github/forks/mochizuki875/CVE-2014-6271-Apache-Debian.svg)
- [https://github.com/ryeyao/CVE-2014-6271_Test](https://github.com/ryeyao/CVE-2014-6271_Test) :  ![starts](https://img.shields.io/github/stars/ryeyao/CVE-2014-6271_Test.svg) ![forks](https://img.shields.io/github/forks/ryeyao/CVE-2014-6271_Test.svg)
- [https://github.com/APSL/salt-shellshock](https://github.com/APSL/salt-shellshock) :  ![starts](https://img.shields.io/github/stars/APSL/salt-shellshock.svg) ![forks](https://img.shields.io/github/forks/APSL/salt-shellshock.svg)
- [https://github.com/gabemarshall/shocknaww](https://github.com/gabemarshall/shocknaww) :  ![starts](https://img.shields.io/github/stars/gabemarshall/shocknaww.svg) ![forks](https://img.shields.io/github/forks/gabemarshall/shocknaww.svg)
- [https://github.com/TheRealCiscoo/Shellshock-Exploit](https://github.com/TheRealCiscoo/Shellshock-Exploit) :  ![starts](https://img.shields.io/github/stars/TheRealCiscoo/Shellshock-Exploit.svg) ![forks](https://img.shields.io/github/forks/TheRealCiscoo/Shellshock-Exploit.svg)
- [https://github.com/Gurguii/cgi-bin-shellshock](https://github.com/Gurguii/cgi-bin-shellshock) :  ![starts](https://img.shields.io/github/stars/Gurguii/cgi-bin-shellshock.svg) ![forks](https://img.shields.io/github/forks/Gurguii/cgi-bin-shellshock.svg)
- [https://github.com/themson/shellshock](https://github.com/themson/shellshock) :  ![starts](https://img.shields.io/github/stars/themson/shellshock.svg) ![forks](https://img.shields.io/github/forks/themson/shellshock.svg)
- [https://github.com/sunnyjiang/shellshocker-android](https://github.com/sunnyjiang/shellshocker-android) :  ![starts](https://img.shields.io/github/stars/sunnyjiang/shellshocker-android.svg) ![forks](https://img.shields.io/github/forks/sunnyjiang/shellshocker-android.svg)
- [https://github.com/somhm-solutions/Shell-Shock](https://github.com/somhm-solutions/Shell-Shock) :  ![starts](https://img.shields.io/github/stars/somhm-solutions/Shell-Shock.svg) ![forks](https://img.shields.io/github/forks/somhm-solutions/Shell-Shock.svg)
- [https://github.com/MuirlandOracle/CVE-2014-6271-IPFire](https://github.com/MuirlandOracle/CVE-2014-6271-IPFire) :  ![starts](https://img.shields.io/github/stars/MuirlandOracle/CVE-2014-6271-IPFire.svg) ![forks](https://img.shields.io/github/forks/MuirlandOracle/CVE-2014-6271-IPFire.svg)
- [https://github.com/352926/shellshock_crawler](https://github.com/352926/shellshock_crawler) :  ![starts](https://img.shields.io/github/stars/352926/shellshock_crawler.svg) ![forks](https://img.shields.io/github/forks/352926/shellshock_crawler.svg)
- [https://github.com/wenyu1999/bash-shellshock](https://github.com/wenyu1999/bash-shellshock) :  ![starts](https://img.shields.io/github/stars/wenyu1999/bash-shellshock.svg) ![forks](https://img.shields.io/github/forks/wenyu1999/bash-shellshock.svg)
- [https://github.com/cved-sources/cve-2014-6271](https://github.com/cved-sources/cve-2014-6271) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2014-6271.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2014-6271.svg)
- [https://github.com/hadrian3689/shellshock](https://github.com/hadrian3689/shellshock) :  ![starts](https://img.shields.io/github/stars/hadrian3689/shellshock.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/shellshock.svg)
- [https://github.com/villadora/CVE-2014-6271](https://github.com/villadora/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/villadora/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/villadora/CVE-2014-6271.svg)
- [https://github.com/AlissonFaoli/Shellshock](https://github.com/AlissonFaoli/Shellshock) :  ![starts](https://img.shields.io/github/stars/AlissonFaoli/Shellshock.svg) ![forks](https://img.shields.io/github/forks/AlissonFaoli/Shellshock.svg)
- [https://github.com/moften/CVE-2014-6271](https://github.com/moften/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2014-6271.svg)
- [https://github.com/Dilith006/CVE-2014-6271](https://github.com/Dilith006/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/Dilith006/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/Dilith006/CVE-2014-6271.svg)
- [https://github.com/mritunjay-k/CVE-2014-6271](https://github.com/mritunjay-k/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/mritunjay-k/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/mritunjay-k/CVE-2014-6271.svg)
- [https://github.com/rsherstnev/CVE-2014-6271](https://github.com/rsherstnev/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/rsherstnev/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/rsherstnev/CVE-2014-6271.svg)
- [https://github.com/hackintoanetwork/shellshock](https://github.com/hackintoanetwork/shellshock) :  ![starts](https://img.shields.io/github/stars/hackintoanetwork/shellshock.svg) ![forks](https://img.shields.io/github/forks/hackintoanetwork/shellshock.svg)
- [https://github.com/Brandaoo/CVE-2014-6271](https://github.com/Brandaoo/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/Brandaoo/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/Brandaoo/CVE-2014-6271.svg)
- [https://github.com/RadYio/CVE-2014-6271](https://github.com/RadYio/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/RadYio/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/RadYio/CVE-2014-6271.svg)
- [https://github.com/woltage/CVE-2014-6271](https://github.com/woltage/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/woltage/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/woltage/CVE-2014-6271.svg)
- [https://github.com/Sindadziy/cve-2014-6271](https://github.com/Sindadziy/cve-2014-6271) :  ![starts](https://img.shields.io/github/stars/Sindadziy/cve-2014-6271.svg) ![forks](https://img.shields.io/github/forks/Sindadziy/cve-2014-6271.svg)
- [https://github.com/mattclegg/CVE-2014-6271](https://github.com/mattclegg/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/mattclegg/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/mattclegg/CVE-2014-6271.svg)
- [https://github.com/kowshik-sundararajan/CVE-2014-6271](https://github.com/kowshik-sundararajan/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/kowshik-sundararajan/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/kowshik-sundararajan/CVE-2014-6271.svg)
- [https://github.com/Aruthw/CVE-2014-6271](https://github.com/Aruthw/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/Aruthw/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/Aruthw/CVE-2014-6271.svg)
- [https://github.com/knightc0de/Shellshock_vuln_Exploit](https://github.com/knightc0de/Shellshock_vuln_Exploit) :  ![starts](https://img.shields.io/github/stars/knightc0de/Shellshock_vuln_Exploit.svg) ![forks](https://img.shields.io/github/forks/knightc0de/Shellshock_vuln_Exploit.svg)
- [https://github.com/Pilou-Pilou/docker_CVE-2014-6271.](https://github.com/Pilou-Pilou/docker_CVE-2014-6271.) :  ![starts](https://img.shields.io/github/stars/Pilou-Pilou/docker_CVE-2014-6271..svg) ![forks](https://img.shields.io/github/forks/Pilou-Pilou/docker_CVE-2014-6271..svg)
- [https://github.com/shawntns/exploit-CVE-2014-6271](https://github.com/shawntns/exploit-CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/shawntns/exploit-CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/shawntns/exploit-CVE-2014-6271.svg)
- [https://github.com/hanmin0512/CVE-2014-6271_pwnable](https://github.com/hanmin0512/CVE-2014-6271_pwnable) :  ![starts](https://img.shields.io/github/stars/hanmin0512/CVE-2014-6271_pwnable.svg) ![forks](https://img.shields.io/github/forks/hanmin0512/CVE-2014-6271_pwnable.svg)
- [https://github.com/dlitz/bash-cve-2014-6271-fixes](https://github.com/dlitz/bash-cve-2014-6271-fixes) :  ![starts](https://img.shields.io/github/stars/dlitz/bash-cve-2014-6271-fixes.svg) ![forks](https://img.shields.io/github/forks/dlitz/bash-cve-2014-6271-fixes.svg)
- [https://github.com/rrreeeyyy/cve-2014-6271-spec](https://github.com/rrreeeyyy/cve-2014-6271-spec) :  ![starts](https://img.shields.io/github/stars/rrreeeyyy/cve-2014-6271-spec.svg) ![forks](https://img.shields.io/github/forks/rrreeeyyy/cve-2014-6271-spec.svg)
- [https://github.com/cyberharsh/Shellbash-CVE-2014-6271](https://github.com/cyberharsh/Shellbash-CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/cyberharsh/Shellbash-CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/Shellbash-CVE-2014-6271.svg)
- [https://github.com/rashmikadileeshara/CVE-2014-6271-Shellshock-](https://github.com/rashmikadileeshara/CVE-2014-6271-Shellshock-) :  ![starts](https://img.shields.io/github/stars/rashmikadileeshara/CVE-2014-6271-Shellshock-.svg) ![forks](https://img.shields.io/github/forks/rashmikadileeshara/CVE-2014-6271-Shellshock-.svg)
- [https://github.com/YunchoHang/CVE-2014-6271-SHELLSHOCK](https://github.com/YunchoHang/CVE-2014-6271-SHELLSHOCK) :  ![starts](https://img.shields.io/github/stars/YunchoHang/CVE-2014-6271-SHELLSHOCK.svg) ![forks](https://img.shields.io/github/forks/YunchoHang/CVE-2014-6271-SHELLSHOCK.svg)
- [https://github.com/jblaine/cookbook-bash-CVE-2014-6271](https://github.com/jblaine/cookbook-bash-CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/jblaine/cookbook-bash-CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/jblaine/cookbook-bash-CVE-2014-6271.svg)
- [https://github.com/kelleykong/cve-2014-6271-mengjia-kong](https://github.com/kelleykong/cve-2014-6271-mengjia-kong) :  ![starts](https://img.shields.io/github/stars/kelleykong/cve-2014-6271-mengjia-kong.svg) ![forks](https://img.shields.io/github/forks/kelleykong/cve-2014-6271-mengjia-kong.svg)
- [https://github.com/ilismal/Nessus_CVE-2014-6271_check](https://github.com/ilismal/Nessus_CVE-2014-6271_check) :  ![starts](https://img.shields.io/github/stars/ilismal/Nessus_CVE-2014-6271_check.svg) ![forks](https://img.shields.io/github/forks/ilismal/Nessus_CVE-2014-6271_check.svg)
- [https://github.com/w4fz5uck5/ShockZaum-CVE-2014-6271](https://github.com/w4fz5uck5/ShockZaum-CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/w4fz5uck5/ShockZaum-CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/w4fz5uck5/ShockZaum-CVE-2014-6271.svg)
- [https://github.com/huanlu/cve-2014-6271-huan-lu](https://github.com/huanlu/cve-2014-6271-huan-lu) :  ![starts](https://img.shields.io/github/stars/huanlu/cve-2014-6271-huan-lu.svg) ![forks](https://img.shields.io/github/forks/huanlu/cve-2014-6271-huan-lu.svg)
- [https://github.com/ryancnelson/patched-bash-4.3](https://github.com/ryancnelson/patched-bash-4.3) :  ![starts](https://img.shields.io/github/stars/ryancnelson/patched-bash-4.3.svg) ![forks](https://img.shields.io/github/forks/ryancnelson/patched-bash-4.3.svg)
- [https://github.com/Sindayifu/CVE-2019-14287-CVE-2014-6271](https://github.com/Sindayifu/CVE-2019-14287-CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/Sindayifu/CVE-2019-14287-CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/Sindayifu/CVE-2019-14287-CVE-2014-6271.svg)
- [https://github.com/TheRealCiscoo/Shellshock](https://github.com/TheRealCiscoo/Shellshock) :  ![starts](https://img.shields.io/github/stars/TheRealCiscoo/Shellshock.svg) ![forks](https://img.shields.io/github/forks/TheRealCiscoo/Shellshock.svg)
- [https://github.com/FilipStudeny/-CVE-2014-6271-Shellshock-Remote-Command-Injection-](https://github.com/FilipStudeny/-CVE-2014-6271-Shellshock-Remote-Command-Injection-) :  ![starts](https://img.shields.io/github/stars/FilipStudeny/-CVE-2014-6271-Shellshock-Remote-Command-Injection-.svg) ![forks](https://img.shields.io/github/forks/FilipStudeny/-CVE-2014-6271-Shellshock-Remote-Command-Injection-.svg)
- [https://github.com/anujbhan/shellshock-victim-host](https://github.com/anujbhan/shellshock-victim-host) :  ![starts](https://img.shields.io/github/stars/anujbhan/shellshock-victim-host.svg) ![forks](https://img.shields.io/github/forks/anujbhan/shellshock-victim-host.svg)
- [https://github.com/renanvicente/puppet-shellshock](https://github.com/renanvicente/puppet-shellshock) :  ![starts](https://img.shields.io/github/stars/renanvicente/puppet-shellshock.svg) ![forks](https://img.shields.io/github/forks/renanvicente/puppet-shellshock.svg)
- [https://github.com/RAJMadhusankha/Shellshock-CVE-2014-6271-Exploitation-and-Analysis](https://github.com/RAJMadhusankha/Shellshock-CVE-2014-6271-Exploitation-and-Analysis) :  ![starts](https://img.shields.io/github/stars/RAJMadhusankha/Shellshock-CVE-2014-6271-Exploitation-and-Analysis.svg) ![forks](https://img.shields.io/github/forks/RAJMadhusankha/Shellshock-CVE-2014-6271-Exploitation-and-Analysis.svg)
- [https://github.com/u20024804/bash-3.2-fixed-CVE-2014-6271](https://github.com/u20024804/bash-3.2-fixed-CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/u20024804/bash-3.2-fixed-CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/u20024804/bash-3.2-fixed-CVE-2014-6271.svg)
- [https://github.com/u20024804/bash-4.2-fixed-CVE-2014-6271](https://github.com/u20024804/bash-4.2-fixed-CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/u20024804/bash-4.2-fixed-CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/u20024804/bash-4.2-fixed-CVE-2014-6271.svg)
- [https://github.com/u20024804/bash-4.3-fixed-CVE-2014-6271](https://github.com/u20024804/bash-4.3-fixed-CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/u20024804/bash-4.3-fixed-CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/u20024804/bash-4.3-fixed-CVE-2014-6271.svg)
- [https://github.com/teedeedubya/bash-fix-exploit](https://github.com/teedeedubya/bash-fix-exploit) :  ![starts](https://img.shields.io/github/stars/teedeedubya/bash-fix-exploit.svg) ![forks](https://img.shields.io/github/forks/teedeedubya/bash-fix-exploit.svg)
- [https://github.com/ariarijp/vagrant-shellshock](https://github.com/ariarijp/vagrant-shellshock) :  ![starts](https://img.shields.io/github/stars/ariarijp/vagrant-shellshock.svg) ![forks](https://img.shields.io/github/forks/ariarijp/vagrant-shellshock.svg)
- [https://github.com/justzx2011/bash-up](https://github.com/justzx2011/bash-up) :  ![starts](https://img.shields.io/github/stars/justzx2011/bash-up.svg) ![forks](https://img.shields.io/github/forks/justzx2011/bash-up.svg)
- [https://github.com/internero/debian-lenny-bash_3.2.52-cve-2014-6271](https://github.com/internero/debian-lenny-bash_3.2.52-cve-2014-6271) :  ![starts](https://img.shields.io/github/stars/internero/debian-lenny-bash_3.2.52-cve-2014-6271.svg) ![forks](https://img.shields.io/github/forks/internero/debian-lenny-bash_3.2.52-cve-2014-6271.svg)
- [https://github.com/heikipikker/shellshock-shell](https://github.com/heikipikker/shellshock-shell) :  ![starts](https://img.shields.io/github/stars/heikipikker/shellshock-shell.svg) ![forks](https://img.shields.io/github/forks/heikipikker/shellshock-shell.svg)
- [https://github.com/ajansha/shellshock](https://github.com/ajansha/shellshock) :  ![starts](https://img.shields.io/github/stars/ajansha/shellshock.svg) ![forks](https://img.shields.io/github/forks/ajansha/shellshock.svg)
- [https://github.com/JohnRyk/ICMPShock3](https://github.com/JohnRyk/ICMPShock3) :  ![starts](https://img.shields.io/github/stars/JohnRyk/ICMPShock3.svg) ![forks](https://img.shields.io/github/forks/JohnRyk/ICMPShock3.svg)


## CVE-2014-2022
 SQL injection vulnerability in includes/api/4/breadcrumbs_create.php in vBulletin 4.2.2, 4.2.1, 4.2.0 PL2, and earlier allows remote authenticated users to execute arbitrary SQL commands via the conceptid argument in an xmlrpc API request.

- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)


## CVE-2014-1773
 Microsoft Internet Explorer 9 through 11 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site, aka "Internet Explorer Memory Corruption Vulnerability," a different vulnerability than CVE-2014-1783, CVE-2014-1784, CVE-2014-1786, CVE-2014-1795, CVE-2014-1805, CVE-2014-2758, CVE-2014-2759, CVE-2014-2765, CVE-2014-2766, and CVE-2014-2775.

- [https://github.com/day6reak/CVE-2014-1773](https://github.com/day6reak/CVE-2014-1773) :  ![starts](https://img.shields.io/github/stars/day6reak/CVE-2014-1773.svg) ![forks](https://img.shields.io/github/forks/day6reak/CVE-2014-1773.svg)


## CVE-2014-1447
 Race condition in the virNetServerClientStartKeepAlive function in libvirt before 1.2.1 allows remote attackers to cause a denial of service (libvirtd crash) by closing a connection before a keepalive response is sent.

- [https://github.com/tagatac/libvirt-CVE-2014-1447](https://github.com/tagatac/libvirt-CVE-2014-1447) :  ![starts](https://img.shields.io/github/stars/tagatac/libvirt-CVE-2014-1447.svg) ![forks](https://img.shields.io/github/forks/tagatac/libvirt-CVE-2014-1447.svg)


## CVE-2014-0346
 DO NOT USE THIS CANDIDATE NUMBER.  ConsultIDs: CVE-2014-0160.  Reason: This candidate is a reservation duplicate of CVE-2014-0160.  Notes: All CVE users should reference CVE-2014-0160 instead of this candidate.  All references and descriptions in this candidate have been removed to prevent accidental usage

- [https://github.com/Songul-Kizilay/CVE-2014-0346](https://github.com/Songul-Kizilay/CVE-2014-0346) :  ![starts](https://img.shields.io/github/stars/Songul-Kizilay/CVE-2014-0346.svg) ![forks](https://img.shields.io/github/forks/Songul-Kizilay/CVE-2014-0346.svg)


## CVE-2014-0291
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who requested this candidate did not associate it with any vulnerability during 2014. Notes: none

- [https://github.com/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204](https://github.com/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204) :  ![starts](https://img.shields.io/github/stars/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204.svg) ![forks](https://img.shields.io/github/forks/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204.svg)


## CVE-2014-0224
 OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the "CCS Injection" vulnerability.

- [https://github.com/Tripwire/OpenSSL-CCS-Inject-Test](https://github.com/Tripwire/OpenSSL-CCS-Inject-Test) :  ![starts](https://img.shields.io/github/stars/Tripwire/OpenSSL-CCS-Inject-Test.svg) ![forks](https://img.shields.io/github/forks/Tripwire/OpenSSL-CCS-Inject-Test.svg)
- [https://github.com/ssllabs/openssl-ccs-cve-2014-0224](https://github.com/ssllabs/openssl-ccs-cve-2014-0224) :  ![starts](https://img.shields.io/github/stars/ssllabs/openssl-ccs-cve-2014-0224.svg) ![forks](https://img.shields.io/github/forks/ssllabs/openssl-ccs-cve-2014-0224.svg)
- [https://github.com/secretnonempty/CVE-2014-0224](https://github.com/secretnonempty/CVE-2014-0224) :  ![starts](https://img.shields.io/github/stars/secretnonempty/CVE-2014-0224.svg) ![forks](https://img.shields.io/github/forks/secretnonempty/CVE-2014-0224.svg)
- [https://github.com/anthophilee/A2SV--SSL-VUL-Scan](https://github.com/anthophilee/A2SV--SSL-VUL-Scan) :  ![starts](https://img.shields.io/github/stars/anthophilee/A2SV--SSL-VUL-Scan.svg) ![forks](https://img.shields.io/github/forks/anthophilee/A2SV--SSL-VUL-Scan.svg)
- [https://github.com/iph0n3/CVE-2014-0224](https://github.com/iph0n3/CVE-2014-0224) :  ![starts](https://img.shields.io/github/stars/iph0n3/CVE-2014-0224.svg) ![forks](https://img.shields.io/github/forks/iph0n3/CVE-2014-0224.svg)
- [https://github.com/droptables/ccs-eval](https://github.com/droptables/ccs-eval) :  ![starts](https://img.shields.io/github/stars/droptables/ccs-eval.svg) ![forks](https://img.shields.io/github/forks/droptables/ccs-eval.svg)


## CVE-2014-0195
 The dtls1_reassemble_fragment function in d1_both.c in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly validate fragment lengths in DTLS ClientHello messages, which allows remote attackers to execute arbitrary code or cause a denial of service (buffer overflow and application crash) via a long non-initial fragment.

- [https://github.com/ricedu/CVE-2014-0195](https://github.com/ricedu/CVE-2014-0195) :  ![starts](https://img.shields.io/github/stars/ricedu/CVE-2014-0195.svg) ![forks](https://img.shields.io/github/forks/ricedu/CVE-2014-0195.svg)
- [https://github.com/PezwariNaan/CVE-2014-0195](https://github.com/PezwariNaan/CVE-2014-0195) :  ![starts](https://img.shields.io/github/stars/PezwariNaan/CVE-2014-0195.svg) ![forks](https://img.shields.io/github/forks/PezwariNaan/CVE-2014-0195.svg)


## CVE-2014-0166
 The wp_validate_auth_cookie function in wp-includes/pluggable.php in WordPress before 3.7.2 and 3.8.x before 3.8.2 does not properly determine the validity of authentication cookies, which makes it easier for remote attackers to obtain access via a forged cookie.

- [https://github.com/Ettack/POC-CVE-2014-0166](https://github.com/Ettack/POC-CVE-2014-0166) :  ![starts](https://img.shields.io/github/stars/Ettack/POC-CVE-2014-0166.svg) ![forks](https://img.shields.io/github/forks/Ettack/POC-CVE-2014-0166.svg)

