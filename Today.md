# Update 2026-10-12
## CVE-2026-108592
 mini-swe-agent 1.10.0 through 2.4.6 contains an information exposure vulnerability in BubblewrapEnvironment because bwrap omits --clearenv, so sandboxed commands inherit the host environment. Attackers using prompt injection in processed task content can make the agent read API keys from the environment and exfiltrate them over the shared network.

- [https://github.com/asvorg/CVE-2026-108592-poc](https://github.com/asvorg/CVE-2026-108592-poc) :  ![starts](https://img.shields.io/github/stars/asvorg/CVE-2026-108592-poc.svg) ![forks](https://img.shields.io/github/forks/asvorg/CVE-2026-108592-poc.svg)


## CVE-2026-107806
 Nginx UI is a web user interface for the Nginx web server. From 2.3.8 until 2.5.0, an authenticated administrator with an active secure session can submit attacker-controlled portable backup key material and a matching manifest to POST /api/restore. The restore flow trusts the supplied key, decrypts attacker-controlled contents, and replaces the live app.ini, including protected nginx command settings such as TestConfigCmd. Triggering POST /api/nginx/test then executes the restored command in the Nginx UI runtime context, affecting confidentiality, integrity, and availability. This issue is fixed in version 2.5.0.

- [https://github.com/murrez/CVE-2026-107806](https://github.com/murrez/CVE-2026-107806) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-107806.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-107806.svg)


## CVE-2026-107181
 Telegram Desktop before 7.2.9 contains an IPC record-separator injection vulnerability in Core::Sandbox that allows remote attackers to inject OPEN: records via crafted tg:// links containing unescaped semicolons. Attackers can reach the interpret: scheme handler to upload local files, including tdata session keys, to an attacker channel, enabling account takeover.

- [https://github.com/SeanDishman/telegram-cve-2026-107181](https://github.com/SeanDishman/telegram-cve-2026-107181) :  ![starts](https://img.shields.io/github/stars/SeanDishman/telegram-cve-2026-107181.svg) ![forks](https://img.shields.io/github/forks/SeanDishman/telegram-cve-2026-107181.svg)


## CVE-2026-106610
 Incorrect Privilege Assignment vulnerability in miniOrange miniorange otp verification miniorange-otp-verification allows Privilege Escalation.This issue affects miniorange otp verification: from n/a through 5.5.7.

- [https://github.com/KevineCharles/CVE-2026-106610-miniorange-otp-ato](https://github.com/KevineCharles/CVE-2026-106610-miniorange-otp-ato) :  ![starts](https://img.shields.io/github/stars/KevineCharles/CVE-2026-106610-miniorange-otp-ato.svg) ![forks](https://img.shields.io/github/forks/KevineCharles/CVE-2026-106610-miniorange-otp-ato.svg)


## CVE-2026-106445
 Handlebars provides the power necessary to let users build semantic templates. From 4.0.0 until 4.7.10, Handlebars lookupProperty returns Function.prototype.constructor before applying the prototype-access deny list because constructor is an own property of Function.prototype. When an attacker can render a controlled template with allowProtoMethodsByDefault enabled and an accessible function in the template context, the template can traverse from that function through its prototype to Function.prototype and then obtain the Function constructor through the own-property bypass. This permits attacker-controlled JavaScript to execute with the server application's privileges. This issue is fixed in version 4.7.10.

- [https://github.com/murrez/CVE-2026-106445](https://github.com/murrez/CVE-2026-106445) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-106445.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-106445.svg)


## CVE-2026-104286
 An improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiMail 7.4.0 through 7.4.8, FortiMail 7.2.0 through 7.2.9 may allow an unauthenticated attacker to write arbitrary files on the underlying system via crafted HTTP or HTTPS requests.

- [https://github.com/kh20134/fortimail-cve-2026-104286-response](https://github.com/kh20134/fortimail-cve-2026-104286-response) :  ![starts](https://img.shields.io/github/stars/kh20134/fortimail-cve-2026-104286-response.svg) ![forks](https://img.shields.io/github/forks/kh20134/fortimail-cve-2026-104286-response.svg)


## CVE-2026-103690
 A flaw has been found in itsourcecode Leave Management System 1.0. This vulnerability affects unknown code of the file /module/leave/controller.php. Executing a manipulation of the argument LEAVEID can lead to sql injection. The attack may be performed from remote. The exploit has been published and may be used.

- [https://github.com/Masuer-mengxing/CVE-2026-103690](https://github.com/Masuer-mengxing/CVE-2026-103690) :  ![starts](https://img.shields.io/github/stars/Masuer-mengxing/CVE-2026-103690.svg) ![forks](https://img.shields.io/github/forks/Masuer-mengxing/CVE-2026-103690.svg)


## CVE-2026-102428
 Joomla Extension - ordasoft.com - Unauthenticated SQL injection in OrdaSoft Joomla CCK  8.3.16 - The order column for records was user provided and not properly validated, leading to a SQL injection vector.

- [https://github.com/MRdark-ops/sqli-cve-2026-102428](https://github.com/MRdark-ops/sqli-cve-2026-102428) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/sqli-cve-2026-102428.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/sqli-cve-2026-102428.svg)
- [https://github.com/murrez/CVE-2026-102428](https://github.com/murrez/CVE-2026-102428) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-102428.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-102428.svg)


## CVE-2026-94503
 Unrestricted Upload of File with Dangerous Type vulnerability in PX-lab Zombify zombify allows Upload a Web Shell to a Web Server.This issue affects Zombify: from n/a through 1.7.7.

- [https://github.com/Wayang1337/CVE-2026-94503](https://github.com/Wayang1337/CVE-2026-94503) :  ![starts](https://img.shields.io/github/stars/Wayang1337/CVE-2026-94503.svg) ![forks](https://img.shields.io/github/forks/Wayang1337/CVE-2026-94503.svg)


## CVE-2026-93687
 braces through 3.0.3 contains a stack overflow vulnerability in the recursive AST walkers that lack depth guards. Attackers can supply deeply nested brace patterns under the character limit to exhaust the call stack and terminate the Node.js process with an uncaught RangeError.

- [https://github.com/BernydotJar/braces-security-backport](https://github.com/BernydotJar/braces-security-backport) :  ![starts](https://img.shields.io/github/stars/BernydotJar/braces-security-backport.svg) ![forks](https://img.shields.io/github/forks/BernydotJar/braces-security-backport.svg)


## CVE-2026-85097
 The Bricksforge plugin for WordPress is vulnerable to unauthenticated arbitrary file upload in versions up to, and including, 3.1.8.9. This is due to insufficient validation of the attacker-controlled URL field in the 'temporaryFileUploads' parameter during form submission. An unauthenticated attacker can first obtain a valid nonce via the bricksforge_regenerate_nonce AJAX endpoint, then upload a GIF/PHP polyglot file to the temporary upload directory where MIME type validation is correctly performed. Subsequently, the attacker can submit a form with a crafted 'temporaryFileUploads' parameter where the server-side file path points to the validated GIF file, but the attacker-controlled url field ends with a .php extension. This makes it possible for unauthenticated attackers to upload and execute arbitrary PHP code on the server.

- [https://github.com/Wayang1337/CVE-2026-85097](https://github.com/Wayang1337/CVE-2026-85097) :  ![starts](https://img.shields.io/github/stars/Wayang1337/CVE-2026-85097.svg) ![forks](https://img.shields.io/github/forks/Wayang1337/CVE-2026-85097.svg)


## CVE-2026-84570
 A logic issue was addressed with improved checks. This issue is fixed in macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7. An app may be able to bypass Gatekeeper checks.

- [https://github.com/redinpulse/CVE-2026-84568](https://github.com/redinpulse/CVE-2026-84568) :  ![starts](https://img.shields.io/github/stars/redinpulse/CVE-2026-84568.svg) ![forks](https://img.shields.io/github/forks/redinpulse/CVE-2026-84568.svg)


## CVE-2026-84568
 A path traversal issue was addressed with improved path validation. This issue is fixed in macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7. An attacker with control of a network directory server may be able to execute arbitrary code with root privileges.

- [https://github.com/redinpulse/CVE-2026-84568](https://github.com/redinpulse/CVE-2026-84568) :  ![starts](https://img.shields.io/github/stars/redinpulse/CVE-2026-84568.svg) ![forks](https://img.shields.io/github/forks/redinpulse/CVE-2026-84568.svg)


## CVE-2026-84411
 The web management service in affected RouterOS versions contains an integer underflow in its HTTP request body handling that is reachable before authentication. This can be leveraged by an unauthenticated network attacker to achieve arbitrary code execution as root, or to cause a denial of service, using a single crafted request.

- [https://github.com/maxprog-svg/CVE-2026-84411](https://github.com/maxprog-svg/CVE-2026-84411) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-84411.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-84411.svg)


## CVE-2026-69414
 Microsoft is aware of an elevation of privilege in the Microsoft Malware Protection Engine in Microsoft Defender publicly referred to as &quot;ShieldBreak &quot;.

- [https://github.com/maxprog-svg/CVE-2026-69414](https://github.com/maxprog-svg/CVE-2026-69414) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-69414.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-69414.svg)


## CVE-2026-50656
 Microsoft is aware of an elevation of privilege in the Microsoft Malware Protection Engine in Microsoft Defender publicly referred to as &quot;RoguePlanet &quot;.

- [https://github.com/maxprog-svg/CVE-2026-69414](https://github.com/maxprog-svg/CVE-2026-69414) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-69414.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-69414.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/pubglite55/oppofindN2-ghostlock](https://github.com/pubglite55/oppofindN2-ghostlock) :  ![starts](https://img.shields.io/github/stars/pubglite55/oppofindN2-ghostlock.svg) ![forks](https://img.shields.io/github/forks/pubglite55/oppofindN2-ghostlock.svg)
- [https://github.com/mouseos/aquos-r6-ghostlock](https://github.com/mouseos/aquos-r6-ghostlock) :  ![starts](https://img.shields.io/github/stars/mouseos/aquos-r6-ghostlock.svg) ![forks](https://img.shields.io/github/forks/mouseos/aquos-r6-ghostlock.svg)


## CVE-2026-21589
 This is a vulnerability in Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center. Crowd Data Center, Crucible and Fisheye. This Arbitrary File Access vulnerability allows an unauthenticated attacker to access specific files within the web application root directory in affected versions. Exploitation requires prior knowledge of the target file's exact name and path; this vulnerability does not allow attackers to enumerate or list directory contents. In some configurations, there may be some sensitive files that make this highly severe. This vulnerability allows an unauthenticated remote attacker to access specific files within the web application root directory in affected versions. The vulnerability must be addressed for affected versions of: -- Bitbucket Data Center, introduced in version = 4.6.0, fix versions: 9.4.26, 10.2.8, 10.5.1 -- Confluence Data Center, introduced in version = 5.10.0, fix versions 9.2.26, 10.2.19 -- Crowd Data Center, introduced in version = 2.11.0, fix versions 6.3.7, 7.0.3, 7.1.7, 7.2.4 -- Jira Software Data Center, introduced in version = 7.1.0, fix versions 9.12.40, 10.3.26, 11.3.12 -- Jira Service Management Data Center, introduced in version = 3.1.0, fix versions 5.12.40, 10.3.26, 11.3.12 -- Bamboo Data Center = 7.0.1, fix versions 10.2.24, 12.1.12 -- Crucible, fix versions 4.9.15 -- Fisheye, fix version 4.9.15 -- Exploitation requires prior knowledge of the target file's exact name and path. The vulnerability does not include the capability to enumerate or list directory contents.

- [https://github.com/webserverdude/f5_CVE-2026-21589_mitigation](https://github.com/webserverdude/f5_CVE-2026-21589_mitigation) :  ![starts](https://img.shields.io/github/stars/webserverdude/f5_CVE-2026-21589_mitigation.svg) ![forks](https://img.shields.io/github/forks/webserverdude/f5_CVE-2026-21589_mitigation.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/ctn-Qvo/CVE-2026-43499-so-build](https://github.com/ctn-Qvo/CVE-2026-43499-so-build) :  ![starts](https://img.shields.io/github/stars/ctn-Qvo/CVE-2026-43499-so-build.svg) ![forks](https://img.shields.io/github/forks/ctn-Qvo/CVE-2026-43499-so-build.svg)
- [https://github.com/vn-ncvinh/CVE-2026-43499-OPPO-6.12.58](https://github.com/vn-ncvinh/CVE-2026-43499-OPPO-6.12.58) :  ![starts](https://img.shields.io/github/stars/vn-ncvinh/CVE-2026-43499-OPPO-6.12.58.svg) ![forks](https://img.shields.io/github/forks/vn-ncvinh/CVE-2026-43499-OPPO-6.12.58.svg)


## CVE-2026-3710
 A security vulnerability has been detected in code-projects Simple Flight Ticket Booking System 1.0. This impacts an unknown function of the file /Adminadd.php. The manipulation of the argument flightno/airplaneid/departure/dtime/arrival/atime/ec/ep/bc/bp leads to sql injection. Remote exploitation of the attack is possible. The exploit has been disclosed publicly and may be used.

- [https://github.com/KyrieKlay/CVE-2026-37107](https://github.com/KyrieKlay/CVE-2026-37107) :  ![starts](https://img.shields.io/github/stars/KyrieKlay/CVE-2026-37107.svg) ![forks](https://img.shields.io/github/forks/KyrieKlay/CVE-2026-37107.svg)


## CVE-2025-69872
 DiskCache (python-diskcache) through 5.6.3 uses Python pickle for serialization by default. An attacker with write access to the cache directory can achieve arbitrary code execution when a victim application reads from the cache.

- [https://github.com/secondwindoss/diskcache-community](https://github.com/secondwindoss/diskcache-community) :  ![starts](https://img.shields.io/github/stars/secondwindoss/diskcache-community.svg) ![forks](https://img.shields.io/github/forks/secondwindoss/diskcache-community.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/HexBytee/FreePBX-SQLi-RCE](https://github.com/HexBytee/FreePBX-SQLi-RCE) :  ![starts](https://img.shields.io/github/stars/HexBytee/FreePBX-SQLi-RCE.svg) ![forks](https://img.shields.io/github/forks/HexBytee/FreePBX-SQLi-RCE.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182](https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg)


## CVE-2025-9548
 A potential null pointer dereference vulnerability was reported in the Lenovo Power Management Driver that could allow a local authenticated user to cause a Windows blue screen error.

- [https://github.com/CyberFrenchie/CVE-2025-9548](https://github.com/CyberFrenchie/CVE-2025-9548) :  ![starts](https://img.shields.io/github/stars/CyberFrenchie/CVE-2025-9548.svg) ![forks](https://img.shields.io/github/forks/CyberFrenchie/CVE-2025-9548.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC](https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC.svg)
- [https://github.com/xiaoLvChen/CVE-2025-55182](https://github.com/xiaoLvChen/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/xiaoLvChen/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/xiaoLvChen/CVE-2025-55182.svg)


## CVE-2025-1122
Bypass operating system verification via exploiting the NV_Read functionality during the Challenge-Response process.

- [https://github.com/MCRideable3963/RMASmoke-v2](https://github.com/MCRideable3963/RMASmoke-v2) :  ![starts](https://img.shields.io/github/stars/MCRideable3963/RMASmoke-v2.svg) ![forks](https://img.shields.io/github/forks/MCRideable3963/RMASmoke-v2.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/lewiskb/Docker-Lab-CVE-2024-4367](https://github.com/lewiskb/Docker-Lab-CVE-2024-4367) :  ![starts](https://img.shields.io/github/stars/lewiskb/Docker-Lab-CVE-2024-4367.svg) ![forks](https://img.shields.io/github/forks/lewiskb/Docker-Lab-CVE-2024-4367.svg)


## CVE-2023-20696
 In preloader, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07856356 / ALPS07874388 (For MT6880 and MT6890 only); Issue ID: ALPS07856356 / ALPS07874388 (For MT6880 and MT6890 only).

- [https://github.com/ELF-RC/mtk_logo_toolkit](https://github.com/ELF-RC/mtk_logo_toolkit) :  ![starts](https://img.shields.io/github/stars/ELF-RC/mtk_logo_toolkit.svg) ![forks](https://img.shields.io/github/forks/ELF-RC/mtk_logo_toolkit.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-42023
 A vulnerability has been identified in ModelSim Simulation (All versions), Questa Simulation (All versions). The RSA white-box implementation in affected applications insufficiently protects the built-in private keys that are required to decrypt electronic intellectual property (IP) data in accordance with the IEEE 1735 recommended practice. This could allow a sophisticated attacker to discover the keys, bypassing the protection intended by the IEEE 1735 recommended practice.

- [https://github.com/Geeoon/ModelSim-Decryptor](https://github.com/Geeoon/ModelSim-Decryptor) :  ![starts](https://img.shields.io/github/stars/Geeoon/ModelSim-Decryptor.svg) ![forks](https://img.shields.io/github/forks/Geeoon/ModelSim-Decryptor.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/gunzf0x/CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2021-41773.svg)
- [https://github.com/sotiak/CVE-2021-41773](https://github.com/sotiak/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-41773.svg)
- [https://github.com/Park123r/CVE-2021-41773](https://github.com/Park123r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Park123r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Park123r/CVE-2021-41773.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/FDLAlfrid/odin-od105-devkit](https://github.com/FDLAlfrid/odin-od105-devkit) :  ![starts](https://img.shields.io/github/stars/FDLAlfrid/odin-od105-devkit.svg) ![forks](https://img.shields.io/github/forks/FDLAlfrid/odin-od105-devkit.svg)

