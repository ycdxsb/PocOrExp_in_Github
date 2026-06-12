# Update 2026-06-12
## CVE-2026-50751
 A logic flow weakness in Remote Access and Mobile Access certificate validation in deprecated IKEv1 key exchange allows an unauthenticated remote attacker to bypass user authentication and establish a remote access VPN connection without a valid user password.

- [https://github.com/fernstedt/CVE-2026-50751](https://github.com/fernstedt/CVE-2026-50751) :  ![starts](https://img.shields.io/github/stars/fernstedt/CVE-2026-50751.svg) ![forks](https://img.shields.io/github/forks/fernstedt/CVE-2026-50751.svg)
- [https://github.com/fevar54/CVE-2026-50751---Check-Point-IKEv1-Authentication-Bypass-Exploit](https://github.com/fevar54/CVE-2026-50751---Check-Point-IKEv1-Authentication-Bypass-Exploit) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-50751---Check-Point-IKEv1-Authentication-Bypass-Exploit.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-50751---Check-Point-IKEv1-Authentication-Bypass-Exploit.svg)


## CVE-2026-49975
This issue affects Apache HTTP Server: from 2.4.17 through 2.4.67.

- [https://github.com/LSG-PolarBear/CVE-2026-49975](https://github.com/LSG-PolarBear/CVE-2026-49975) :  ![starts](https://img.shields.io/github/stars/LSG-PolarBear/CVE-2026-49975.svg) ![forks](https://img.shields.io/github/forks/LSG-PolarBear/CVE-2026-49975.svg)
- [https://github.com/LiaoZiqi-GZFLS/CVE-2026-49975](https://github.com/LiaoZiqi-GZFLS/CVE-2026-49975) :  ![starts](https://img.shields.io/github/stars/LiaoZiqi-GZFLS/CVE-2026-49975.svg) ![forks](https://img.shields.io/github/forks/LiaoZiqi-GZFLS/CVE-2026-49975.svg)
- [https://github.com/EQSTLab/CVE-2026-49975](https://github.com/EQSTLab/CVE-2026-49975) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-49975.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-49975.svg)


## CVE-2026-48962
Arbitrary Perl in the output glob executes at the calling process's privilege.

- [https://github.com/JoakimBulow/CVE-2026-48962](https://github.com/JoakimBulow/CVE-2026-48962) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-48962.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-48962.svg)


## CVE-2026-47291
 Integer overflow or wraparound in Windows HTTP.sys allows an unauthorized attacker to execute code over a network.

- [https://github.com/ManagerEmpty/CVE-2026-47291-httpsys](https://github.com/ManagerEmpty/CVE-2026-47291-httpsys) :  ![starts](https://img.shields.io/github/stars/ManagerEmpty/CVE-2026-47291-httpsys.svg) ![forks](https://img.shields.io/github/forks/ManagerEmpty/CVE-2026-47291-httpsys.svg)


## CVE-2026-46529
 Atril Document Viewer is the default document reader of the MATE desktop environment for Linux. A single-click remote code execution vulnerability in versions prior to 1.26.3 and 1.28.4 allows an attacker to achieve arbitrary code execution as the user by tricking them into clicking a link inside a malicious PDF document. The PDF can be packaged as a polyglot file that is simultaneously a valid PDF and a valid ELF shared library, making the attack a single-file, single-click, configuration-independent RCE on stock atril installations. The root cause is `shell/ev-application.c:ev_spawn`, which builds a command line from attacker-controlled PDF link-destination fields without applying `g_shell_quote`. The cmdline is then handed to `g_app_info_create_from_commandline`, which shell-parses it back into argv — splitting any embedded `--gtk-module=PATH` into a separate argv element. GTK then `dlopen()`s the path during init, running any `__attribute__((constructor))` it finds. Versions 1.26.3 and 1.28.4 contain a patch for the issue. This is the same defect class as CVE-2023-51698 (CBT `--checkpoint-action` injection in `comics-document.c`, fixed in 1.6.2) but in a different code path (`shell/ev-application.c`) that the original patch did not touch.

- [https://github.com/N1et/CVE-2026-46529](https://github.com/N1et/CVE-2026-46529) :  ![starts](https://img.shields.io/github/stars/N1et/CVE-2026-46529.svg) ![forks](https://img.shields.io/github/forks/N1et/CVE-2026-46529.svg)


## CVE-2026-44963
 A vulnerability allowing remote code execution (RCE) on the Backup Server by an authenticated domain user.

- [https://github.com/HORKimhab/CVE-2026-44963](https://github.com/HORKimhab/CVE-2026-44963) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-44963.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-44963.svg)


## CVE-2026-44295
 protobufjs-cli is the command line add-on for protobuf.js. Prior to 1.2.1 and 2.0.2, pbjs static code generation could emit unsafe JavaScript identifiers derived from schema-controlled names. When generating static JavaScript from a crafted schema or JSON descriptor, certain namespace, enum, service, or derived full names could be written into the generated output without sufficient sanitization. This vulnerability is fixed in 1.2.1 and 2.0.2.

- [https://github.com/HORKimhab/CVE-2026-442_](https://github.com/HORKimhab/CVE-2026-442_) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-442_.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-442_.svg)


## CVE-2026-44294
 protobufjs compiles protobuf definitions into JavaScript (JS) functions. Prior to 7.5.6 and 8.0.2, protobufjs generated JavaScript property accessors from schema-controlled field and oneof names. Certain control characters in field names were not escaped before being embedded into generated function bodies. A crafted schema or JSON descriptor could therefore cause generated encode, decode, verify, or conversion functions to fail during compilation. This vulnerability is fixed in 7.5.6 and 8.0.2.

- [https://github.com/HORKimhab/CVE-2026-442_](https://github.com/HORKimhab/CVE-2026-442_) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-442_.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-442_.svg)


## CVE-2026-44292
 protobufjs compiles protobuf definitions into JavaScript (JS) functions. Prior to 7.5.6 and 8.0.2, protobufjs generated message constructors copied enumerable properties from a provided properties object without filtering the __proto__ key. If an application constructed a message from an attacker-controlled plain object, an own enumerable __proto__ property could alter the prototype of that individual message instance. This vulnerability is fixed in 7.5.6 and 8.0.2.

- [https://github.com/HORKimhab/CVE-2026-442_](https://github.com/HORKimhab/CVE-2026-442_) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-442_.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-442_.svg)


## CVE-2026-44291
 protobufjs compiles protobuf definitions into JavaScript (JS) functions. Prior to 7.5.6 and 8.0.2, protobufjs used plain objects with inherited prototypes for internal type lookup tables used by generated encode and decode functions. If Object.prototype had already been polluted, those lookup tables could resolve attacker-controlled inherited properties as valid protobuf type information. This could cause attacker-controlled strings to be emitted into generated JavaScript code. This vulnerability is fixed in 7.5.6 and 8.0.2.

- [https://github.com/HORKimhab/CVE-2026-442_](https://github.com/HORKimhab/CVE-2026-442_) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-442_.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-442_.svg)


## CVE-2026-44290
 protobufjs compiles protobuf definitions into JavaScript (JS) functions. Prior to 7.5.6 and 8.0.2, protobufjs allowed certain schema option paths to traverse through inherited object properties while applying options. A crafted protobuf schema or JSON descriptor could cause option handling to write to properties on global JavaScript constructors, corrupting process-wide built-in functionality. This vulnerability is fixed in 7.5.6 and 8.0.2.

- [https://github.com/HORKimhab/CVE-2026-442_](https://github.com/HORKimhab/CVE-2026-442_) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-442_.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-442_.svg)


## CVE-2026-44289
 protobufjs compiles protobuf definitions into JavaScript (JS) functions. Prior to 7.5.6 and 8.0.2, protobufjs could recurse without a depth limit while decoding nested protobuf data. This affected both skipping unknown group fields and generated decoding of nested message fields. A crafted protobuf binary payload could cause the JavaScript call stack to be exhausted during decoding. This vulnerability is fixed in 7.5.6 and 8.0.2.

- [https://github.com/HORKimhab/CVE-2026-442_](https://github.com/HORKimhab/CVE-2026-442_) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-442_.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-442_.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/LiaoZiqi-GZFLS/CVE-2026-42945](https://github.com/LiaoZiqi-GZFLS/CVE-2026-42945) :  ![starts](https://img.shields.io/github/stars/LiaoZiqi-GZFLS/CVE-2026-42945.svg) ![forks](https://img.shields.io/github/forks/LiaoZiqi-GZFLS/CVE-2026-42945.svg)


## CVE-2026-42568
 Yamcs is a mission control framework. Prior to versions 5.13.0 and 5.12.7, an LDAP injection vulnerability exists in `org.yamcs.security.LdapAuthModule` when constructing search filters. The username parameter is inserted directly into the LDAP filter without proper RFC 4515 escaping. Versions 5.13.0 and 5.12.7 patch the issue.

- [https://github.com/ex-cal1bur/CVE-2026-42568](https://github.com/ex-cal1bur/CVE-2026-42568) :  ![starts](https://img.shields.io/github/stars/ex-cal1bur/CVE-2026-42568.svg) ![forks](https://img.shields.io/github/forks/ex-cal1bur/CVE-2026-42568.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/devstuff/harden-docker-seccomp](https://github.com/devstuff/harden-docker-seccomp) :  ![starts](https://img.shields.io/github/stars/devstuff/harden-docker-seccomp.svg) ![forks](https://img.shields.io/github/forks/devstuff/harden-docker-seccomp.svg)


## CVE-2026-28318
 SolarWinds Serv-U is susceptible to specially crafted POST requests that crash the Serv-U service without authentication using Content-Encoding: deflate. Mitigation steps are provided to secure customer environments in the SolarWinds Trust Center if you are unable to deploy the update

- [https://github.com/EaEa0001/servu-cve-2026-28318-poc](https://github.com/EaEa0001/servu-cve-2026-28318-poc) :  ![starts](https://img.shields.io/github/stars/EaEa0001/servu-cve-2026-28318-poc.svg) ![forks](https://img.shields.io/github/forks/EaEa0001/servu-cve-2026-28318-poc.svg)


## CVE-2026-25089
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8, FortiSandbox 4.2 all versions, FortiSandbox Cloud 5.0.4 through 5.0.5, FortiSandbox PaaS 5.0.4 through 5.0.5 may allow an unauthenticated attacker to execute unauthorized commands via specifically crafted HTTP requests

- [https://github.com/HORKimhab/CVE-2026-25089](https://github.com/HORKimhab/CVE-2026-25089) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-25089.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-25089.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/seguridadentrerios/CVE-2026-23111](https://github.com/seguridadentrerios/CVE-2026-23111) :  ![starts](https://img.shields.io/github/stars/seguridadentrerios/CVE-2026-23111.svg) ![forks](https://img.shields.io/github/forks/seguridadentrerios/CVE-2026-23111.svg)


## CVE-2026-20245
Cisco recommends that customers upgrade to the fixed software that is documented in the  that was published on May 14, 2026, and verify the configuration of the edge devices.

- [https://github.com/fevar54/CVE-2026-20245---Cisco-SD-WAN-Privilege-Escalation-Exploit](https://github.com/fevar54/CVE-2026-20245---Cisco-SD-WAN-Privilege-Escalation-Exploit) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-20245---Cisco-SD-WAN-Privilege-Escalation-Exploit.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-20245---Cisco-SD-WAN-Privilege-Escalation-Exploit.svg)


## CVE-2026-11645
 Out of bounds read and write in V8 in Google Chrome prior to 149.0.7827.103 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/adamshaikhma/CVE-2026-11645](https://github.com/adamshaikhma/CVE-2026-11645) :  ![starts](https://img.shields.io/github/stars/adamshaikhma/CVE-2026-11645.svg) ![forks](https://img.shields.io/github/forks/adamshaikhma/CVE-2026-11645.svg)
- [https://github.com/fevar54/CVE-2026-11645-Out-of-bounds-Read-Write](https://github.com/fevar54/CVE-2026-11645-Out-of-bounds-Read-Write) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-11645-Out-of-bounds-Read-Write.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-11645-Out-of-bounds-Read-Write.svg)


## CVE-2026-10523
 An Authentication Bypass vulnerability (CWE-288) in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated attacker to create arbitrary administrative accounts and obtain full administrative access

- [https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523](https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523.svg)


## CVE-2026-10520
 An OS Command Injection vulnerability in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated user to achieve root-level remote code execution

- [https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523](https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523.svg)
- [https://github.com/ogenich/CVE-2026-10520](https://github.com/ogenich/CVE-2026-10520) :  ![starts](https://img.shields.io/github/stars/ogenich/CVE-2026-10520.svg) ![forks](https://img.shields.io/github/forks/ogenich/CVE-2026-10520.svg)


## CVE-2026-9067
 The Schema & Structured Data for WP & AMP WordPress plugin before 1.60 does not check user capabilities on its frontend AJAX file-upload handlers and does not validate the actual content of uploaded files against the endpoint's intended media type, allowing unauthenticated users to upload any file type accepted by WordPress's media library through endpoints that should only accept images or videos.

- [https://github.com/Polosss/By-Poloss..-..CVE-2026-9067](https://github.com/Polosss/By-Poloss..-..CVE-2026-9067) :  ![starts](https://img.shields.io/github/stars/Polosss/By-Poloss..-..CVE-2026-9067.svg) ![forks](https://img.shields.io/github/forks/Polosss/By-Poloss..-..CVE-2026-9067.svg)


## CVE-2026-7473
This issue has been reported as being exploited in the wild.

- [https://github.com/fevar54/CVE-2026-7473---Arista-EOS-Tunnel-Decapsulation-Bypass](https://github.com/fevar54/CVE-2026-7473---Arista-EOS-Tunnel-Decapsulation-Bypass) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-7473---Arista-EOS-Tunnel-Decapsulation-Bypass.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-7473---Arista-EOS-Tunnel-Decapsulation-Bypass.svg)


## CVE-2026-5718
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file upload in versions up to, and including, 1.3.9.7. This is due to insufficient file type validation that occurs when custom blacklist types are configured, which replaces the default dangerous extension denylist instead of merging with it, and the wpcf7_antiscript_file_name() sanitization function being bypassed for filenames containing non-ASCII characters. This makes it possible for unauthenticated attackers to upload arbitrary files, such as PHP files, to the server, which can be leveraged to achieve remote code execution. The vulnerability was originally reported by Leonid Semenenko (lsemenenko) and partially patched in version 1.3.9.7. A bypass for the patch was separately discovered and reported by Nguyen Hung (Mitchell).

- [https://github.com/xxconi/CVE-2026-5718-PR-V-EXPLO-T](https://github.com/xxconi/CVE-2026-5718-PR-V-EXPLO-T) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-5718-PR-V-EXPLO-T.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-5718-PR-V-EXPLO-T.svg)


## CVE-2026-5027
 The 'POST /api/v2/files' endpoint does not sanitize the 'filename' parameter from the multipart form data, allowing an attacker to write files to arbitrary locations on the filesystem using path traversal sequences ('../').

- [https://github.com/Layer-6/CVE-2026-5027-Langflow](https://github.com/Layer-6/CVE-2026-5027-Langflow) :  ![starts](https://img.shields.io/github/stars/Layer-6/CVE-2026-5027-Langflow.svg) ![forks](https://img.shields.io/github/forks/Layer-6/CVE-2026-5027-Langflow.svg)


## CVE-2026-0776
The specific flaw exists within the discord_rpc module. The product loads a file from an unsecured location. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of a target user. Was ZDI-CAN-27057.

- [https://github.com/0x18F/CVE-2026-0776](https://github.com/0x18F/CVE-2026-0776) :  ![starts](https://img.shields.io/github/stars/0x18F/CVE-2026-0776.svg) ![forks](https://img.shields.io/github/forks/0x18F/CVE-2026-0776.svg)


## CVE-2026-0542
ServiceNow addressed this vulnerability by deploying a security update to hosted instances. Relevant security updates also have been provided to ServiceNow self-hosted customers and partners. Further, the vulnerability is addressed in the listed patches and hot fixes. While we are not currently aware of exploitation against customer instances, we recommend customers promptly apply appropriate updates or upgrade if they have not already done so.

- [https://github.com/HORKimhab/CVE-2026-0542](https://github.com/HORKimhab/CVE-2026-0542) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-0542.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-0542.svg)


## CVE-2026-0257
Panorama and Cloud NGFW are not impacted by these issues.

- [https://github.com/grayxploit/CVE-2026-0257](https://github.com/grayxploit/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/grayxploit/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/grayxploit/CVE-2026-0257.svg)


## CVE-2026-0023
 In createSessionInternal of PackageInstallerService.java, there is a possible way for an app to update its ownership due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/QM4RS/CVE-2026-0023-Update-Ownership-PoC](https://github.com/QM4RS/CVE-2026-0023-Update-Ownership-PoC) :  ![starts](https://img.shields.io/github/stars/QM4RS/CVE-2026-0023-Update-Ownership-PoC.svg) ![forks](https://img.shields.io/github/forks/QM4RS/CVE-2026-0023-Update-Ownership-PoC.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/AakiTT/CVE-2025-30208](https://github.com/AakiTT/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/AakiTT/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/AakiTT/CVE-2025-30208.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/SwapnilDeshpande/cve-2025-29927-lab](https://github.com/SwapnilDeshpande/cve-2025-29927-lab) :  ![starts](https://img.shields.io/github/stars/SwapnilDeshpande/cve-2025-29927-lab.svg) ![forks](https://img.shields.io/github/forks/SwapnilDeshpande/cve-2025-29927-lab.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/vasilysaint/CVE-2025-24893](https://github.com/vasilysaint/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/vasilysaint/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/vasilysaint/CVE-2025-24893.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/Dhananjayasj/CVE-2025-24813-Apache-Tomcat-Partial-PUT-Deserialization-RCE-](https://github.com/Dhananjayasj/CVE-2025-24813-Apache-Tomcat-Partial-PUT-Deserialization-RCE-) :  ![starts](https://img.shields.io/github/stars/Dhananjayasj/CVE-2025-24813-Apache-Tomcat-Partial-PUT-Deserialization-RCE-.svg) ![forks](https://img.shields.io/github/forks/Dhananjayasj/CVE-2025-24813-Apache-Tomcat-Partial-PUT-Deserialization-RCE-.svg)


## CVE-2025-4123
The default Content-Security-Policy (CSP) in Grafana will block the XSS though the `connect-src` directive.

- [https://github.com/AakiTT/CVE-2025-4123](https://github.com/AakiTT/CVE-2025-4123) :  ![starts](https://img.shields.io/github/stars/AakiTT/CVE-2025-4123.svg) ![forks](https://img.shields.io/github/forks/AakiTT/CVE-2025-4123.svg)


## CVE-2024-2887
 Type Confusion in WebAssembly in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to execute arbitrary code via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/ad3210/CVE-2024-2887-REPORT](https://github.com/ad3210/CVE-2024-2887-REPORT) :  ![starts](https://img.shields.io/github/stars/ad3210/CVE-2024-2887-REPORT.svg) ![forks](https://img.shields.io/github/forks/ad3210/CVE-2024-2887-REPORT.svg)


## CVE-2024-0406
 A flaw was discovered in the mholt/archiver package. This flaw allows an attacker to create a specially crafted tar file, which, when unpacked, may allow access to restricted files or directories. This issue can allow the creation or overwriting of files with the user's or application's privileges using the library.

- [https://github.com/symphony2colour/Desires](https://github.com/symphony2colour/Desires) :  ![starts](https://img.shields.io/github/stars/symphony2colour/Desires.svg) ![forks](https://img.shields.io/github/forks/symphony2colour/Desires.svg)


## CVE-2023-36808
 GLPI is a free asset and IT management software package. Starting in version 0.80 and prior to version 10.0.8, Computer Virtual Machine form and GLPI inventory request can be used to perform a SQL injection attack. Version 10.0.8 has a patch for this issue. As a workaround, one may disable native inventory.

- [https://github.com/fransosiche/exploit-cve-2023-36808](https://github.com/fransosiche/exploit-cve-2023-36808) :  ![starts](https://img.shields.io/github/stars/fransosiche/exploit-cve-2023-36808.svg) ![forks](https://img.shields.io/github/forks/fransosiche/exploit-cve-2023-36808.svg)


## CVE-2023-32629
 Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels

- [https://github.com/amar-imamovic/CVE-2023-2640-CVE-2023-32629-Interactive-PoC](https://github.com/amar-imamovic/CVE-2023-2640-CVE-2023-32629-Interactive-PoC) :  ![starts](https://img.shields.io/github/stars/amar-imamovic/CVE-2023-2640-CVE-2023-32629-Interactive-PoC.svg) ![forks](https://img.shields.io/github/forks/amar-imamovic/CVE-2023-2640-CVE-2023-32629-Interactive-PoC.svg)


## CVE-2023-2640
 On Ubuntu kernels carrying both c914c0e27eb0 and "UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs", an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks.

- [https://github.com/amar-imamovic/CVE-2023-2640-CVE-2023-32629-Interactive-PoC](https://github.com/amar-imamovic/CVE-2023-2640-CVE-2023-32629-Interactive-PoC) :  ![starts](https://img.shields.io/github/stars/amar-imamovic/CVE-2023-2640-CVE-2023-32629-Interactive-PoC.svg) ![forks](https://img.shields.io/github/forks/amar-imamovic/CVE-2023-2640-CVE-2023-32629-Interactive-PoC.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel’s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/achnouri/TwoMillion-Machine](https://github.com/achnouri/TwoMillion-Machine) :  ![starts](https://img.shields.io/github/stars/achnouri/TwoMillion-Machine.svg) ![forks](https://img.shields.io/github/forks/achnouri/TwoMillion-Machine.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/AyoubNajim/cve-2022-0847dirtypipe-exploit](https://github.com/AyoubNajim/cve-2022-0847dirtypipe-exploit) :  ![starts](https://img.shields.io/github/stars/AyoubNajim/cve-2022-0847dirtypipe-exploit.svg) ![forks](https://img.shields.io/github/forks/AyoubNajim/cve-2022-0847dirtypipe-exploit.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/rideckszz/poc-CVE-2019-9053](https://github.com/rideckszz/poc-CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/rideckszz/poc-CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/rideckszz/poc-CVE-2019-9053.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/krisdewa/CVE-2017-9841-PHPUnit-Remote-Code-Execution-PoC](https://github.com/krisdewa/CVE-2017-9841-PHPUnit-Remote-Code-Execution-PoC) :  ![starts](https://img.shields.io/github/stars/krisdewa/CVE-2017-9841-PHPUnit-Remote-Code-Execution-PoC.svg) ![forks](https://img.shields.io/github/forks/krisdewa/CVE-2017-9841-PHPUnit-Remote-Code-Execution-PoC.svg)


## CVE-2013-4660
 The JS-YAML module before 2.0.5 for Node.js parses input without properly considering the unsafe !!js/function tag, which allows remote attackers to execute arbitrary code via a crafted string that triggers an eval operation.

- [https://github.com/leehunkoo/cve-2013-4660_PoC](https://github.com/leehunkoo/cve-2013-4660_PoC) :  ![starts](https://img.shields.io/github/stars/leehunkoo/cve-2013-4660_PoC.svg) ![forks](https://img.shields.io/github/forks/leehunkoo/cve-2013-4660_PoC.svg)

