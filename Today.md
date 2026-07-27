# Update 2026-07-27
## CVE-2026-66374
 Knot Resolver before 6.4.1 allows remote code execution via a heap-based buffer overflow in the DoQ (DNS-over-QUIC) receive path.

- [https://github.com/venglin/knot-doq](https://github.com/venglin/knot-doq) :  ![starts](https://img.shields.io/github/stars/venglin/knot-doq.svg) ![forks](https://img.shields.io/github/forks/venglin/knot-doq.svg)


## CVE-2026-65694
 Microweber CMS through 2.0.20 contains a path traversal vulnerability in the static file controller that allows unauthenticated remote attackers to read arbitrary files by supplying directory traversal sequences in the path query parameter. Attackers can send a single unauthenticated HTTP GET request exploiting the failure of normalize_path() to strip traversal sequences, disclosing sensitive files such as environment configuration files containing credentials and system files.

- [https://github.com/abdugafforov-bobur/CVE-2026-65694-PoC](https://github.com/abdugafforov-bobur/CVE-2026-65694-PoC) :  ![starts](https://img.shields.io/github/stars/abdugafforov-bobur/CVE-2026-65694-PoC.svg) ![forks](https://img.shields.io/github/forks/abdugafforov-bobur/CVE-2026-65694-PoC.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/imXur/WordPress-CVE-2026-63030-Analysis](https://github.com/imXur/WordPress-CVE-2026-63030-Analysis) :  ![starts](https://img.shields.io/github/stars/imXur/WordPress-CVE-2026-63030-Analysis.svg) ![forks](https://img.shields.io/github/forks/imXur/WordPress-CVE-2026-63030-Analysis.svg)


## CVE-2026-61946
 Unauthenticated Insecure Direct Object References (IDOR) in Easy Appointments = 3.12.27 versions.

- [https://github.com/Rat5ak/CVE-2026-61946-Easy-Appointments-IDOR](https://github.com/Rat5ak/CVE-2026-61946-Easy-Appointments-IDOR) :  ![starts](https://img.shields.io/github/stars/Rat5ak/CVE-2026-61946-Easy-Appointments-IDOR.svg) ![forks](https://img.shields.io/github/forks/Rat5ak/CVE-2026-61946-Easy-Appointments-IDOR.svg)


## CVE-2026-60206
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0 and  15.1.1.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via SAML to compromise Oracle WebLogic Server.  While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.9 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/Debajyoti0-0/CVE-2026-60206](https://github.com/Debajyoti0-0/CVE-2026-60206) :  ![starts](https://img.shields.io/github/stars/Debajyoti0-0/CVE-2026-60206.svg) ![forks](https://img.shields.io/github/forks/Debajyoti0-0/CVE-2026-60206.svg)


## CVE-2026-54902
 Oj (Optimized JSON) is a JSON parser and Object marshaller packaged as a Ruby gem. Prior to version 3.17.2, is vulnerable to Use-After-Free when in SAJ mode. The Oj::Parser does not protect cached object keys (≥ 35 bytes) from garbage collection, and a Ruby callback that triggers GC inside hash_end can cause the key string to be reclaimed while the C parser still holds a pointer to it. The subsequent access to the freed string VALUE results in a segfault, confirmed by an RIP pointing to address 0x4242 (a canary-style pattern suggesting control over the freed memory's content). This issue has been fixed in version 3.17.2.

- [https://github.com/HORKimhab/CVE-2026-54900](https://github.com/HORKimhab/CVE-2026-54900) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-54900.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-54900.svg)


## CVE-2026-54900
 Oj (Optimized JSON) is a JSON parser and Object marshaller packaged as a Ruby gem. In versions prior to 3.17.2, when in usual mode with create_id enabled, Oj::Parser#parse is vulnerable to heap corruption via a negative-size memcpy. When a JSON object key is exactly 65,535 bytes long, an integer truncation in form_attr (usual.c:63) converts the length to -1 before passing it to memcpy. This causes memcpy to copy SIZE_MAX bytes (interpreted as a huge size_t), corrupting heap memory and crashing the process. The issue has been fixed in version 3.17.2.

- [https://github.com/HORKimhab/CVE-2026-54900](https://github.com/HORKimhab/CVE-2026-54900) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-54900.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-54900.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/tc4dy/CVE-2026-54121-PoC-Exploit](https://github.com/tc4dy/CVE-2026-54121-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-54121-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-54121-PoC-Exploit.svg)
- [https://github.com/0xBlackash/CVE-2026-54121](https://github.com/0xBlackash/CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-54121.svg)
- [https://github.com/HORKimhab/CVE-2026-54121](https://github.com/HORKimhab/CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-54121.svg)


## CVE-2026-50522
 Deserialization of untrusted data in Microsoft Office SharePoint allows an unauthorized attacker to execute code over a network.

- [https://github.com/4minx/CVE-2026-50522](https://github.com/4minx/CVE-2026-50522) :  ![starts](https://img.shields.io/github/stars/4minx/CVE-2026-50522.svg) ![forks](https://img.shields.io/github/forks/4minx/CVE-2026-50522.svg)


## CVE-2026-48908
 A vulnerability in SP Page Builder for Joomla allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.

- [https://github.com/imXur/CVE-2026-48908-Joomla-SP-Page-Builder-RCE](https://github.com/imXur/CVE-2026-48908-Joomla-SP-Page-Builder-RCE) :  ![starts](https://img.shields.io/github/stars/imXur/CVE-2026-48908-Joomla-SP-Page-Builder-RCE.svg) ![forks](https://img.shields.io/github/forks/imXur/CVE-2026-48908-Joomla-SP-Page-Builder-RCE.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/tchuin2609/YellowKey-Bitlocker](https://github.com/tchuin2609/YellowKey-Bitlocker) :  ![starts](https://img.shields.io/github/stars/tchuin2609/YellowKey-Bitlocker.svg) ![forks](https://img.shields.io/github/forks/tchuin2609/YellowKey-Bitlocker.svg)
- [https://github.com/tchuin2609/tchuin2609.github.io](https://github.com/tchuin2609/tchuin2609.github.io) :  ![starts](https://img.shields.io/github/stars/tchuin2609/tchuin2609.github.io.svg) ![forks](https://img.shields.io/github/forks/tchuin2609/tchuin2609.github.io.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/No-22-Github/UnPlus](https://github.com/No-22-Github/UnPlus) :  ![starts](https://img.shields.io/github/stars/No-22-Github/UnPlus.svg) ![forks](https://img.shields.io/github/forks/No-22-Github/UnPlus.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/0xDVRK/CVE-2026-41651](https://github.com/0xDVRK/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/0xDVRK/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/0xDVRK/CVE-2026-41651.svg)


## CVE-2026-40901
 DataEase is an open-source data visualization and analytics platform. Versions 2.10.20 and below ship the legacy velocity-1.7.jar, which pulls in commons-collections-3.2.1.jar containing the InvokerTransformer deserialization gadget chain. Quartz 2.3.2, also bundled in the application, deserializes job data BLOBs from the qrtz_job_details table using ObjectInputStream with no deserialization filter or class allowlist. An authenticated attacker who can write to the Quartz job table, such as through the previously described SQL injection in previewSql, can replace a scheduled job's JOB_DATA with a malicious CommonsCollections6 gadget chain payload. When the Quartz cron trigger fires, the payload is deserialized and executes arbitrary commands as root inside the container, achieving full remote code execution. This issue has been fixed in version 2.10.21.

- [https://github.com/joaovicdev/EXPLOIT-CVE-2026-40901](https://github.com/joaovicdev/EXPLOIT-CVE-2026-40901) :  ![starts](https://img.shields.io/github/stars/joaovicdev/EXPLOIT-CVE-2026-40901.svg) ![forks](https://img.shields.io/github/forks/joaovicdev/EXPLOIT-CVE-2026-40901.svg)


## CVE-2026-32194
 Improper neutralization of special elements used in a command ('command injection') in Microsoft Bing Images allows an unauthorized attacker to execute code over a network.

- [https://github.com/HORKimhab/CVE-2026-32194](https://github.com/HORKimhab/CVE-2026-32194) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-32194.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-32194.svg)


## CVE-2026-26216
 Crawl4AI versions prior to 0.8.0 contain a remote code execution vulnerability in the Docker API deployment. The /crawl endpoint accepts a hooks parameter containing Python code that is executed using exec(). The __import__ builtin was included in the allowed builtins, allowing unauthenticated remote attackers to import arbitrary modules and execute system commands. Successful exploitation allows full server compromise, including arbitrary command execution, file read and write access, sensitive data exfiltration, and lateral movement within internal networks.

- [https://github.com/joaovicdev/EXPLOIT-CVE-2026-26216](https://github.com/joaovicdev/EXPLOIT-CVE-2026-26216) :  ![starts](https://img.shields.io/github/stars/joaovicdev/EXPLOIT-CVE-2026-26216.svg) ![forks](https://img.shields.io/github/forks/joaovicdev/EXPLOIT-CVE-2026-26216.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/JakeSwiz/telnet-inetutils-auth-bypass-CVE-2026-24061](https://github.com/JakeSwiz/telnet-inetutils-auth-bypass-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/JakeSwiz/telnet-inetutils-auth-bypass-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/JakeSwiz/telnet-inetutils-auth-bypass-CVE-2026-24061.svg)
- [https://github.com/s-vx/CVE-2026-24061](https://github.com/s-vx/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/s-vx/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/s-vx/CVE-2026-24061.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/HORKimhab/CVE-2026-16723](https://github.com/HORKimhab/CVE-2026-16723) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-16723.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-16723.svg)


## CVE-2026-12960
Security Update for ASUS Router Android App ' section on the ASUS Security Advisory for more information.

- [https://github.com/l0lsec/CVE-2026-12960](https://github.com/l0lsec/CVE-2026-12960) :  ![starts](https://img.shields.io/github/stars/l0lsec/CVE-2026-12960.svg) ![forks](https://img.shields.io/github/forks/l0lsec/CVE-2026-12960.svg)


## CVE-2026-5156
 A vulnerability was determined in Tenda CH22 1.0.0.1. This impacts the function formQuickIndex of the file /goform/QuickIndex of the component Parameter Handler. This manipulation of the argument mit_linktype causes stack-based buffer overflow. The attack is possible to be carried out remotely. The exploit has been publicly disclosed and may be utilized.

- [https://github.com/1337Skid/CVE-2026-51565](https://github.com/1337Skid/CVE-2026-51565) :  ![starts](https://img.shields.io/github/stars/1337Skid/CVE-2026-51565.svg) ![forks](https://img.shields.io/github/forks/1337Skid/CVE-2026-51565.svg)
- [https://github.com/1337Skid/CVE-2026-51564](https://github.com/1337Skid/CVE-2026-51564) :  ![starts](https://img.shields.io/github/stars/1337Skid/CVE-2026-51564.svg) ![forks](https://img.shields.io/github/forks/1337Skid/CVE-2026-51564.svg)


## CVE-2026-1426
 The Advanced AJAX Product Filters plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.1.9.6 via deserialization of untrusted input in the shortcode_check function within the Live Composer compatibility layer. This makes it possible for authenticated attackers, with Author-level access and above, to inject a PHP Object. No known POP chain is present in the vulnerable software, which means this vulnerability has no impact unless another plugin or theme containing a POP chain is installed on the site. If a POP chain is present via an additional plugin or theme installed on the target system, it may allow the attacker to perform actions like delete arbitrary files, retrieve sensitive data, or execute code depending on the POP chain present. Note: This vulnerability requires the Live Composer plugin to also be installed and active.

- [https://github.com/liyuxuan504-byte/CVE-2026-14266](https://github.com/liyuxuan504-byte/CVE-2026-14266) :  ![starts](https://img.shields.io/github/stars/liyuxuan504-byte/CVE-2026-14266.svg) ![forks](https://img.shields.io/github/forks/liyuxuan504-byte/CVE-2026-14266.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/ayato-shitomi/WebLab_CVE-2025-29927](https://github.com/ayato-shitomi/WebLab_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ayato-shitomi/WebLab_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ayato-shitomi/WebLab_CVE-2025-29927.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-](https://github.com/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-) :  ![starts](https://img.shields.io/github/stars/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-.svg) ![forks](https://img.shields.io/github/forks/Udayveer17/Remote-Code-Execution-CVE-2024-28397-pyload-ng-js2py-.svg)


## CVE-2023-31903
 GuppY CMS 6.00.10 is vulnerable to Unrestricted File Upload which allows remote attackers to execute arbitrary code by uploading a php file.

- [https://github.com/blue0x1/GuppY-exploit-rce](https://github.com/blue0x1/GuppY-exploit-rce) :  ![starts](https://img.shields.io/github/stars/blue0x1/GuppY-exploit-rce.svg) ![forks](https://img.shields.io/github/forks/blue0x1/GuppY-exploit-rce.svg)

