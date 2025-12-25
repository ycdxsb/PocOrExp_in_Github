# Update 2025-12-25
## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/nehkark/CVE-2025-68613](https://github.com/nehkark/CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/nehkark/CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/nehkark/CVE-2025-68613.svg)
- [https://github.com/GnuTLam/POC-CVE-2025-68613](https://github.com/GnuTLam/POC-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/GnuTLam/POC-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/GnuTLam/POC-CVE-2025-68613.svg)
- [https://github.com/ali-py3/Exploit-CVE-2025-68613](https://github.com/ali-py3/Exploit-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/ali-py3/Exploit-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/ali-py3/Exploit-CVE-2025-68613.svg)
- [https://github.com/intbjw/CVE-2025-68613-poc-via-copilot](https://github.com/intbjw/CVE-2025-68613-poc-via-copilot) :  ![starts](https://img.shields.io/github/stars/intbjw/CVE-2025-68613-poc-via-copilot.svg) ![forks](https://img.shields.io/github/forks/intbjw/CVE-2025-68613-poc-via-copilot.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/chrahman/react2shell-CVE-2025-55182-full-rce-script](https://github.com/chrahman/react2shell-CVE-2025-55182-full-rce-script) :  ![starts](https://img.shields.io/github/stars/chrahman/react2shell-CVE-2025-55182-full-rce-script.svg) ![forks](https://img.shields.io/github/forks/chrahman/react2shell-CVE-2025-55182-full-rce-script.svg)


## CVE-2025-66213
 Coolify is an open-source and self-hostable tool for managing servers, applications, and databases. Prior to version 4.0.0-beta.451, an authenticated command injection vulnerability in the File Storage Directory Mount Path functionality allows users with application/service management permissions to execute arbitrary commands as root on managed servers. The file_storage_directory_source parameter is passed directly to shell commands without proper sanitization, enabling full remote code execution on the host system. Version 4.0.0-beta.451 fixes the issue.

- [https://github.com/0xrakan/coolify-cve-2025-66209-66213](https://github.com/0xrakan/coolify-cve-2025-66209-66213) :  ![starts](https://img.shields.io/github/stars/0xrakan/coolify-cve-2025-66209-66213.svg) ![forks](https://img.shields.io/github/forks/0xrakan/coolify-cve-2025-66209-66213.svg)


## CVE-2025-66212
 Coolify is an open-source and self-hostable tool for managing servers, applications, and databases. Prior to version 4.0.0-beta.451, an authenticated command injection vulnerability in the Dynamic Proxy Configuration Filename handling allows users with application/service management permissions to execute arbitrary commands as root on managed servers. Proxy configuration filenames are passed to shell commands without proper escaping, enabling full remote code execution. Version 4.0.0-beta.451 fixes the issue.

- [https://github.com/0xrakan/coolify-cve-2025-66209-66213](https://github.com/0xrakan/coolify-cve-2025-66209-66213) :  ![starts](https://img.shields.io/github/stars/0xrakan/coolify-cve-2025-66209-66213.svg) ![forks](https://img.shields.io/github/forks/0xrakan/coolify-cve-2025-66209-66213.svg)


## CVE-2025-66211
 Coolify is an open-source and self-hostable tool for managing servers, applications, and databases. Prior to version 4.0.0-beta.451, an authenticated command injection vulnerability in PostgreSQL Init Script Filename handling allows users with application/service management permissions to execute arbitrary commands as root on managed servers. PostgreSQL initialization script filenames are passed to shell commands without proper validation, enabling full remote code execution. Version 4.0.0-beta.451 fixes the issue.

- [https://github.com/0xrakan/coolify-cve-2025-66209-66213](https://github.com/0xrakan/coolify-cve-2025-66209-66213) :  ![starts](https://img.shields.io/github/stars/0xrakan/coolify-cve-2025-66209-66213.svg) ![forks](https://img.shields.io/github/forks/0xrakan/coolify-cve-2025-66209-66213.svg)


## CVE-2025-66210
 Coolify is an open-source and self-hostable tool for managing servers, applications, and databases. Prior to version 4.0.0-beta.451, an authenticated command injection vulnerability in the Database Import functionality allows users with application/service management permissions to execute arbitrary commands as root on managed servers. Database names used in import operations are passed directly to shell commands without sanitization, enabling full remote code execution. Version 4.0.0-beta.451 fixes the issue.

- [https://github.com/0xrakan/coolify-cve-2025-66209-66213](https://github.com/0xrakan/coolify-cve-2025-66209-66213) :  ![starts](https://img.shields.io/github/stars/0xrakan/coolify-cve-2025-66209-66213.svg) ![forks](https://img.shields.io/github/forks/0xrakan/coolify-cve-2025-66209-66213.svg)


## CVE-2025-66209
 Coolify is an open-source and self-hostable tool for managing servers, applications, and databases. Prior to version 4.0.0-beta.451, an authenticated command injection vulnerability in the Database Backup functionality allows users with application/service management permissions to execute arbitrary commands as root on managed servers. Database names used in backup operations are passed directly to shell commands without sanitization, enabling full remote code execution. Version 4.0.0-beta.451 fixes the issue.

- [https://github.com/0xrakan/coolify-cve-2025-66209-66213](https://github.com/0xrakan/coolify-cve-2025-66209-66213) :  ![starts](https://img.shields.io/github/stars/0xrakan/coolify-cve-2025-66209-66213.svg) ![forks](https://img.shields.io/github/forks/0xrakan/coolify-cve-2025-66209-66213.svg)


## CVE-2025-65964
 n8n is an open source workflow automation platform. Versions 0.123.1 through 1.119.1 do not have adequate protections to prevent RCE through the project's pre-commit hooks. The Add Config operation allows workflows to set arbitrary Git configuration values, including core.hooksPath, which can point to a malicious Git hook that executes arbitrary commands on the n8n host during subsequent Git operations. Exploitation requires the ability to create or modify an n8n workflow using the Git node. This issue is fixed in version 1.119.2. Workarounds include excluding the Git Node (Docs) and avoiding cloning or interacting with untrusted repositories using the Git Node.

- [https://github.com/Pinus97/CVE-2025-65964-POC](https://github.com/Pinus97/CVE-2025-65964-POC) :  ![starts](https://img.shields.io/github/stars/Pinus97/CVE-2025-65964-POC.svg) ![forks](https://img.shields.io/github/forks/Pinus97/CVE-2025-65964-POC.svg)


## CVE-2025-65354
 Improper input handling in /Grocery/search_products_itname.php inPuneethReddyHC event-management 1.0 permits SQL injection via the sitem_name POST parameter. Crafted payloads can alter query logic and disclose database contents. Exploitation may result in sensitive data disclosure and backend compromise.

- [https://github.com/amaansiddd787/CVE-2025-65354](https://github.com/amaansiddd787/CVE-2025-65354) :  ![starts](https://img.shields.io/github/stars/amaansiddd787/CVE-2025-65354.svg) ![forks](https://img.shields.io/github/forks/amaansiddd787/CVE-2025-65354.svg)


## CVE-2025-62215
 Concurrent execution using shared resource with improper synchronization ('race condition') in Windows Kernel allows an authorized attacker to elevate privileges locally.

- [https://github.com/theman001/CVE-2025-62215](https://github.com/theman001/CVE-2025-62215) :  ![starts](https://img.shields.io/github/stars/theman001/CVE-2025-62215.svg) ![forks](https://img.shields.io/github/forks/theman001/CVE-2025-62215.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/Syrins/CVE-2025-55182-React2Shell-RCE](https://github.com/Syrins/CVE-2025-55182-React2Shell-RCE) :  ![starts](https://img.shields.io/github/stars/Syrins/CVE-2025-55182-React2Shell-RCE.svg) ![forks](https://img.shields.io/github/forks/Syrins/CVE-2025-55182-React2Shell-RCE.svg)


## CVE-2025-54068
 Livewire is a full-stack framework for Laravel. In Livewire v3 up to and including v3.6.3, a vulnerability allows unauthenticated attackers to achieve remote command execution in specific scenarios. The issue stems from how certain component property updates are hydrated. This vulnerability is unique to Livewire v3 and does not affect prior major versions. Exploitation requires a component to be mounted and configured in a particular way, but does not require authentication or user interaction. This issue has been patched in Livewire v3.6.4. All users are strongly encouraged to upgrade to this version or later as soon as possible. No known workarounds are available.

- [https://github.com/synacktiv/Livepyre](https://github.com/synacktiv/Livepyre) :  ![starts](https://img.shields.io/github/stars/synacktiv/Livepyre.svg) ![forks](https://img.shields.io/github/forks/synacktiv/Livepyre.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927](https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sn1p3rt3s7/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sn1p3rt3s7/NextJS_CVE-2025-29927.svg)
- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/seahcy/CVE-2025-24813](https://github.com/seahcy/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/seahcy/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/seahcy/CVE-2025-24813.svg)


## CVE-2025-14733
 An Out-of-bounds Write vulnerability in WatchGuard Fireware OS may allow a remote unauthenticated attacker to execute arbitrary code. This vulnerability affects both the Mobile User VPN with IKEv2 and the Branch Office VPN using IKEv2 when configured with a dynamic gateway peer.This vulnerability affects Fireware OS 11.10.2 up to and including 11.12.4_Update1, 12.0 up to and including 12.11.5 and 2025.1 up to and including 2025.1.3.

- [https://github.com/machevalia/CVE-2025-14733](https://github.com/machevalia/CVE-2025-14733) :  ![starts](https://img.shields.io/github/stars/machevalia/CVE-2025-14733.svg) ![forks](https://img.shields.io/github/forks/machevalia/CVE-2025-14733.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/tovd-go/CVE-2025-8110](https://github.com/tovd-go/CVE-2025-8110) :  ![starts](https://img.shields.io/github/stars/tovd-go/CVE-2025-8110.svg) ![forks](https://img.shields.io/github/forks/tovd-go/CVE-2025-8110.svg)
- [https://github.com/111ddea/goga-cve-2025-8110](https://github.com/111ddea/goga-cve-2025-8110) :  ![starts](https://img.shields.io/github/stars/111ddea/goga-cve-2025-8110.svg) ![forks](https://img.shields.io/github/forks/111ddea/goga-cve-2025-8110.svg)


## CVE-2025-3464
Refer to the 'Security Update for Armoury Crate App' section on the ASUS Security Advisory for more information.

- [https://github.com/jeffaf/CVE-2025-3464-AsIO3-LPE](https://github.com/jeffaf/CVE-2025-3464-AsIO3-LPE) :  ![starts](https://img.shields.io/github/stars/jeffaf/CVE-2025-3464-AsIO3-LPE.svg) ![forks](https://img.shields.io/github/forks/jeffaf/CVE-2025-3464-AsIO3-LPE.svg)


## CVE-2025-1455
 The Royal Elementor Addons and Templates plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the Woo Grid widget in all versions up to, and including, 1.7.1012 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Ashwesker/Blackash-CVE-2025-14558](https://github.com/Ashwesker/Blackash-CVE-2025-14558) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2025-14558.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2025-14558.svg)


## CVE-2024-57521
 SQL Injection vulnerability in RuoYi v.4.7.9 and before allows a remote attacker to execute arbitrary code via the createTable function in SqlUtil.java.

- [https://github.com/mrlihd/CVE-2024-57521-SQL-Injection-PoC](https://github.com/mrlihd/CVE-2024-57521-SQL-Injection-PoC) :  ![starts](https://img.shields.io/github/stars/mrlihd/CVE-2024-57521-SQL-Injection-PoC.svg) ![forks](https://img.shields.io/github/forks/mrlihd/CVE-2024-57521-SQL-Injection-PoC.svg)


## CVE-2024-47554
Users are recommended to upgrade to version 2.14.0 or later, which fixes the issue.

- [https://github.com/PawelMurdzek/CVE-2024-47554-PoC](https://github.com/PawelMurdzek/CVE-2024-47554-PoC) :  ![starts](https://img.shields.io/github/stars/PawelMurdzek/CVE-2024-47554-PoC.svg) ![forks](https://img.shields.io/github/forks/PawelMurdzek/CVE-2024-47554-PoC.svg)


## CVE-2023-36482
 An issue was discovered in Samsung NFC S3NRN4V, S3NSN4V, S3NSEN4, SEN82AB, and S3NRN82. A buffer copy without checking its input size can cause an NFC service restart.

- [https://github.com/qazianwar222/Samsung_S3NRN82_Research](https://github.com/qazianwar222/Samsung_S3NRN82_Research) :  ![starts](https://img.shields.io/github/stars/qazianwar222/Samsung_S3NRN82_Research.svg) ![forks](https://img.shields.io/github/forks/qazianwar222/Samsung_S3NRN82_Research.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)
- [https://github.com/RizqiSec/CVE-2021-41773](https://github.com/RizqiSec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RizqiSec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RizqiSec/CVE-2021-41773.svg)
- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)


## CVE-2017-1000486
 Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution

- [https://github.com/0xdsm/pwnfaces](https://github.com/0xdsm/pwnfaces) :  ![starts](https://img.shields.io/github/stars/0xdsm/pwnfaces.svg) ![forks](https://img.shields.io/github/forks/0xdsm/pwnfaces.svg)


## CVE-2017-20192
 The Formidable Form Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting via multiple parameters submitted during form entries like 'after_html' in versions before 2.05.03 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts that execute in a victim's browser.

- [https://github.com/flame-11/CVE-2017-20192-formidable-forms](https://github.com/flame-11/CVE-2017-20192-formidable-forms) :  ![starts](https://img.shields.io/github/stars/flame-11/CVE-2017-20192-formidable-forms.svg) ![forks](https://img.shields.io/github/forks/flame-11/CVE-2017-20192-formidable-forms.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/nulltrace1336/PHP-CGI-Argument-Injection-Exploit](https://github.com/nulltrace1336/PHP-CGI-Argument-Injection-Exploit) :  ![starts](https://img.shields.io/github/stars/nulltrace1336/PHP-CGI-Argument-Injection-Exploit.svg) ![forks](https://img.shields.io/github/forks/nulltrace1336/PHP-CGI-Argument-Injection-Exploit.svg)

