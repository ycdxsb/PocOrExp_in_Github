# Update 2026-01-30
## CVE-2026-24858
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] vulnerability in Fortinet FortiAnalyzer 7.6.0 through 7.6.5, FortiAnalyzer 7.4.0 through 7.4.9, FortiAnalyzer 7.2.0 through 7.2.11, FortiAnalyzer 7.0.0 through 7.0.15, FortiManager 7.6.0 through 7.6.5, FortiManager 7.4.0 through 7.4.9, FortiManager 7.2.0 through 7.2.11, FortiManager 7.0.0 through 7.0.15, FortiOS 7.6.0 through 7.6.5, FortiOS 7.4.0 through 7.4.10, FortiOS 7.2.0 through 7.2.12, FortiOS 7.0.0 through 7.0.18, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4.0 through 7.4.12, FortiProxy 7.2 all versions, FortiProxy 7.0 all versions, FortiWeb 8.0.0 through 8.0.3, FortiWeb 7.6.0 through 7.6.6, FortiWeb 7.4.0 through 7.4.11 may allow an attacker with a FortiCloud account and a registered device to log into other devices registered to other accounts, if FortiCloud SSO authentication is enabled on those devices.

- [https://github.com/m0d0ri205/CVE-2026-24858](https://github.com/m0d0ri205/CVE-2026-24858) :  ![starts](https://img.shields.io/github/stars/m0d0ri205/CVE-2026-24858.svg) ![forks](https://img.shields.io/github/forks/m0d0ri205/CVE-2026-24858.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/Gabs-hub/CVE-2026-24061_Lab](https://github.com/Gabs-hub/CVE-2026-24061_Lab) :  ![starts](https://img.shields.io/github/stars/Gabs-hub/CVE-2026-24061_Lab.svg) ![forks](https://img.shields.io/github/forks/Gabs-hub/CVE-2026-24061_Lab.svg)
- [https://github.com/Parad0x7e/CVE-2026-24061](https://github.com/Parad0x7e/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Parad0x7e/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Parad0x7e/CVE-2026-24061.svg)
- [https://github.com/hilwa24/CVE-2026-24061](https://github.com/hilwa24/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/hilwa24/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/hilwa24/CVE-2026-24061.svg)
- [https://github.com/0x7556/CVE-2026-24061](https://github.com/0x7556/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0x7556/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0x7556/CVE-2026-24061.svg)
- [https://github.com/dotelpenguin/telnetd_CVE-2026-24061_tester](https://github.com/dotelpenguin/telnetd_CVE-2026-24061_tester) :  ![starts](https://img.shields.io/github/stars/dotelpenguin/telnetd_CVE-2026-24061_tester.svg) ![forks](https://img.shields.io/github/forks/dotelpenguin/telnetd_CVE-2026-24061_tester.svg)
- [https://github.com/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-](https://github.com/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-) :  ![starts](https://img.shields.io/github/stars/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-.svg) ![forks](https://img.shields.io/github/forks/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-.svg)


## CVE-2026-23829
 Mailpit is an email testing tool and API for developers. Prior to version 1.28.3, Mailpit's SMTP server is vulnerable to Header Injection due to an insufficient Regular Expression used to validate `RCPT TO` and `MAIL FROM` addresses. An attacker can inject arbitrary SMTP headers (or corrupt existing ones) by including carriage return characters (`\r`) in the email address. This header injection occurs because the regex intended to filter control characters fails to exclude `\r` and `\n` when used inside a character class. Version 1.28.3 fixes this issue.

- [https://github.com/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover](https://github.com/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover.svg)


## CVE-2026-23550
 Incorrect Privilege Assignment vulnerability in Modular DS allows Privilege Escalation.This issue affects Modular DS: from n/a through 2.5.1.

- [https://github.com/O99099O/By-Poloss..-..CVE-2026-23550](https://github.com/O99099O/By-Poloss..-..CVE-2026-23550) :  ![starts](https://img.shields.io/github/stars/O99099O/By-Poloss..-..CVE-2026-23550.svg) ![forks](https://img.shields.io/github/forks/O99099O/By-Poloss..-..CVE-2026-23550.svg)


## CVE-2026-22794
 Appsmith is a platform to build admin panels, internal tools, and dashboards. Prior to 1.93, the server uses the Origin value from the request headers as the email link baseUrl without validation. If an attacker controls the Origin, password reset / email verification links in emails can be generated pointing to the attacker’s domain, causing authentication tokens to be exposed and potentially leading to account takeover. This vulnerability is fixed in 1.93.

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-22794](https://github.com/Ashwesker/Ashwesker-CVE-2026-22794) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-22794.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-22794.svg)


## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.

- [https://github.com/IncursioHack/CVE-2026-21509-PoC](https://github.com/IncursioHack/CVE-2026-21509-PoC) :  ![starts](https://img.shields.io/github/stars/IncursioHack/CVE-2026-21509-PoC.svg) ![forks](https://img.shields.io/github/forks/IncursioHack/CVE-2026-21509-PoC.svg)


## CVE-2026-20805
 Exposure of sensitive information to an unauthorized actor in Desktop Windows Manager allows an authorized attacker to disclose information locally.

- [https://github.com/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data](https://github.com/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data) :  ![starts](https://img.shields.io/github/stars/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data.svg) ![forks](https://img.shields.io/github/forks/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data.svg)


## CVE-2026-1470
An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations.

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-1470](https://github.com/Ashwesker/Ashwesker-CVE-2026-1470) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-1470.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-1470.svg)


## CVE-2026-1056
 The Snow Monkey Forms plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the 'generate_user_dirpath' function in all versions up to, and including, 12.0.3. This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php).

- [https://github.com/ch4r0nn/CVE-2026-1056-POC](https://github.com/ch4r0nn/CVE-2026-1056-POC) :  ![starts](https://img.shields.io/github/stars/ch4r0nn/CVE-2026-1056-POC.svg) ![forks](https://img.shields.io/github/forks/ch4r0nn/CVE-2026-1056-POC.svg)


## CVE-2026-0920
 The LA-Studio Element Kit for Elementor plugin for WordPress is vulnerable to Administrative User Creation in all versions up to, and including, 1.5.6.3. This is due to the 'ajax_register_handle' function not restricting what user roles a user can register with. This makes it possible for unauthenticated attackers to supply the 'lakit_bkrole' parameter during registration and gain administrator access to the site.

- [https://github.com/John-doe-code-a11/CVE-2026-0920](https://github.com/John-doe-code-a11/CVE-2026-0920) :  ![starts](https://img.shields.io/github/stars/John-doe-code-a11/CVE-2026-0920.svg) ![forks](https://img.shields.io/github/forks/John-doe-code-a11/CVE-2026-0920.svg)


## CVE-2025-69256
 The Serverless Framework is a framework for using AWS Lambda and other managed cloud services to build applications. Starting in version 4.29.0 and prior to version 4.29.3, a command injection vulnerability exists in the Serverless Framework's built-in MCP server package (@serverless/mcp). This vulnerability only affects users of the experimental MCP server feature (serverless mcp), which represents less than 0.1% of Serverless Framework users. The core Serverless Framework CLI and deployment functionality are not affected. The vulnerability is caused by the unsanitized use of input parameters within a call to `child_process.exec`, enabling an attacker to inject arbitrary system commands. Successful exploitation can lead to remote code execution under the server process's privileges. The server constructs and executes shell commands using unvalidated user input directly within command-line strings. This introduces the possibility of shell metacharacter injection (`|`, ``, `&&`, etc.). Version 4.29.3 fixes the issue.

- [https://github.com/SimoesCTT/CTT-Serverless-RCE-v1.0---Convergent-Time-Theory-Enhanced-MCP-Exploit](https://github.com/SimoesCTT/CTT-Serverless-RCE-v1.0---Convergent-Time-Theory-Enhanced-MCP-Exploit) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Serverless-RCE-v1.0---Convergent-Time-Theory-Enhanced-MCP-Exploit.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Serverless-RCE-v1.0---Convergent-Time-Theory-Enhanced-MCP-Exploit.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/Rishi-kaul/n8n-CVE-2025-68613](https://github.com/Rishi-kaul/n8n-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/Rishi-kaul/n8n-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/Rishi-kaul/n8n-CVE-2025-68613.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-56005
 An undocumented and unsafe feature in the PLY (Python Lex-Yacc) library 3.11 allows Remote Code Execution (RCE) via the `picklefile` parameter in the `yacc()` function. This parameter accepts a `.pkl` file that is deserialized with `pickle.load()` without validation. Because `pickle` allows execution of embedded code via `__reduce__()`, an attacker can achieve code execution by passing a malicious pickle file. The parameter is not mentioned in official documentation or the GitHub repository, yet it is active in the PyPI version. This introduces a stealthy backdoor and persistence risk.

- [https://github.com/bohmiiidd/Undocumument_RCE_PLY-yacc-CVE-2025-56005](https://github.com/bohmiiidd/Undocumument_RCE_PLY-yacc-CVE-2025-56005) :  ![starts](https://img.shields.io/github/stars/bohmiiidd/Undocumument_RCE_PLY-yacc-CVE-2025-56005.svg) ![forks](https://img.shields.io/github/forks/bohmiiidd/Undocumument_RCE_PLY-yacc-CVE-2025-56005.svg)


## CVE-2025-43529
 A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 26.2, Safari 26.2, iOS 18.7.3 and iPadOS 18.7.3, iOS 26.2 and iPadOS 26.2, macOS Tahoe 26.2, visionOS 26.2, tvOS 26.2. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 was also issued in response to this report.

- [https://github.com/SimoesCTT/Convergent-Time-Theory-Enhanced-iOS-Safari-RCE-CVE-2025-43529-](https://github.com/SimoesCTT/Convergent-Time-Theory-Enhanced-iOS-Safari-RCE-CVE-2025-43529-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/Convergent-Time-Theory-Enhanced-iOS-Safari-RCE-CVE-2025-43529-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/Convergent-Time-Theory-Enhanced-iOS-Safari-RCE-CVE-2025-43529-.svg)


## CVE-2025-36911
 In key-based pairing, there is a possible ID due to a logic error in the code. This could lead to remote (proximal/adjacent) information disclosure of user's conversations and location with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/SteamPunk424/CVE-2025-36911-Wisper_Pair_Target_Finder](https://github.com/SteamPunk424/CVE-2025-36911-Wisper_Pair_Target_Finder) :  ![starts](https://img.shields.io/github/stars/SteamPunk424/CVE-2025-36911-Wisper_Pair_Target_Finder.svg) ![forks](https://img.shields.io/github/forks/SteamPunk424/CVE-2025-36911-Wisper_Pair_Target_Finder.svg)


## CVE-2025-29774
 xml-crypto is an XML digital signature and encryption library for Node.js. An attacker may be able to exploit a vulnerability in versions prior to 6.0.1, 3.2.1, and 2.1.6 to bypass authentication or authorization mechanisms in systems that rely on xml-crypto for verifying signed XML documents. The vulnerability allows an attacker to modify a valid signed XML message in a way that still passes signature verification checks. For example, it could be used to alter critical identity or access control attributes, enabling an attacker with a valid account to escalate privileges or impersonate another user. Users of versions 6.0.0 and prior should upgrade to version 6.0.1 to receive a fix. Those who are still using v2.x or v3.x should upgrade to patched versions 2.1.6 or 3.2.1, respectively.

- [https://github.com/Mrrishuyt/mrrishuyt.github.io](https://github.com/Mrrishuyt/mrrishuyt.github.io) :  ![starts](https://img.shields.io/github/stars/Mrrishuyt/mrrishuyt.github.io.svg) ![forks](https://img.shields.io/github/forks/Mrrishuyt/mrrishuyt.github.io.svg)
- [https://github.com/Mrrishuyt/Phantom-Signature-Attack](https://github.com/Mrrishuyt/Phantom-Signature-Attack) :  ![starts](https://img.shields.io/github/stars/Mrrishuyt/Phantom-Signature-Attack.svg) ![forks](https://img.shields.io/github/forks/Mrrishuyt/Phantom-Signature-Attack.svg)


## CVE-2025-15467
OpenSSL 1.1.1 and 1.0.2 are not affected by this issue.

- [https://github.com/balgan/CVE-2025-15467](https://github.com/balgan/CVE-2025-15467) :  ![starts](https://img.shields.io/github/stars/balgan/CVE-2025-15467.svg) ![forks](https://img.shields.io/github/forks/balgan/CVE-2025-15467.svg)


## CVE-2025-3102
 The SureTriggers: All-in-One Automation Platform plugin for WordPress is vulnerable to an authentication bypass leading to administrative account creation due to a missing empty value check on the 'secret_key' value in the 'autheticate_user' function in all versions up to, and including, 1.0.78. This makes it possible for unauthenticated attackers to create administrator accounts on the target website when the plugin is installed and activated but not configured with an API key.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance](https://github.com/peiqiF4ck/WebFrameworkTools-5.5-enhance) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.5-enhance.svg)
- [https://github.com/Nxploited/CVE-2025-3102](https://github.com/Nxploited/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-3102.svg)
- [https://github.com/itsismarcos/vanda-CVE-2025-3102](https://github.com/itsismarcos/vanda-CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/itsismarcos/vanda-CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/itsismarcos/vanda-CVE-2025-3102.svg)
- [https://github.com/rhz0d/CVE-2025-3102](https://github.com/rhz0d/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/rhz0d/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/rhz0d/CVE-2025-3102.svg)
- [https://github.com/SUPRAAA-1337/CVE-2025-3102-exploit](https://github.com/SUPRAAA-1337/CVE-2025-3102-exploit) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/CVE-2025-3102-exploit.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/CVE-2025-3102-exploit.svg)
- [https://github.com/SUPRAAA-1337/CVE-2025-3102](https://github.com/SUPRAAA-1337/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/CVE-2025-3102.svg)
- [https://github.com/y0uki-sec/CVE-2025-3102](https://github.com/y0uki-sec/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/y0uki-sec/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/y0uki-sec/CVE-2025-3102.svg)
- [https://github.com/dennisec/CVE-2025-3102](https://github.com/dennisec/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/dennisec/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/dennisec/CVE-2025-3102.svg)
- [https://github.com/0xgh057r3c0n/CVE-2025-3102](https://github.com/0xgh057r3c0n/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-3102.svg)
- [https://github.com/baribut/CVE-2025-3102](https://github.com/baribut/CVE-2025-3102) :  ![starts](https://img.shields.io/github/stars/baribut/CVE-2025-3102.svg) ![forks](https://img.shields.io/github/forks/baribut/CVE-2025-3102.svg)
- [https://github.com/SUPRAAA-1337/CVE-2025-3102_v2](https://github.com/SUPRAAA-1337/CVE-2025-3102_v2) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/CVE-2025-3102_v2.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/CVE-2025-3102_v2.svg)


## CVE-2023-35317
 Windows Server Update Service (WSUS) Elevation of Privilege Vulnerability

- [https://github.com/salman5230/CVE-2025-59287](https://github.com/salman5230/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/salman5230/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/salman5230/CVE-2025-59287.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/stfnw/reproducer-poc-CVE-2022-0847](https://github.com/stfnw/reproducer-poc-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/stfnw/reproducer-poc-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/stfnw/reproducer-poc-CVE-2022-0847.svg)


## CVE-2021-24499
 The Workreap WordPress theme before 2.2.2 AJAX actions workreap_award_temp_file_uploader and workreap_temp_file_uploader did not perform nonce checks, or validate that the request is from a valid user in any other way. The endpoints allowed for uploading arbitrary files to the uploads/workreap-temp directory. Uploaded files were neither sanitized nor validated, allowing an unauthenticated visitor to upload executable code such as php scripts.

- [https://github.com/jayhutajulu1/CVE-2021-24499](https://github.com/jayhutajulu1/CVE-2021-24499) :  ![starts](https://img.shields.io/github/stars/jayhutajulu1/CVE-2021-24499.svg) ![forks](https://img.shields.io/github/forks/jayhutajulu1/CVE-2021-24499.svg)


## CVE-2020-14343
 A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vulnerable to this flaw. This flaw allows an attacker to execute arbitrary code on the system by abusing the python/object/new constructor. This flaw is due to an incomplete fix for CVE-2020-1747.

- [https://github.com/sijie52/yasa-cve-2020-14343](https://github.com/sijie52/yasa-cve-2020-14343) :  ![starts](https://img.shields.io/github/stars/sijie52/yasa-cve-2020-14343.svg) ![forks](https://img.shields.io/github/forks/sijie52/yasa-cve-2020-14343.svg)


## CVE-2020-11107
 An issue was discovered in XAMPP before 7.2.29, 7.3.x before 7.3.16 , and 7.4.x before 7.4.4 on Windows. An unprivileged user can change a .exe configuration in xampp-contol.ini for all users (including admins) to enable arbitrary command execution.

- [https://github.com/Mohnad-AL-saif/Mohnad-AL-saif-CVE-2020-11107-XAMPP-Local-Privilege-Escalation](https://github.com/Mohnad-AL-saif/Mohnad-AL-saif-CVE-2020-11107-XAMPP-Local-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/Mohnad-AL-saif/Mohnad-AL-saif-CVE-2020-11107-XAMPP-Local-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/Mohnad-AL-saif/Mohnad-AL-saif-CVE-2020-11107-XAMPP-Local-Privilege-Escalation.svg)


## CVE-2020-1971
 The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the "-crl_download" option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).

- [https://github.com/honeyvig/CVE-2020-1971](https://github.com/honeyvig/CVE-2020-1971) :  ![starts](https://img.shields.io/github/stars/honeyvig/CVE-2020-1971.svg) ![forks](https://img.shields.io/github/forks/honeyvig/CVE-2020-1971.svg)


## CVE-2019-11707
 A type confusion vulnerability can occur when manipulating JavaScript objects due to issues in Array.pop. This can allow for an exploitable crash. We are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects Firefox ESR  60.7.1, Firefox  67.0.3, and Thunderbird  60.7.2.

- [https://github.com/CosminGGeorgescu/CVE-2019-11707-PoC](https://github.com/CosminGGeorgescu/CVE-2019-11707-PoC) :  ![starts](https://img.shields.io/github/stars/CosminGGeorgescu/CVE-2019-11707-PoC.svg) ![forks](https://img.shields.io/github/forks/CosminGGeorgescu/CVE-2019-11707-PoC.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/Wyl-cmd/CVE-2017-7921-Research-Toolkit](https://github.com/Wyl-cmd/CVE-2017-7921-Research-Toolkit) :  ![starts](https://img.shields.io/github/stars/Wyl-cmd/CVE-2017-7921-Research-Toolkit.svg) ![forks](https://img.shields.io/github/forks/Wyl-cmd/CVE-2017-7921-Research-Toolkit.svg)


## CVE-2015-3224
 request.rb in Web Console before 2.1.3, as used with Ruby on Rails 3.x and 4.x, does not properly restrict the use of X-Forwarded-For headers in determining a client's IP address, which allows remote attackers to bypass the whitelisted_ips protection mechanism via a crafted request.

- [https://github.com/roriruri9370/Whitelist-bypass](https://github.com/roriruri9370/Whitelist-bypass) :  ![starts](https://img.shields.io/github/stars/roriruri9370/Whitelist-bypass.svg) ![forks](https://img.shields.io/github/forks/roriruri9370/Whitelist-bypass.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Efehamzaa/Metasploit-Red-Pentest-Lab](https://github.com/Efehamzaa/Metasploit-Red-Pentest-Lab) :  ![starts](https://img.shields.io/github/stars/Efehamzaa/Metasploit-Red-Pentest-Lab.svg) ![forks](https://img.shields.io/github/forks/Efehamzaa/Metasploit-Red-Pentest-Lab.svg)

