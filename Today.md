# Update 2026-08-01
## CVE-2026-66066
 Action Pack is a framework for handling and responding to web requests. In versions prior to 7.2.3.2, 8.0.5.1 and 8.1.3.1, Active Storage does not disable libvips operations marked unsafe for untrusted content, allowing a crafted upload to invoke such an operation. Consuming applications are affected when configured to use libvips and accept image uploads from untrusted users. An unauthenticated attacker may exploit this behavior to read arbitrary files accessible to the Rails process, including environment variables and application secrets. Exposure of credentials such as secret_key_base or external-service tokens may enable remote code execution or lateral movement. This issue has been fixed in versions 7.2.3.2, 8.0.5.1 and 8.1.3.1.

- [https://github.com/Zer0SumGam3/CVE-2026-66066-POC](https://github.com/Zer0SumGam3/CVE-2026-66066-POC) :  ![starts](https://img.shields.io/github/stars/Zer0SumGam3/CVE-2026-66066-POC.svg) ![forks](https://img.shields.io/github/forks/Zer0SumGam3/CVE-2026-66066-POC.svg)
- [https://github.com/rails/rails-forensics-CVE-2026-66066](https://github.com/rails/rails-forensics-CVE-2026-66066) :  ![starts](https://img.shields.io/github/stars/rails/rails-forensics-CVE-2026-66066.svg) ![forks](https://img.shields.io/github/forks/rails/rails-forensics-CVE-2026-66066.svg)
- [https://github.com/0xBlackash/CVE-2026-66066](https://github.com/0xBlackash/CVE-2026-66066) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-66066.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-66066.svg)
- [https://github.com/paveg/rails-activestorage-vips-audit](https://github.com/paveg/rails-activestorage-vips-audit) :  ![starts](https://img.shields.io/github/stars/paveg/rails-activestorage-vips-audit.svg) ![forks](https://img.shields.io/github/forks/paveg/rails-activestorage-vips-audit.svg)


## CVE-2026-65883
 Joomla Extension - aimy-extensions.com - RCE via PHP object injection in Aimy Captcha-Less Form Guard 18.0 - 20.0 - A forged clfgd field allows PHP objection injection and thereby remote code execution.

- [https://github.com/shinthink/CVE-2026-65883](https://github.com/shinthink/CVE-2026-65883) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-65883.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-65883.svg)


## CVE-2026-64600
sequence counter changes across the ILOCK cycle.

- [https://github.com/litosmartin/CVE-2026-64600-Refluxfs-PoC](https://github.com/litosmartin/CVE-2026-64600-Refluxfs-PoC) :  ![starts](https://img.shields.io/github/stars/litosmartin/CVE-2026-64600-Refluxfs-PoC.svg) ![forks](https://img.shields.io/github/forks/litosmartin/CVE-2026-64600-Refluxfs-PoC.svg)


## CVE-2026-63077
 In JetBrains TeamCity before 2026.1.3, 2025.11.7 unauthenticated remote code execution was possible via the agent polling protocol

- [https://github.com/unveiledhistory49/teamcity-cve-2026-63077-remediation](https://github.com/unveiledhistory49/teamcity-cve-2026-63077-remediation) :  ![starts](https://img.shields.io/github/stars/unveiledhistory49/teamcity-cve-2026-63077-remediation.svg) ![forks](https://img.shields.io/github/forks/unveiledhistory49/teamcity-cve-2026-63077-remediation.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2026-63030-WP2Shell](https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2026-63030-WP2Shell) :  ![starts](https://img.shields.io/github/stars/Industri4l-H3ll-Xpl0it3rs/CVE-2026-63030-WP2Shell.svg) ![forks](https://img.shields.io/github/forks/Industri4l-H3ll-Xpl0it3rs/CVE-2026-63030-WP2Shell.svg)


## CVE-2026-61511
 vBulletin 5.x through 5.7.5 and 6.x through 6.2.1 contains an eval injection vulnerability in the vB5_Template_Runtime::runMaths() method within the template runtime that allows unauthenticated remote attackers to execute arbitrary PHP code by supplying crafted input through the pagenav[pagenumber] parameter. Attackers can exploit the insufficiently restrictive regex filter by using phpfuck-style encoding with permitted characters to inject and execute arbitrary PHP code via the unauthenticated ajax/render template route without any authentication.

- [https://github.com/shootcannon/CVE-2026-61511](https://github.com/shootcannon/CVE-2026-61511) :  ![starts](https://img.shields.io/github/stars/shootcannon/CVE-2026-61511.svg) ![forks](https://img.shields.io/github/forks/shootcannon/CVE-2026-61511.svg)


## CVE-2026-61424
 Joomla Extension - dj-extensions.com - Unauthenticated arbitrary file upload in DJ-Classifieds  3.11.2 - The Joomla extension DJ-Classifieds is vulnerable to an unauthenticated file upload, leading to full RCE.

- [https://github.com/shinthink/CVE-2026-61424](https://github.com/shinthink/CVE-2026-61424) :  ![starts](https://img.shields.io/github/stars/shinthink/CVE-2026-61424.svg) ![forks](https://img.shields.io/github/forks/shinthink/CVE-2026-61424.svg)


## CVE-2026-57827
 Joomla Extension - rsjoomla.com - Unauthenticated file upload in RSFiles component  1.17.12 - The Joomla extension RSFiles is vulnerable to an unauthenticated arbitrary file upload that allows uploading executable files and leads to full RCE.

- [https://github.com/Candisexterior171/CVE-2026-57827](https://github.com/Candisexterior171/CVE-2026-57827) :  ![starts](https://img.shields.io/github/stars/Candisexterior171/CVE-2026-57827.svg) ![forks](https://img.shields.io/github/forks/Candisexterior171/CVE-2026-57827.svg)


## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/nawalacheker1/CVE-2026-46331](https://github.com/nawalacheker1/CVE-2026-46331) :  ![starts](https://img.shields.io/github/stars/nawalacheker1/CVE-2026-46331.svg) ![forks](https://img.shields.io/github/forks/nawalacheker1/CVE-2026-46331.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/WitAqua-tools/Root-My-Device](https://github.com/WitAqua-tools/Root-My-Device) :  ![starts](https://img.shields.io/github/stars/WitAqua-tools/Root-My-Device.svg) ![forks](https://img.shields.io/github/forks/WitAqua-tools/Root-My-Device.svg)
- [https://github.com/fancyzll/CVE-2026-43499_OPPO-MT6835](https://github.com/fancyzll/CVE-2026-43499_OPPO-MT6835) :  ![starts](https://img.shields.io/github/stars/fancyzll/CVE-2026-43499_OPPO-MT6835.svg) ![forks](https://img.shields.io/github/forks/fancyzll/CVE-2026-43499_OPPO-MT6835.svg)


## CVE-2026-41472
 CyberPanel versions prior to 2.4.4 contain a stored cross-site scripting vulnerability in the AI Scanner dashboard where the POST /api/ai-scanner/callback endpoint lacks authentication and allows unauthenticated attackers to inject malicious JavaScript by overwriting the findings_json field of ScanHistory records. Attackers can inject JavaScript that executes in an administrator's authenticated session when they visit the AI Scanner dashboard, allowing them to issue same-origin requests to plant cron jobs and achieve remote code execution on the server.

- [https://github.com/whiteov3rflow/CVE-2026-41472-POC](https://github.com/whiteov3rflow/CVE-2026-41472-POC) :  ![starts](https://img.shields.io/github/stars/whiteov3rflow/CVE-2026-41472-POC.svg) ![forks](https://img.shields.io/github/forks/whiteov3rflow/CVE-2026-41472-POC.svg)


## CVE-2026-39875
 A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sequoia 15.7.8, macOS Sonoma 14.8.8, macOS Tahoe 26.6. A malicious app may be able to gain root privileges.

- [https://github.com/5ky9uy/CVE-2026-39875-macOS-CUPS](https://github.com/5ky9uy/CVE-2026-39875-macOS-CUPS) :  ![starts](https://img.shields.io/github/stars/5ky9uy/CVE-2026-39875-macOS-CUPS.svg) ![forks](https://img.shields.io/github/forks/5ky9uy/CVE-2026-39875-macOS-CUPS.svg)


## CVE-2026-33937
 Handlebars provides the power necessary to let users build semantic templates. In versions 4.0.0 through 4.7.8, `Handlebars.compile()` accepts a pre-parsed AST object in addition to a template string. The `value` field of a `NumberLiteral` AST node is emitted directly into the generated JavaScript without quoting or sanitization. An attacker who can supply a crafted AST to `compile()` can therefore inject and execute arbitrary JavaScript, leading to Remote Code Execution on the server. Version 4.7.9 fixes the issue. Some workarounds are available. Validate input type before calling `Handlebars.compile()`; ensure the argument is always a  `string`, never a plain object or JSON-deserialized value. Use the Handlebars runtime-only build (`handlebars/runtime`) on the server if templates are pre-compiled at build time; `compile()` will be unavailable.

- [https://github.com/garlic-wizard/CVE-2026-33937-for-DarkZeroReturns](https://github.com/garlic-wizard/CVE-2026-33937-for-DarkZeroReturns) :  ![starts](https://img.shields.io/github/stars/garlic-wizard/CVE-2026-33937-for-DarkZeroReturns.svg) ![forks](https://img.shields.io/github/forks/garlic-wizard/CVE-2026-33937-for-DarkZeroReturns.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/1neptune/CopyFail](https://github.com/1neptune/CopyFail) :  ![starts](https://img.shields.io/github/stars/1neptune/CopyFail.svg) ![forks](https://img.shields.io/github/forks/1neptune/CopyFail.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/Nowafen/CVE-2026-16723](https://github.com/Nowafen/CVE-2026-16723) :  ![starts](https://img.shields.io/github/stars/Nowafen/CVE-2026-16723.svg) ![forks](https://img.shields.io/github/forks/Nowafen/CVE-2026-16723.svg)
- [https://github.com/EQSTLab/CVE-2026-16723](https://github.com/EQSTLab/CVE-2026-16723) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-16723.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-16723.svg)


## CVE-2026-6000
 A vulnerability was found in code-projects Online Library Management System 1.0. Affected is an unknown function of the file /sql/library.sql of the component SQL Database Backup File Handler. Performing a manipulation results in information disclosure. The attack may be initiated remotely. The exploit has been made public and could be used.

- [https://github.com/EQSTLab/CVE-2026-60004](https://github.com/EQSTLab/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-60004.svg)
- [https://github.com/0xBlackash/CVE-2026-60004](https://github.com/0xBlackash/CVE-2026-60004) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-60004.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-60004.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-64446
 A relative path traversal vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an attacker to execute administrative commands on the system via crafted HTTP or HTTPS requests.

- [https://github.com/CerberusMrXi/FortiWeb-cve-2025-64446-RCE-exploit](https://github.com/CerberusMrXi/FortiWeb-cve-2025-64446-RCE-exploit) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/FortiWeb-cve-2025-64446-RCE-exploit.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/FortiWeb-cve-2025-64446-RCE-exploit.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182](https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg)
- [https://github.com/yz9yt/React2Shell-CTF](https://github.com/yz9yt/React2Shell-CTF) :  ![starts](https://img.shields.io/github/stars/yz9yt/React2Shell-CTF.svg) ![forks](https://img.shields.io/github/forks/yz9yt/React2Shell-CTF.svg)


## CVE-2025-49091
 KDE Konsole before 25.04.2 allows remote code execution in a certain scenario. It supports loading URLs from the scheme handlers such as a ssh:// or telnet:// or rlogin:// URL. This can be executed regardless of whether the ssh, telnet, or rlogin binary is available. In this mode, there is a code path where if that binary is not available, Konsole falls back to using /bin/bash for the given arguments (i.e., the URL) provided. This allows an attacker to execute arbitrary code.

- [https://github.com/thefreestyleresearcher/CVE-2025-49091-Gajim-RCE](https://github.com/thefreestyleresearcher/CVE-2025-49091-Gajim-RCE) :  ![starts](https://img.shields.io/github/stars/thefreestyleresearcher/CVE-2025-49091-Gajim-RCE.svg) ![forks](https://img.shields.io/github/forks/thefreestyleresearcher/CVE-2025-49091-Gajim-RCE.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/HeltonPojo/CVE-2025-32432](https://github.com/HeltonPojo/CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/HeltonPojo/CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/HeltonPojo/CVE-2025-32432.svg)


## CVE-2025-25296
 Label Studio is an open source data labeling tool. Prior to version 1.16.0, Label Studio's `/projects/upload-example` endpoint allows injection of arbitrary HTML through a `GET` request with an appropriately crafted `label_config` query parameter. By crafting a specially formatted XML label config with inline task data containing malicious HTML/JavaScript, an attacker can achieve Cross-Site Scripting (XSS). While the application has a Content Security Policy (CSP), it is only set in report-only mode, making it ineffective at preventing script execution. The vulnerability exists because the upload-example endpoint renders user-provided HTML content without proper sanitization on a GET request. This allows attackers to inject and execute arbitrary JavaScript in victims' browsers by getting them to visit a maliciously crafted URL. This is considered vulnerable because it enables attackers to execute JavaScript in victims' contexts, potentially allowing theft of sensitive data, session hijacking, or other malicious actions. Version 1.16.0 contains a patch for the issue.

- [https://github.com/math-x-io/CVE-2025-25296](https://github.com/math-x-io/CVE-2025-25296) :  ![starts](https://img.shields.io/github/stars/math-x-io/CVE-2025-25296.svg) ![forks](https://img.shields.io/github/forks/math-x-io/CVE-2025-25296.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/dheeraj-jayaswal/CICD-Goat-Vapt-Writeup](https://github.com/dheeraj-jayaswal/CICD-Goat-Vapt-Writeup) :  ![starts](https://img.shields.io/github/stars/dheeraj-jayaswal/CICD-Goat-Vapt-Writeup.svg) ![forks](https://img.shields.io/github/forks/dheeraj-jayaswal/CICD-Goat-Vapt-Writeup.svg)


## CVE-2024-21762
 A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/belky-me/vamp-forticheck](https://github.com/belky-me/vamp-forticheck) :  ![starts](https://img.shields.io/github/stars/belky-me/vamp-forticheck.svg) ![forks](https://img.shields.io/github/forks/belky-me/vamp-forticheck.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/s1d6point7bugcrowd/CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH](https://github.com/s1d6point7bugcrowd/CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH) :  ![starts](https://img.shields.io/github/stars/s1d6point7bugcrowd/CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH.svg) ![forks](https://img.shields.io/github/forks/s1d6point7bugcrowd/CVE-2024-6387-Race-Condition-in-Signal-Handling-for-OpenSSH.svg)

