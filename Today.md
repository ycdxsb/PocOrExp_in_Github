# Update 2026-08-31
## CVE-2026-82286
 gpt-crawler through 1.5.1 fails to validate the outputFileName parameter in the POST /crawl endpoint, allowing unauthenticated attackers to write arbitrary files to any filesystem path. Attackers can supply absolute paths or parent-directory segments to overwrite existing files with content sourced from attacker-controlled URLs.

- [https://github.com/BiiTts/CVE-2026-82286-gpt-crawler-Arbitrary-File-Write](https://github.com/BiiTts/CVE-2026-82286-gpt-crawler-Arbitrary-File-Write) :  ![starts](https://img.shields.io/github/stars/BiiTts/CVE-2026-82286-gpt-crawler-Arbitrary-File-Write.svg) ![forks](https://img.shields.io/github/forks/BiiTts/CVE-2026-82286-gpt-crawler-Arbitrary-File-Write.svg)


## CVE-2026-82078
 An unsafe dynamic class loading vulnerability exists in the database connection utilities of PaperCut MF and PaperCut NG. The application instantiates database driver classes based on configurable driver names without validating against an allowlist of approved drivers. If an attacker can manipulate system configuration parameters, this enables the execution of arbitrary Java bytecode residing on the application classpath under the security context of the PaperCut server process.

- [https://github.com/yora1928/PaperCut-CVE-2026-81578-82078](https://github.com/yora1928/PaperCut-CVE-2026-81578-82078) :  ![starts](https://img.shields.io/github/stars/yora1928/PaperCut-CVE-2026-81578-82078.svg) ![forks](https://img.shields.io/github/forks/yora1928/PaperCut-CVE-2026-81578-82078.svg)
- [https://github.com/virologi-info/papercut-toolkit](https://github.com/virologi-info/papercut-toolkit) :  ![starts](https://img.shields.io/github/stars/virologi-info/papercut-toolkit.svg) ![forks](https://img.shields.io/github/forks/virologi-info/papercut-toolkit.svg)


## CVE-2026-81578
 An improper access control vulnerability exists in the web management interface of PaperCut MF and PaperCut NG. Under specific conditions, unauthenticated remote requests targeting administrative functions can trigger backend actions prior to the  completion of access validation checks. This allows an unauthenticated remote attacker to modify certain system configurations.

- [https://github.com/yora1928/PaperCut-CVE-2026-81578-82078](https://github.com/yora1928/PaperCut-CVE-2026-81578-82078) :  ![starts](https://img.shields.io/github/stars/yora1928/PaperCut-CVE-2026-81578-82078.svg) ![forks](https://img.shields.io/github/forks/yora1928/PaperCut-CVE-2026-81578-82078.svg)
- [https://github.com/virologi-info/papercut-toolkit](https://github.com/virologi-info/papercut-toolkit) :  ![starts](https://img.shields.io/github/stars/virologi-info/papercut-toolkit.svg) ![forks](https://img.shields.io/github/forks/virologi-info/papercut-toolkit.svg)


## CVE-2026-68929
 FastGPT is an open-source LLM platform for building AI applications on a knowledge base. In versions prior to 4.15.2, the WeChat (iLink) share-channel endpoints authorize requests using only the public shareId, with no authenticated identity or team-ownership check. As a result, an unauthenticated attacker who knows a victim team's shareId can take that team's WeChat bot offline or hijack the channel to their own bot: the logout endpoint is gated only by an existence check yet wipes the outLink's stored WeChat token, and the QR-code status endpoint performs no authorization at all and writes attacker-supplied bot credentials into the outLink identified by shareId. By generating a QR for a victim shareId, scanning it with their own WeChat, and calling the status endpoint, an attacker binds the victim team's app to the attacker's bot, exposing the app's private responses, displacing the legitimate binding, and consuming the victim's resources. The shareId is exposed in every shared chat URL, iframe, and embed, so it is not a secret. This issue is fixed in version 4.15.2.

- [https://github.com/Hunt-Benito/your-bot-my-inbox-cve-2026-68929-fastgpt-unauthenticated-wechat-channel-hijack](https://github.com/Hunt-Benito/your-bot-my-inbox-cve-2026-68929-fastgpt-unauthenticated-wechat-channel-hijack) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/your-bot-my-inbox-cve-2026-68929-fastgpt-unauthenticated-wechat-channel-hijack.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/your-bot-my-inbox-cve-2026-68929-fastgpt-unauthenticated-wechat-channel-hijack.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/aungko186/YellowKey-BitLocker-CVE-2026-45585](https://github.com/aungko186/YellowKey-BitLocker-CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/aungko186/YellowKey-BitLocker-CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/aungko186/YellowKey-BitLocker-CVE-2026-45585.svg)


## CVE-2026-45071
 Symfony is a PHP framework for web and console applications and a set of reusable PHP components. Prior to 5.4.52, 6.4.40, 7.4.12, and 8.0.12, Crawler::addXmlContent() set DOMDocument::$validateOnParse = true before loadXML(), re-enabling external entity resolution and allowing attacker-supplied XML to expand file:// entities such as local files. This issue is fixed in versions 5.4.52, 6.4.40, 7.4.12, and 8.0.12.

- [https://github.com/bozellqp/zk-xml-probe](https://github.com/bozellqp/zk-xml-probe) :  ![starts](https://img.shields.io/github/stars/bozellqp/zk-xml-probe.svg) ![forks](https://img.shields.io/github/forks/bozellqp/zk-xml-probe.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/hackyangwen-lgtm/rmg-s9180-fzg1](https://github.com/hackyangwen-lgtm/rmg-s9180-fzg1) :  ![starts](https://img.shields.io/github/stars/hackyangwen-lgtm/rmg-s9180-fzg1.svg) ![forks](https://img.shields.io/github/forks/hackyangwen-lgtm/rmg-s9180-fzg1.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/FranklinF25/cve-2026-42533](https://github.com/FranklinF25/cve-2026-42533) :  ![starts](https://img.shields.io/github/stars/FranklinF25/cve-2026-42533.svg) ![forks](https://img.shields.io/github/forks/FranklinF25/cve-2026-42533.svg)


## CVE-2026-23989
 REVA is an interoperability platform. Prior to 2.42.3 and 2.40.3, a bug in the GRPC authorization middleware of the "Reva" component of OpenCloud allows a malicious user to bypass the scope verification of a public link. By exploiting this via the the "archiver" service this can be leveraged to create an archive (zip or tar-file) containing all resources that this creator of the public link has access to. This vulnerability is fixed in 2.42.3 and 2.40.3.

- [https://github.com/dinosn/cve-2026-23989-opencloud-lab](https://github.com/dinosn/cve-2026-23989-opencloud-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/cve-2026-23989-opencloud-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/cve-2026-23989-opencloud-lab.svg)


## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).

- [https://github.com/KaiserdesMonats/CVE-2026-21962-Blog](https://github.com/KaiserdesMonats/CVE-2026-21962-Blog) :  ![starts](https://img.shields.io/github/stars/KaiserdesMonats/CVE-2026-21962-Blog.svg) ![forks](https://img.shields.io/github/forks/KaiserdesMonats/CVE-2026-21962-Blog.svg)


## CVE-2026-20357
The vulnerabilities tracked by CVE-2026-20357 are related to missing authentication for critical function issues that are grouped under the Common Weakness Enumeration (CWE) CWE-306.

- [https://github.com/danish1162/CVE-2026-2035703-x300](https://github.com/danish1162/CVE-2026-2035703-x300) :  ![starts](https://img.shields.io/github/stars/danish1162/CVE-2026-2035703-x300.svg) ![forks](https://img.shields.io/github/forks/danish1162/CVE-2026-2035703-x300.svg)


## CVE-2026-19745
 A flaw has been found in Calix GigaSpire 26.1.0. Impacted is an unknown function of the file utilities_configurationsave.cgi of the component Web Management Interface. Executing a manipulation of the argument sessionKey can lead to denial of service. The attack can be launched remotely. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/drbloop2000/CVE-2026-19745](https://github.com/drbloop2000/CVE-2026-19745) :  ![starts](https://img.shields.io/github/stars/drbloop2000/CVE-2026-19745.svg) ![forks](https://img.shields.io/github/forks/drbloop2000/CVE-2026-19745.svg)


## CVE-2026-18729
 IBM Langflow OSS 1.0.0 through 1.11.1 could allow a remote authenticated attacker to execute arbitrary code due to improper control of generation of code.

- [https://github.com/rmhowe425/POC-CVE-2026-18729](https://github.com/rmhowe425/POC-CVE-2026-18729) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-18729.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-18729.svg)


## CVE-2026-12243
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/morzelowski/CVE-2026-12243-NLTK-PoC](https://github.com/morzelowski/CVE-2026-12243-NLTK-PoC) :  ![starts](https://img.shields.io/github/stars/morzelowski/CVE-2026-12243-NLTK-PoC.svg) ![forks](https://img.shields.io/github/forks/morzelowski/CVE-2026-12243-NLTK-PoC.svg)


## CVE-2026-9198
 IBM Langflow OSS 1.0.0 through 1.10.0 allows unauthenticated attackers to chain /api/v1/auto_login (mints SUPERUSER tokens to any network caller) with /api/v1/validate/code (executes user code via exec()) to achieve full RCE on default Langflow deployments

- [https://github.com/joaovicdev/EXPLOIT-CVE-2026-9198](https://github.com/joaovicdev/EXPLOIT-CVE-2026-9198) :  ![starts](https://img.shields.io/github/stars/joaovicdev/EXPLOIT-CVE-2026-9198.svg) ![forks](https://img.shields.io/github/forks/joaovicdev/EXPLOIT-CVE-2026-9198.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Cxyofficial/k50g-pocof4gt-cve-2026-43499-test](https://github.com/Cxyofficial/k50g-pocof4gt-cve-2026-43499-test) :  ![starts](https://img.shields.io/github/stars/Cxyofficial/k50g-pocof4gt-cve-2026-43499-test.svg) ![forks](https://img.shields.io/github/forks/Cxyofficial/k50g-pocof4gt-cve-2026-43499-test.svg)


## CVE-2026-4001
 The Woocommerce Custom Product Addons Pro plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 5.4.1 via the custom pricing formula eval() in the process_custom_formula() function within includes/process/price.php. This is due to insufficient sanitization and validation of user-submitted field values before passing them to PHP's eval() function. The sanitize_values() method strips HTML tags but does not escape single quotes or prevent PHP code injection. This makes it possible for unauthenticated attackers to execute arbitrary code on the server by submitting a crafted value to a WCPA text field configured with custom pricing formula (pricingType: "custom" with {this.value}).

- [https://github.com/htrxuan/hdwebmobile-formula-pricing](https://github.com/htrxuan/hdwebmobile-formula-pricing) :  ![starts](https://img.shields.io/github/stars/htrxuan/hdwebmobile-formula-pricing.svg) ![forks](https://img.shields.io/github/forks/htrxuan/hdwebmobile-formula-pricing.svg)


## CVE-2026-1801
 A flaw was found in libsoup, an HTTP client/server library. This HTTP Request Smuggling vulnerability arises from non-RFC-compliant parsing in the soup_filter_input_stream_read_line() logic, where libsoup accepts malformed chunk headers, such as lone line feed (LF) characters instead of the required carriage return and line feed (CRLF). A remote attacker can exploit this without authentication or user interaction by sending specially crafted chunked requests. This allows libsoup to parse and process multiple HTTP requests from a single network message, potentially leading to information disclosure.

- [https://github.com/misterdengi/CVE-2026-1801C](https://github.com/misterdengi/CVE-2026-1801C) :  ![starts](https://img.shields.io/github/stars/misterdengi/CVE-2026-1801C.svg) ![forks](https://img.shields.io/github/forks/misterdengi/CVE-2026-1801C.svg)


## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.

- [https://github.com/sahmsec/CVE-2026-1357](https://github.com/sahmsec/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/sahmsec/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/sahmsec/CVE-2026-1357.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)


## CVE-2024-49138
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/NadineElliottCyber/SOC335-CVE-2024-49138-Investigation](https://github.com/NadineElliottCyber/SOC335-CVE-2024-49138-Investigation) :  ![starts](https://img.shields.io/github/stars/NadineElliottCyber/SOC335-CVE-2024-49138-Investigation.svg) ![forks](https://img.shields.io/github/forks/NadineElliottCyber/SOC335-CVE-2024-49138-Investigation.svg)


## CVE-2024-30088
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/cyghtinc/cve-2024-30088-binary-LPE-PRIVIELEGE-ESCALATION-CYGHT-TOCTOU](https://github.com/cyghtinc/cve-2024-30088-binary-LPE-PRIVIELEGE-ESCALATION-CYGHT-TOCTOU) :  ![starts](https://img.shields.io/github/stars/cyghtinc/cve-2024-30088-binary-LPE-PRIVIELEGE-ESCALATION-CYGHT-TOCTOU.svg) ![forks](https://img.shields.io/github/forks/cyghtinc/cve-2024-30088-binary-LPE-PRIVIELEGE-ESCALATION-CYGHT-TOCTOU.svg)


## CVE-2024-12692
 Type Confusion in V8 in Google Chrome prior to 131.0.6778.204 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/VictorNS69/CVE-2024-12381](https://github.com/VictorNS69/CVE-2024-12381) :  ![starts](https://img.shields.io/github/stars/VictorNS69/CVE-2024-12381.svg) ![forks](https://img.shields.io/github/forks/VictorNS69/CVE-2024-12381.svg)


## CVE-2024-12381
 Type Confusion in V8 in Google Chrome prior to 131.0.6778.139 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/VictorNS69/CVE-2024-12381](https://github.com/VictorNS69/CVE-2024-12381) :  ![starts](https://img.shields.io/github/stars/VictorNS69/CVE-2024-12381.svg) ![forks](https://img.shields.io/github/forks/VictorNS69/CVE-2024-12381.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/Gadorach/vankyo-s30-bootloader-unlock](https://github.com/Gadorach/vankyo-s30-bootloader-unlock) :  ![starts](https://img.shields.io/github/stars/Gadorach/vankyo-s30-bootloader-unlock.svg) ![forks](https://img.shields.io/github/forks/Gadorach/vankyo-s30-bootloader-unlock.svg)


## CVE-2022-24713
 regex is an implementation of regular expressions for the Rust language. The regex crate features built-in mitigations to prevent denial of service attacks caused by untrusted regexes, or untrusted input matched by trusted regexes. Those (tunable) mitigations already provide sane defaults to prevent attacks. This guarantee is documented and it's considered part of the crate's API. Unfortunately a bug was discovered in the mitigations designed to prevent untrusted regexes to take an arbitrary amount of time during parsing, and it's possible to craft regexes that bypass such mitigations. This makes it possible to perform denial of service attacks by sending specially crafted regexes to services accepting user-controlled, untrusted regexes. All versions of the regex crate before or equal to 1.5.4 are affected by this issue. The fix is include starting from regex 1.5.5. All users accepting user-controlled regexes are recommended to upgrade immediately to the latest version of the regex crate. Unfortunately there is no fixed set of problematic regexes, as there are practically infinite regexes that could be crafted to exploit this vulnerability. Because of this, it us not recommend to deny known problematic regexes.

- [https://github.com/jpeisach/CVE-2022-24713-POC](https://github.com/jpeisach/CVE-2022-24713-POC) :  ![starts](https://img.shields.io/github/stars/jpeisach/CVE-2022-24713-POC.svg) ![forks](https://img.shields.io/github/forks/jpeisach/CVE-2022-24713-POC.svg)


## CVE-2022-2588
 It was discovered that the cls_route filter implementation in the Linux kernel would not remove an old filter from the hashtable before freeing it if its handle had the value 0.

- [https://github.com/LSinus/CacheMeIfYouCan](https://github.com/LSinus/CacheMeIfYouCan) :  ![starts](https://img.shields.io/github/stars/LSinus/CacheMeIfYouCan.svg) ![forks](https://img.shields.io/github/forks/LSinus/CacheMeIfYouCan.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)


## CVE-2020-28022
 Exim 4 before 4.94.2 has Improper Restriction of Write Operations within the Bounds of a Memory Buffer. This occurs when processing name=value pairs within MAIL FROM and RCPT TO commands.

- [https://github.com/t1b4n3/CVE-2020-28022](https://github.com/t1b4n3/CVE-2020-28022) :  ![starts](https://img.shields.io/github/stars/t1b4n3/CVE-2020-28022.svg) ![forks](https://img.shields.io/github/forks/t1b4n3/CVE-2020-28022.svg)

