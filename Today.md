# Update 2026-09-01
## CVE-2026-82539
 A vulnerability was determined in TOTOLINK A720R 4.1.5cu.630_B20250509. This impacts the function setMacFilterRules of the file cstecgi.cgi of the component MAC Filtering. Executing a manipulation of the argument desc can lead to memory corruption. The attack may be launched remotely. The exploit has been publicly disclosed and may be utilized.

- [https://github.com/Xernary/CVE-2026-82539](https://github.com/Xernary/CVE-2026-82539) :  ![starts](https://img.shields.io/github/stars/Xernary/CVE-2026-82539.svg) ![forks](https://img.shields.io/github/forks/Xernary/CVE-2026-82539.svg)


## CVE-2026-82222
This issue affects GiveWP: from n/a through 4.16.7.1.

- [https://github.com/dinosn/givewp-cve-2026-82222-rce-lab](https://github.com/dinosn/givewp-cve-2026-82222-rce-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/givewp-cve-2026-82222-rce-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/givewp-cve-2026-82222-rce-lab.svg)
- [https://github.com/UdinChan/cve-2026-82222-poc](https://github.com/UdinChan/cve-2026-82222-poc) :  ![starts](https://img.shields.io/github/stars/UdinChan/cve-2026-82222-poc.svg) ![forks](https://img.shields.io/github/forks/UdinChan/cve-2026-82222-poc.svg)


## CVE-2026-80724
(CVE-2026-68445) and drm/panthor (CVE-2024-53071).

- [https://github.com/suruurism/cve-writeups-and-pocs](https://github.com/suruurism/cve-writeups-and-pocs) :  ![starts](https://img.shields.io/github/stars/suruurism/cve-writeups-and-pocs.svg) ![forks](https://img.shields.io/github/forks/suruurism/cve-writeups-and-pocs.svg)


## CVE-2026-78906
 Race condition in ANGLE in Google Chrome prior to 152.0.7977.65 allowed a remote attacker to potentially execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/vxssroott/CVE-2026-78906-ChatGPT-Prompt-Injection](https://github.com/vxssroott/CVE-2026-78906-ChatGPT-Prompt-Injection) :  ![starts](https://img.shields.io/github/stars/vxssroott/CVE-2026-78906-ChatGPT-Prompt-Injection.svg) ![forks](https://img.shields.io/github/forks/vxssroott/CVE-2026-78906-ChatGPT-Prompt-Injection.svg)


## CVE-2026-78905
 Type confusion in ANGLE in Google Chrome prior to 152.0.7977.65 allowed a remote attacker to potentially execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/vxssroott/CVE-2026-78905-Facebook-Account-Takeover](https://github.com/vxssroott/CVE-2026-78905-Facebook-Account-Takeover) :  ![starts](https://img.shields.io/github/stars/vxssroott/CVE-2026-78905-Facebook-Account-Takeover.svg) ![forks](https://img.shields.io/github/forks/vxssroott/CVE-2026-78905-Facebook-Account-Takeover.svg)


## CVE-2026-78904
 Type confusion in ANGLE in Google Chrome prior to 152.0.7977.65 allowed a remote attacker to potentially execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/vxssroott/CVE-2026-78904-Digital-Dinar-Drain](https://github.com/vxssroott/CVE-2026-78904-Digital-Dinar-Drain) :  ![starts](https://img.shields.io/github/stars/vxssroott/CVE-2026-78904-Digital-Dinar-Drain.svg) ![forks](https://img.shields.io/github/forks/vxssroott/CVE-2026-78904-Digital-Dinar-Drain.svg)


## CVE-2026-78903
 Incomplete cleanup in SiteIsolation in Google Chrome prior to 152.0.7977.65 allowed a remote attacker who had compromised the renderer process to bypass site isolation via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/vxssroott/CVE-2026-78903-SWIFT-Kick-to-the-Creds](https://github.com/vxssroott/CVE-2026-78903-SWIFT-Kick-to-the-Creds) :  ![starts](https://img.shields.io/github/stars/vxssroott/CVE-2026-78903-SWIFT-Kick-to-the-Creds.svg) ![forks](https://img.shields.io/github/forks/vxssroott/CVE-2026-78903-SWIFT-Kick-to-the-Creds.svg)


## CVE-2026-76581
 The WPMU DEV Dashboard plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 5.0.1. This is due to inconsistent and ambiguous HMAC message construction between the unauthenticated `wdpsso_step1` and `wdpsso_step2` AJAX actions, where step 1 signs and discloses an unseparated concatenation of the token, state, redirect, and domain values, while step 2 verifies an unseparated concatenation that omits the domain field. This makes it possible for unauthenticated attackers, on sites connected to WPMU DEV with Hub SSO enabled and mapped to an administrator, to obtain a valid HMAC from step 1 and replay it to step 2 by moving the domain value into the redirect field, resulting in an authenticated administrator session.

- [https://github.com/HORKimhab/CVE-2026-76581](https://github.com/HORKimhab/CVE-2026-76581) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-76581.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-76581.svg)
- [https://github.com/hackersroot/CVE-2026-76581-Detector](https://github.com/hackersroot/CVE-2026-76581-Detector) :  ![starts](https://img.shields.io/github/stars/hackersroot/CVE-2026-76581-Detector.svg) ![forks](https://img.shields.io/github/forks/hackersroot/CVE-2026-76581-Detector.svg)


## CVE-2026-67363
 Joomla Extension - balbooa.com - Pre-auth Payment Amount Tampering in Balbooa Forms  2.4.3.2 - The stripeCharges and payAuthorize endpoints accept the charge total from a client-controlled request parameter and forward it to the payment gateway without recomputing it from the form's configured product prices. Neither endpoint enforces authentication or CSRF checks. An unauthenticated attacker can purchase any priced item for an arbitrary amount (e.g., $0.01), and can additionally forge line items, quantities, and shipping.

- [https://github.com/Lulztigre/cve-2026-67363-67364](https://github.com/Lulztigre/cve-2026-67363-67364) :  ![starts](https://img.shields.io/github/stars/Lulztigre/cve-2026-67363-67364.svg) ![forks](https://img.shields.io/github/forks/Lulztigre/cve-2026-67363-67364.svg)


## CVE-2026-65351
 This issue was addressed through improved state management. This issue is fixed in Safari 26.6.1, iOS 26.6.1 and iPadOS 26.6.1, macOS Tahoe 26.6.2. Processing maliciously crafted web content may lead to an unexpected Safari crash.

- [https://github.com/e4zyy/Project-CVE-2026-65351](https://github.com/e4zyy/Project-CVE-2026-65351) :  ![starts](https://img.shields.io/github/stars/e4zyy/Project-CVE-2026-65351.svg) ![forks](https://img.shields.io/github/forks/e4zyy/Project-CVE-2026-65351.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/Sec-Dan/WP2Shell-Scanner](https://github.com/Sec-Dan/WP2Shell-Scanner) :  ![starts](https://img.shields.io/github/stars/Sec-Dan/WP2Shell-Scanner.svg) ![forks](https://img.shields.io/github/forks/Sec-Dan/WP2Shell-Scanner.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/Sec-Dan/WP2Shell-Scanner](https://github.com/Sec-Dan/WP2Shell-Scanner) :  ![starts](https://img.shields.io/github/stars/Sec-Dan/WP2Shell-Scanner.svg) ![forks](https://img.shields.io/github/forks/Sec-Dan/WP2Shell-Scanner.svg)


## CVE-2026-60004
 Gitea before 1.27.1 allows remote code execution via the diffpatch API through Git hook installation.

- [https://github.com/InfoSec-DB/CVE-2026-60004-Gitea-Validator](https://github.com/InfoSec-DB/CVE-2026-60004-Gitea-Validator) :  ![starts](https://img.shields.io/github/stars/InfoSec-DB/CVE-2026-60004-Gitea-Validator.svg) ![forks](https://img.shields.io/github/forks/InfoSec-DB/CVE-2026-60004-Gitea-Validator.svg)
- [https://github.com/InfoSec-DB/CVE-2026-60004-Gitea-RCE-PoC](https://github.com/InfoSec-DB/CVE-2026-60004-Gitea-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/InfoSec-DB/CVE-2026-60004-Gitea-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/InfoSec-DB/CVE-2026-60004-Gitea-RCE-PoC.svg)


## CVE-2026-56121
 Feast before 0.63.0 contains an unsafe deserialization vulnerability that allows unauthenticated or unauthorized attackers to achieve remote code execution by sending a crafted gRPC request to the registry server. The user_defined_function.body field of an OnDemandFeatureView spec is decoded from base64 and passed to dill.loads() before any authorization check is performed, enabling attackers to embed a malicious serialized Python object with an arbitrary __reduce__ method to execute OS commands as the feast service account.

- [https://github.com/joaovicdev/EXPLOIT-CVE-2026-56121](https://github.com/joaovicdev/EXPLOIT-CVE-2026-56121) :  ![starts](https://img.shields.io/github/stars/joaovicdev/EXPLOIT-CVE-2026-56121.svg) ![forks](https://img.shields.io/github/forks/joaovicdev/EXPLOIT-CVE-2026-56121.svg)


## CVE-2026-48611
 Improper authentication checks in the OAuth implementation allow account hijacking even when OAuth is not configured or enabled leading to unauthorized access in default installations.

- [https://github.com/Ethicalgrey/phpBB-CVE-2026-48611](https://github.com/Ethicalgrey/phpBB-CVE-2026-48611) :  ![starts](https://img.shields.io/github/stars/Ethicalgrey/phpBB-CVE-2026-48611.svg) ![forks](https://img.shields.io/github/forks/Ethicalgrey/phpBB-CVE-2026-48611.svg)


## CVE-2026-45833
 A code injection vulnerability in version 0.4.17 or later of the ChromaDB Python project allows an authenticated attacker to run arbitrary code on the server by sending a malicious model repository and trust_remote_code set to true in the /api/v2/tenants/default_tenant/databases/default_database/collections/{collection_id} if they have the UPDATE_COLLECTION permission.

- [https://github.com/e4zyy/Project-CVE-2026-45833](https://github.com/e4zyy/Project-CVE-2026-45833) :  ![starts](https://img.shields.io/github/stars/e4zyy/Project-CVE-2026-45833.svg) ![forks](https://img.shields.io/github/forks/e4zyy/Project-CVE-2026-45833.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/Neccie/YellowKey-Bitlocker-CVE-2026-45585](https://github.com/Neccie/YellowKey-Bitlocker-CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/Neccie/YellowKey-Bitlocker-CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/Neccie/YellowKey-Bitlocker-CVE-2026-45585.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/ReBiliBin/ghostlock-oppo-watch3pro](https://github.com/ReBiliBin/ghostlock-oppo-watch3pro) :  ![starts](https://img.shields.io/github/stars/ReBiliBin/ghostlock-oppo-watch3pro.svg) ![forks](https://img.shields.io/github/forks/ReBiliBin/ghostlock-oppo-watch3pro.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/FranklinF25/cve-2026-42945](https://github.com/FranklinF25/cve-2026-42945) :  ![starts](https://img.shields.io/github/stars/FranklinF25/cve-2026-42945.svg) ![forks](https://img.shields.io/github/forks/FranklinF25/cve-2026-42945.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/pyroceper/copy-fail-CVE-2026-31431](https://github.com/pyroceper/copy-fail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/pyroceper/copy-fail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/pyroceper/copy-fail-CVE-2026-31431.svg)


## CVE-2026-18741
 Worksuite SaaS versions prior to 6.0.14 contains a stored cross-site scripting vulnerability in the Asset Management module that allows authenticated administrators to inject arbitrary JavaScript by entering malicious payloads into the Location and Description fields when creating a new asset. Attackers can store crafted HTML script tags in the application database that execute automatically in the browsers of any user who views the affected asset, potentially leading to session hijacking, credential theft, and unauthorized actions on behalf of authenticated users.

- [https://github.com/LindHunt/CVE-2026-18741](https://github.com/LindHunt/CVE-2026-18741) :  ![starts](https://img.shields.io/github/stars/LindHunt/CVE-2026-18741.svg) ![forks](https://img.shields.io/github/forks/LindHunt/CVE-2026-18741.svg)


## CVE-2026-12513
 The Shared Files  WordPress plugin before 1.7.67, shared-files-pro WordPress plugin before 1.7.68 do not properly sanitize a file path taken from a frontend file submission and their single-pass traversal filter is bypassable, allowing unauthenticated users to store a path that points outside the uploads directory. When the corresponding file entry is later permanently deleted, an arbitrary file on the server (such as wp-config.php) is deleted, leading to denial of service and potential site takeover.

- [https://github.com/MinhHK68/CVE-2026-12513](https://github.com/MinhHK68/CVE-2026-12513) :  ![starts](https://img.shields.io/github/stars/MinhHK68/CVE-2026-12513.svg) ![forks](https://img.shields.io/github/forks/MinhHK68/CVE-2026-12513.svg)


## CVE-2026-8452
 Memory overflow vulnerability NetScaler ADC and NetScaler Gateway leading to unpredictable or erroneous behavior and Denial of Service if the appliance is configured as a Gateway (SSL VPN, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server

- [https://github.com/maxprog-svg/CitrixBleedCVE-2026-8452-2025-5777](https://github.com/maxprog-svg/CitrixBleedCVE-2026-8452-2025-5777) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CitrixBleedCVE-2026-8452-2025-5777.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CitrixBleedCVE-2026-8452-2025-5777.svg)


## CVE-2026-7948
 Race in Chromoting in Google Chrome on Windows prior to 148.0.7778.96 allowed a local attacker to perform privilege escalation via a malicious file. (Chromium security severity: Medium)

- [https://github.com/ExploreIO/CVE-2026-79483-FastGPT-NoSQL-Injection](https://github.com/ExploreIO/CVE-2026-79483-FastGPT-NoSQL-Injection) :  ![starts](https://img.shields.io/github/stars/ExploreIO/CVE-2026-79483-FastGPT-NoSQL-Injection.svg) ![forks](https://img.shields.io/github/forks/ExploreIO/CVE-2026-79483-FastGPT-NoSQL-Injection.svg)


## CVE-2026-7474
 HashiCorp Nomad and Nomad Enterprise prior to 2.0.1 are vulnerable to code execution on the client host through a path traversal attack. This vulnerability (CVE-2026-7474) is fixed in Nomad 2.0.1, 1.11.5 and 1.10.11.

- [https://github.com/M4xSec/0day-Exploits](https://github.com/M4xSec/0day-Exploits) :  ![starts](https://img.shields.io/github/stars/M4xSec/0day-Exploits.svg) ![forks](https://img.shields.io/github/forks/M4xSec/0day-Exploits.svg)


## CVE-2026-2526
 A vulnerability was found in Wavlink WL-WN579A3 up to 20210219. This impacts the function multi_ssid of the file /cgi-bin/wireless.cgi. Performing a manipulation of the argument SSID2G2 results in command injection. The attack may be initiated remotely. The exploit has been made public and could be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/therealfraudman/cve-2026-25262-msm8909-PoC](https://github.com/therealfraudman/cve-2026-25262-msm8909-PoC) :  ![starts](https://img.shields.io/github/stars/therealfraudman/cve-2026-25262-msm8909-PoC.svg) ![forks](https://img.shields.io/github/forks/therealfraudman/cve-2026-25262-msm8909-PoC.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/JotaEspig/CVE-2025-66478-PoC-Reverse-Shell](https://github.com/JotaEspig/CVE-2025-66478-PoC-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/JotaEspig/CVE-2025-66478-PoC-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/JotaEspig/CVE-2025-66478-PoC-Reverse-Shell.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-6440
 The WooCommerce Designer Pro plugin for WordPress, used by the Pricom - Printing Company & Design Services WordPress theme, is vulnerable to arbitrary file uploads due to missing file type validation in the 'wcdp_save_canvas_design_ajax' function in all versions up to, and including, 1.9.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/katranSefa/CVE-2025-6440](https://github.com/katranSefa/CVE-2025-6440) :  ![starts](https://img.shields.io/github/stars/katranSefa/CVE-2025-6440.svg) ![forks](https://img.shields.io/github/forks/katranSefa/CVE-2025-6440.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/maxprog-svg/CitrixBleedCVE-2026-8452-2025-5777](https://github.com/maxprog-svg/CitrixBleedCVE-2026-8452-2025-5777) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CitrixBleedCVE-2026-8452-2025-5777.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CitrixBleedCVE-2026-8452-2025-5777.svg)


## CVE-2025-5548
 A vulnerability, which was classified as critical, was found in FreeFloat FTP Server 1.0. Affected is an unknown function of the component NOOP Command Handler. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/alvarosr/CVE-2025-5548](https://github.com/alvarosr/CVE-2025-5548) :  ![starts](https://img.shields.io/github/stars/alvarosr/CVE-2025-5548.svg) ![forks](https://img.shields.io/github/forks/alvarosr/CVE-2025-5548.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg)


## CVE-2024-42365
 Asterisk is an open source private branch exchange (PBX) and telephony toolkit. Prior to asterisk versions 18.24.2, 20.9.2, and 21.4.2 and certified-asterisk versions 18.9-cert11 and 20.7-cert2, an AMI user with `write=originate` may change all configuration files in the `/etc/asterisk/` directory. This occurs because they are able to curl remote files and write them to disk, but are also able to append to existing files using the `FILE` function inside the `SET` application. This issue may result in privilege escalation, remote code execution and/or blind server-side request forgery with arbitrary protocol. Asterisk versions 18.24.2, 20.9.2, and 21.4.2 and certified-asterisk versions 18.9-cert11 and 20.7-cert2 contain a fix for this issue.

- [https://github.com/Raajgupta01/htb-machine-ringdown](https://github.com/Raajgupta01/htb-machine-ringdown) :  ![starts](https://img.shields.io/github/stars/Raajgupta01/htb-machine-ringdown.svg) ![forks](https://img.shields.io/github/forks/Raajgupta01/htb-machine-ringdown.svg)


## CVE-2024-41127
 Monkeytype is a minimalistic and customizable typing test. Monkeytype is vulnerable to Poisoned Pipeline Execution through Code Injection in its ci-failure-comment.yml GitHub Workflow, enabling attackers to gain pull-requests write access. The ci-failure-comment.yml workflow is triggered when the Monkey CI workflow completes. When it runs, it will download an artifact uploaded by the triggering workflow and assign the contents of ./pr_num/pr_num.txt artifact to the steps.pr_num_reader.outputs.content WorkFlow variable. It is not validated that the variable is actually a number and later it is interpolated into a JS script allowing an attacker to change the code to be executed. This issue leads to pull-requests write access. This vulnerability is fixed in 24.30.0.

- [https://github.com/pvharmo2/gha-lab-83342297e0](https://github.com/pvharmo2/gha-lab-83342297e0) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-83342297e0.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-83342297e0.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe](https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg)
- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2020-36762
 A vulnerability was found in ONS Digital RAS Collection Instrument up to 2.0.27 and classified as critical. Affected by this issue is the function jobs of the file .github/workflows/comment.yml. The manipulation of the argument $COMMENT_BODY leads to os command injection. Upgrading to version 2.0.28 is able to address this issue. The name of the patch is dcaad2540f7d50c512ff2e031d3778dd9337db2b. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-234248.

- [https://github.com/pvharmo2/gha-lab-e4a85583c3](https://github.com/pvharmo2/gha-lab-e4a85583c3) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-e4a85583c3.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-e4a85583c3.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/Vaibhav91one/drupalgeddon2-cve-lab](https://github.com/Vaibhav91one/drupalgeddon2-cve-lab) :  ![starts](https://img.shields.io/github/stars/Vaibhav91one/drupalgeddon2-cve-lab.svg) ![forks](https://img.shields.io/github/forks/Vaibhav91one/drupalgeddon2-cve-lab.svg)


## CVE-2017-1000251
 The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.

- [https://github.com/ahmedalouane95-cell/Simulation-d-attaque-BlueBorne-sur-v-hicule-connect-](https://github.com/ahmedalouane95-cell/Simulation-d-attaque-BlueBorne-sur-v-hicule-connect-) :  ![starts](https://img.shields.io/github/stars/ahmedalouane95-cell/Simulation-d-attaque-BlueBorne-sur-v-hicule-connect-.svg) ![forks](https://img.shields.io/github/forks/ahmedalouane95-cell/Simulation-d-attaque-BlueBorne-sur-v-hicule-connect-.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/Vaibhav91one/shellshock-cve-lab](https://github.com/Vaibhav91one/shellshock-cve-lab) :  ![starts](https://img.shields.io/github/stars/Vaibhav91one/shellshock-cve-lab.svg) ![forks](https://img.shields.io/github/forks/Vaibhav91one/shellshock-cve-lab.svg)

