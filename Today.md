# Update 2026-08-16
## CVE-2026-73673
 Netis NC63 router firmware V3.0.0.3327 contains an unauthenticated firmware update vulnerability that allows unauthenticated attackers to submit unsigned firmware images by exploiting a missing authentication enforcement flaw in the Boa web server and netis.cgi CGI dispatcher. Attackers can send a multipart POST request to /cgi-bin/upload_fw.cgi without a valid session cookie, bypassing authentication because Boa grants access to any path containing '.cgi' regardless of cookie validation, and netis.cgi reads but does not enforce the authentication state before invoking the firmware update handler, which accepts images validated only by a forgeable additive checksum and static product strings rather than a cryptographic signature, potentially enabling persistent router compromise.

- [https://github.com/ozcanpng/CVE-2026-73673](https://github.com/ozcanpng/CVE-2026-73673) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2026-73673.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2026-73673.svg)


## CVE-2026-72550
 An SQL injection vulnerability in Friendica through the 2026.08-dev branch allows unauthenticated remote attackers to execute arbitrary SQL statements via the photo-view order parameter. The parameter is concatenated unescaped into a SHOW COLUMNS query via a bare PDO::query() call, enabling stacked statement injection. An unauthenticated attacker can read, modify, or delete the entire database.

- [https://github.com/abdugafforov-bobur/CVE-2026-72550-poc](https://github.com/abdugafforov-bobur/CVE-2026-72550-poc) :  ![starts](https://img.shields.io/github/stars/abdugafforov-bobur/CVE-2026-72550-poc.svg) ![forks](https://img.shields.io/github/forks/abdugafforov-bobur/CVE-2026-72550-poc.svg)


## CVE-2026-64600
sequence counter changes across the ILOCK cycle.

- [https://github.com/0xSec1/CVE-2026-64600-RefluXFS-PoC](https://github.com/0xSec1/CVE-2026-64600-RefluXFS-PoC) :  ![starts](https://img.shields.io/github/stars/0xSec1/CVE-2026-64600-RefluXFS-PoC.svg) ![forks](https://img.shields.io/github/forks/0xSec1/CVE-2026-64600-RefluXFS-PoC.svg)


## CVE-2026-54433
 In Roundcube Webmail before 1.6.17 and 1.7.x before 1.7.2, there is Stored Cross-Site Scripting (XSS) via a crafted plain-text email message. The attacker-controlled JavaScript executes within the victim's authenticated session simply by opening or previewing the message (zero-click).

- [https://github.com/aramosf/CVE-2026-54433](https://github.com/aramosf/CVE-2026-54433) :  ![starts](https://img.shields.io/github/stars/aramosf/CVE-2026-54433.svg) ![forks](https://img.shields.io/github/forks/aramosf/CVE-2026-54433.svg)


## CVE-2026-53365
but was pre-existing.

- [https://github.com/HORKimhab/CVE-2026-53365](https://github.com/HORKimhab/CVE-2026-53365) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-53365.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-53365.svg)


## CVE-2026-52715
 Unauthenticated SQL Injection in GEO my WordPress = 4.5.5 versions.

- [https://github.com/686f6c61/POC-GeoLeak-CVE-2026-52715](https://github.com/686f6c61/POC-GeoLeak-CVE-2026-52715) :  ![starts](https://img.shields.io/github/stars/686f6c61/POC-GeoLeak-CVE-2026-52715.svg) ![forks](https://img.shields.io/github/forks/686f6c61/POC-GeoLeak-CVE-2026-52715.svg)


## CVE-2026-46300
bytes into @to's linear data rather than transferring frag descriptors.

- [https://github.com/Kentox493/CVE-2026-46300_Fragnesia](https://github.com/Kentox493/CVE-2026-46300_Fragnesia) :  ![starts](https://img.shields.io/github/stars/Kentox493/CVE-2026-46300_Fragnesia.svg) ![forks](https://img.shields.io/github/forks/Kentox493/CVE-2026-46300_Fragnesia.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/hmascs/KSuRoot](https://github.com/hmascs/KSuRoot) :  ![starts](https://img.shields.io/github/stars/hmascs/KSuRoot.svg) ![forks](https://img.shields.io/github/forks/hmascs/KSuRoot.svg)
- [https://github.com/Bugel/cve-2026-43499-m3q-azf1](https://github.com/Bugel/cve-2026-43499-m3q-azf1) :  ![starts](https://img.shields.io/github/stars/Bugel/cve-2026-43499-m3q-azf1.svg) ![forks](https://img.shields.io/github/forks/Bugel/cve-2026-43499-m3q-azf1.svg)
- [https://github.com/fusiondrive/CVE-2026-43499-ZFOLD4](https://github.com/fusiondrive/CVE-2026-43499-ZFOLD4) :  ![starts](https://img.shields.io/github/stars/fusiondrive/CVE-2026-43499-ZFOLD4.svg) ![forks](https://img.shields.io/github/forks/fusiondrive/CVE-2026-43499-ZFOLD4.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Kentox493/CVE-2026-42945_NginxRift](https://github.com/Kentox493/CVE-2026-42945_NginxRift) :  ![starts](https://img.shields.io/github/stars/Kentox493/CVE-2026-42945_NginxRift.svg) ![forks](https://img.shields.io/github/forks/Kentox493/CVE-2026-42945_NginxRift.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Leeyoonjoo/CVE-2026-42533](https://github.com/Leeyoonjoo/CVE-2026-42533) :  ![starts](https://img.shields.io/github/stars/Leeyoonjoo/CVE-2026-42533.svg) ![forks](https://img.shields.io/github/forks/Leeyoonjoo/CVE-2026-42533.svg)


## CVE-2026-31816
 Budibase is a low code platform for creating internal tools, workflows, and admin panels. In 3.31.4 and earlier, the Budibase server's authorized() middleware that protects every server-side API endpoint can be completely bypassed by appending a webhook path pattern to the query string of any request. The isWebhookEndpoint() function uses an unanchored regex that tests against ctx.request.url, which in Koa includes the full URL with query parameters. When the regex matches, the authorized() middleware immediately calls return next(), skipping all authentication, authorization, role checks, and CSRF protection. This means a completely unauthenticated, remote attacker can access any server-side API endpoint by simply appending ?/webhooks/trigger (or any webhook pattern variant) to the URL.

- [https://github.com/K3ysTr0K3R/CVE-2026-31816](https://github.com/K3ysTr0K3R/CVE-2026-31816) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-31816.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-31816.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/nisec-eric/cve-2026-31431](https://github.com/nisec-eric/cve-2026-31431) :  ![starts](https://img.shields.io/github/stars/nisec-eric/cve-2026-31431.svg) ![forks](https://img.shields.io/github/forks/nisec-eric/cve-2026-31431.svg)


## CVE-2026-27912
 Improper authorization in Windows Kerberos allows an authorized attacker to elevate privileges over an adjacent network.

- [https://github.com/oxstussz-eng/Kerberos-CVE-2026-27912](https://github.com/oxstussz-eng/Kerberos-CVE-2026-27912) :  ![starts](https://img.shields.io/github/stars/oxstussz-eng/Kerberos-CVE-2026-27912.svg) ![forks](https://img.shields.io/github/forks/oxstussz-eng/Kerberos-CVE-2026-27912.svg)


## CVE-2026-13610
 The KiviCare  WordPress plugin before 4.5.2 does not restrict the roles assignable through its unauthenticated registration endpoint, allowing unauthenticated attackers to create an active, privileged clinic-staff (doctor) account with full access to patient records, billing and clinic data.

- [https://github.com/ghostpels/CVE-2026-13610](https://github.com/ghostpels/CVE-2026-13610) :  ![starts](https://img.shields.io/github/stars/ghostpels/CVE-2026-13610.svg) ![forks](https://img.shields.io/github/forks/ghostpels/CVE-2026-13610.svg)


## CVE-2026-8452
 Memory overflow vulnerability NetScaler ADC and NetScaler Gateway leading to unpredictable or erroneous behavior and Denial of Service if the appliance is configured as a Gateway (SSL VPN, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server

- [https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-PreAuth-RCE-CVE-2026-8452](https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-PreAuth-RCE-CVE-2026-8452) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-PreAuth-RCE-CVE-2026-8452.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-PreAuth-RCE-CVE-2026-8452.svg)


## CVE-2026-5435
 The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library version 2.2 and newer fail to enforce the caller-supplied buffer length, and can result in an out-of-bounds write when printing TSIG records.

- [https://github.com/KovachVL/CVE-2026-54356](https://github.com/KovachVL/CVE-2026-54356) :  ![starts](https://img.shields.io/github/stars/KovachVL/CVE-2026-54356.svg) ![forks](https://img.shields.io/github/forks/KovachVL/CVE-2026-54356.svg)


## CVE-2025-70559
 pdfminer.six before 20251230 contains an insecure deserialization vulnerability in the CMap loading mechanism. The library uses Python pickle to deserialize CMap cache files without validation. An attacker with the ability to place a malicious pickle file in a location accessible to the application can trigger arbitrary code execution or privilege escalation when the file is loaded by a trusted process. This is caused by an incomplete patch to CVE-2025-64512.

- [https://github.com/isukasanuj/CVE-2025-70559](https://github.com/isukasanuj/CVE-2025-70559) :  ![starts](https://img.shields.io/github/stars/isukasanuj/CVE-2025-70559.svg) ![forks](https://img.shields.io/github/forks/isukasanuj/CVE-2025-70559.svg)


## CVE-2025-68472
 MindsDB is a platform for building artificial intelligence from enterprise data. Prior to version 25.11.1, an unauthenticated path traversal in the file upload API lets any caller read arbitrary files from the server filesystem and move them into MindsDB’s storage, exposing sensitive data. The PUT handler in file.py directly joins user-controlled data into a filesystem path when the request body is JSON and source_type is not "url". Only multipart uploads and URL-sourced uploads receive sanitization; JSON uploads lack any call to clear_filename or equivalent checks. This vulnerability is fixed in 25.11.1.

- [https://github.com/ExploreUnknowed/CVE-2025-68472](https://github.com/ExploreUnknowed/CVE-2025-68472) :  ![starts](https://img.shields.io/github/stars/ExploreUnknowed/CVE-2025-68472.svg) ![forks](https://img.shields.io/github/forks/ExploreUnknowed/CVE-2025-68472.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/Liam-Worsley/CVE-2025-32433-PoC-Analysis](https://github.com/Liam-Worsley/CVE-2025-32433-PoC-Analysis) :  ![starts](https://img.shields.io/github/stars/Liam-Worsley/CVE-2025-32433-PoC-Analysis.svg) ![forks](https://img.shields.io/github/forks/Liam-Worsley/CVE-2025-32433-PoC-Analysis.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/0xPb1/Next.js-CVE-2025-29927](https://github.com/0xPb1/Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPb1/Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPb1/Next.js-CVE-2025-29927.svg)

