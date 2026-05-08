# Update 2026-05-08
## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/bughunt4me/cpanelCVE-2026-41940](https://github.com/bughunt4me/cpanelCVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/bughunt4me/cpanelCVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/bughunt4me/cpanelCVE-2026-41940.svg)
- [https://github.com/Andrei-Dr/cpanel-cve-2026-41940-ioc](https://github.com/Andrei-Dr/cpanel-cve-2026-41940-ioc) :  ![starts](https://img.shields.io/github/stars/Andrei-Dr/cpanel-cve-2026-41940-ioc.svg) ![forks](https://img.shields.io/github/forks/Andrei-Dr/cpanel-cve-2026-41940-ioc.svg)
- [https://github.com/Ap0dexMe0/CVE-2026-41940](https://github.com/Ap0dexMe0/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/Ap0dexMe0/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/Ap0dexMe0/CVE-2026-41940.svg)
- [https://github.com/murrez/CVE-2026-41940](https://github.com/murrez/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-41940.svg)
- [https://github.com/OhmGun/whmxploit---CVE-2026-41940](https://github.com/OhmGun/whmxploit---CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/OhmGun/whmxploit---CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/OhmGun/whmxploit---CVE-2026-41940.svg)
- [https://github.com/Defacto-ridgepole254/CVE-2026-41940-Exploit-PoC](https://github.com/Defacto-ridgepole254/CVE-2026-41940-Exploit-PoC) :  ![starts](https://img.shields.io/github/stars/Defacto-ridgepole254/CVE-2026-41940-Exploit-PoC.svg) ![forks](https://img.shields.io/github/forks/Defacto-ridgepole254/CVE-2026-41940-Exploit-PoC.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/Kowntaewook/CVE-2026-41651-analysis](https://github.com/Kowntaewook/CVE-2026-41651-analysis) :  ![starts](https://img.shields.io/github/stars/Kowntaewook/CVE-2026-41651-analysis.svg) ![forks](https://img.shields.io/github/forks/Kowntaewook/CVE-2026-41651-analysis.svg)


## CVE-2026-39363
 Vite is a frontend tooling framework for JavaScript. From 6.0.0 to before 6.4.2, 7.3.2, and 8.0.5, if it is possible to connect to the Vite dev server’s WebSocket without an Origin header, an attacker can invoke fetchModule via the custom WebSocket event vite:invoke and combine file://... with ?raw (or ?inline) to retrieve the contents of arbitrary files on the server as a JavaScript string (e.g., export default "..."). The access control enforced in the HTTP request path (such as server.fs.allow) is not applied to this WebSocket-based execution path. This vulnerability is fixed in 6.4.2, 7.3.2, and 8.0.5.

- [https://github.com/f4s1on/CVE-2026-39363](https://github.com/f4s1on/CVE-2026-39363) :  ![starts](https://img.shields.io/github/stars/f4s1on/CVE-2026-39363.svg) ![forks](https://img.shields.io/github/forks/f4s1on/CVE-2026-39363.svg)


## CVE-2026-36358
 Cross Site Scripting vulnerability in Juzaweb CMS v.5.0.0 allows a remote attacker via execute arbitrary code via a crafted script to the Add Banner Ads function

- [https://github.com/yuhuamiao/CVE-2026-36358](https://github.com/yuhuamiao/CVE-2026-36358) :  ![starts](https://img.shields.io/github/stars/yuhuamiao/CVE-2026-36358.svg) ![forks](https://img.shields.io/github/forks/yuhuamiao/CVE-2026-36358.svg)


## CVE-2026-33324
 SQLBot is an intelligent Text-to-SQL system based on large language models and RAG. In versions 1.7.0 and earlier, the Text2SQL chat interface is vulnerable to prompt injection. The user-provided question parameter is directly concatenated into the LLM prompt without filtering or escaping, and the SQL extracted from the LLM response is executed against the database without validation or sanitization. An authenticated attacker can craft a malicious question to manipulate the LLM into generating and executing arbitrary SQL statements. When connected to a PostgreSQL data source, this can lead to remote code execution via COPY FROM PROGRAM. This issue has been fixed in version 1.7.1.

- [https://github.com/CryptReaper12/CVE-2026-33324](https://github.com/CryptReaper12/CVE-2026-33324) :  ![starts](https://img.shields.io/github/stars/CryptReaper12/CVE-2026-33324.svg) ![forks](https://img.shields.io/github/forks/CryptReaper12/CVE-2026-33324.svg)


## CVE-2026-32710
 MariaDB server is a community developed fork of MySQL server. An authenticated user can crash MariaDB versions 11.4 before 11.4.10 and 11.8 before 11.8.6 via a bug in JSON_SCHEMA_VALID() function. Under certain conditions it might be possible to turn the crash into a remote code execution. These conditions require tight control over memory layout which is generally only attainable in a lab environment. This issue is fixed in MariaDB 11.4.10, MariaDB 11.8.6, and MariaDB 12.2.2.

- [https://github.com/dinosn/CVE-2026-32710](https://github.com/dinosn/CVE-2026-32710) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-32710.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-32710.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/Smarttfoxx/copyfail](https://github.com/Smarttfoxx/copyfail) :  ![starts](https://img.shields.io/github/stars/Smarttfoxx/copyfail.svg) ![forks](https://img.shields.io/github/forks/Smarttfoxx/copyfail.svg)
- [https://github.com/AdityaBhatt3010/CVE-2026-31431](https://github.com/AdityaBhatt3010/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2026-31431.svg)
- [https://github.com/AliHzSec/CVE-2026-31431](https://github.com/AliHzSec/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/AliHzSec/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/AliHzSec/CVE-2026-31431.svg)
- [https://github.com/darioomatos/cve-2026-31431-copyfail](https://github.com/darioomatos/cve-2026-31431-copyfail) :  ![starts](https://img.shields.io/github/stars/darioomatos/cve-2026-31431-copyfail.svg) ![forks](https://img.shields.io/github/forks/darioomatos/cve-2026-31431-copyfail.svg)
- [https://github.com/pascal-gujer/CVE-2026-31431](https://github.com/pascal-gujer/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/pascal-gujer/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/pascal-gujer/CVE-2026-31431.svg)
- [https://github.com/DENNISDGR/CVE-2026-31431-poc](https://github.com/DENNISDGR/CVE-2026-31431-poc) :  ![starts](https://img.shields.io/github/stars/DENNISDGR/CVE-2026-31431-poc.svg) ![forks](https://img.shields.io/github/forks/DENNISDGR/CVE-2026-31431-poc.svg)
- [https://github.com/zenzue/CVE-2026-31431-Checker-Mitigator](https://github.com/zenzue/CVE-2026-31431-Checker-Mitigator) :  ![starts](https://img.shields.io/github/stars/zenzue/CVE-2026-31431-Checker-Mitigator.svg) ![forks](https://img.shields.io/github/forks/zenzue/CVE-2026-31431-Checker-Mitigator.svg)
- [https://github.com/Phalanx-CCS/Copy-Fail](https://github.com/Phalanx-CCS/Copy-Fail) :  ![starts](https://img.shields.io/github/stars/Phalanx-CCS/Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/Phalanx-CCS/Copy-Fail.svg)


## CVE-2026-27960
 OpenCTI is an open source platform for managing cyber threat intelligence knowledge and observables. In versions 6.6.0 through 6.9.12, there is a privilege escalation vulnerability that can be exploited by unauthenticated attackers to query the API as any existing user, including the default admin account. This issue has been fixed in version 6.9.13. As a workaround, the default admin can be disabled using the `APP__ADMIN__EXTERNALLY_MANAGED` configuration.

- [https://github.com/ByteWraith1/CVE-2026-27960](https://github.com/ByteWraith1/CVE-2026-27960) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-27960.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-27960.svg)


## CVE-2026-27944
 Nginx UI is a web user interface for the Nginx web server. Prior to version 2.3.3, the /api/backup endpoint is accessible without authentication and discloses the encryption keys required to decrypt the backup in the X-Backup-Security response header. This allows an unauthenticated attacker to download a full system backup containing sensitive data (user credentials, session tokens, SSL private keys, Nginx configurations) and decrypt it immediately. This issue has been patched in version 2.3.3.

- [https://github.com/jake-young-dev/CVE-2026-27944](https://github.com/jake-young-dev/CVE-2026-27944) :  ![starts](https://img.shields.io/github/stars/jake-young-dev/CVE-2026-27944.svg) ![forks](https://img.shields.io/github/forks/jake-young-dev/CVE-2026-27944.svg)


## CVE-2026-26336
 Hyland Alfresco allows unauthenticated attackers to read arbitrary files from protected directories (like WEB-INF) via the "/share/page/resource/" endpoint, thus leading to the disclosure of sensitive configuration files.

- [https://github.com/CEAarab/CVE-2026-26336-PoC](https://github.com/CEAarab/CVE-2026-26336-PoC) :  ![starts](https://img.shields.io/github/stars/CEAarab/CVE-2026-26336-PoC.svg) ![forks](https://img.shields.io/github/forks/CEAarab/CVE-2026-26336-PoC.svg)


## CVE-2026-23918
Users are recommended to upgrade to version 2.4.67, which fixes the issue.

- [https://github.com/rhasan-com/CVE-2026-23918](https://github.com/rhasan-com/CVE-2026-23918) :  ![starts](https://img.shields.io/github/stars/rhasan-com/CVE-2026-23918.svg) ![forks](https://img.shields.io/github/forks/rhasan-com/CVE-2026-23918.svg)
- [https://github.com/xeloxa/CVE-2026-23918-Apache-H2-PoC](https://github.com/xeloxa/CVE-2026-23918-Apache-H2-PoC) :  ![starts](https://img.shields.io/github/stars/xeloxa/CVE-2026-23918-Apache-H2-PoC.svg) ![forks](https://img.shields.io/github/forks/xeloxa/CVE-2026-23918-Apache-H2-PoC.svg)
- [https://github.com/seguridadentrerios/CVE-2026-23918](https://github.com/seguridadentrerios/CVE-2026-23918) :  ![starts](https://img.shields.io/github/stars/seguridadentrerios/CVE-2026-23918.svg) ![forks](https://img.shields.io/github/forks/seguridadentrerios/CVE-2026-23918.svg)
- [https://github.com/hackervlogofficial/CVE-2026-23918](https://github.com/hackervlogofficial/CVE-2026-23918) :  ![starts](https://img.shields.io/github/stars/hackervlogofficial/CVE-2026-23918.svg) ![forks](https://img.shields.io/github/forks/hackervlogofficial/CVE-2026-23918.svg)
- [https://github.com/CYFARE/CVE-2026-23918-Apache-HTTP-Server-DoubleFree-PoC](https://github.com/CYFARE/CVE-2026-23918-Apache-HTTP-Server-DoubleFree-PoC) :  ![starts](https://img.shields.io/github/stars/CYFARE/CVE-2026-23918-Apache-HTTP-Server-DoubleFree-PoC.svg) ![forks](https://img.shields.io/github/forks/CYFARE/CVE-2026-23918-Apache-HTTP-Server-DoubleFree-PoC.svg)
- [https://github.com/aa022/CVE-2026-23918-Passive-Audit](https://github.com/aa022/CVE-2026-23918-Passive-Audit) :  ![starts](https://img.shields.io/github/stars/aa022/CVE-2026-23918-Passive-Audit.svg) ![forks](https://img.shields.io/github/forks/aa022/CVE-2026-23918-Passive-Audit.svg)


## CVE-2026-7720
 A weakness has been identified in Totolink WA300 5.2cu.7112_B20190227. The impacted element is the function setLanguageCfg of the file /cgi-bin/cstecgi.cgi of the component POST Request Handler. This manipulation of the argument langType causes command injection. Remote exploitation of the attack is possible. The exploit has been made available to the public and could be used for attacks.

- [https://github.com/davidrxchester/CVE-2026-7020](https://github.com/davidrxchester/CVE-2026-7020) :  ![starts](https://img.shields.io/github/stars/davidrxchester/CVE-2026-7020.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/CVE-2026-7020.svg)


## CVE-2026-7411
 In Eclipse BaSyx Java Server SDK versions prior to 2.0.0-milestone-10, inadequate path normalization in the Submodel HTTP API allows an unauthenticated remote attacker to perform a path traversal attack. By supplying a maliciously crafted fileName parameter during a file upload operation, an attacker can bypass intended storage boundaries and write arbitrary files to any location on the host filesystem accessible by the Java process. This can lead to Remote Code Execution (RCE) and complete system compromise.

- [https://github.com/CryptReaper12/CVE-2026-7411](https://github.com/CryptReaper12/CVE-2026-7411) :  ![starts](https://img.shields.io/github/stars/CryptReaper12/CVE-2026-7411.svg) ![forks](https://img.shields.io/github/forks/CryptReaper12/CVE-2026-7411.svg)


## CVE-2026-7020
 A security flaw has been discovered in Ollama up to 0.20.2. This affects the function digestToPath of the file x/imagegen/transfer/transfer.go of the component Tensor Model Transfer Handler. The manipulation of the argument digest results in path traversal. The attack may be performed from remote. This attack is characterized by high complexity. The exploitability is reported as difficult. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/davidrxchester/CVE-2026-7020](https://github.com/davidrxchester/CVE-2026-7020) :  ![starts](https://img.shields.io/github/stars/davidrxchester/CVE-2026-7020.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/CVE-2026-7020.svg)


## CVE-2026-4190
 A vulnerability was detected in JawherKl node-api-postgres up to 2.5. This impacts the function User.getAll of the file models/user.js. The manipulation of the argument sort results in sql injection. The attack can be executed remotely. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/Christbowel/CVE-2026-41900-POC](https://github.com/Christbowel/CVE-2026-41900-POC) :  ![starts](https://img.shields.io/github/stars/Christbowel/CVE-2026-41900-POC.svg) ![forks](https://img.shields.io/github/forks/Christbowel/CVE-2026-41900-POC.svg)


## CVE-2026-2441
 Use after free in CSS in Google Chrome prior to 145.0.7632.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/MartinaStarone/CVE-2026-2441](https://github.com/MartinaStarone/CVE-2026-2441) :  ![starts](https://img.shields.io/github/stars/MartinaStarone/CVE-2026-2441.svg) ![forks](https://img.shields.io/github/forks/MartinaStarone/CVE-2026-2441.svg)


## CVE-2026-0300
Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.

- [https://github.com/qassam-315/PAN-OS-User-ID-Buffer-Overflow-PoC](https://github.com/qassam-315/PAN-OS-User-ID-Buffer-Overflow-PoC) :  ![starts](https://img.shields.io/github/stars/qassam-315/PAN-OS-User-ID-Buffer-Overflow-PoC.svg) ![forks](https://img.shields.io/github/forks/qassam-315/PAN-OS-User-ID-Buffer-Overflow-PoC.svg)
- [https://github.com/mr-r3b00t/CVE-2026-0300](https://github.com/mr-r3b00t/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2026-0300.svg)
- [https://github.com/p3Nt3st3r-sTAr/CVE-2026-0300-POC](https://github.com/p3Nt3st3r-sTAr/CVE-2026-0300-POC) :  ![starts](https://img.shields.io/github/stars/p3Nt3st3r-sTAr/CVE-2026-0300-POC.svg) ![forks](https://img.shields.io/github/forks/p3Nt3st3r-sTAr/CVE-2026-0300-POC.svg)
- [https://github.com/0xBlackash/CVE-2026-0300](https://github.com/0xBlackash/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-0300.svg)
- [https://github.com/shizuku198411/CVE-2026-0300](https://github.com/shizuku198411/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/shizuku198411/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/shizuku198411/CVE-2026-0300.svg)
- [https://github.com/bannned-bit/CVE-2026-0300-PANOS](https://github.com/bannned-bit/CVE-2026-0300-PANOS) :  ![starts](https://img.shields.io/github/stars/bannned-bit/CVE-2026-0300-PANOS.svg) ![forks](https://img.shields.io/github/forks/bannned-bit/CVE-2026-0300-PANOS.svg)
- [https://github.com/TailwindRG/cve-2026-0300-audit](https://github.com/TailwindRG/cve-2026-0300-audit) :  ![starts](https://img.shields.io/github/stars/TailwindRG/cve-2026-0300-audit.svg) ![forks](https://img.shields.io/github/forks/TailwindRG/cve-2026-0300-audit.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/devtint/CVE-2026-0073](https://github.com/devtint/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/devtint/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/devtint/CVE-2026-0073.svg)
- [https://github.com/adityatelange/poc-CVE-2026-0073](https://github.com/adityatelange/poc-CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/adityatelange/poc-CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/adityatelange/poc-CVE-2026-0073.svg)
- [https://github.com/MartinPSDev/CVE-2026-0073-Android-ADBD-bypass-POC](https://github.com/MartinPSDev/CVE-2026-0073-Android-ADBD-bypass-POC) :  ![starts](https://img.shields.io/github/stars/MartinPSDev/CVE-2026-0073-Android-ADBD-bypass-POC.svg) ![forks](https://img.shields.io/github/forks/MartinPSDev/CVE-2026-0073-Android-ADBD-bypass-POC.svg)
- [https://github.com/ByteWraith1/CVE-2026-0073](https://github.com/ByteWraith1/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-0073.svg)
- [https://github.com/CryptReaper12/CVE-2026-0073](https://github.com/CryptReaper12/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/CryptReaper12/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/CryptReaper12/CVE-2026-0073.svg)


## CVE-2025-70149
 CodeAstro Membership Management System 1.0 is vulnerable to SQL Injection in print_membership_card.php via the ID parameter.

- [https://github.com/Anusha-Khan29/CVE-2025-70149-SQL-Injection](https://github.com/Anusha-Khan29/CVE-2025-70149-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/Anusha-Khan29/CVE-2025-70149-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/Anusha-Khan29/CVE-2025-70149-SQL-Injection.svg)


## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/HarisAidhin/Poc_CVE-2025-68645](https://github.com/HarisAidhin/Poc_CVE-2025-68645) :  ![starts](https://img.shields.io/github/stars/HarisAidhin/Poc_CVE-2025-68645.svg) ![forks](https://img.shields.io/github/forks/HarisAidhin/Poc_CVE-2025-68645.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/DAEMON-404/pearlescent](https://github.com/DAEMON-404/pearlescent) :  ![starts](https://img.shields.io/github/stars/DAEMON-404/pearlescent.svg) ![forks](https://img.shields.io/github/forks/DAEMON-404/pearlescent.svg)


## CVE-2025-4632
 Improper limitation of a pathname to a restricted directory vulnerability in Samsung MagicINFO 9 Server version before 21.1052 allows attackers to write arbitrary file as system authority.

- [https://github.com/digitalsurgn/CVE-2025-4632_POC](https://github.com/digitalsurgn/CVE-2025-4632_POC) :  ![starts](https://img.shields.io/github/stars/digitalsurgn/CVE-2025-4632_POC.svg) ![forks](https://img.shields.io/github/forks/digitalsurgn/CVE-2025-4632_POC.svg)


## CVE-2025-4321
 In a Bluetooth device, using RS9116-WiseConnect SDK experiences a Denial of Service, if it receives malformed L2CAP packets, only hard reset will bring the device to normal operation

- [https://github.com/Villain-arc-begins/Patch-management-](https://github.com/Villain-arc-begins/Patch-management-) :  ![starts](https://img.shields.io/github/stars/Villain-arc-begins/Patch-management-.svg) ![forks](https://img.shields.io/github/forks/Villain-arc-begins/Patch-management-.svg)


## CVE-2025-0133
For GlobalProtect users with Clientless VPN enabled, there is a limited impact on confidentiality due to inherent risks of Clientless VPN that facilitate credential theft. You can read more about this risk in the informational bulletin  PAN-SA-2025-0005 https://security.paloaltonetworks.com/PAN-SA-2025-0005   https://security.paloaltonetworks.com/PAN-SA-2025-0005 . There is no impact to confidentiality for GlobalProtect users if you did not enable (or you disable) Clientless VPN.

- [https://github.com/cruxN3T/CVE-2025-0133](https://github.com/cruxN3T/CVE-2025-0133) :  ![starts](https://img.shields.io/github/stars/cruxN3T/CVE-2025-0133.svg) ![forks](https://img.shields.io/github/forks/cruxN3T/CVE-2025-0133.svg)


## CVE-2024-35133
 IBM Security Verify Access 10.0.0 through 10.0.8 OIDC Provider could allow a remote authenticated attacker to conduct phishing attacks, using an open redirect attack. By persuading a victim to visit a specially crafted Web site, a remote attacker could exploit this vulnerability to spoof the URL displayed to redirect a user to a malicious Web site that would appear to be trusted. This could allow the attacker to obtain highly sensitive information or conduct further attacks against the victim.

- [https://github.com/Ozozuz/IBM-Security-Verify-oAuth_Token_Steal-CVE-2024-35133](https://github.com/Ozozuz/IBM-Security-Verify-oAuth_Token_Steal-CVE-2024-35133) :  ![starts](https://img.shields.io/github/stars/Ozozuz/IBM-Security-Verify-oAuth_Token_Steal-CVE-2024-35133.svg) ![forks](https://img.shields.io/github/forks/Ozozuz/IBM-Security-Verify-oAuth_Token_Steal-CVE-2024-35133.svg)


## CVE-2024-30051
 Windows DWM Core Library Elevation of Privilege Vulnerability

- [https://github.com/devianntsec/CVE-2024-30051](https://github.com/devianntsec/CVE-2024-30051) :  ![starts](https://img.shields.io/github/stars/devianntsec/CVE-2024-30051.svg) ![forks](https://img.shields.io/github/forks/devianntsec/CVE-2024-30051.svg)


## CVE-2024-1086
We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.

- [https://github.com/garatc/bitpixie](https://github.com/garatc/bitpixie) :  ![starts](https://img.shields.io/github/stars/garatc/bitpixie.svg) ![forks](https://img.shields.io/github/forks/garatc/bitpixie.svg)


## CVE-2023-22527
Most recent supported versions of Confluence Data Center and Server are not affected by this vulnerability as it was ultimately mitigated during regular version updates. However, Atlassian recommends that customers take care to install the latest version to protect their instances from non-critical vulnerabilities outlined in Atlassian’s January Security Bulletin.

- [https://github.com/ycseo-git/CVE-2023-22527](https://github.com/ycseo-git/CVE-2023-22527) :  ![starts](https://img.shields.io/github/stars/ycseo-git/CVE-2023-22527.svg) ![forks](https://img.shields.io/github/forks/ycseo-git/CVE-2023-22527.svg)


## CVE-2023-21563
 BitLocker Security Feature Bypass Vulnerability

- [https://github.com/garatc/bitpixie](https://github.com/garatc/bitpixie) :  ![starts](https://img.shields.io/github/stars/garatc/bitpixie.svg) ![forks](https://img.shields.io/github/forks/garatc/bitpixie.svg)


## CVE-2022-0739
 The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied POST data before it is used in a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to unauthenticated users), leading to an unauthenticated SQL Injection

- [https://github.com/DAEMON-404/HTB-Lab-Writeups](https://github.com/DAEMON-404/HTB-Lab-Writeups) :  ![starts](https://img.shields.io/github/stars/DAEMON-404/HTB-Lab-Writeups.svg) ![forks](https://img.shields.io/github/forks/DAEMON-404/HTB-Lab-Writeups.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/DAEMON-404/HTB-Lab-Writeups](https://github.com/DAEMON-404/HTB-Lab-Writeups) :  ![starts](https://img.shields.io/github/stars/DAEMON-404/HTB-Lab-Writeups.svg) ![forks](https://img.shields.io/github/forks/DAEMON-404/HTB-Lab-Writeups.svg)

