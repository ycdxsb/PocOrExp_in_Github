# Update 2026-10-18
## CVE-2026-111444
 Wheels through 4.1.2 allows SQL injection on MySQL/MariaDB with backslash escaping enabled (NO_BACKSLASH_ESCAPES absent) when an application supplies request data to inline-literal paths. These include opt-in parameterize=false queries and IN lists, and positions in developer-written where strings that the parser does not bind, such as BETWEEN bounds, function arguments and LIKE ESCAPE literals. Doubling single quotes without accounting for backslash escapes allows a value to alter the query. Bound paths are not affected; whereBetween() is bound from 4.1.2. This is fixed in 4.2.0.

- [https://github.com/Syscallh00k/CVE-2026-111444](https://github.com/Syscallh00k/CVE-2026-111444) :  ![starts](https://img.shields.io/github/stars/Syscallh00k/CVE-2026-111444.svg) ![forks](https://img.shields.io/github/forks/Syscallh00k/CVE-2026-111444.svg)


## CVE-2026-111389
 Frappe HRMS 14.x before 14.38.2, 15.x before 15.64.0, and 16.x before 16.18.0 contains a SQL injection vulnerability in some endpoints caused by missing input validation. Any authenticated attacker, including a low-privilege account, can send specially crafted requests to these endpoints to extract sensitive information from the database.

- [https://github.com/Syscallh00k/CVE-2026-111389](https://github.com/Syscallh00k/CVE-2026-111389) :  ![starts](https://img.shields.io/github/stars/Syscallh00k/CVE-2026-111389.svg) ![forks](https://img.shields.io/github/forks/Syscallh00k/CVE-2026-111389.svg)


## CVE-2026-111283
 BMC Helix Network Management on-prem before 26.3.01 contains an authentication bypass vulnerability that allows unauthenticated attackers to log in as the local administrator with any password when SAML single sign-on is configured. Attackers can submit the administrator username with an arbitrary password on the web login page to obtain a SuperAdmin session, modify device credentials, run device commands, and alter audit records.

- [https://github.com/cybliminal/cve-2026-111283-bmc-helix-network-management-local-administrator-any-password](https://github.com/cybliminal/cve-2026-111283-bmc-helix-network-management-local-administrator-any-password) :  ![starts](https://img.shields.io/github/stars/cybliminal/cve-2026-111283-bmc-helix-network-management-local-administrator-any-password.svg) ![forks](https://img.shields.io/github/forks/cybliminal/cve-2026-111283-bmc-helix-network-management-local-administrator-any-password.svg)


## CVE-2026-110896
 Missing Authorization vulnerability in WP Chill Passster content-protector allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects Passster: from n/a through 4.3.18.

- [https://github.com/azqzazq1/CVE-2026-110896](https://github.com/azqzazq1/CVE-2026-110896) :  ![starts](https://img.shields.io/github/stars/azqzazq1/CVE-2026-110896.svg) ![forks](https://img.shields.io/github/forks/azqzazq1/CVE-2026-110896.svg)


## CVE-2026-108598
 Floci 1.1.0 before 2.2.0 contains a code injection vulnerability in VtlTemplateEngine that allows unauthenticated attackers to execute commands via unrestricted Velocity mapping templates. Attackers can create a REST API with a MOCK integration whose template uses $util reflection to reach Runtime or ProcessBuilder, executing OS commands in the Floci JVM.

- [https://github.com/Sidesploitx/CVE-2026-108598](https://github.com/Sidesploitx/CVE-2026-108598) :  ![starts](https://img.shields.io/github/stars/Sidesploitx/CVE-2026-108598.svg) ![forks](https://img.shields.io/github/forks/Sidesploitx/CVE-2026-108598.svg)


## CVE-2026-104745
 The Customer Email Verification for WooCommerce plugin for WordPress is vulnerable to Privilege Escalation via the `alg_wc_ev_verify_email` parameter in versions up to, and including, 3.3.0. The vulnerability exists because `alg_wc_ev_generate_user_code()` generates the per-user activation secret using `wp_rand(100)` when the plugin's 'Encoding method' is set to 'hashids', producing only ~101 possible values (~7 bits of entropy); the resulting token is a reversible Hashids encoding with no cryptographic MAC, and the unauthenticated `verify()` handler — hooked to `init` at `PHP_INT_MAX` with no nonce check and no rate limiting — accepts and acts on the attacker-controlled `?alg_wc_ev_verify_email=` GET parameter directly. This makes it possible for unauthenticated attackers to gain authentication as any unverified WordPress account, including administrator-level accounts, by brute-forcing the trivially small activation code space via a forged verification URL. Exploitation requires that the 'Encoding method' setting be changed to 'hashids' (non-default), that the attacker recover or brute-force the Hashids salt (which defaults to an `md5(time())` value set at first initialization), and that the target account's email address remain unverified.

- [https://github.com/rxsklife/CVE-2026-104745](https://github.com/rxsklife/CVE-2026-104745) :  ![starts](https://img.shields.io/github/stars/rxsklife/CVE-2026-104745.svg) ![forks](https://img.shields.io/github/forks/rxsklife/CVE-2026-104745.svg)


## CVE-2026-104715
 A flaw was found in cifs-utils. This flaw allows an unprivileged local user to achieve privilege escalation. When a privileged service mounts a Common Internet File System (CIFS) share using a user-controlled credentials file, input values are not properly sanitized before being assembled into mount options. A local attacker can exploit this vulnerability to inject unauthorized mount options, allowing them to bypass permission checks and execute files with administrative (root) privileges.

- [https://github.com/M3aCulpa/CVE-2026-104715](https://github.com/M3aCulpa/CVE-2026-104715) :  ![starts](https://img.shields.io/github/stars/M3aCulpa/CVE-2026-104715.svg) ![forks](https://img.shields.io/github/forks/M3aCulpa/CVE-2026-104715.svg)


## CVE-2026-102764
 The vulnerability exists within internal components of BeyondTrust’s Remote Support product. The components did not adequately validate the origin of the messages it received. Under the right conditions, this could allow an attacker to perform file operations on the appliance.

- [https://github.com/Worthes/CVE-2026-102764-Proof-of-concept](https://github.com/Worthes/CVE-2026-102764-Proof-of-concept) :  ![starts](https://img.shields.io/github/stars/Worthes/CVE-2026-102764-Proof-of-concept.svg) ![forks](https://img.shields.io/github/forks/Worthes/CVE-2026-102764-Proof-of-concept.svg)


## CVE-2026-102607
 ZoneMinder is a free, open source closed-circuit television software application. Prior to 1.38.3, the exportEvents() function concatenates the attacker-controlled exportFile request parameter into a shell command without neutralizing shell metacharacters when an authenticated user with View Events or View Snapshots permission submits an event export request with a crafted exportFile value, a valid CSRF token, and exportDetail enabled. The affected components are exportEvents(), exportFile, web/ajax/event.php, web/skins/classic/includes/export_functions.php. In this attack mechanism, the crafted exportFile value reaches the trailing directory argument of a tar or zip command executed by exec(). The attacker can execute arbitrary operating system commands as the web server user. This issue is fixed in version 1.38.3.

- [https://github.com/d4kw1n/CVE-2026-102607-ZoneMinder](https://github.com/d4kw1n/CVE-2026-102607-ZoneMinder) :  ![starts](https://img.shields.io/github/stars/d4kw1n/CVE-2026-102607-ZoneMinder.svg) ![forks](https://img.shields.io/github/forks/d4kw1n/CVE-2026-102607-ZoneMinder.svg)


## CVE-2026-99999
A more complete validation at input is forthcoming, but needs more work.

- [https://github.com/MChorfa/csumguard](https://github.com/MChorfa/csumguard) :  ![starts](https://img.shields.io/github/stars/MChorfa/csumguard.svg) ![forks](https://img.shields.io/github/forks/MChorfa/csumguard.svg)


## CVE-2026-97229
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 19.2 before 19.2.8, 19.3 before 19.3.5, and 19.4 before 19.4.2 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server via a specially crafted regular expression in a CI/CD configuration, due to insufficient regular expression validation.

- [https://github.com/OppositDeer/Gitlab-RCE-CVE-2026-97229](https://github.com/OppositDeer/Gitlab-RCE-CVE-2026-97229) :  ![starts](https://img.shields.io/github/stars/OppositDeer/Gitlab-RCE-CVE-2026-97229.svg) ![forks](https://img.shields.io/github/forks/OppositDeer/Gitlab-RCE-CVE-2026-97229.svg)


## CVE-2026-96889
 A flaw was found in librsvg. When processing an SVG document containing nested XML inclusions (Xincludes) with duplicate entity declarations, a use-after-free error can occur. This vulnerability arises because the library incorrectly frees an XML entity that is still in use by the parser. An attacker could potentially exploit this to cause a denial of service or execute arbitrary code.

- [https://github.com/lion9453/CVE-2026-96889-nextjs-rce](https://github.com/lion9453/CVE-2026-96889-nextjs-rce) :  ![starts](https://img.shields.io/github/stars/lion9453/CVE-2026-96889-nextjs-rce.svg) ![forks](https://img.shields.io/github/forks/lion9453/CVE-2026-96889-nextjs-rce.svg)


## CVE-2026-96656
 Plex Media Server before 1.43.3.10861 allows an admin user to write arbitrary files that may be executed on load. The preference TranscoderH264Options is appended verbatim to x264's option string on every transcode. At startup, all .so files are run without signature, execute bit, or symbol checks.

- [https://github.com/code-zm/plex2shell](https://github.com/code-zm/plex2shell) :  ![starts](https://img.shields.io/github/stars/code-zm/plex2shell.svg) ![forks](https://img.shields.io/github/forks/code-zm/plex2shell.svg)


## CVE-2026-96655
 Plex Media Server before 1.43.3.10861 allows an authenticated user to request arbitrary internal or external addresses via the '/video/:/transcode/universal' path parameter.

- [https://github.com/code-zm/plex2shell](https://github.com/code-zm/plex2shell) :  ![starts](https://img.shields.io/github/stars/code-zm/plex2shell.svg) ![forks](https://img.shields.io/github/forks/code-zm/plex2shell.svg)


## CVE-2026-96654
 Plex Media Server before 1.43.3.10861 does not correctly neutralize URL values included in 'searchOne,' allowing an attacker to call other plugins' functions and supply their own parameters.

- [https://github.com/code-zm/plex2shell](https://github.com/code-zm/plex2shell) :  ![starts](https://img.shields.io/github/stars/code-zm/plex2shell.svg) ![forks](https://img.shields.io/github/forks/code-zm/plex2shell.svg)


## CVE-2026-96652
 Plex Media Server before 1.43.3.10861 allows SSRF via '/player/timeline'. An attacker using any X-Plex-Token value can include a full URL in the 'protocol' parameter and force the Plex server to POST to the attacker's chosen destination.

- [https://github.com/code-zm/plex2shell](https://github.com/code-zm/plex2shell) :  ![starts](https://img.shields.io/github/stars/code-zm/plex2shell.svg) ![forks](https://img.shields.io/github/forks/code-zm/plex2shell.svg)


## CVE-2026-94134
Users of apache-airflow-providers-ssh and apache-airflow-providers-sftp are recommended to upgrade to apache-airflow-providers-ssh 7.0.0 and apache-airflow-providers-sftp 7.0.0 or later. The deferrable SFTP code paths had the same default and are covered separately by CVE-2026-94135; apache-airflow-providers-sftp 7.0.0 fixes both.

- [https://github.com/MosesOX/POC-CVE-2026-94134](https://github.com/MosesOX/POC-CVE-2026-94134) :  ![starts](https://img.shields.io/github/stars/MosesOX/POC-CVE-2026-94134.svg) ![forks](https://img.shields.io/github/forks/MosesOX/POC-CVE-2026-94134.svg)


## CVE-2026-90817
 An unauthenticated Remote Code Execution vulnerability was found in the survey passthrough routing and Data Import processing logic, in which a malicious user could potentially exploit it by manipulating HTTP requests to access an unintended controller route from a public survey context and by supplying a crafted file-path/stream parameter during import handling. If successfully exploited, this could allow the attacker to remotely execute arbitrary code on the REDCap server. The attacker does not have to be authenticated in order to exploit this, but exploitation requires knowledge of a valid public survey hash. This vulnerability exists in REDCap 13.3.0 and higher.

- [https://github.com/ctsit/redcap_cve_2026_90817_scan](https://github.com/ctsit/redcap_cve_2026_90817_scan) :  ![starts](https://img.shields.io/github/stars/ctsit/redcap_cve_2026_90817_scan.svg) ![forks](https://img.shields.io/github/forks/ctsit/redcap_cve_2026_90817_scan.svg)


## CVE-2026-89079
 The Theme My Login plugin for WordPress is vulnerable to privilege escalation via account takeover in versions up to, and including, 7.2.1. This is due to the plugin not properly validating a user's identity prior to updating their password. This makes it possible for unauthenticated attackers to change arbitrary user's passwords on multi-site setups in certain configurations.

- [https://github.com/murrez/CVE-2026-89079](https://github.com/murrez/CVE-2026-89079) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-89079.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-89079.svg)


## CVE-2026-61979
 Unauthenticated Privilege Escalation in SAML SP Single Sign On = 5.4.3 versions.

- [https://github.com/BIBILZERODAY/CVE-2026-61979-miniOrange-SAML-Auth-Bypass-Exploit](https://github.com/BIBILZERODAY/CVE-2026-61979-miniOrange-SAML-Auth-Bypass-Exploit) :  ![starts](https://img.shields.io/github/stars/BIBILZERODAY/CVE-2026-61979-miniOrange-SAML-Auth-Bypass-Exploit.svg) ![forks](https://img.shields.io/github/forks/BIBILZERODAY/CVE-2026-61979-miniOrange-SAML-Auth-Bypass-Exploit.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/BIBILZERODAY/CVE-2026-60137---WordPress-Core-Critical-SQL-Injection-SQLi-PoC](https://github.com/BIBILZERODAY/CVE-2026-60137---WordPress-Core-Critical-SQL-Injection-SQLi-PoC) :  ![starts](https://img.shields.io/github/stars/BIBILZERODAY/CVE-2026-60137---WordPress-Core-Critical-SQL-Injection-SQLi-PoC.svg) ![forks](https://img.shields.io/github/forks/BIBILZERODAY/CVE-2026-60137---WordPress-Core-Critical-SQL-Injection-SQLi-PoC.svg)


## CVE-2026-59970
 Tandoor Recipes is an application for managing recipes, planning meals, and building shopping lists. Prior to 2.6.10, passes an administrator-controlled AI provider URL directly to LiteLLM without applying the server's outbound-request SSRF checks when an authenticated user creates a Space, configures an AI provider with a URL targeting an internal address, and invokes an AI action. In cookbook/views/api.py, the affected AI actions call completion through TARGET/api/ai-import/ and api/ai-step-sort/ while bypassing safe_request. The attack works because the server connects to the supplied provider URL from each AI action and exposes connection success, refusal, or timeout as a blind network-reachability oracle. This can reach internal services, other hosts on the server network, and cloud metadata endpoints and map reachable internal hosts and ports. This issue is fixed in version 2.6.10.

- [https://github.com/asvorg/CVE-2026-59970-poc](https://github.com/asvorg/CVE-2026-59970-poc) :  ![starts](https://img.shields.io/github/stars/asvorg/CVE-2026-59970-poc.svg) ![forks](https://img.shields.io/github/forks/asvorg/CVE-2026-59970-poc.svg)


## CVE-2026-55781
 NanaZip is the 7-Zip derivative intended for the modern Windows experience. Prior to 6.5.1749.0, NanaZip's UFS and FFS image handler in NanaZip.Codecs.Archive.Ufs.cpp validates the superblock block size only against the MINBSIZE lower bound and does not validate the fs_fsize fragment size, allowing attacker-controlled 32-bit fields to flow into indirect-block, directory, and extraction buffer allocations. A tiny crafted UFS image can force multi-gigabyte allocations during open or extraction, causing memory exhaustion or process termination. This issue is fixed in version 6.5.1749.0.

- [https://github.com/NT2DEV/CVE-2026-55781-poc](https://github.com/NT2DEV/CVE-2026-55781-poc) :  ![starts](https://img.shields.io/github/stars/NT2DEV/CVE-2026-55781-poc.svg) ![forks](https://img.shields.io/github/forks/NT2DEV/CVE-2026-55781-poc.svg)


## CVE-2026-53264
period, so no UAF can occur.

- [https://github.com/b1nhack/CVE-2026-53264](https://github.com/b1nhack/CVE-2026-53264) :  ![starts](https://img.shields.io/github/stars/b1nhack/CVE-2026-53264.svg) ![forks](https://img.shields.io/github/forks/b1nhack/CVE-2026-53264.svg)


## CVE-2026-51367
 An issue in Bottinelli Informatica Vedo Suite v.1.2.5 allows a remote attacker to obtain sensitive information via the api_vedo/chat endpoint and the utente_chat parameter

- [https://github.com/StefanoAndreatta/CVE-2026-51367-Insecure-Direct-Object-Reference-IDOR](https://github.com/StefanoAndreatta/CVE-2026-51367-Insecure-Direct-Object-Reference-IDOR) :  ![starts](https://img.shields.io/github/stars/StefanoAndreatta/CVE-2026-51367-Insecure-Direct-Object-Reference-IDOR.svg) ![forks](https://img.shields.io/github/forks/StefanoAndreatta/CVE-2026-51367-Insecure-Direct-Object-Reference-IDOR.svg)


## CVE-2026-51366
 SQL Injection vulnerability in Bottinelli Informatica Vedo Suite v.1.2.5 allows a remote attacker to execute arbitrary code via the api_vedo/chat endpoint and the utente_chat parameter

- [https://github.com/StefanoAndreatta/CVE-2026-51366-SQL-Injection-leading-to-Remote-Code-Execution](https://github.com/StefanoAndreatta/CVE-2026-51366-SQL-Injection-leading-to-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/StefanoAndreatta/CVE-2026-51366-SQL-Injection-leading-to-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/StefanoAndreatta/CVE-2026-51366-SQL-Injection-leading-to-Remote-Code-Execution.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/zhubaohe123/ghostlock-kit-v2](https://github.com/zhubaohe123/ghostlock-kit-v2) :  ![starts](https://img.shields.io/github/stars/zhubaohe123/ghostlock-kit-v2.svg) ![forks](https://img.shields.io/github/forks/zhubaohe123/ghostlock-kit-v2.svg)


## CVE-2026-36213
 An issue in Microvirt MEmu Android Emulator 9.2.7.0 allows a local attacker to escalate privileges via the MemuService.exe component.

- [https://github.com/NT2DEV/CVE-2026-36213-poc](https://github.com/NT2DEV/CVE-2026-36213-poc) :  ![starts](https://img.shields.io/github/stars/NT2DEV/CVE-2026-36213-poc.svg) ![forks](https://img.shields.io/github/forks/NT2DEV/CVE-2026-36213-poc.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/1337or420/CVE-2026-33017-Langflow-RCE](https://github.com/1337or420/CVE-2026-33017-Langflow-RCE) :  ![starts](https://img.shields.io/github/stars/1337or420/CVE-2026-33017-Langflow-RCE.svg) ![forks](https://img.shields.io/github/forks/1337or420/CVE-2026-33017-Langflow-RCE.svg)


## CVE-2026-24090
 Cryptographic issue while processing partition table entries allows unauthorized modification of boot flow.

- [https://github.com/wnduddld0513/Lenovo_Qcom_RPMB_Tool](https://github.com/wnduddld0513/Lenovo_Qcom_RPMB_Tool) :  ![starts](https://img.shields.io/github/stars/wnduddld0513/Lenovo_Qcom_RPMB_Tool.svg) ![forks](https://img.shields.io/github/forks/wnduddld0513/Lenovo_Qcom_RPMB_Tool.svg)


## CVE-2026-19607
 A flaw was found in the first-broker-login flow of the keycloak-services component. This component handles the initial authentication and account linking when a user logs in via an external identity provider. The issue allows an attacker to register a matching username on an external provider to trigger a collision in Keycloak, which results in the legitimate user being locked out of their account.

- [https://github.com/7Ragnarok7/CVE-2026-19607](https://github.com/7Ragnarok7/CVE-2026-19607) :  ![starts](https://img.shields.io/github/stars/7Ragnarok7/CVE-2026-19607.svg) ![forks](https://img.shields.io/github/forks/7Ragnarok7/CVE-2026-19607.svg)


## CVE-2026-10809
 A security flaw has been discovered in itsourcecode Fees Management System 1.0. This impacts an unknown function of the file /manage_user.php. The manipulation of the argument ID results in sql injection. The attack can be executed remotely. The exploit has been released to the public and may be used for attacks.

- [https://github.com/FurkanKAYAPINAR/CVE-2026-108097](https://github.com/FurkanKAYAPINAR/CVE-2026-108097) :  ![starts](https://img.shields.io/github/stars/FurkanKAYAPINAR/CVE-2026-108097.svg) ![forks](https://img.shields.io/github/forks/FurkanKAYAPINAR/CVE-2026-108097.svg)


## CVE-2026-9220
 Setracker2 Android Companion App com.tgelec.setracker versions 3.1.5 and prior encrypts requests between the watch and its backend with static hardcoded AES keys and initialization vectors. This allows an attacker to decrypt Setracker2 watch traffic.

- [https://github.com/do4choo/CVE-2026-92209_NoMachine_LPE](https://github.com/do4choo/CVE-2026-92209_NoMachine_LPE) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-92209_NoMachine_LPE.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-92209_NoMachine_LPE.svg)
- [https://github.com/do4choo/CVE-2026-92208_remote_mDNS_overflow](https://github.com/do4choo/CVE-2026-92208_remote_mDNS_overflow) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-92208_remote_mDNS_overflow.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-92208_remote_mDNS_overflow.svg)


## CVE-2026-7998
 Insufficient validation of untrusted input in Dialog in Google Chrome prior to 148.0.7778.96 allowed a remote attacker who had compromised the renderer process to perform UI spoofing via a crafted HTML page. (Chromium security severity: Low)

- [https://github.com/oscerd/CVE-2026-79983](https://github.com/oscerd/CVE-2026-79983) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-79983.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-79983.svg)
- [https://github.com/oscerd/CVE-2026-79985](https://github.com/oscerd/CVE-2026-79985) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-79985.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-79985.svg)
- [https://github.com/oscerd/CVE-2026-79986](https://github.com/oscerd/CVE-2026-79986) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-79986.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-79986.svg)
- [https://github.com/oscerd/CVE-2026-79984](https://github.com/oscerd/CVE-2026-79984) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-79984.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-79984.svg)


## CVE-2026-7816
This issue affects pgAdmin 4: before 9.15.

- [https://github.com/oscerd/CVE-2026-78163](https://github.com/oscerd/CVE-2026-78163) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-78163.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-78163.svg)
- [https://github.com/oscerd/CVE-2026-78165](https://github.com/oscerd/CVE-2026-78165) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-78165.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-78165.svg)
- [https://github.com/oscerd/CVE-2026-78162](https://github.com/oscerd/CVE-2026-78162) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-78162.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-78162.svg)
- [https://github.com/oscerd/CVE-2026-78164](https://github.com/oscerd/CVE-2026-78164) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-78164.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-78164.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/MiaPatsune/cve-2026-43499](https://github.com/MiaPatsune/cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/MiaPatsune/cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/MiaPatsune/cve-2026-43499.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/euriconicacio/copy-fail-CVE-2026-31431-poc](https://github.com/euriconicacio/copy-fail-CVE-2026-31431-poc) :  ![starts](https://img.shields.io/github/stars/euriconicacio/copy-fail-CVE-2026-31431-poc.svg) ![forks](https://img.shields.io/github/forks/euriconicacio/copy-fail-CVE-2026-31431-poc.svg)


## CVE-2026-1047
 The salavat counter Plugin plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'image_url' parameter in all versions up to, and including, 0.9.5 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/BIBILZERODAY/CVE-2026-104736---Proof-of-Concept-PoC-Exploit-Details](https://github.com/BIBILZERODAY/CVE-2026-104736---Proof-of-Concept-PoC-Exploit-Details) :  ![starts](https://img.shields.io/github/stars/BIBILZERODAY/CVE-2026-104736---Proof-of-Concept-PoC-Exploit-Details.svg) ![forks](https://img.shields.io/github/forks/BIBILZERODAY/CVE-2026-104736---Proof-of-Concept-PoC-Exploit-Details.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/thiconickid/sharepoint-zero-day-cs50-cybersecurity](https://github.com/thiconickid/sharepoint-zero-day-cs50-cybersecurity) :  ![starts](https://img.shields.io/github/stars/thiconickid/sharepoint-zero-day-cs50-cybersecurity.svg) ![forks](https://img.shields.io/github/forks/thiconickid/sharepoint-zero-day-cs50-cybersecurity.svg)


## CVE-2025-52097
 Cross Site Scripting vulnerability in InstantASP ltd, InstantForum.NET v.4.1.4 allows an attacker to execute arbitrary code via reflecting un-sanitized input from query string parameters directly into the HTML response without proper output encoding

- [https://github.com/rwilsonecs/CVE-2025-52097](https://github.com/rwilsonecs/CVE-2025-52097) :  ![starts](https://img.shields.io/github/stars/rwilsonecs/CVE-2025-52097.svg) ![forks](https://img.shields.io/github/forks/rwilsonecs/CVE-2025-52097.svg)


## CVE-2024-38063
 Windows TCP/IP Remote Code Execution Vulnerability

- [https://github.com/KernelKraze/CVE-2024-38063_PoC](https://github.com/KernelKraze/CVE-2024-38063_PoC) :  ![starts](https://img.shields.io/github/stars/KernelKraze/CVE-2024-38063_PoC.svg) ![forks](https://img.shields.io/github/forks/KernelKraze/CVE-2024-38063_PoC.svg)


## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/rafaelsoje/infosec-audit-tools](https://github.com/rafaelsoje/infosec-audit-tools) :  ![starts](https://img.shields.io/github/stars/rafaelsoje/infosec-audit-tools.svg) ![forks](https://img.shields.io/github/forks/rafaelsoje/infosec-audit-tools.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/Subzero710/CVE-2024-3094-demo](https://github.com/Subzero710/CVE-2024-3094-demo) :  ![starts](https://img.shields.io/github/stars/Subzero710/CVE-2024-3094-demo.svg) ![forks](https://img.shields.io/github/forks/Subzero710/CVE-2024-3094-demo.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/jermainlaforce/CVE-2022-1388-POC](https://github.com/jermainlaforce/CVE-2022-1388-POC) :  ![starts](https://img.shields.io/github/stars/jermainlaforce/CVE-2022-1388-POC.svg) ![forks](https://img.shields.io/github/forks/jermainlaforce/CVE-2022-1388-POC.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847](https://github.com/pmihsan/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/pmihsan/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/pmihsan/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/cyfrowesny/exiftool-7.44-12.23-exploit-CVE-2021-22204](https://github.com/cyfrowesny/exiftool-7.44-12.23-exploit-CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/cyfrowesny/exiftool-7.44-12.23-exploit-CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/cyfrowesny/exiftool-7.44-12.23-exploit-CVE-2021-22204.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Phineas09/CVE-2021-44228](https://github.com/Phineas09/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Phineas09/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Phineas09/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)
- [https://github.com/gunzf0x/CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2021-41773.svg)
- [https://github.com/sotiak/CVE-2021-41773](https://github.com/sotiak/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-41773.svg)


## CVE-2021-3929
 A DMA reentrancy issue was found in the NVM Express Controller (NVME) emulation in QEMU. This CVE is similar to CVE-2021-3750 and, just like it, when the reentrancy write triggers the reset function nvme_ctrl_reset(), data structs will be freed leading to a use-after-free issue. A malicious guest could use this flaw to crash the QEMU process on the host, resulting in a denial of service condition or, potentially, executing arbitrary code within the context of the QEMU process on the host.

- [https://github.com/abraxas/qemu-nvme-sgl-bar](https://github.com/abraxas/qemu-nvme-sgl-bar) :  ![starts](https://img.shields.io/github/stars/abraxas/qemu-nvme-sgl-bar.svg) ![forks](https://img.shields.io/github/forks/abraxas/qemu-nvme-sgl-bar.svg)

