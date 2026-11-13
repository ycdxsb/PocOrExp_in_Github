# Update 2026-11-13
## CVE-2026-126497
 LibreCAD through 2.2.1.6 contains a heap-based out-of-bounds write vulnerability in the bundled libdxfrw dwgReader18::parseDataPage() function due to unchecked buffer size and page offsets. Attackers can craft an AC1018 (R2004) DWG file with malicious startOffset values that cause decompress18 to write past the heap buffer when opened, causing crashes and potential code execution.

- [https://github.com/zeetee1235/CVE-2026-126497](https://github.com/zeetee1235/CVE-2026-126497) :  ![starts](https://img.shields.io/github/stars/zeetee1235/CVE-2026-126497.svg) ![forks](https://img.shields.io/github/forks/zeetee1235/CVE-2026-126497.svg)


## CVE-2026-126187
 React is a JavaScript library for building user interfaces. From 19.0.0 until 19.0.9, 19.1.10, 19.2.9, and 19.3.1, the react-server-dom-webpack, react-server-dom-parcel, and react-server-dom-turbopack packages are vulnerable to unauthenticated remote code execution through crafted payloads targeting frameworks that support React Server Components. The vulnerability only affects extremely rare cases where responses transport multiple typed arrays and an attacker-controlled value. Applications whose React code does not use a server are not affected. Applications that do not use a framework, bundler, or bundler plugin that supports React Server Components are not affected. This issue is fixed in versions 19.0.9, 19.1.10, 19.2.9, and 19.3.1.

- [https://github.com/briskets/CVE-2026-126187-poc](https://github.com/briskets/CVE-2026-126187-poc) :  ![starts](https://img.shields.io/github/stars/briskets/CVE-2026-126187-poc.svg) ![forks](https://img.shields.io/github/forks/briskets/CVE-2026-126187-poc.svg)
- [https://github.com/rudSarkar/GHSA-673q-mjm6-r5xr](https://github.com/rudSarkar/GHSA-673q-mjm6-r5xr) :  ![starts](https://img.shields.io/github/stars/rudSarkar/GHSA-673q-mjm6-r5xr.svg) ![forks](https://img.shields.io/github/forks/rudSarkar/GHSA-673q-mjm6-r5xr.svg)


## CVE-2026-126170
 A improper encoding or escaping of output vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.2, FortiAnalyzer 7.6.0 through 7.6.7, FortiAnalyzer Cloud 8.0.1 through 8.0.2, FortiAnalyzer Cloud 7.6.0 through 7.6.7, FortiAnalyzer-BigData 7.6.0 through 7.6.2, FortiManager 8.0.0 through 8.0.2, FortiManager 7.6.0 through 7.6.7, FortiManager Cloud 8.0.1 through 8.0.2, FortiManager Cloud 7.6.0 through 7.6.7 may allow an unauthenticated attacker to execute unauthorized code or commands via a specially crafted HTTP request

- [https://github.com/Ghost-Bx1/cve-2026-126170-fortimanager-jsonrpc-rce](https://github.com/Ghost-Bx1/cve-2026-126170-fortimanager-jsonrpc-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-126170-fortimanager-jsonrpc-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-126170-fortimanager-jsonrpc-rce.svg)


## CVE-2026-125753
 ABP Framework 2.9.0 before 10.6.2 and 10.7.0 pre-releases before 10.7.0 contain a path traversal vulnerability in DefaultBlobFilePathCalculator that allows unauthenticated attackers to access files outside the blob container. Attackers can send %5C-encoded backslashes through the Blogging api/blogging/files/{name} endpoint on Windows hosts to read files like appsettings.json containing signing keys and connection strings.

- [https://github.com/yuwkaaa/CVE-2026-125753](https://github.com/yuwkaaa/CVE-2026-125753) :  ![starts](https://img.shields.io/github/stars/yuwkaaa/CVE-2026-125753.svg) ![forks](https://img.shields.io/github/forks/yuwkaaa/CVE-2026-125753.svg)


## CVE-2026-125439
 Missing Authorization vulnerability in Kit Kit (formerly ConvertKit) convertkit allows Exploiting Incorrectly Configured Access Control Security Levels.This issue affects Kit (formerly ConvertKit): from n/a through 3.5.0.

- [https://github.com/kanokwut/CVE-2026-125439-poc](https://github.com/kanokwut/CVE-2026-125439-poc) :  ![starts](https://img.shields.io/github/stars/kanokwut/CVE-2026-125439-poc.svg) ![forks](https://img.shields.io/github/forks/kanokwut/CVE-2026-125439-poc.svg)


## CVE-2026-125350
 Use after free in XML in Google Chrome prior to 157.0.8103.50 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/TJT001/CVE-2026-125350-PoC](https://github.com/TJT001/CVE-2026-125350-PoC) :  ![starts](https://img.shields.io/github/stars/TJT001/CVE-2026-125350-PoC.svg) ![forks](https://img.shields.io/github/forks/TJT001/CVE-2026-125350-PoC.svg)


## CVE-2026-124194
 Product ui does not warn user of unsafe actions in Microsoft Office Outlook allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/AmesianX/CVE-2026-124194-poc](https://github.com/AmesianX/CVE-2026-124194-poc) :  ![starts](https://img.shields.io/github/stars/AmesianX/CVE-2026-124194-poc.svg) ![forks](https://img.shields.io/github/forks/AmesianX/CVE-2026-124194-poc.svg)
- [https://github.com/Ghost-Bx1/cve-2026-124194-outlook-ntlm-hash-leak](https://github.com/Ghost-Bx1/cve-2026-124194-outlook-ntlm-hash-leak) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-124194-outlook-ntlm-hash-leak.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-124194-outlook-ntlm-hash-leak.svg)


## CVE-2026-124079
 rConfig Core 8.0.0 before 8.2.19 and rConfig Pro before 8.4.1 contain a deserialization of untrusted data vulnerability that allows unauthenticated network attackers to execute arbitrary code by pushing a crafted serialized job onto the Redis-backed Laravel Horizon queue, which runs without authentication in affected deployments. Laravel's CallQueuedHandler unserializes the job without class restrictions, allowing attackers to instantiate the existing App\\Jobs\\TaskDownloadRun class and invoke an attacker-controlled Artisan command. Attackers can leverage the bundled laravel/tinker package to execute arbitrary PHP and operating system commands as the queue worker's user, write a persistent web shell into the web-served storage/app/public directory, and read database credentials, stored device credentials, and API tokens. Where Redis is not directly reachable, authenticated attackers can deliver the payload through the application by configuring a device target that points at the rConfig server's loopback address.

- [https://github.com/googlesky/CVE-2026-124079](https://github.com/googlesky/CVE-2026-124079) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-124079.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-124079.svg)


## CVE-2026-123618
 ABP Framework before 10.7.1 contains an authentication bypass vulnerability that skips account state and two-factor checks when password login succeeds through a registered IExternalLoginProvider. Attackers holding the external directory password for deactivated, locked, or 2FA-protected accounts can obtain valid access tokens from the /connect/token password grant.

- [https://github.com/yuwkaaa/CVE-2026-123618](https://github.com/yuwkaaa/CVE-2026-123618) :  ![starts](https://img.shields.io/github/stars/yuwkaaa/CVE-2026-123618.svg) ![forks](https://img.shields.io/github/forks/yuwkaaa/CVE-2026-123618.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/Doseuser/CVE-2026-123158](https://github.com/Doseuser/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/Doseuser/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/Doseuser/CVE-2026-123158.svg)
- [https://github.com/MMitsuha/CVE-2026-123158](https://github.com/MMitsuha/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/MMitsuha/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/MMitsuha/CVE-2026-123158.svg)
- [https://github.com/douglasmun/CVE-2026-123158_sshole_lab](https://github.com/douglasmun/CVE-2026-123158_sshole_lab) :  ![starts](https://img.shields.io/github/stars/douglasmun/CVE-2026-123158_sshole_lab.svg) ![forks](https://img.shields.io/github/forks/douglasmun/CVE-2026-123158_sshole_lab.svg)


## CVE-2026-121529
 A origin validation error vulnerability in Fortinet FortiClientMac 7.4.0 through 7.4.7, FortiClientWindows 7.4.0 through 7.4.7, FortiClientWindows 7.2.0 through 7.2.14, FortiClientWindowsPAM 7.4.7, FortiClientWindowsPAM 7.2.14 may allow an unauthorized remote attacker to execute unauthorized code or commands. Successful exploitation requires interaction with the victim.

- [https://github.com/ashrafzaryouh/CVE-2026-121529](https://github.com/ashrafzaryouh/CVE-2026-121529) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-121529.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-121529.svg)
- [https://github.com/googlesky/CVE-2026-121529](https://github.com/googlesky/CVE-2026-121529) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-121529.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-121529.svg)
- [https://github.com/Ghost-Bx1/cve-2026-121529-forticlient-cors-rce](https://github.com/Ghost-Bx1/cve-2026-121529-forticlient-cors-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-121529-forticlient-cors-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-121529-forticlient-cors-rce.svg)
- [https://github.com/googlesky/Fortinet2Shell](https://github.com/googlesky/Fortinet2Shell) :  ![starts](https://img.shields.io/github/stars/googlesky/Fortinet2Shell.svg) ![forks](https://img.shields.io/github/forks/googlesky/Fortinet2Shell.svg)


## CVE-2026-120017
 SAP NetWeaver AS ABAP and ABAP Platform does not perform sufficient verification of incoming authentication assertions under certain configurations. An unauthenticated attacker could submit specially crafted data to bypass authentication and impersonate arbitrary users, including privileged accounts. Successful exploitation could cause a full system compromise, with the impact potentially extending to connected components and systems beyond the affected system. This results in a high impact on confidentiality, integrity, and availability of the application.

- [https://github.com/foxcornlab/sap-patchday-scanner](https://github.com/foxcornlab/sap-patchday-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/sap-patchday-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/sap-patchday-scanner.svg)


## CVE-2026-119948
 Stack-based buffer overflow in Windows Active Directory allows an authorized attacker to execute code over a network.

- [https://github.com/Ghost-Bx1/cve-2026-119948-windows-ad-rce](https://github.com/Ghost-Bx1/cve-2026-119948-windows-ad-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-119948-windows-ad-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-119948-windows-ad-rce.svg)


## CVE-2026-118383
 A use-after-free in the replication component of MongoDB Server can occur when a newly elected replica set primary completes catch-up. The condition can be caused by requests that do not require authentication, and may result in the server terminating unexpectedly or, under certain conditions, arbitrary code execution in the context of the server process. Replica set members are affected, including the shard and config server replica set members of sharded clusters; standalone mongod instances are not.

- [https://github.com/googlesky/CVE-2026-118383](https://github.com/googlesky/CVE-2026-118383) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-118383.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-118383.svg)


## CVE-2026-117635
 The `/api/v1/admin` route group did not enforce the `public-only` restriction of personal access tokens. A public-only token with admin scope issued by a site administrator could therefore list private organizations and the email addresses of all users, create organizations, obtain runner registration tokens and create new site administrator accounts, the last of which persists after the token is revoked. Tokens of users who are not site administrators cannot reach these routes; public-only tokens are now rejected on the admin API.

- [https://github.com/omarkurt/CVE-2026-117635](https://github.com/omarkurt/CVE-2026-117635) :  ![starts](https://img.shields.io/github/stars/omarkurt/CVE-2026-117635.svg) ![forks](https://img.shields.io/github/forks/omarkurt/CVE-2026-117635.svg)


## CVE-2026-116606
 An authentication bypass in Barracuda Email Security Gateway versions earlier than 9.4.0.030 allows an unauthenticated remote attacker to invoke a configuration-import function and restore a crafted, compatible backup archive, resulting in unauthorized modification of the appliance’s global configuration.

- [https://github.com/ZeroHackOrg/barracuda-esg-zeroday-cve-2026-116606-analysis](https://github.com/ZeroHackOrg/barracuda-esg-zeroday-cve-2026-116606-analysis) :  ![starts](https://img.shields.io/github/stars/ZeroHackOrg/barracuda-esg-zeroday-cve-2026-116606-analysis.svg) ![forks](https://img.shields.io/github/forks/ZeroHackOrg/barracuda-esg-zeroday-cve-2026-116606-analysis.svg)


## CVE-2026-115252
 The Confection WordPress Cable WordPress plugin from 0.4.0 to 0.4.7 does not perform any capability or nonce checks before saving its settings and writing one of them, unmodified, into a standalone PHP file that it then serves, allowing unauthenticated users to execute arbitrary PHP code on the server.

- [https://github.com/Ghost-Bx1/cve-2026-115252-wordpress-php-injection-rce](https://github.com/Ghost-Bx1/cve-2026-115252-wordpress-php-injection-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-115252-wordpress-php-injection-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-115252-wordpress-php-injection-rce.svg)


## CVE-2026-112174
 Local privilege escalation vulnerability in Iperius Backup 8.8.3, due to insufficient separation between the graphical user interface running with elevated privileges and local users with low privileges. When the backup service is configured to run persistently with Administrator privileges, a local attacker with low privileges can use the native Windows dialogues exposed by the application to run programmes that inherit its elevated context. This allows commands to be executed with SYSTEM or Administrator privileges, depending on the application’s context, and compromises the affected Windows system.

- [https://github.com/jonastrikex/CVE-2026-112174-Iperius-Backup-version-8.8.3-PoC](https://github.com/jonastrikex/CVE-2026-112174-Iperius-Backup-version-8.8.3-PoC) :  ![starts](https://img.shields.io/github/stars/jonastrikex/CVE-2026-112174-Iperius-Backup-version-8.8.3-PoC.svg) ![forks](https://img.shields.io/github/forks/jonastrikex/CVE-2026-112174-Iperius-Backup-version-8.8.3-PoC.svg)


## CVE-2026-111560
 Improper neutralization of shell metacharacters in the timezone configuration field in certain Barracuda appliance products using common Barracuda code allows an authenticated administrator to inject OS commands that execute with root privileges when the crafted timezone value is subsequently processed.

- [https://github.com/ZeroHackOrg/barracuda-esg-zeroday-cve-2026-116606-analysis](https://github.com/ZeroHackOrg/barracuda-esg-zeroday-cve-2026-116606-analysis) :  ![starts](https://img.shields.io/github/stars/ZeroHackOrg/barracuda-esg-zeroday-cve-2026-116606-analysis.svg) ![forks](https://img.shields.io/github/forks/ZeroHackOrg/barracuda-esg-zeroday-cve-2026-116606-analysis.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/MchinaMd57764/CVE-2026-111497-PoC](https://github.com/MchinaMd57764/CVE-2026-111497-PoC) :  ![starts](https://img.shields.io/github/stars/MchinaMd57764/CVE-2026-111497-PoC.svg) ![forks](https://img.shields.io/github/forks/MchinaMd57764/CVE-2026-111497-PoC.svg)


## CVE-2026-110264
 An issue has been discovered in GitLab CE/EE affecting all versions from 7.0 before 18.11.13, 19.0 before 19.0.10, 19.1 before 19.1.9, 19.2 before 19.2.9, 19.3 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server due to integer overflow when compiling a specially crafted regular expression.

- [https://github.com/Ghost-Bx1/cve-2026-110264-gitlab-regex-rce](https://github.com/Ghost-Bx1/cve-2026-110264-gitlab-regex-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-110264-gitlab-regex-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-110264-gitlab-regex-rce.svg)


## CVE-2026-105437
untrusted repositories.

- [https://github.com/googlesky/CVE-2026-105437](https://github.com/googlesky/CVE-2026-105437) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-105437.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-105437.svg)


## CVE-2026-105425
 OS command injection in Ivanti Sentry before versions 11.0.0, 10.8.3, and 10.7.4 as well as in Ivanti EPMM before versions 12.11.0.0, 12.10.0.1, and 12.9.0.3 allows a remote authenticated attacker with admin privileges to achieve remote code execution.

- [https://github.com/mustafasaydam/CVE-2026-105425-PoC](https://github.com/mustafasaydam/CVE-2026-105425-PoC) :  ![starts](https://img.shields.io/github/stars/mustafasaydam/CVE-2026-105425-PoC.svg) ![forks](https://img.shields.io/github/forks/mustafasaydam/CVE-2026-105425-PoC.svg)


## CVE-2026-105016
 Heap-based buffer overflow in Microsoft QUIC allows an unauthorized attacker to execute code over a network.

- [https://github.com/LHeiakim/CVE-2026-105016-RCE-PoC](https://github.com/LHeiakim/CVE-2026-105016-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/LHeiakim/CVE-2026-105016-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/LHeiakim/CVE-2026-105016-RCE-PoC.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/qq2770355800/ExtractKit](https://github.com/qq2770355800/ExtractKit) :  ![starts](https://img.shields.io/github/stars/qq2770355800/ExtractKit.svg) ![forks](https://img.shields.io/github/forks/qq2770355800/ExtractKit.svg)


## CVE-2026-89324
 The Basel Post Types plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 1.18. The vulnerability exists because a missing-quotes coding error in the defined() call for SECURE_AUTH_SALT inside BASEL_Auth::get_config() causes PHP to evaluate the constant's value rather than its name, making the check always fail and permanently falling back to the static hardcoded salt 2NlBUibcszrVtNmDnxqDbwCOpLWq91eatIz6O1O that is publicly visible in the theme source code; because this salt is static and known, an attacker can compute a valid Opauth signature entirely offline and submit a forged ?opauth callback to the unauthenticated init hook endpoint processed by register_or_login. This makes it possible for unauthenticated attackers to authenticate as any existing WordPress user, including administrators, by forging a callback tied to a known target account email address — bypassing all password verification, multi-factor authentication, and ownership checks, and receiving a fully authenticated session cookie via wc_set_customer_auth_cookie(). Exploitation requires WooCommerce to be active and at least one Basel social-login provider (Facebook, Google, or VKontakte) to be configured with a valid app_id and app_secret in the theme settings.

- [https://github.com/im0xfay/CVE-2026-89324](https://github.com/im0xfay/CVE-2026-89324) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-89324.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-89324.svg)


## CVE-2026-89126
 SAP Web Dispatcher does not sufficiently validate certain network input processed by an internal component. An unauthenticated attacker could send specially crafted network traffic to trigger a memory corruption condition in the affected functionality. Successful exploitation could allow the attacker to execute arbitrary code and fully compromise the system, resulting in a high impact on confidentiality, integrity and availability of the system.

- [https://github.com/foxcornlab/sap-patchday-scanner](https://github.com/foxcornlab/sap-patchday-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/sap-patchday-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/sap-patchday-scanner.svg)


## CVE-2026-89103
 SAP Gateway activates the default Access Control List with high privileges allowing categorization of external attacker as internal application server. As a result an unauthenticated attacker with network access to the SAP Gateway could exploit this weakness to potentially perform unauthorized actions within the application environment, resulting in a high impact on the confidentiality, integrity, and availability of the affected system.

- [https://github.com/foxcornlab/sap-patchday-scanner](https://github.com/foxcornlab/sap-patchday-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/sap-patchday-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/sap-patchday-scanner.svg)


## CVE-2026-76964
 SAP NetWeaver Application Server ABAP does not sufficiently validate certain network input processed by an internal component. An unauthenticated attacker could send specially crafted network traffic to trigger a memory corruption condition in the affected functionality. Successful exploitation could allow the attacker to execute arbitrary code and fully compromise the system, resulting in a high impact on confidentiality, integrity and availability of the system.

- [https://github.com/foxcornlab/sap-patchday-scanner](https://github.com/foxcornlab/sap-patchday-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/sap-patchday-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/sap-patchday-scanner.svg)


## CVE-2026-76466
Note: Cisco Expressway Series refers to Cisco Expressway Core (Expressway-C) devices and Cisco Expressway Edge (Expressway-E) devices.

- [https://github.com/dinosn/cve-2026-76466](https://github.com/dinosn/cve-2026-76466) :  ![starts](https://img.shields.io/github/stars/dinosn/cve-2026-76466.svg) ![forks](https://img.shields.io/github/forks/dinosn/cve-2026-76466.svg)


## CVE-2026-70054
 Heap-based buffer overflow in Windows NetBIOS allows an authorized attacker to elevate privileges locally.

- [https://github.com/D7EAD/CVE-2026-70054](https://github.com/D7EAD/CVE-2026-70054) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-70054.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-70054.svg)


## CVE-2026-68982
Users are advised to upgrade to apache-airflow 3.4.0 or later, in which the worker claims the callback through the Execution API, validating the token, before running it.

- [https://github.com/Ghost-Bx1/cve-2026-68982-airflow-celery-rce](https://github.com/Ghost-Bx1/cve-2026-68982-airflow-celery-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-68982-airflow-celery-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-68982-airflow-celery-rce.svg)


## CVE-2026-67176
 Chargemap contains an open redirect vulnerability in the authentication login endpoint. A remote, unauthenticated attacker could send a crafted URL to a victim and redirect them to an attacker controlled domain. Fixed 2026-07-17.

- [https://github.com/praksokchea/CVE-2026-67176](https://github.com/praksokchea/CVE-2026-67176) :  ![starts](https://img.shields.io/github/stars/praksokchea/CVE-2026-67176.svg) ![forks](https://img.shields.io/github/forks/praksokchea/CVE-2026-67176.svg)


## CVE-2026-67175
 Chargemap contains a stored cross-site scripting vulnerability that allows a remote, authenticated attacker to craft a malicious payload in the user profile page that executes when another user views the attacker's profile. Fixed 2026-07-17.

- [https://github.com/praksokchea/CVE-2026-67175](https://github.com/praksokchea/CVE-2026-67175) :  ![starts](https://img.shields.io/github/stars/praksokchea/CVE-2026-67175.svg) ![forks](https://img.shields.io/github/forks/praksokchea/CVE-2026-67175.svg)


## CVE-2026-65971
 Livewire PowerGrid creates data tables based on Laravel Livewire library. From version 6.0.0 to before version 6.10.4, the public Livewire property sortDirection is interpolated verbatim into a raw SQL ORDER BY clause and is not restricted to asc/desc, allowing arbitrary SQL injection through POST /livewire/update. This issue has been patched in version 6.10.4.

- [https://github.com/BiiTts/POC-CVE-2026-65971](https://github.com/BiiTts/POC-CVE-2026-65971) :  ![starts](https://img.shields.io/github/stars/BiiTts/POC-CVE-2026-65971.svg) ![forks](https://img.shields.io/github/forks/BiiTts/POC-CVE-2026-65971.svg)


## CVE-2026-65843
 sync-rpc runs asynchronous commands synchronously by putting them in a separate proces. Prior to version 1.3.7, if an attacker could guess the correct port and it was not blocked via a firewall, it was possible to load and execute arbitrary JavaScript files stored on the server running sync-rpc. This issue has been patched in version 1.3.7.

- [https://github.com/MaddyGuthridge/sync-rce](https://github.com/MaddyGuthridge/sync-rce) :  ![starts](https://img.shields.io/github/stars/MaddyGuthridge/sync-rce.svg) ![forks](https://img.shields.io/github/forks/MaddyGuthridge/sync-rce.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/saretawa/wp2blind](https://github.com/saretawa/wp2blind) :  ![starts](https://img.shields.io/github/stars/saretawa/wp2blind.svg) ![forks](https://img.shields.io/github/forks/saretawa/wp2blind.svg)


## CVE-2026-62314
 Anubis is a Web AI Firewall Utility that challenges users' connections in order to protect upstream resources from scraper bots. From 1.22.0 until 1.26.0-pre1, lib/policy/checker.go PathChecker.Check() trusted the client-controlled X-Original-URI header before matching r.URL.Path, allowing an HTTP client to match default data/common/keep-internet-working.yaml ALLOW rules such as ^/\.well-known/.*$ and bypass the Anubis challenge. This issue is fixed in version 1.26.0-pre1.

- [https://github.com/celikfana-lab/anubis-solver](https://github.com/celikfana-lab/anubis-solver) :  ![starts](https://img.shields.io/github/stars/celikfana-lab/anubis-solver.svg) ![forks](https://img.shields.io/github/forks/celikfana-lab/anubis-solver.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/saretawa/wp2blind](https://github.com/saretawa/wp2blind) :  ![starts](https://img.shields.io/github/stars/saretawa/wp2blind.svg) ![forks](https://img.shields.io/github/forks/saretawa/wp2blind.svg)


## CVE-2026-44212
 PrestaShop is an open source e-commerce web application. Prior to 8.2.6 and 9.1.1, there is a stored Cross-Site Scripting (XSS) vulnerability in the PrestaShop back-office Customer Service view. An unauthenticated attacker can submit the public Contact Us form with a malicious email address. The payload is stored in the database and executed when a back-office employee opens the affected customer thread, enabling session hijacking and full back-office takeover. This vulnerability is fixed in 8.2.6 and 9.1.1.

- [https://github.com/fstivicic/prestashop17-security-patches](https://github.com/fstivicic/prestashop17-security-patches) :  ![starts](https://img.shields.io/github/stars/fstivicic/prestashop17-security-patches.svg) ![forks](https://img.shields.io/github/forks/fstivicic/prestashop17-security-patches.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/ihamn/matisse-public](https://github.com/ihamn/matisse-public) :  ![starts](https://img.shields.io/github/stars/ihamn/matisse-public.svg) ![forks](https://img.shields.io/github/forks/ihamn/matisse-public.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/SameerAlSahab/twentysixify](https://github.com/SameerAlSahab/twentysixify) :  ![starts](https://img.shields.io/github/stars/SameerAlSahab/twentysixify.svg) ![forks](https://img.shields.io/github/forks/SameerAlSahab/twentysixify.svg)


## CVE-2026-33050
 GeoNode is a geospatial content management system, a platform for the management and publication of geospatial data. Prior to 5.1.0, a crafted vector file layer name supplied during upload allows a low-privileged remote user to inject shell syntax and execute arbitrary operating-system commands on the GeoNode server. This issue is fixed in version 5.1.0.

- [https://github.com/comradezephyr/CVE-2026-33050](https://github.com/comradezephyr/CVE-2026-33050) :  ![starts](https://img.shields.io/github/stars/comradezephyr/CVE-2026-33050.svg) ![forks](https://img.shields.io/github/forks/comradezephyr/CVE-2026-33050.svg)


## CVE-2026-19803
 The Printcart Store – Web to Print Product Designer for WooCommerce plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 2.13.2. This is due to the `nbu_crop_image` AJAX handler accepting a user-supplied `url` parameter that `Nbdesigner_IO::convert_url_to_path()` concatenates onto the uploads base directory without normalizing or stripping `../` sequences, and then deriving both the output directory and output file extension via `pathinfo()` from the same attacker-controlled path — with no `stripImage()` call before `writeImage()` is invoked. This makes it possible for unauthenticated attackers to write attacker-controlled PHP content to arbitrary locations outside the uploads directory, resulting in remote code execution when the written file is subsequently requested. This vulnerability is only exploitable when the `nbdesigner_upload_popup_style` site option is set to `a` (Advanced Upload Popup), which causes the handler to be registered for unauthenticated requests; however, the required `save-design` nonce is printed on the fully public frontend `upload-design-file` page, making it trivially obtainable by any anonymous visitor once that configuration is active.

- [https://github.com/Aureels/CVE-2026-19803](https://github.com/Aureels/CVE-2026-19803) :  ![starts](https://img.shields.io/github/stars/Aureels/CVE-2026-19803.svg) ![forks](https://img.shields.io/github/forks/Aureels/CVE-2026-19803.svg)


## CVE-2026-11176
 Inappropriate implementation in Media in Google Chrome prior to 149.0.7827.53 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/suominen/CVE-2026-111760](https://github.com/suominen/CVE-2026-111760) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-111760.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-111760.svg)
- [https://github.com/Ghost-Bx1/cve-2026-111760-git-submodule-symlink-rce](https://github.com/Ghost-Bx1/cve-2026-111760-git-submodule-symlink-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-111760-git-submodule-symlink-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-111760-git-submodule-symlink-rce.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/xvanpan/CVE-2026-109618](https://github.com/xvanpan/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/xvanpan/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/xvanpan/CVE-2026-109618.svg)
- [https://github.com/debugactiveprocess/CVE-2026-109618](https://github.com/debugactiveprocess/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/debugactiveprocess/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/debugactiveprocess/CVE-2026-109618.svg)


## CVE-2026-7695
 A vulnerability has been found in Acrel Electrical EEMS Enterprise Power Operation and Maintenance Cloud Platform 1.3.0. This affects an unknown function of the file /SubstationWEBV2/main/elecMaxMinAvgValue. The manipulation of the argument fCircuitids leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/ansonhsu-ai/synology-dsm-cve-2026-76954-ste](https://github.com/ansonhsu-ai/synology-dsm-cve-2026-76954-ste) :  ![starts](https://img.shields.io/github/stars/ansonhsu-ai/synology-dsm-cve-2026-76954-ste.svg) ![forks](https://img.shields.io/github/forks/ansonhsu-ai/synology-dsm-cve-2026-76954-ste.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/dnlid/CVE-2026-43499](https://github.com/dnlid/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/dnlid/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/dnlid/CVE-2026-43499.svg)
- [https://github.com/igconitoguy/CVE-2026-43499-Poc-Analysis](https://github.com/igconitoguy/CVE-2026-43499-Poc-Analysis) :  ![starts](https://img.shields.io/github/stars/igconitoguy/CVE-2026-43499-Poc-Analysis.svg) ![forks](https://img.shields.io/github/forks/igconitoguy/CVE-2026-43499-Poc-Analysis.svg)


## CVE-2026-2039
The specific flaw exists within the configuration of the MArc.Store.Remoting.exe process, which listens on port 8018. The issue results from the lack of authorization prior to allowing access to functionality. An attacker can leverage this in conjunction with other vulnerabilities to execute code in the context of SYSTEM. Was ZDI-CAN-28597.

- [https://github.com/MicrosoftARMAssembler/CVE-2026-2039819-PoC](https://github.com/MicrosoftARMAssembler/CVE-2026-2039819-PoC) :  ![starts](https://img.shields.io/github/stars/MicrosoftARMAssembler/CVE-2026-2039819-PoC.svg) ![forks](https://img.shields.io/github/forks/MicrosoftARMAssembler/CVE-2026-2039819-PoC.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/godylockz/CVE-2025-32432](https://github.com/godylockz/CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/godylockz/CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/godylockz/CVE-2025-32432.svg)


## CVE-2024-47176
 CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL. When combined with other vulnerabilities, such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker can execute arbitrary commands remotely on the target machine without authentication when a malicious printer is printed to.

- [https://github.com/Md-Nafiul-Hamim/cups-browse-exploit-detection](https://github.com/Md-Nafiul-Hamim/cups-browse-exploit-detection) :  ![starts](https://img.shields.io/github/stars/Md-Nafiul-Hamim/cups-browse-exploit-detection.svg) ![forks](https://img.shields.io/github/forks/Md-Nafiul-Hamim/cups-browse-exploit-detection.svg)


## CVE-2024-36779
 Sourcecodester Stock Management System v1.0 is vulnerable to SQL Injection via editCategories.php.

- [https://github.com/rw-a3/rw-stock](https://github.com/rw-a3/rw-stock) :  ![starts](https://img.shields.io/github/stars/rw-a3/rw-stock.svg) ![forks](https://img.shields.io/github/forks/rw-a3/rw-stock.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/astr4liteEx/CVE-2024-36401](https://github.com/astr4liteEx/CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/astr4liteEx/CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/astr4liteEx/CVE-2024-36401.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/OblivionDH/oblivion-cve-2024-25600-scanner](https://github.com/OblivionDH/oblivion-cve-2024-25600-scanner) :  ![starts](https://img.shields.io/github/stars/OblivionDH/oblivion-cve-2024-25600-scanner.svg) ![forks](https://img.shields.io/github/forks/OblivionDH/oblivion-cve-2024-25600-scanner.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/itnsapurbalingga/POC-CVE-2024-23897](https://github.com/itnsapurbalingga/POC-CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/itnsapurbalingga/POC-CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/itnsapurbalingga/POC-CVE-2024-23897.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/lasthopebro/Noregressh](https://github.com/lasthopebro/Noregressh) :  ![starts](https://img.shields.io/github/stars/lasthopebro/Noregressh.svg) ![forks](https://img.shields.io/github/forks/lasthopebro/Noregressh.svg)


## CVE-2024-4442
 The Salon booking system plugin for WordPress is vulnerable to arbitrary file deletion in all versions up to, and including, 9.8. This is due to the plugin not properly validating the path of an uploaded file prior to deleting it. This makes it possible for unauthenticated attackers to delete arbitrary files, including the wp-config.php file, which can make site takeover and remote code execution possible. This was partially patched in 9.9, and sufficiently patched in 10.0. CVE-2024-37231 appears to be a duplicate of this issue.

- [https://github.com/rw-a3/rw-salon](https://github.com/rw-a3/rw-salon) :  ![starts](https://img.shields.io/github/stars/rw-a3/rw-salon.svg) ![forks](https://img.shields.io/github/forks/rw-a3/rw-salon.svg)


## CVE-2024-3495
 The Country State City Dropdown CF7 plugin for WordPress is vulnerable to SQL Injection via the ‘cnt’ and 'sid' parameters in versions up to, and including, 2.7.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/rw-a3/rw-country-state-city-auto-dropdown](https://github.com/rw-a3/rw-country-state-city-auto-dropdown) :  ![starts](https://img.shields.io/github/stars/rw-a3/rw-country-state-city-auto-dropdown.svg) ![forks](https://img.shields.io/github/forks/rw-a3/rw-country-state-city-auto-dropdown.svg)


## CVE-2023-46604
which fixes this issue.

- [https://github.com/Abdelhalim11/CyberDefenders-OpenWire](https://github.com/Abdelhalim11/CyberDefenders-OpenWire) :  ![starts](https://img.shields.io/github/stars/Abdelhalim11/CyberDefenders-OpenWire.svg) ![forks](https://img.shields.io/github/forks/Abdelhalim11/CyberDefenders-OpenWire.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)


## CVE-2021-36260
 A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.

- [https://github.com/ZeroHackOrg/camera-hacking](https://github.com/ZeroHackOrg/camera-hacking) :  ![starts](https://img.shields.io/github/stars/ZeroHackOrg/camera-hacking.svg) ![forks](https://img.shields.io/github/forks/ZeroHackOrg/camera-hacking.svg)


## CVE-2021-30563
 Type Confusion in V8 in Google Chrome prior to 91.0.4472.164 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/RemiPelloux/HackoogleMini](https://github.com/RemiPelloux/HackoogleMini) :  ![starts](https://img.shields.io/github/stars/RemiPelloux/HackoogleMini.svg) ![forks](https://img.shields.io/github/forks/RemiPelloux/HackoogleMini.svg)


## CVE-2020-24186
 A Remote Code Execution vulnerability exists in the gVectors wpDiscuz plugin 7.0 through 7.0.4 for WordPress, which allows unauthenticated users to upload any type of file, including PHP files via the wmuUploadFiles AJAX action.

- [https://github.com/SimonL01/wpdiscuz-cve-2020-24186](https://github.com/SimonL01/wpdiscuz-cve-2020-24186) :  ![starts](https://img.shields.io/github/stars/SimonL01/wpdiscuz-cve-2020-24186.svg) ![forks](https://img.shields.io/github/forks/SimonL01/wpdiscuz-cve-2020-24186.svg)


## CVE-2018-19320
 The GDrv low-level driver in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before 1.57, XTREME GAMING ENGINE before 1.26, and OC GURU II v2.08 exposes ring0 memcpy-like functionality that could allow a local attacker to take complete control of the affected system.

- [https://github.com/saretawa/megumin.exe](https://github.com/saretawa/megumin.exe) :  ![starts](https://img.shields.io/github/stars/saretawa/megumin.exe.svg) ![forks](https://img.shields.io/github/forks/saretawa/megumin.exe.svg)


## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.

- [https://github.com/HarshithM834/cyse425-samba-security-assessment](https://github.com/HarshithM834/cyse425-samba-security-assessment) :  ![starts](https://img.shields.io/github/stars/HarshithM834/cyse425-samba-security-assessment.svg) ![forks](https://img.shields.io/github/forks/HarshithM834/cyse425-samba-security-assessment.svg)


## CVE-2013-1453
 plugins/system/highlight/highlight.php in Joomla! 3.0.x through 3.0.2 and 2.5.x through 2.5.8 allows attackers to unserialize arbitrary PHP objects to obtain sensitive information, delete arbitrary directories, conduct SQL injection attacks, and possibly have other impacts via the highlight parameter.  Note: it was originally reported that this issue only allowed attackers to obtain sensitive information, but later analysis demonstrated that other attacks exist.

- [https://github.com/stupazz/joomla-cve-2013-1453](https://github.com/stupazz/joomla-cve-2013-1453) :  ![starts](https://img.shields.io/github/stars/stupazz/joomla-cve-2013-1453.svg) ![forks](https://img.shields.io/github/forks/stupazz/joomla-cve-2013-1453.svg)


## CVE-2009-2265
 Multiple directory traversal vulnerabilities in FCKeditor before 2.6.4.1 allow remote attackers to create executable files in arbitrary directories via directory traversal sequences in the input to unspecified connector modules, as exploited in the wild for remote code execution in July 2009, related to the file browser and the editor/filemanager/connectors/ directory.

- [https://github.com/d4ytox/CVE-2009-2265](https://github.com/d4ytox/CVE-2009-2265) :  ![starts](https://img.shields.io/github/stars/d4ytox/CVE-2009-2265.svg) ![forks](https://img.shields.io/github/forks/d4ytox/CVE-2009-2265.svg)

