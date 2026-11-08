# Update 2026-11-08
## CVE-2026-123488
 Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an unauthenticated SQL injection vulnerability in the element search endpoint because the attribute parameter is concatenated into the query unsanitized and emulated PDO prepares allow stacked statements. Remote attackers can read and write the database, setting the admin flag or overwriting password hashes in the users table to gain administrator access.

- [https://github.com/fixedbyreboot/CVE-2026-123488-POC](https://github.com/fixedbyreboot/CVE-2026-123488-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-123488-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-123488-POC.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/Hika-sec/sshole-scanner](https://github.com/Hika-sec/sshole-scanner) :  ![starts](https://img.shields.io/github/stars/Hika-sec/sshole-scanner.svg) ![forks](https://img.shields.io/github/forks/Hika-sec/sshole-scanner.svg)
- [https://github.com/Maalfer/CVE-2026-123158](https://github.com/Maalfer/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/Maalfer/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/Maalfer/CVE-2026-123158.svg)
- [https://github.com/HackSpeak/CVE-2026-123158](https://github.com/HackSpeak/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-123158.svg)
- [https://github.com/halilkirazkaya/CVE-2026-123158](https://github.com/halilkirazkaya/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/halilkirazkaya/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/halilkirazkaya/CVE-2026-123158.svg)
- [https://github.com/Funcan/sshole](https://github.com/Funcan/sshole) :  ![starts](https://img.shields.io/github/stars/Funcan/sshole.svg) ![forks](https://img.shields.io/github/forks/Funcan/sshole.svg)
- [https://github.com/ansonhsu-ai/sshhole-cve-2026-123158-ste](https://github.com/ansonhsu-ai/sshhole-cve-2026-123158-ste) :  ![starts](https://img.shields.io/github/stars/ansonhsu-ai/sshhole-cve-2026-123158-ste.svg) ![forks](https://img.shields.io/github/forks/ansonhsu-ai/sshhole-cve-2026-123158-ste.svg)
- [https://github.com/CriticalWombat/sshole_scanner-CVE-2026-123158](https://github.com/CriticalWombat/sshole_scanner-CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/CriticalWombat/sshole_scanner-CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/CriticalWombat/sshole_scanner-CVE-2026-123158.svg)
- [https://github.com/mc493/openssh-musl-enterprise--hardening-cve-2026-123158](https://github.com/mc493/openssh-musl-enterprise--hardening-cve-2026-123158) :  ![starts](https://img.shields.io/github/stars/mc493/openssh-musl-enterprise--hardening-cve-2026-123158.svg) ![forks](https://img.shields.io/github/forks/mc493/openssh-musl-enterprise--hardening-cve-2026-123158.svg)
- [https://github.com/crash00xd/CVE-2026-123158_SSHRole_PoC](https://github.com/crash00xd/CVE-2026-123158_SSHRole_PoC) :  ![starts](https://img.shields.io/github/stars/crash00xd/CVE-2026-123158_SSHRole_PoC.svg) ![forks](https://img.shields.io/github/forks/crash00xd/CVE-2026-123158_SSHRole_PoC.svg)
- [https://github.com/lpizziniacofortinet/cve-2026-123158-openssh-musl-lab](https://github.com/lpizziniacofortinet/cve-2026-123158-openssh-musl-lab) :  ![starts](https://img.shields.io/github/stars/lpizziniacofortinet/cve-2026-123158-openssh-musl-lab.svg) ![forks](https://img.shields.io/github/forks/lpizziniacofortinet/cve-2026-123158-openssh-musl-lab.svg)
- [https://github.com/Hel1um17/sshole-bypass-openssh-password](https://github.com/Hel1um17/sshole-bypass-openssh-password) :  ![starts](https://img.shields.io/github/stars/Hel1um17/sshole-bypass-openssh-password.svg) ![forks](https://img.shields.io/github/forks/Hel1um17/sshole-bypass-openssh-password.svg)
- [https://github.com/techtaek77/sshole-guide](https://github.com/techtaek77/sshole-guide) :  ![starts](https://img.shields.io/github/stars/techtaek77/sshole-guide.svg) ![forks](https://img.shields.io/github/forks/techtaek77/sshole-guide.svg)
- [https://github.com/mlazzarotto/ansible-sshole-remediate](https://github.com/mlazzarotto/ansible-sshole-remediate) :  ![starts](https://img.shields.io/github/stars/mlazzarotto/ansible-sshole-remediate.svg) ![forks](https://img.shields.io/github/forks/mlazzarotto/ansible-sshole-remediate.svg)
- [https://github.com/shenxianpeng/check-sshole](https://github.com/shenxianpeng/check-sshole) :  ![starts](https://img.shields.io/github/stars/shenxianpeng/check-sshole.svg) ![forks](https://img.shields.io/github/forks/shenxianpeng/check-sshole.svg)
- [https://github.com/akarkode/alpine-openssh-sshole-auth-bypass](https://github.com/akarkode/alpine-openssh-sshole-auth-bypass) :  ![starts](https://img.shields.io/github/stars/akarkode/alpine-openssh-sshole-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/akarkode/alpine-openssh-sshole-auth-bypass.svg)
- [https://github.com/techdevfun/alpinegate](https://github.com/techdevfun/alpinegate) :  ![starts](https://img.shields.io/github/stars/techdevfun/alpinegate.svg) ![forks](https://img.shields.io/github/forks/techdevfun/alpinegate.svg)


## CVE-2026-123025
 An OS Command Injection vulnerability was discovered in the Google Cloud DNS validation module of the OPNsense os-acme-client plugin through 4.17. The DnsGcloud::prepare() method decodes the dns_gcloud_key model field and directly interpolates the string fields gcloud_account and gcloud_project into a shell command passed to proc_open() via LeUtils::run_shell_command() without any validation or escaping. A remote authenticated user with privileges to issue or renew certificates through the WebGUI/API can achieve arbitrary code execution as root.

- [https://github.com/cppghoul/CVE-2026-123025](https://github.com/cppghoul/CVE-2026-123025) :  ![starts](https://img.shields.io/github/stars/cppghoul/CVE-2026-123025.svg) ![forks](https://img.shields.io/github/forks/cppghoul/CVE-2026-123025.svg)


## CVE-2026-123014
 iTerm2 before 3.7.7beta2 has an argument injection vulnerability in the x-man-page: URL handler, allowing an attacker to execute arbitrary commands with the privileges of the logged-in user by inducing the user to open a crafted URL in iTerm2. Percent-encoded NUL characters survive input sanitization and are subsequently converted to whitespace during command-line parsing, allowing injection of additional arguments to /usr/bin/man. An attacker can inject the -P option to select an attacker-controlled pager command. NOTE: this issue exists because of an incomplete fix for CVE-2023-46321.

- [https://github.com/giki-shergill/CVE-2026-123014---iTerm2-Terminal](https://github.com/giki-shergill/CVE-2026-123014---iTerm2-Terminal) :  ![starts](https://img.shields.io/github/stars/giki-shergill/CVE-2026-123014---iTerm2-Terminal.svg) ![forks](https://img.shields.io/github/forks/giki-shergill/CVE-2026-123014---iTerm2-Terminal.svg)


## CVE-2026-120491
 Wing FTP Server before 8.2.6 contains a stored cross-site scripting vulnerability that allows authenticated web-client users to inject script by sending a crafted nowpath parameter to webclient/makethumb.html. Attackers can break out of the directory CDATA section in admin_get_lastconn.html XML to forge a connection id, which executes in administrators' browsers when admin_connection_list.html auto-refreshes, enabling Lua console abuse.

- [https://github.com/3jee/CVE-2026-120491](https://github.com/3jee/CVE-2026-120491) :  ![starts](https://img.shields.io/github/stars/3jee/CVE-2026-120491.svg) ![forks](https://img.shields.io/github/forks/3jee/CVE-2026-120491.svg)


## CVE-2026-120209
 AJ-Report through 1.7.1 signs share tokens with a hard-coded JWT secret, allowing attackers to forge valid Share-Tokens offline. Attackers can mint a token with reportCode 'dataSet' to access the testTransform endpoint, which passes scripts to GroovyClassLoader for unauthenticated remote code execution.

- [https://github.com/Nxploited/CVE-2026-120209](https://github.com/Nxploited/CVE-2026-120209) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-120209.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-120209.svg)


## CVE-2026-119977
 WordPress Core is vulnerable to Remote Code Execution in versions 4.7 through 7.1.3. This is due to predictable, web-accessible staging paths used during full-package core upgrades. This makes it possible for unauthenticated attackers to execute code on the server during the upgrade window.

- [https://github.com/paulmann/Bash_WP-CLI_Update](https://github.com/paulmann/Bash_WP-CLI_Update) :  ![starts](https://img.shields.io/github/stars/paulmann/Bash_WP-CLI_Update.svg) ![forks](https://img.shields.io/github/forks/paulmann/Bash_WP-CLI_Update.svg)
- [https://github.com/hacermuden/CVE-2026-119977](https://github.com/hacermuden/CVE-2026-119977) :  ![starts](https://img.shields.io/github/stars/hacermuden/CVE-2026-119977.svg) ![forks](https://img.shields.io/github/forks/hacermuden/CVE-2026-119977.svg)


## CVE-2026-118570
 Cross-Site Request Forgery (CSRF) vulnerability in Drupal Fasttoggle allows Cross Site Request Forgery. This issue affects Fasttoggle versions: from 0.0.0 to 4.1.1.

- [https://github.com/yuwkaaa/CVE-2026-118570](https://github.com/yuwkaaa/CVE-2026-118570) :  ![starts](https://img.shields.io/github/stars/yuwkaaa/CVE-2026-118570.svg) ![forks](https://img.shields.io/github/forks/yuwkaaa/CVE-2026-118570.svg)


## CVE-2026-118569
 Incorrect Authorization vulnerability in Drupal Fasttoggle allows Forceful Browsing. This issue affects Fasttoggle versions: from 0.0.0 to 4.1.1.

- [https://github.com/yuwkaaa/CVE-2026-118569](https://github.com/yuwkaaa/CVE-2026-118569) :  ![starts](https://img.shields.io/github/stars/yuwkaaa/CVE-2026-118569.svg) ![forks](https://img.shields.io/github/forks/yuwkaaa/CVE-2026-118569.svg)


## CVE-2026-118423
 The WP Libre Form WordPress plugin 1.5.0.1 does not validate the type of files uploaded through its form submissions, allowing unauthenticated attackers to upload PHP files to a web-accessible location and execute them, leading to remote code execution.

- [https://github.com/im0xfay/CVE-2026-118423](https://github.com/im0xfay/CVE-2026-118423) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-118423.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-118423.svg)
- [https://github.com/thiscitze/cve-2026-118423-poc](https://github.com/thiscitze/cve-2026-118423-poc) :  ![starts](https://img.shields.io/github/stars/thiscitze/cve-2026-118423-poc.svg) ![forks](https://img.shields.io/github/forks/thiscitze/cve-2026-118423-poc.svg)
- [https://github.com/Sable-Research/CVE-2026-118423-WP-Libre-Form](https://github.com/Sable-Research/CVE-2026-118423-WP-Libre-Form) :  ![starts](https://img.shields.io/github/stars/Sable-Research/CVE-2026-118423-WP-Libre-Form.svg) ![forks](https://img.shields.io/github/forks/Sable-Research/CVE-2026-118423-WP-Libre-Form.svg)


## CVE-2026-116779
 FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to 1.11.3, sofia_presence_handle_sip_i_message() split the To user of an inbound SIP MESSAGE on a plus sign and treated the left side as a chat protocol selector. Selecting the api chat proto reached switch_api_execute(), allowing a peer whose MESSAGE was accepted to run FreeSWITCH API commands, including operating-system command sinks, with the daemon's privileges. Inbound chat is enabled on the stock internal and external profiles, and any authenticated profile account is sufficient; stock directory users without password material can also remove that barrier in affected configurations. The flaw permits configuration and credential disclosure, arbitrary call control, and command execution, and exploitation has been observed in the wild. This issue is fixed in version 1.11.3.

- [https://github.com/hackzuoji/freeswitch-cve-2026-116779-POC](https://github.com/hackzuoji/freeswitch-cve-2026-116779-POC) :  ![starts](https://img.shields.io/github/stars/hackzuoji/freeswitch-cve-2026-116779-POC.svg) ![forks](https://img.shields.io/github/forks/hackzuoji/freeswitch-cve-2026-116779-POC.svg)


## CVE-2026-116214
 MacCMS v10 before 2026.1000.4054 contains an authentication bypass vulnerability that allows unauthenticated attackers to reset any member's password because check_msg() never compares msg_to. Attackers can request a recovery code to their own mailbox via user/findpass_msg, then submit it to user/findpass_reset with the victim's email or phone to take over the account.

- [https://github.com/zapstiko/CVE-2026-116214](https://github.com/zapstiko/CVE-2026-116214) :  ![starts](https://img.shields.io/github/stars/zapstiko/CVE-2026-116214.svg) ![forks](https://img.shields.io/github/forks/zapstiko/CVE-2026-116214.svg)


## CVE-2026-114630
 The ELEX WordPress HelpDesk & Customer Ticketing System plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the factory_reset function in all versions up to, and including, 3.3.8 This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php). This vulnerability is exploitable via a two-step chain: an unauthenticated attacker first stores an arbitrary ticket_attachment_path value by submitting a ticket through the nopriv eh_crm_new_ticket_post AJAX endpoint (whose nonce is publicly exposed via the [wsdesk_support] shortcode), then triggers the factory_reset routine via a GET request to wp-admin/admin.php?page=wsdesk_factory_reset, which is guarded only by is_admin() — a request-type check — rather than a capability check, causing unlink() to be called on the attacker-supplied path.

- [https://github.com/thiscitze/cve-2026-114630-poc](https://github.com/thiscitze/cve-2026-114630-poc) :  ![starts](https://img.shields.io/github/stars/thiscitze/cve-2026-114630-poc.svg) ![forks](https://img.shields.io/github/forks/thiscitze/cve-2026-114630-poc.svg)


## CVE-2026-114612
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From 1.87.0 until 1.100.4, 1.101.3, 1.102.2, 1.103.1, and 1.104.0-rc.2, the proxy reuses one cryptographic context for at-rest secrets and session tokens, allowing an authenticated internal user to have crafted metadata containing a forged administrator credential encrypted and returned by the API-key flow. Replaying that ciphertext as a bearer token causes the proxy to trust the forged proxy administrator identity, permitting administrative access and arbitrary commands through the MCP stdio endpoint. Versions 1.87.0 through 1.90.x require EXPERIMENTAL_UI_LOGIN to be enabled, while versions after 1.91.0 are exploitable in the default configuration. This issue was fixed in LiteLLM 1.100.4, 1.101.3, 1.102.2, 1.103.1, and 1.104.0-rc.2.

- [https://github.com/FORTBRIDGE-UK/CVEs](https://github.com/FORTBRIDGE-UK/CVEs) :  ![starts](https://img.shields.io/github/stars/FORTBRIDGE-UK/CVEs.svg) ![forks](https://img.shields.io/github/forks/FORTBRIDGE-UK/CVEs.svg)


## CVE-2026-113615
 The GS JWT Authentication for WP REST API WordPress plugin through 1.0.0 does not sanitize or parameterize a request value before using it in SQL queries on several unauthenticated REST routes, allowing unauthenticated attackers to perform SQL injection and obtain an administrator session.

- [https://github.com/thiscitze/cve-2026-113615-poc](https://github.com/thiscitze/cve-2026-113615-poc) :  ![starts](https://img.shields.io/github/stars/thiscitze/cve-2026-113615-poc.svg) ![forks](https://img.shields.io/github/forks/thiscitze/cve-2026-113615-poc.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/Hika-sec/http2shell-CVE-2026-111497](https://github.com/Hika-sec/http2shell-CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/Hika-sec/http2shell-CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/Hika-sec/http2shell-CVE-2026-111497.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/shellharbor/php-7.4-cve-2026-docker](https://github.com/shellharbor/php-7.4-cve-2026-docker) :  ![starts](https://img.shields.io/github/stars/shellharbor/php-7.4-cve-2026-docker.svg) ![forks](https://img.shields.io/github/forks/shellharbor/php-7.4-cve-2026-docker.svg)
- [https://github.com/Evil0ctal/php2shell-scanner](https://github.com/Evil0ctal/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/Evil0ctal/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/Evil0ctal/php2shell-scanner.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/shellharbor/php-8.1-cve-2026-docker](https://github.com/shellharbor/php-8.1-cve-2026-docker) :  ![starts](https://img.shields.io/github/stars/shellharbor/php-8.1-cve-2026-docker.svg) ![forks](https://img.shields.io/github/forks/shellharbor/php-8.1-cve-2026-docker.svg)
- [https://github.com/shellharbor/php-7.4-cve-2026-docker](https://github.com/shellharbor/php-7.4-cve-2026-docker) :  ![starts](https://img.shields.io/github/stars/shellharbor/php-7.4-cve-2026-docker.svg) ![forks](https://img.shields.io/github/forks/shellharbor/php-7.4-cve-2026-docker.svg)


## CVE-2026-101678
 Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J).   The supported version that is affected is 26.7.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Connectors.  Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of MySQL Connectors. CVSS 3.1 Base Score 4.3 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L).

- [https://github.com/ryanmurf/mysql-connector-j-cve-2026-101678-repro](https://github.com/ryanmurf/mysql-connector-j-cve-2026-101678-repro) :  ![starts](https://img.shields.io/github/stars/ryanmurf/mysql-connector-j-cve-2026-101678-repro.svg) ![forks](https://img.shields.io/github/forks/ryanmurf/mysql-connector-j-cve-2026-101678-repro.svg)


## CVE-2026-100109
 The Security For WooCommerce WordPress plugin from 1.0.10 to 1.0.16 does not perform capability checks when creating users through an action available to unauthenticated visitors, and lets the caller choose the new account's role, allowing unauthenticated attackers to create administrator accounts and take over the site.

- [https://github.com/thiscitze/cve-2026-100109-poc](https://github.com/thiscitze/cve-2026-100109-poc) :  ![starts](https://img.shields.io/github/stars/thiscitze/cve-2026-100109-poc.svg) ![forks](https://img.shields.io/github/forks/thiscitze/cve-2026-100109-poc.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/s97472091-pixel/verification-gap-cve-2026-98432](https://github.com/s97472091-pixel/verification-gap-cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/s97472091-pixel/verification-gap-cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/s97472091-pixel/verification-gap-cve-2026-98432.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/kzktor/ic-timer-lpe](https://github.com/kzktor/ic-timer-lpe) :  ![starts](https://img.shields.io/github/stars/kzktor/ic-timer-lpe.svg) ![forks](https://img.shields.io/github/forks/kzktor/ic-timer-lpe.svg)
- [https://github.com/Dream-Rainy/CVE-2026-98260](https://github.com/Dream-Rainy/CVE-2026-98260) :  ![starts](https://img.shields.io/github/stars/Dream-Rainy/CVE-2026-98260.svg) ![forks](https://img.shields.io/github/forks/Dream-Rainy/CVE-2026-98260.svg)
- [https://github.com/VinSon326/CVE-2026-98260-iQOO12](https://github.com/VinSon326/CVE-2026-98260-iQOO12) :  ![starts](https://img.shields.io/github/stars/VinSon326/CVE-2026-98260-iQOO12.svg) ![forks](https://img.shields.io/github/forks/VinSon326/CVE-2026-98260-iQOO12.svg)
- [https://github.com/SecPhases/CVE-2026-98260-GhostKey](https://github.com/SecPhases/CVE-2026-98260-GhostKey) :  ![starts](https://img.shields.io/github/stars/SecPhases/CVE-2026-98260-GhostKey.svg) ![forks](https://img.shields.io/github/forks/SecPhases/CVE-2026-98260-GhostKey.svg)
- [https://github.com/nemoiwkryang/CVE-2026-98260-pkt110-kernelsu](https://github.com/nemoiwkryang/CVE-2026-98260-pkt110-kernelsu) :  ![starts](https://img.shields.io/github/stars/nemoiwkryang/CVE-2026-98260-pkt110-kernelsu.svg) ![forks](https://img.shields.io/github/forks/nemoiwkryang/CVE-2026-98260-pkt110-kernelsu.svg)
- [https://github.com/ANYAEGW/CVE-2026-98260-amg-an00](https://github.com/ANYAEGW/CVE-2026-98260-amg-an00) :  ![starts](https://img.shields.io/github/stars/ANYAEGW/CVE-2026-98260-amg-an00.svg) ![forks](https://img.shields.io/github/forks/ANYAEGW/CVE-2026-98260-amg-an00.svg)


## CVE-2026-97229
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 19.2 before 19.2.8, 19.3 before 19.3.5, and 19.4 before 19.4.2 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server via a specially crafted regular expression in a CI/CD configuration, due to insufficient regular expression validation.

- [https://github.com/Ghost-Bx1/cve-2026-97229-gitlab-ci-rce](https://github.com/Ghost-Bx1/cve-2026-97229-gitlab-ci-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-97229-gitlab-ci-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-97229-gitlab-ci-rce.svg)


## CVE-2026-84473
 Authentication Bypass / Missing Brute-Force Protection in remote.php/webdav/ in ownCloud ownCloud server 10.16.3 allows an unauthenticated remote attacker to perform unlimited online password guessing against WebDAV accounts via repeated HTTP Basic Authentication requests to the WebDAV endpoint.

- [https://github.com/KOBUKOVUI/CVE-2026-84473](https://github.com/KOBUKOVUI/CVE-2026-84473) :  ![starts](https://img.shields.io/github/stars/KOBUKOVUI/CVE-2026-84473.svg) ![forks](https://img.shields.io/github/forks/KOBUKOVUI/CVE-2026-84473.svg)


## CVE-2026-83844
 Out-of-bounds read in Windows Paint allows an unauthorized attacker to execute code over a network.

- [https://github.com/LilPoule/CVE-2026-83844](https://github.com/LilPoule/CVE-2026-83844) :  ![starts](https://img.shields.io/github/stars/LilPoule/CVE-2026-83844.svg) ![forks](https://img.shields.io/github/forks/LilPoule/CVE-2026-83844.svg)
- [https://github.com/0xBlackash/CVE-2026-83844](https://github.com/0xBlackash/CVE-2026-83844) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-83844.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-83844.svg)
- [https://github.com/Cobrastrike62/CVE-2026-83844-Detection](https://github.com/Cobrastrike62/CVE-2026-83844-Detection) :  ![starts](https://img.shields.io/github/stars/Cobrastrike62/CVE-2026-83844-Detection.svg) ![forks](https://img.shields.io/github/forks/Cobrastrike62/CVE-2026-83844-Detection.svg)
- [https://github.com/mokshshah18/CVE-2026-83844-PoC-MS-paint-v-11.2609.401.0](https://github.com/mokshshah18/CVE-2026-83844-PoC-MS-paint-v-11.2609.401.0) :  ![starts](https://img.shields.io/github/stars/mokshshah18/CVE-2026-83844-PoC-MS-paint-v-11.2609.401.0.svg) ![forks](https://img.shields.io/github/forks/mokshshah18/CVE-2026-83844-PoC-MS-paint-v-11.2609.401.0.svg)


## CVE-2026-83542
Users are recommended to upgrade to version 24.09.08, which fixes this issue.

- [https://github.com/foxcornlab/ofbiz-scanner](https://github.com/foxcornlab/ofbiz-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/ofbiz-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/ofbiz-scanner.svg)


## CVE-2026-80914
listening, alive socket, and bail out otherwise.

- [https://github.com/nanhang-950/CVE-2026-80914-POC](https://github.com/nanhang-950/CVE-2026-80914-POC) :  ![starts](https://img.shields.io/github/stars/nanhang-950/CVE-2026-80914-POC.svg) ![forks](https://img.shields.io/github/forks/nanhang-950/CVE-2026-80914-POC.svg)


## CVE-2026-61082
 Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J).  Supported versions that are affected are 9.7.0-9.7.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Connectors.  Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all MySQL Connectors accessible data. CVSS 3.1 Base Score 6.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N).

- [https://github.com/ryanmurf/mysql-connector-j-cve-2026-61082-repro](https://github.com/ryanmurf/mysql-connector-j-cve-2026-61082-repro) :  ![starts](https://img.shields.io/github/stars/ryanmurf/mysql-connector-j-cve-2026-61082-repro.svg) ![forks](https://img.shields.io/github/forks/ryanmurf/mysql-connector-j-cve-2026-61082-repro.svg)


## CVE-2026-60623
 Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J).  Supported versions that are affected are 9.7.0-9.7.1. Difficult to exploit vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Connectors.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all MySQL Connectors accessible data as well as  unauthorized access to critical data or complete access to all MySQL Connectors accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of MySQL Connectors. CVSS 3.1 Base Score 7.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:L).

- [https://github.com/ryanmurf/mysql-connector-j-cve-2026-60623-repro](https://github.com/ryanmurf/mysql-connector-j-cve-2026-60623-repro) :  ![starts](https://img.shields.io/github/stars/ryanmurf/mysql-connector-j-cve-2026-60623-repro.svg) ![forks](https://img.shields.io/github/forks/ryanmurf/mysql-connector-j-cve-2026-60623-repro.svg)


## CVE-2026-60586
 Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J).  Supported versions that are affected are 9.7.0-9.7.1. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Connectors.  While the vulnerability is in MySQL Connectors, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all MySQL Connectors accessible data. CVSS 3.1 Base Score 7.7 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N).

- [https://github.com/ryanmurf/mysql-connector-j-cve-2026-60586-repro](https://github.com/ryanmurf/mysql-connector-j-cve-2026-60586-repro) :  ![starts](https://img.shields.io/github/stars/ryanmurf/mysql-connector-j-cve-2026-60586-repro.svg) ![forks](https://img.shields.io/github/forks/ryanmurf/mysql-connector-j-cve-2026-60586-repro.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/anubis-claud/CVE-2026-54121-Certighost](https://github.com/anubis-claud/CVE-2026-54121-Certighost) :  ![starts](https://img.shields.io/github/stars/anubis-claud/CVE-2026-54121-Certighost.svg) ![forks](https://img.shields.io/github/forks/anubis-claud/CVE-2026-54121-Certighost.svg)


## CVE-2026-50679
 Heap-based buffer overflow in Microsoft Windows Search Component allows an authorized attacker to elevate privileges locally.

- [https://github.com/h4urek/CVE-2026-50679](https://github.com/h4urek/CVE-2026-50679) :  ![starts](https://img.shields.io/github/stars/h4urek/CVE-2026-50679.svg) ![forks](https://img.shields.io/github/forks/h4urek/CVE-2026-50679.svg)


## CVE-2026-48356
 Adobe Commerce is affected by an Unrestricted Upload of File with Dangerous Type vulnerability that could result in arbitrary code execution in the context of the current user, potentially gaining elevated access or control over the victim's account or session. Exploitation of this issue requires user interaction in that a victim must visit a maliciously crafted URL or interact with a compromised web page. Scope is changed.

- [https://github.com/Ghost-Bx1/cve-2026-48356-magento-file-upload-rce](https://github.com/Ghost-Bx1/cve-2026-48356-magento-file-upload-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-48356-magento-file-upload-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-48356-magento-file-upload-rce.svg)
- [https://github.com/Cyber-BansalAI/polyshell-2026](https://github.com/Cyber-BansalAI/polyshell-2026) :  ![starts](https://img.shields.io/github/stars/Cyber-BansalAI/polyshell-2026.svg) ![forks](https://img.shields.io/github/forks/Cyber-BansalAI/polyshell-2026.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Escosis/V2463A-LPE](https://github.com/Escosis/V2463A-LPE) :  ![starts](https://img.shields.io/github/stars/Escosis/V2463A-LPE.svg) ![forks](https://img.shields.io/github/forks/Escosis/V2463A-LPE.svg)
- [https://github.com/thedavidweng/ghostlock-z3q](https://github.com/thedavidweng/ghostlock-z3q) :  ![starts](https://img.shields.io/github/stars/thedavidweng/ghostlock-z3q.svg) ![forks](https://img.shields.io/github/forks/thedavidweng/ghostlock-z3q.svg)
- [https://github.com/tingao/debian-on-s23-ultra](https://github.com/tingao/debian-on-s23-ultra) :  ![starts](https://img.shields.io/github/stars/tingao/debian-on-s23-ultra.svg) ![forks](https://img.shields.io/github/forks/tingao/debian-on-s23-ultra.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/EmilyTsum/Shizuka](https://github.com/EmilyTsum/Shizuka) :  ![starts](https://img.shields.io/github/stars/EmilyTsum/Shizuka.svg) ![forks](https://img.shields.io/github/forks/EmilyTsum/Shizuka.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/thiscitze/cve-2026-41651-poc](https://github.com/thiscitze/cve-2026-41651-poc) :  ![starts](https://img.shields.io/github/stars/thiscitze/cve-2026-41651-poc.svg) ![forks](https://img.shields.io/github/forks/thiscitze/cve-2026-41651-poc.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/LaRemontada12/CVE-2026-39987-Marimo-RCE-SOC-Detection](https://github.com/LaRemontada12/CVE-2026-39987-Marimo-RCE-SOC-Detection) :  ![starts](https://img.shields.io/github/stars/LaRemontada12/CVE-2026-39987-Marimo-RCE-SOC-Detection.svg) ![forks](https://img.shields.io/github/forks/LaRemontada12/CVE-2026-39987-Marimo-RCE-SOC-Detection.svg)


## CVE-2026-33871
 Netty is an asynchronous, event-driven network application framework. In versions prior to 4.1.132.Final and 4.2.10.Final, a remote user can trigger a Denial of Service (DoS) against a Netty HTTP/2 server by sending a flood of `CONTINUATION` frames. The server's lack of a limit on the number of `CONTINUATION` frames, combined with a bypass of existing size-based mitigations using zero-byte frames, allows an user to cause excessive CPU consumption with minimal bandwidth, rendering the server unresponsive. Versions 4.1.132.Final and 4.2.10.Final fix the issue.

- [https://github.com/iam-s21-caece/PoC-CVE-2026-33871](https://github.com/iam-s21-caece/PoC-CVE-2026-33871) :  ![starts](https://img.shields.io/github/stars/iam-s21-caece/PoC-CVE-2026-33871.svg) ![forks](https://img.shields.io/github/forks/iam-s21-caece/PoC-CVE-2026-33871.svg)


## CVE-2026-33439
 Open Access Management (OpenAM) is an access management solution. Prior to 16.0.6, OpenIdentityPlatform OpenAM is vulnerable to pre-authentication Remote Code Execution (RCE) via unsafe Java deserialization of the jato.clientSession HTTP parameter. This bypasses the WhitelistObjectInputStream mitigation that was applied to the jato.pageSession parameter after CVE-2021-35464. An unauthenticated attacker can achieve arbitrary command execution on the server by sending a crafted serialized Java object as the jato.clientSession GET/POST parameter to any JATO ViewBean endpoint whose JSP contains jato:form tags (e.g., the Password Reset pages). This vulnerability is fixed in 16.0.6.

- [https://github.com/duohnson/CVE-2026-33439-PoC](https://github.com/duohnson/CVE-2026-33439-PoC) :  ![starts](https://img.shields.io/github/stars/duohnson/CVE-2026-33439-PoC.svg) ![forks](https://img.shields.io/github/forks/duohnson/CVE-2026-33439-PoC.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/NSK-394/kavach-loop](https://github.com/NSK-394/kavach-loop) :  ![starts](https://img.shields.io/github/stars/NSK-394/kavach-loop.svg) ![forks](https://img.shields.io/github/forks/NSK-394/kavach-loop.svg)


## CVE-2026-22766
 Dell Wyse Management Suite, versions prior to WMS 5.5, contain an Unrestricted Upload of File with Dangerous Type vulnerability. A high privileged attacker with remote access could potentially exploit this vulnerability, leading to Remote execution.

- [https://github.com/Xitro01/CVE-2026-22765-poc](https://github.com/Xitro01/CVE-2026-22765-poc) :  ![starts](https://img.shields.io/github/stars/Xitro01/CVE-2026-22765-poc.svg) ![forks](https://img.shields.io/github/forks/Xitro01/CVE-2026-22765-poc.svg)


## CVE-2026-22765
 Dell Wyse Management Suite, versions prior to WMS 5.5, contain a Missing Authorization vulnerability. A low privileged attacker with remote access could potentially exploit this vulnerability, leading to Elevation of Privileges.

- [https://github.com/Xitro01/CVE-2026-22765-poc](https://github.com/Xitro01/CVE-2026-22765-poc) :  ![starts](https://img.shields.io/github/stars/Xitro01/CVE-2026-22765-poc.svg) ![forks](https://img.shields.io/github/forks/Xitro01/CVE-2026-22765-poc.svg)


## CVE-2026-20700
 A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 26.3 and iPadOS 26.3, macOS Tahoe 26.3, tvOS 26.3, visionOS 26.3, watchOS 26.3. An attacker with memory write capability may be able to execute arbitrary code. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 and CVE-2025-43529 were also issued in response to this report.

- [https://github.com/haroonwattoo556677-max/ios-forensic-exploitation-framework](https://github.com/haroonwattoo556677-max/ios-forensic-exploitation-framework) :  ![starts](https://img.shields.io/github/stars/haroonwattoo556677-max/ios-forensic-exploitation-framework.svg) ![forks](https://img.shields.io/github/forks/haroonwattoo556677-max/ios-forensic-exploitation-framework.svg)


## CVE-2026-20253
 In Splunk Enterprise 10.2 versions below 10.2.4 and 10 versions below 10.0.7, an unauthenticated user could create or truncate arbitrary files through a PostgreSQL sidecar service endpoint. The vulnerability exists because the PostgreSQL sidecar service endpoint lacks authentication controls, allowing any network-reachable user to invoke file operations without credentials. Splunk Enterprise versions 9.4 and earlier are not affected. If you cannot immediately upgrade to a fixed version, you can mitigate this vulnerability by disabling the PostgreSQL sidecar service.

- [https://github.com/NSK-394/owasp-nettacker-contribution](https://github.com/NSK-394/owasp-nettacker-contribution) :  ![starts](https://img.shields.io/github/stars/NSK-394/owasp-nettacker-contribution.svg) ![forks](https://img.shields.io/github/forks/NSK-394/owasp-nettacker-contribution.svg)


## CVE-2026-19586
leading to full compromise of the affected device.

- [https://github.com/bgorzelic/omada-advisory-check](https://github.com/bgorzelic/omada-advisory-check) :  ![starts](https://img.shields.io/github/stars/bgorzelic/omada-advisory-check.svg) ![forks](https://img.shields.io/github/forks/bgorzelic/omada-advisory-check.svg)


## CVE-2026-19219
 In Progress® Telerik® UI for AJAX prior to v2026.3.812, insufficient integrity protection of dialog request parameters used by the RadEditor file browser may allow an attacker who has obtained certain application encryption key material to alter the folders the file browser reads from, writes to, and uploads into, potentially resulting in remote code execution.

- [https://github.com/kjry8sb/CVE-2026-19219](https://github.com/kjry8sb/CVE-2026-19219) :  ![starts](https://img.shields.io/github/stars/kjry8sb/CVE-2026-19219.svg) ![forks](https://img.shields.io/github/forks/kjry8sb/CVE-2026-19219.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/gorgeoushos/CVE-2026-109618-research](https://github.com/gorgeoushos/CVE-2026-109618-research) :  ![starts](https://img.shields.io/github/stars/gorgeoushos/CVE-2026-109618-research.svg) ![forks](https://img.shields.io/github/forks/gorgeoushos/CVE-2026-109618-research.svg)
- [https://github.com/xvanpan/CVE-2026-109619](https://github.com/xvanpan/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xvanpan/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xvanpan/CVE-2026-109619.svg)
- [https://github.com/syrex1013/CVE-2026-109619](https://github.com/syrex1013/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/syrex1013/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/syrex1013/CVE-2026-109619.svg)


## CVE-2026-6023
 In Progress® Telerik® UI for AJAX versions 2024.4.1114 through 2026.1.421, the RadFilter control is vulnerable to insecure deserialization when restoring filter state if the state is exposed to the client. If an attacker tampers with this state, a server-side remote code execution is possible.

- [https://github.com/kjry8sb/CVE-2026-6023](https://github.com/kjry8sb/CVE-2026-6023) :  ![starts](https://img.shields.io/github/stars/kjry8sb/CVE-2026-6023.svg) ![forks](https://img.shields.io/github/forks/kjry8sb/CVE-2026-6023.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Cyb3rCr0wCC/CVE-2026-43499_study](https://github.com/Cyb3rCr0wCC/CVE-2026-43499_study) :  ![starts](https://img.shields.io/github/stars/Cyb3rCr0wCC/CVE-2026-43499_study.svg) ![forks](https://img.shields.io/github/forks/Cyb3rCr0wCC/CVE-2026-43499_study.svg)


## CVE-2026-1217
 The Yoast Duplicate Post plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the clone_bulk_action_handler() and republish_request() functions in all versions up to, and including, 4.5. This makes it possible for authenticated attackers, with Contributor-level access and above, to duplicate any post on the site including private, draft, and trashed posts they shouldn't have access to. Additionally, attackers with Author-level access and above can use the Rewrite & Republish feature to overwrite any published post with their own content.

- [https://github.com/refiaa/CVE-2026-121720](https://github.com/refiaa/CVE-2026-121720) :  ![starts](https://img.shields.io/github/stars/refiaa/CVE-2026-121720.svg) ![forks](https://img.shields.io/github/forks/refiaa/CVE-2026-121720.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/zhaoboy9692/CVE-2026-109618_](https://github.com/zhaoboy9692/CVE-2026-109618_) :  ![starts](https://img.shields.io/github/stars/zhaoboy9692/CVE-2026-109618_.svg) ![forks](https://img.shields.io/github/forks/zhaoboy9692/CVE-2026-109618_.svg)
- [https://github.com/santihabib/CVE-2026-109619](https://github.com/santihabib/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/santihabib/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/santihabib/CVE-2026-109619.svg)
- [https://github.com/tuwiliyt/cve-2026-109618](https://github.com/tuwiliyt/cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/tuwiliyt/cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/tuwiliyt/cve-2026-109618.svg)


## CVE-2026-0264
Panorama, Cloud NGFW, and Prisma® Access are not impacted by this vulnerability.

- [https://github.com/iam-s21-caece/PoC-CVE-2026-0264](https://github.com/iam-s21-caece/PoC-CVE-2026-0264) :  ![starts](https://img.shields.io/github/stars/iam-s21-caece/PoC-CVE-2026-0264.svg) ![forks](https://img.shields.io/github/forks/iam-s21-caece/PoC-CVE-2026-0264.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/Ossipher/CVE-2025-49132_HTB_SEASON10](https://github.com/Ossipher/CVE-2025-49132_HTB_SEASON10) :  ![starts](https://img.shields.io/github/stars/Ossipher/CVE-2025-49132_HTB_SEASON10.svg) ![forks](https://img.shields.io/github/forks/Ossipher/CVE-2025-49132_HTB_SEASON10.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/Ghost-Bx1/cve-2025-32433-erlang-ssh-preauth-rce](https://github.com/Ghost-Bx1/cve-2025-32433-erlang-ssh-preauth-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2025-32433-erlang-ssh-preauth-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2025-32433-erlang-ssh-preauth-rce.svg)


## CVE-2024-24576
The fix is included in Rust 1.77.2. Note that the new escaping logic for batch files errs on the conservative side, and could reject valid arguments. Those who implement the escaping themselves or only handle trusted inputs on Windows can also use the `CommandExt::raw_arg` method to bypass the standard library's escaping logic.

- [https://github.com/federiconbaez/cortex9-rust-batbadbut-args-model](https://github.com/federiconbaez/cortex9-rust-batbadbut-args-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-rust-batbadbut-args-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-rust-batbadbut-args-model.svg)


## CVE-2024-21762
 A out-of-bounds write vulnerability in Fortinet FortiOS 7.4.0 through 7.4.2, FortiOS 7.2.0 through 7.2.6, FortiOS 7.0.0 through 7.0.13, FortiOS 6.4.0 through 6.4.14, FortiOS 6.2.0 through 6.2.15, FortiOS 6.0 all versions, FortiProxy 7.4.0 through 7.4.2, FortiProxy 7.2.0 through 7.2.8, FortiProxy 7.0.0 through 7.0.14, FortiProxy 2.0.0 through 2.0.13, FortiProxy 01.02 all versions, FortiProxy 1.2 all versions, FortiProxy 01.01 all versions, FortiProxy 1.1 all versions, FortiProxy 01.00 all versions allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/IzanInPublic/CVE-2024-21762-Safe-Check](https://github.com/IzanInPublic/CVE-2024-21762-Safe-Check) :  ![starts](https://img.shields.io/github/stars/IzanInPublic/CVE-2024-21762-Safe-Check.svg) ![forks](https://img.shields.io/github/forks/IzanInPublic/CVE-2024-21762-Safe-Check.svg)


## CVE-2024-5717
The specific flaw exists within the implementation of the HTTP API. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-24165.

- [https://github.com/jankesec/logsign-rce](https://github.com/jankesec/logsign-rce) :  ![starts](https://img.shields.io/github/stars/jankesec/logsign-rce.svg) ![forks](https://img.shields.io/github/forks/jankesec/logsign-rce.svg)


## CVE-2024-5716
The specific flaw exists within the password reset mechanism. The issue results from the lack of restriction of excessive authentication attempts. An attacker can leverage this vulnerability to reset a user's password and bypass authentication on the system. Was ZDI-CAN-24164.

- [https://github.com/jankesec/logsign-rce](https://github.com/jankesec/logsign-rce) :  ![starts](https://img.shields.io/github/stars/jankesec/logsign-rce.svg) ![forks](https://img.shields.io/github/forks/jankesec/logsign-rce.svg)


## CVE-2023-48795
 The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

- [https://github.com/federiconbaez/cortex9-terrapin-strict-kex-model](https://github.com/federiconbaez/cortex9-terrapin-strict-kex-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-terrapin-strict-kex-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-terrapin-strict-kex-model.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/federiconbaez/cortex9-http2-rapid-reset-stream-accounting-model](https://github.com/federiconbaez/cortex9-http2-rapid-reset-stream-accounting-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-http2-rapid-reset-stream-accounting-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-http2-rapid-reset-stream-accounting-model.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/xsvebmx/teclast-m50pro-unisoc-root](https://github.com/xsvebmx/teclast-m50pro-unisoc-root) :  ![starts](https://img.shields.io/github/stars/xsvebmx/teclast-m50pro-unisoc-root.svg) ![forks](https://img.shields.io/github/forks/xsvebmx/teclast-m50pro-unisoc-root.svg)


## CVE-2022-38181
 The Arm Mali GPU kernel driver allows unprivileged users to access freed memory because GPU memory operations are mishandled. This affects Bifrost r0p0 through r38p1, and r39p0; Valhall r19p0 through r38p1, and r39p0; and Midgard r4p0 through r32p0.

- [https://github.com/lRENyaaa/AGM3-W09HN-TMP-ROOT-CVE-2022-38181](https://github.com/lRENyaaa/AGM3-W09HN-TMP-ROOT-CVE-2022-38181) :  ![starts](https://img.shields.io/github/stars/lRENyaaa/AGM3-W09HN-TMP-ROOT-CVE-2022-38181.svg) ![forks](https://img.shields.io/github/forks/lRENyaaa/AGM3-W09HN-TMP-ROOT-CVE-2022-38181.svg)


## CVE-2022-25236
 xmlparse.c in Expat (aka libexpat) before 2.4.5 allows attackers to insert namespace-separator characters into namespace URIs.

- [https://github.com/federiconbaez/cortex9-expat-namespace-separator-model](https://github.com/federiconbaez/cortex9-expat-namespace-separator-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-expat-namespace-separator-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-expat-namespace-separator-model.svg)


## CVE-2022-25235
 xmltok_impl.c in Expat (aka libexpat) before 2.4.5 lacks certain validation of encoding, such as checks for whether a UTF-8 character is valid in a certain context.

- [https://github.com/federiconbaez/cortex9-expat-utf8-name-validation-model](https://github.com/federiconbaez/cortex9-expat-utf8-name-validation-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-expat-utf8-name-validation-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-expat-utf8-name-validation-model.svg)


## CVE-2022-24765
 Git for Windows is a fork of Git containing Windows-specific patches. This vulnerability affects users working on multi-user machines, where untrusted parties have write access to the same hard disk. Those untrusted parties could create the folder `C:\.git`, which would be picked up by Git operations run supposedly outside a repository while searching for a Git directory. Git would then respect any config in said Git directory. Git Bash users who set `GIT_PS1_SHOWDIRTYSTATE` are vulnerable as well. Users who installed posh-gitare vulnerable simply by starting a PowerShell. Users of IDEs such as Visual Studio are vulnerable: simply creating a new project would already read and respect the config specified in `C:\.git\config`. Users of the Microsoft fork of Git are vulnerable simply by starting a Git Bash. The problem has been patched in Git for Windows v2.35.2. Users unable to upgrade may create the folder `.git` on all drives where Git commands are run, and remove read/write access from those folders as a workaround. Alternatively, define or extend `GIT_CEILING_DIRECTORIES` to cover the _parent_ directory of the user profile, e.g. `C:\Users` if the user profile is located in `C:\Users\my-user-name`.

- [https://github.com/federiconbaez/cortex9-git-safe-directory-discovery-model](https://github.com/federiconbaez/cortex9-git-safe-directory-discovery-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-git-safe-directory-discovery-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-git-safe-directory-discovery-model.svg)


## CVE-2022-24713
 regex is an implementation of regular expressions for the Rust language. The regex crate features built-in mitigations to prevent denial of service attacks caused by untrusted regexes, or untrusted input matched by trusted regexes. Those (tunable) mitigations already provide sane defaults to prevent attacks. This guarantee is documented and it's considered part of the crate's API. Unfortunately a bug was discovered in the mitigations designed to prevent untrusted regexes to take an arbitrary amount of time during parsing, and it's possible to craft regexes that bypass such mitigations. This makes it possible to perform denial of service attacks by sending specially crafted regexes to services accepting user-controlled, untrusted regexes. All versions of the regex crate before or equal to 1.5.4 are affected by this issue. The fix is include starting from regex 1.5.5. All users accepting user-controlled regexes are recommended to upgrade immediately to the latest version of the regex crate. Unfortunately there is no fixed set of problematic regexes, as there are practically infinite regexes that could be crafted to exploit this vulnerability. Because of this, it us not recommend to deny known problematic regexes.

- [https://github.com/federiconbaez/cortex9-rust-regex-empty-repetition-size-limit-model](https://github.com/federiconbaez/cortex9-rust-regex-empty-repetition-size-limit-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-rust-regex-empty-repetition-size-limit-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-rust-regex-empty-repetition-size-limit-model.svg)


## CVE-2022-3949
 A vulnerability, which was classified as problematic, has been found in Sourcecodester Simple Cashiering System. This issue affects some unknown processing of the component User Account Handler. The manipulation of the argument fullname leads to cross site scripting. The attack may be initiated remotely. The associated identifier of this vulnerability is VDB-213455.

- [https://github.com/maikroservice/CVE-2022-3949](https://github.com/maikroservice/CVE-2022-3949) :  ![starts](https://img.shields.io/github/stars/maikroservice/CVE-2022-3949.svg) ![forks](https://img.shields.io/github/forks/maikroservice/CVE-2022-3949.svg)


## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).

- [https://github.com/federiconbaez/cortex9-openssl-bn-mod-sqrt-loop-model](https://github.com/federiconbaez/cortex9-openssl-bn-mod-sqrt-loop-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-openssl-bn-mod-sqrt-loop-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-openssl-bn-mod-sqrt-loop-model.svg)


## CVE-2021-37713
 The npm package "tar" (aka node-tar) before versions 4.4.18, 5.0.10, and 6.1.9 has an arbitrary file creation/overwrite and arbitrary code execution vulnerability. node-tar aims to guarantee that any file whose location would be outside of the extraction target directory is not extracted. This is, in part, accomplished by sanitizing absolute paths of entries within the archive, skipping archive entries that contain `..` path portions, and resolving the sanitized paths against the extraction target directory. This logic was insufficient on Windows systems when extracting tar files that contained a path that was not an absolute path, but specified a drive letter different from the extraction target, such as `C:some\path`. If the drive letter does not match the extraction target, for example `D:\extraction\dir`, then the result of `path.resolve(extractionDirectory, entryPath)` would resolve against the current working directory on the `C:` drive, rather than the extraction target directory. Additionally, a `..` portion of the path could occur immediately after the drive letter, such as `C:../foo`, and was not properly sanitized by the logic that checked for `..` within the normalized and split portions of the path. This only affects users of `node-tar` on Windows systems. These issues were addressed in releases 4.4.18, 5.0.10 and 6.1.9. The v3 branch of node-tar has been deprecated and did not receive patches for these issues. If you are still using a v3 release we recommend you update to a more recent version of node-tar. There is no reasonable way to work around this issue without performing the same path normalization procedures that node-tar now does. Users are encouraged to upgrade to the latest patched versions of node-tar, rather than attempt to sanitize paths themselves.

- [https://github.com/federiconbaez/cortex9-node-tar-path-sanitization-model](https://github.com/federiconbaez/cortex9-node-tar-path-sanitization-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-node-tar-path-sanitization-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-node-tar-path-sanitization-model.svg)


## CVE-2021-32804
 The npm package "tar" (aka node-tar) before versions 6.1.1, 5.0.6, 4.4.14, and 3.3.2 has a arbitrary File Creation/Overwrite vulnerability due to insufficient absolute path sanitization. node-tar aims to prevent extraction of absolute file paths by turning absolute paths into relative paths when the `preservePaths` flag is not set to `true`. This is achieved by stripping the absolute path root from any absolute file paths contained in a tar file. For example `/home/user/.bashrc` would turn into `home/user/.bashrc`. This logic was insufficient when file paths contained repeated path roots such as `////home/user/.bashrc`. `node-tar` would only strip a single path root from such paths. When given an absolute file path with repeating path roots, the resulting path (e.g. `///home/user/.bashrc`) would still resolve to an absolute path, thus allowing arbitrary file creation and overwrite. This issue was addressed in releases 3.2.2, 4.4.14, 5.0.6 and 6.1.1. Users may work around this vulnerability without upgrading by creating a custom `onentry` method which sanitizes the `entry.path` or a `filter` method which removes entries with absolute paths. See referenced GitHub Advisory for details. Be aware of CVE-2021-32803 which fixes a similar bug in later versions of tar.

- [https://github.com/federiconbaez/cortex9-node-tar-path-sanitization-model](https://github.com/federiconbaez/cortex9-node-tar-path-sanitization-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-node-tar-path-sanitization-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-node-tar-path-sanitization-model.svg)


## CVE-2021-28879
 In the standard library in Rust before 1.52.0, the Zip implementation can report an incorrect size due to an integer overflow. This bug can lead to a buffer overflow when a consumed Zip iterator is used again.

- [https://github.com/federiconbaez/cortex9-rust-zip-size-hint-overflow-model](https://github.com/federiconbaez/cortex9-rust-zip-size-hint-overflow-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-rust-zip-size-hint-overflow-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-rust-zip-size-hint-overflow-model.svg)


## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.

- [https://github.com/federiconbaez/cortex9-git-case-insensitive-symlink-checkout-model](https://github.com/federiconbaez/cortex9-git-case-insensitive-symlink-checkout-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-git-case-insensitive-symlink-checkout-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-git-case-insensitive-symlink-checkout-model.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)
- [https://github.com/Park123r/CVE-2021-41773](https://github.com/Park123r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Park123r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Park123r/CVE-2021-41773.svg)


## CVE-2021-3712
 ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING structure which contains a buffer holding the string data and a field holding the buffer length. This contrasts with normal C strings which are repesented as a buffer for the string data which is terminated with a NUL (0) byte. Although not a strict requirement, ASN.1 strings that are parsed using OpenSSL's own "d2i" functions (and other similar parsing functions) as well as any string whose value has been set with the ASN1_STRING_set() function will additionally NUL terminate the byte array in the ASN1_STRING structure. However, it is possible for applications to directly construct valid ASN1_STRING structures which do not NUL terminate the byte array by directly setting the "data" and "length" fields in the ASN1_STRING array. This can also happen by using the ASN1_STRING_set0() function. Numerous OpenSSL functions that print ASN.1 data have been found to assume that the ASN1_STRING byte array will be NUL terminated, even though this is not guaranteed for strings that have been directly constructed. Where an application requests an ASN.1 structure to be printed, and where that ASN.1 structure contains ASN1_STRINGs that have been directly constructed by the application without NUL terminating the "data" field, then a read buffer overrun can occur. The same thing can also occur during name constraints processing of certificates (for example if a certificate has been directly constructed by the application instead of loading it via the OpenSSL parsing functions, and the certificate contains non NUL terminated ASN1_STRING structures). It can also occur in the X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() functions. If a malicious actor can cause an application to directly construct an ASN1_STRING and then process it through one of the affected OpenSSL functions then this issue could be hit. This might result in a crash (causing a Denial of Service attack). It could also result in the disclosure of private memory contents (such as private keys, or sensitive plaintext). Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). Fixed in OpenSSL 1.0.2za (Affected 1.0.2-1.0.2y).

- [https://github.com/federiconbaez/cortex9-openssl-asn1-string-nul-scanner](https://github.com/federiconbaez/cortex9-openssl-asn1-string-nul-scanner) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-openssl-asn1-string-nul-scanner.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-openssl-asn1-string-nul-scanner.svg)


## CVE-2020-27824
 A flaw was found in OpenJPEG’s encoder in the opj_dwt_calc_explicit_stepsizes() function. This flaw allows an attacker who can supply crafted input to decomposition levels to cause a buffer overflow. The highest threat from this vulnerability is to system availability.

- [https://github.com/pazhanivel07/openjpeg-2.3.0_CVE-2020-27824](https://github.com/pazhanivel07/openjpeg-2.3.0_CVE-2020-27824) :  ![starts](https://img.shields.io/github/stars/pazhanivel07/openjpeg-2.3.0_CVE-2020-27824.svg) ![forks](https://img.shields.io/github/forks/pazhanivel07/openjpeg-2.3.0_CVE-2020-27824.svg)


## CVE-2020-27818
 A flaw was found in the check_chunk_name() function of pngcheck-2.4.0. An attacker able to pass a malicious file to be processed by pngcheck could cause a temporary denial of service, posing a low risk to application availability.

- [https://github.com/13m0n4de/pngcheck-vulns](https://github.com/13m0n4de/pngcheck-vulns) :  ![starts](https://img.shields.io/github/stars/13m0n4de/pngcheck-vulns.svg) ![forks](https://img.shields.io/github/forks/13m0n4de/pngcheck-vulns.svg)


## CVE-2020-26235
 In Rust time crate from version 0.2.7 and before version 0.2.23, unix-like operating systems may segfault due to dereferencing a dangling pointer in specific circumstances. This requires the user to set any environment variable in a different thread than the affected functions. The affected functions are time::UtcOffset::local_offset_at, time::UtcOffset::try_local_offset_at, time::UtcOffset::current_local_offset, time::UtcOffset::try_current_local_offset, time::OffsetDateTime::now_local and time::OffsetDateTime::try_now_local. Non-Unix targets are unaffected. This includes Windows and wasm. The issue was introduced in version 0.2.7 and fixed in version 0.2.23.

- [https://github.com/federiconbaez/cortex9-time-crate-env-race-interleaving-model](https://github.com/federiconbaez/cortex9-time-crate-env-race-interleaving-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-time-crate-env-race-interleaving-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-time-crate-env-race-interleaving-model.svg)


## CVE-2019-10744
 Versions of lodash lower than 4.17.12 are vulnerable to Prototype Pollution. The function defaultsDeep could be tricked into adding or modifying properties of Object.prototype using a constructor payload.

- [https://github.com/federiconbaez/cortex9-lodash-defaultsdeep-prototype-pollution-model](https://github.com/federiconbaez/cortex9-lodash-defaultsdeep-prototype-pollution-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-lodash-defaultsdeep-prototype-pollution-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-lodash-defaultsdeep-prototype-pollution-model.svg)


## CVE-2019-9513
 Some HTTP/2 implementations are vulnerable to resource loops, potentially leading to a denial of service. The attacker creates multiple request streams and continually shuffles the priority of the streams in a way that causes substantial churn to the priority tree. This can consume excess CPU.

- [https://github.com/federiconbaez/cortex9-http2-priority-churn-cost-model](https://github.com/federiconbaez/cortex9-http2-priority-churn-cost-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-http2-priority-churn-cost-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-http2-priority-churn-cost-model.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/dawcwikla/CVE-2019-9053-exploit](https://github.com/dawcwikla/CVE-2019-9053-exploit) :  ![starts](https://img.shields.io/github/stars/dawcwikla/CVE-2019-9053-exploit.svg) ![forks](https://img.shields.io/github/forks/dawcwikla/CVE-2019-9053-exploit.svg)


## CVE-2018-1000810
 The Rust Programming Language Standard Library version 1.29.0, 1.28.0, 1.27.2, 1.27.1, 127.0, 126.2, 126.1, 126.0 contains a CWE-680: Integer Overflow to Buffer Overflow vulnerability in standard library that can result in buffer overflow. This attack appear to be exploitable via str::repeat, passed a large number, can overflow an internal buffer. This vulnerability appears to have been fixed in 1.29.1.

- [https://github.com/federiconbaez/cortex9-rust-str-repeat-capacity-overflow-model](https://github.com/federiconbaez/cortex9-rust-str-repeat-capacity-overflow-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-rust-str-repeat-capacity-overflow-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-rust-str-repeat-capacity-overflow-model.svg)


## CVE-2017-18078
 systemd-tmpfiles in systemd before 237 attempts to support ownership/permission changes on hardlinked files even if the fs.protected_hardlinks sysctl is turned off, which allows local users to bypass intended access restrictions via vectors involving a hard link to a file for which the user lacks write access, as demonstrated by changing the ownership of the /etc/passwd file.

- [https://github.com/federiconbaez/cortex9-tmpfiles-hardlink-chown-race-model](https://github.com/federiconbaez/cortex9-tmpfiles-hardlink-chown-race-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-tmpfiles-hardlink-chown-race-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-tmpfiles-hardlink-chown-race-model.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/Bethelhem-Yirga/hikvision-cve-2017-7921-lab](https://github.com/Bethelhem-Yirga/hikvision-cve-2017-7921-lab) :  ![starts](https://img.shields.io/github/stars/Bethelhem-Yirga/hikvision-cve-2017-7921-lab.svg) ![forks](https://img.shields.io/github/forks/Bethelhem-Yirga/hikvision-cve-2017-7921-lab.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/clrs520/letv-tv-ad-free](https://github.com/clrs520/letv-tv-ad-free) :  ![starts](https://img.shields.io/github/stars/clrs520/letv-tv-ad-free.svg) ![forks](https://img.shields.io/github/forks/clrs520/letv-tv-ad-free.svg)
- [https://github.com/federiconbaez/cortex9-dirtycow-gup-cow-state-model](https://github.com/federiconbaez/cortex9-dirtycow-gup-cow-state-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-dirtycow-gup-cow-state-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-dirtycow-gup-cow-state-model.svg)


## CVE-2015-6831
 Multiple use-after-free vulnerabilities in SPL in PHP before 5.4.44, 5.5.x before 5.5.28, and 5.6.x before 5.6.12 allow remote attackers to execute arbitrary code via vectors involving (1) ArrayObject, (2) SplObjectStorage, and (3) SplDoublyLinkedList, which are mishandled during unserialization.

- [https://github.com/wjdekq113/php54-spl-uaf-rce-chain](https://github.com/wjdekq113/php54-spl-uaf-rce-chain) :  ![starts](https://img.shields.io/github/stars/wjdekq113/php54-spl-uaf-rce-chain.svg) ![forks](https://img.shields.io/github/forks/wjdekq113/php54-spl-uaf-rce-chain.svg)


## CVE-2015-1201
 Privoxy before 3.0.22 allows remote attackers to cause a denial of service (file descriptor consumption) via unspecified vectors.  NOTE: the provenance of this information is unknown; the details are obtained solely from third party information.

- [https://github.com/Akshit0203/CVE-2015-1201-wordpress-Reflex-Gallery-plugin-RCE-PoC](https://github.com/Akshit0203/CVE-2015-1201-wordpress-Reflex-Gallery-plugin-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/Akshit0203/CVE-2015-1201-wordpress-Reflex-Gallery-plugin-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/Akshit0203/CVE-2015-1201-wordpress-Reflex-Gallery-plugin-RCE-PoC.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/federiconbaez/cortex9-heartbleed-heartbeat-bounds-model](https://github.com/federiconbaez/cortex9-heartbleed-heartbeat-bounds-model) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cortex9-heartbleed-heartbeat-bounds-model.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cortex9-heartbleed-heartbeat-bounds-model.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/nabeelapu/vsftpd-2.3.4-backdoor-vulnerability_analysis](https://github.com/nabeelapu/vsftpd-2.3.4-backdoor-vulnerability_analysis) :  ![starts](https://img.shields.io/github/stars/nabeelapu/vsftpd-2.3.4-backdoor-vulnerability_analysis.svg) ![forks](https://img.shields.io/github/forks/nabeelapu/vsftpd-2.3.4-backdoor-vulnerability_analysis.svg)
- [https://github.com/nabeelapu/vsftpd-2.3.4-backdoor-vulnerability-analysis](https://github.com/nabeelapu/vsftpd-2.3.4-backdoor-vulnerability-analysis) :  ![starts](https://img.shields.io/github/stars/nabeelapu/vsftpd-2.3.4-backdoor-vulnerability-analysis.svg) ![forks](https://img.shields.io/github/forks/nabeelapu/vsftpd-2.3.4-backdoor-vulnerability-analysis.svg)

