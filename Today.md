# Update 2026-11-15
## CVE-2026-129110
 sysPass 3.0.1 through 3.2.11 contains an authentication bypass vulnerability that allows unauthenticated attackers to reinstall an already-installed instance by POSTing to the install/install handler, which never checks isInstalled(). Attackers can overwrite config.xml, point the application at an attacker-controlled database, create an administrator account, and plant serialized PublicLink gadget chains triggered via account/viewLink to execute commands.

- [https://github.com/psylinux/CVE-2026-129110-sysPass](https://github.com/psylinux/CVE-2026-129110-sysPass) :  ![starts](https://img.shields.io/github/stars/psylinux/CVE-2026-129110-sysPass.svg) ![forks](https://img.shields.io/github/forks/psylinux/CVE-2026-129110-sysPass.svg)


## CVE-2026-128970
 Psono Server Community Edition versions 1.12.6 through 7.5.0 and Psono Server Enterprise Edition before 7.5.1 do not require accepted group membership when authorizing deletion of group share-rights. The DELETE /share/right/ endpoint checks for a membership matching the target group, the authenticated user, and share_admin=True, but omits accepted=True. An authenticated remote attacker who has been invited to a group with share-admin privileges, and who knows a group share-right UUID, can therefore delete that group's share-right record without accepting the invitation or after declining it. Pending invitations have accepted=None, while declined invitations retain accepted=False and the share_admin flag. Deletion revokes the group's access to the affected share and its contained secrets for all accepted group members, without deleting the underlying data or disclosing secret contents. The issue was fixed in version 7.5.1 of both editions, released on 2026-10-13.

- [https://github.com/R00t3dbyFa17h/security-advisories](https://github.com/R00t3dbyFa17h/security-advisories) :  ![starts](https://img.shields.io/github/stars/R00t3dbyFa17h/security-advisories.svg) ![forks](https://img.shields.io/github/forks/R00t3dbyFa17h/security-advisories.svg)


## CVE-2026-126997
 A vulnerability was identified in JeecgBoot up to 3.9.6. This affects the function RestTemplate.exchange of the file org/jeecg/modules/airag/flow/c/a.class of the component flow-run Endpoint. The manipulation leads to server-side request forgery. Remote exploitation of the attack is possible. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/evenomn/CVE-2026-126997](https://github.com/evenomn/CVE-2026-126997) :  ![starts](https://img.shields.io/github/stars/evenomn/CVE-2026-126997.svg) ![forks](https://img.shields.io/github/forks/evenomn/CVE-2026-126997.svg)


## CVE-2026-126262
 A improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.1, FortiAnalyzer 7.6.0 through 7.6.7, FortiAnalyzer 7.4.0 through 7.4.11, FortiAnalyzer 7.2.0 through 7.2.12, FortiManager 8.0.0, FortiManager 7.6.0 through 7.6.7, FortiManager 7.4.0 through 7.4.11, FortiManager 7.2.0 through 7.2.12 may allow an unauthenticated attacker who has access to the oftp port to execute code or command on the system via crafted OFTP packets.

- [https://github.com/foxcornlab/fortinet-scanner](https://github.com/foxcornlab/fortinet-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/fortinet-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/fortinet-scanner.svg)


## CVE-2026-126261
 A improper authorization vulnerability in Fortinet FortiManager 8.0.0, FortiManager 7.6.0 through 7.6.7, FortiManager 7.4.0 through 7.4.5, FortiManager 7.2.0 through 7.2.8 may allow an unauthenticated attacker that can reach the FGFM port to execute code or commands via crafted FGFM packets.

- [https://github.com/foxcornlab/fortinet-scanner](https://github.com/foxcornlab/fortinet-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/fortinet-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/fortinet-scanner.svg)


## CVE-2026-126259
 A missing authentication for critical function vulnerability in Fortinet FortiOS 8.0.0, FortiOS 7.6.0 through 7.6.7, FortiOS 7.4.0 through 7.4.12, FortiOS 7.2.0 through 7.2.13 may allow an unauthenticated attacker with HA FGSP + standalone-config-sync, or autoscale to execute command as super admin via crafted HA packets.

- [https://github.com/foxcornlab/fortinet-scanner](https://github.com/foxcornlab/fortinet-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/fortinet-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/fortinet-scanner.svg)


## CVE-2026-126254
 A numeric truncation error vulnerability in Fortinet FortiOS 8.0.0 through 8.0.1, FortiOS 7.6.0 through 7.6.7, FortiOS 7.4.0 through 7.4.12, FortiOS 7.2.0 through 7.2.13 may allow a configured ibgp neighbor to send malicious/malformed attributes to all connected routers via a specially crafted request

- [https://github.com/foxcornlab/fortinet-scanner](https://github.com/foxcornlab/fortinet-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/fortinet-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/fortinet-scanner.svg)


## CVE-2026-126253
 A authentication bypass by primary weakness vulnerability in Fortinet FortiOS 8.0.0 through 8.0.1, FortiOS 7.6.0 through 7.6.7, FortiOS 7.4.0 through 7.4.12, FortiOS 7.2.0 through 7.2.13 may allow an unauthenticated attacker to broadcast LSA via specially crafted request

- [https://github.com/foxcornlab/fortinet-scanner](https://github.com/foxcornlab/fortinet-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/fortinet-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/fortinet-scanner.svg)


## CVE-2026-126229
 A authorization bypass through user-controlled key vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.1, FortiAnalyzer 7.6.0 through 7.6.7, FortiAnalyzer 7.4.0 through 7.4.11, FortiAnalyzer 7.2.0 through 7.2.12, FortiAnalyzer 7.0 all versions, FortiAnalyzer Cloud 8.0.1, FortiAnalyzer Cloud 7.6.0 through 7.6.7, FortiAnalyzer Cloud 7.4.1 through 7.4.11, FortiAnalyzer Cloud 7.2.1 through 7.2.12, FortiAnalyzer Cloud 7.0 all versions, FortiManager 8.0.0 through 8.0.1, FortiManager 7.6.0 through 7.6.7, FortiManager 7.4.0 through 7.4.11, FortiManager 7.2.0 through 7.2.12, FortiManager 7.0 all versions, FortiManager Cloud 8.0.1, FortiManager Cloud 7.6.0 through 7.6.7, FortiManager Cloud 7.4.1 through 7.4.11, FortiManager Cloud 7.2.1 through 7.2.12, FortiManager Cloud 7.0 all versions may allow an authenticated administrator to access to other VDOMs via specially crafted HTTP requests.

- [https://github.com/foxcornlab/fortinet-scanner](https://github.com/foxcornlab/fortinet-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/fortinet-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/fortinet-scanner.svg)


## CVE-2026-126170
 A improper encoding or escaping of output vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.2, FortiAnalyzer 7.6.0 through 7.6.7, FortiAnalyzer Cloud 8.0.1 through 8.0.2, FortiAnalyzer Cloud 7.6.0 through 7.6.7, FortiAnalyzer-BigData 7.6.0 through 7.6.2, FortiManager 8.0.0 through 8.0.2, FortiManager 7.6.0 through 7.6.7, FortiManager Cloud 8.0.1 through 8.0.2, FortiManager Cloud 7.6.0 through 7.6.7 may allow an unauthenticated attacker to execute unauthorized code or commands via a specially crafted HTTP request

- [https://github.com/foxcornlab/fortinet-scanner](https://github.com/foxcornlab/fortinet-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/fortinet-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/fortinet-scanner.svg)


## CVE-2026-125350
 Use after free in XML in Google Chrome prior to 157.0.8103.50 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/al4n4n/CVE-2026-125350](https://github.com/al4n4n/CVE-2026-125350) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-125350.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-125350.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/liamromanis101/K8s-container_escape_audit](https://github.com/liamromanis101/K8s-container_escape_audit) :  ![starts](https://img.shields.io/github/stars/liamromanis101/K8s-container_escape_audit.svg) ![forks](https://img.shields.io/github/forks/liamromanis101/K8s-container_escape_audit.svg)
- [https://github.com/Avi99999/sshhole-scanner](https://github.com/Avi99999/sshhole-scanner) :  ![starts](https://img.shields.io/github/stars/Avi99999/sshhole-scanner.svg) ![forks](https://img.shields.io/github/forks/Avi99999/sshhole-scanner.svg)
- [https://github.com/Dylans7j/CVE-2026-123158-OpenSSH-Auth-Bypass](https://github.com/Dylans7j/CVE-2026-123158-OpenSSH-Auth-Bypass) :  ![starts](https://img.shields.io/github/stars/Dylans7j/CVE-2026-123158-OpenSSH-Auth-Bypass.svg) ![forks](https://img.shields.io/github/forks/Dylans7j/CVE-2026-123158-OpenSSH-Auth-Bypass.svg)


## CVE-2026-123039
 The Gaia OS DynamicCLI daemon runs as root and listens on a world-writable local socket (/tmp/dynamic_socket) without authenticating connecting processes. An authenticated local user can send a command to the socket and have it executed as root.

- [https://github.com/googlesky/CVE-2026-123039](https://github.com/googlesky/CVE-2026-123039) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-123039.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-123039.svg)


## CVE-2026-121529
 A origin validation error vulnerability in Fortinet FortiClientMac 7.4.0 through 7.4.7, FortiClientWindows 7.4.0 through 7.4.7, FortiClientWindows 7.2.0 through 7.2.14, FortiClientWindowsPAM 7.4.7, FortiClientWindowsPAM 7.2.14 may allow an unauthorized remote attacker to execute unauthorized code or commands. Successful exploitation requires interaction with the victim.

- [https://github.com/tc4dy/CVE-2026-121529-Toolkit](https://github.com/tc4dy/CVE-2026-121529-Toolkit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-121529-Toolkit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-121529-Toolkit.svg)


## CVE-2026-120490
 On Scalable Platforms, an administrator with permissions to edit and install the Access Control Policy and NAT rules can create a NAT rule that redirects traffic to the Gateway's Sync interface, bypassing the built-in Sync protection. This could allow the administrator to execute operating system commands and write files on the Gateway with superuser privileges.

- [https://github.com/sadshade/checkpoint-gexec-poc](https://github.com/sadshade/checkpoint-gexec-poc) :  ![starts](https://img.shields.io/github/stars/sadshade/checkpoint-gexec-poc.svg) ![forks](https://img.shields.io/github/forks/sadshade/checkpoint-gexec-poc.svg)


## CVE-2026-119618
Affected releases of mod_h2 from GitHub: from 2.0.8 through 2.0.42.

- [https://github.com/toeyhack/cve-2026-119618-apache-lab](https://github.com/toeyhack/cve-2026-119618-apache-lab) :  ![starts](https://img.shields.io/github/stars/toeyhack/cve-2026-119618-apache-lab.svg) ![forks](https://img.shields.io/github/forks/toeyhack/cve-2026-119618-apache-lab.svg)
- [https://github.com/blkph0x/CVE-2026-119618-mod_http2-lab](https://github.com/blkph0x/CVE-2026-119618-mod_http2-lab) :  ![starts](https://img.shields.io/github/stars/blkph0x/CVE-2026-119618-mod_http2-lab.svg) ![forks](https://img.shields.io/github/forks/blkph0x/CVE-2026-119618-mod_http2-lab.svg)


## CVE-2026-119077
 The ELEX WordPress HelpDesk & Customer Ticketing System plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.3.9 via the 'form (specifically the attacker-controlled ticket_label field inside the url-encoded form string)' parameter parameter. This is due to missing server-side authentication and the absence of a class allowlist on deserialization, with the only guard being a nonce publicly emitted on any page carrying the [wsdesk_support] shortcode. This makes it possible for unauthenticated attackers to execute code on the server. A successful exploit requires a single anonymous GET to any public page carrying the [wsdesk_support] shortcode to harvest the publicly emitted wsdesk_nonce value, after which a single unauthenticated POST completes the attack.

- [https://github.com/im0xfay/CVE-2026-119077](https://github.com/im0xfay/CVE-2026-119077) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-119077.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-119077.svg)


## CVE-2026-115252
 The Confection WordPress Cable WordPress plugin from 0.4.0 to 0.4.7 does not perform any capability or nonce checks before saving its settings and writing one of them, unmodified, into a standalone PHP file that it then serves, allowing unauthenticated users to execute arbitrary PHP code on the server.

- [https://github.com/evenomn/CVE-2026-115252](https://github.com/evenomn/CVE-2026-115252) :  ![starts](https://img.shields.io/github/stars/evenomn/CVE-2026-115252.svg) ![forks](https://img.shields.io/github/forks/evenomn/CVE-2026-115252.svg)


## CVE-2026-113408
 Path traversal in Git allows writing to arbitrary file via cloning and committing to bad repository

- [https://github.com/xssdoctor/git-cve-2026-113408-poc](https://github.com/xssdoctor/git-cve-2026-113408-poc) :  ![starts](https://img.shields.io/github/stars/xssdoctor/git-cve-2026-113408-poc.svg) ![forks](https://img.shields.io/github/forks/xssdoctor/git-cve-2026-113408-poc.svg)


## CVE-2026-112522
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2. Processing a maliciously crafted file may lead to unexpected app termination.

- [https://github.com/SudoSaturn/CVE-2026-112522](https://github.com/SudoSaturn/CVE-2026-112522) :  ![starts](https://img.shields.io/github/stars/SudoSaturn/CVE-2026-112522.svg) ![forks](https://img.shields.io/github/forks/SudoSaturn/CVE-2026-112522.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/KarpelesLab/broccoli2shell](https://github.com/KarpelesLab/broccoli2shell) :  ![starts](https://img.shields.io/github/stars/KarpelesLab/broccoli2shell.svg) ![forks](https://img.shields.io/github/forks/KarpelesLab/broccoli2shell.svg)
- [https://github.com/OhMyDitzzy/CVE-2026-111497](https://github.com/OhMyDitzzy/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/OhMyDitzzy/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/OhMyDitzzy/CVE-2026-111497.svg)
- [https://github.com/alequinterok/CVE-2026-111497](https://github.com/alequinterok/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/alequinterok/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/alequinterok/CVE-2026-111497.svg)


## CVE-2026-110697
 A flaw was found in Quay where the robot account listing function constructs a SQL LIKE pattern from user-controlled namespace names without escaping wildcard metacharacters. An attacker who creates a namespace containing an underscore character can match and retrieve robot accounts and their decrypted authentication tokens from other tenants' namespaces, leading to cross-tenant credential theft and unauthorized image operations.

- [https://github.com/googlesky/CVE-2026-110697](https://github.com/googlesky/CVE-2026-110697) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-110697.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-110697.svg)


## CVE-2026-107360
 A flaw was found in rubygem-safemode. Compound assignment expressions in sandboxed code are evaluated without mediating method calls through the Jail allow-list. An authenticated attacker who can supply template content can invoke arbitrary no-argument methods on objects exposed to the template renderer without Jail mediation, including destructive operations such as host deletion and disclosure of non-allow-listed object state.

- [https://github.com/googlesky/CVE-2026-107360](https://github.com/googlesky/CVE-2026-107360) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-107360.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-107360.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/Reallyliked21/galaxy-s24u-dzj3-temp-root](https://github.com/Reallyliked21/galaxy-s24u-dzj3-temp-root) :  ![starts](https://img.shields.io/github/stars/Reallyliked21/galaxy-s24u-dzj3-temp-root.svg) ![forks](https://img.shields.io/github/forks/Reallyliked21/galaxy-s24u-dzj3-temp-root.svg)
- [https://github.com/sabuweis/CVE-2026-98260](https://github.com/sabuweis/CVE-2026-98260) :  ![starts](https://img.shields.io/github/stars/sabuweis/CVE-2026-98260.svg) ![forks](https://img.shields.io/github/forks/sabuweis/CVE-2026-98260.svg)
- [https://github.com/skyrocketingHong/CVE-2026-98260_nezha](https://github.com/skyrocketingHong/CVE-2026-98260_nezha) :  ![starts](https://img.shields.io/github/stars/skyrocketingHong/CVE-2026-98260_nezha.svg) ![forks](https://img.shields.io/github/forks/skyrocketingHong/CVE-2026-98260_nezha.svg)
- [https://github.com/jonrazta89/SamGhostKey](https://github.com/jonrazta89/SamGhostKey) :  ![starts](https://img.shields.io/github/stars/jonrazta89/SamGhostKey.svg) ![forks](https://img.shields.io/github/forks/jonrazta89/SamGhostKey.svg)


## CVE-2026-84770
 Unauthenticated Cross Site Request Forgery (CSRF) in Mang Board WP = 2.3.8 versions.

- [https://github.com/rrr10n/CVE-2026-84770](https://github.com/rrr10n/CVE-2026-84770) :  ![starts](https://img.shields.io/github/stars/rrr10n/CVE-2026-84770.svg) ![forks](https://img.shields.io/github/forks/rrr10n/CVE-2026-84770.svg)


## CVE-2026-67177
 Chargemap contains a stored cross site scripting vulnerability. A remote, unauthenticated attacker could craft a payload in the username field of the account registration page and associate the new account with a victim's email. The attacker could send a forgotten password request to the victim, and the payload would execute when a victim opens the link. Fixed 2026-07-17.

- [https://github.com/praksokchea/CVE-2026-67177](https://github.com/praksokchea/CVE-2026-67177) :  ![starts](https://img.shields.io/github/stars/praksokchea/CVE-2026-67177.svg) ![forks](https://img.shields.io/github/forks/praksokchea/CVE-2026-67177.svg)


## CVE-2026-57747
 Unauthenticated Cross Site Request Forgery (CSRF) in Booked = 3.0.0 versions.

- [https://github.com/ziedelifa/booked-security-backport](https://github.com/ziedelifa/booked-security-backport) :  ![starts](https://img.shields.io/github/stars/ziedelifa/booked-security-backport.svg) ![forks](https://img.shields.io/github/forks/ziedelifa/booked-security-backport.svg)


## CVE-2026-57746
 Subscriber Broken Access Control in Booked = 3.0.0 versions.

- [https://github.com/ziedelifa/booked-security-backport](https://github.com/ziedelifa/booked-security-backport) :  ![starts](https://img.shields.io/github/stars/ziedelifa/booked-security-backport.svg) ![forks](https://img.shields.io/github/forks/ziedelifa/booked-security-backport.svg)


## CVE-2026-53787
 Amasty Order Attributes for Magento 2 before version 4.0.0 contains an unauthenticated arbitrary file upload vulnerability that allows unauthenticated attackers to write arbitrary files to the store's media directory by submitting files of any type or name to the upload endpoint without authentication, session validation, or cart context. Attackers can upload PHP files to achieve remote code execution on servers where the media directory permits PHP execution, or alternatively enable malware hosting, stored cross-site scripting via HTML or SVG uploads, and path traversal to write files outside the intended upload directory.

- [https://github.com/karthi-the-hacker/CVE-2026-53787](https://github.com/karthi-the-hacker/CVE-2026-53787) :  ![starts](https://img.shields.io/github/stars/karthi-the-hacker/CVE-2026-53787.svg) ![forks](https://img.shields.io/github/forks/karthi-the-hacker/CVE-2026-53787.svg)


## CVE-2026-43626
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority, replacedby CVE-2026-70640.

- [https://github.com/Vladimir-tokarev-cyera/llama-cpp-security-patches](https://github.com/Vladimir-tokarev-cyera/llama-cpp-security-patches) :  ![starts](https://img.shields.io/github/stars/Vladimir-tokarev-cyera/llama-cpp-security-patches.svg) ![forks](https://img.shields.io/github/forks/Vladimir-tokarev-cyera/llama-cpp-security-patches.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/dnlid/CVE-2026-43499](https://github.com/dnlid/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/dnlid/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/dnlid/CVE-2026-43499.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/0xv01d/CVE-2026-41651](https://github.com/0xv01d/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/0xv01d/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/0xv01d/CVE-2026-41651.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/0xv01d/CVE-2026-39987](https://github.com/0xv01d/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/0xv01d/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/0xv01d/CVE-2026-39987.svg)


## CVE-2026-34265
 SAP NetWeaver Application Server ABAP allows an unauthenticated attacker to exploit logical errors in DIAG protocol parsing, resulting in memory corruption. This vulnerability could potentially disclose sensitive system information or crash the system, leading to a high impact on the confidentiality, integrity, and availability of the application.

- [https://github.com/redrays-io/SAP-DIAG-Memory-Corruption-CVE-2026-34265](https://github.com/redrays-io/SAP-DIAG-Memory-Corruption-CVE-2026-34265) :  ![starts](https://img.shields.io/github/stars/redrays-io/SAP-DIAG-Memory-Corruption-CVE-2026-34265.svg) ![forks](https://img.shields.io/github/forks/redrays-io/SAP-DIAG-Memory-Corruption-CVE-2026-34265.svg)


## CVE-2026-22341
 Authentication Bypass Using an Alternate Path or Channel vulnerability in Case-Themes Booked booked allows Authentication Abuse.This issue affects Booked: from n/a through = 3.0.0.

- [https://github.com/ziedelifa/booked-security-backport](https://github.com/ziedelifa/booked-security-backport) :  ![starts](https://img.shields.io/github/stars/ziedelifa/booked-security-backport.svg) ![forks](https://img.shields.io/github/forks/ziedelifa/booked-security-backport.svg)


## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.

- [https://github.com/maxprog-svg/CVE-2026-21509](https://github.com/maxprog-svg/CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-21509.svg)


## CVE-2026-11746
 A vulnerability has been identified in centraldogma-server versions prior to 0.84.0, where enabling ZooKeeper replication without setting replication.secret causes the server to silently fall back to a hard-coded, publicly known secret. This default credential authenticates the embedded ZooKeeper ensemble, allowing an attacker with network access to read the full replication log or join the quorum and execute arbitrary replicated commands across the cluster.

- [https://github.com/l00neyhacker/CVE-2026-117463](https://github.com/l00neyhacker/CVE-2026-117463) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-117463.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-117463.svg)
- [https://github.com/l00neyhacker/CVE-2026-117462](https://github.com/l00neyhacker/CVE-2026-117462) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-117462.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-117462.svg)
- [https://github.com/l00neyhacker/CVE-2026-117464](https://github.com/l00neyhacker/CVE-2026-117464) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-117464.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-117464.svg)
- [https://github.com/l00neyhacker/CVE-2026-117465](https://github.com/l00neyhacker/CVE-2026-117465) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-117465.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-117465.svg)
- [https://github.com/l00neyhacker/CVE-2026-117461](https://github.com/l00neyhacker/CVE-2026-117461) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-117461.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-117461.svg)


## CVE-2026-11745
 A vulnerability has been identified in centraldogma-server-mirror-git versions prior to 0.84.0, where the Git mirror SSH client does not verify remote host keys for git+ssh:// connections, allowing an on-path attacker to perform man-in-the-middle attacks and compromise mirrored repositories.

- [https://github.com/l00neyhacker/CVE-2026-117459](https://github.com/l00neyhacker/CVE-2026-117459) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-117459.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-117459.svg)
- [https://github.com/l00neyhacker/CVE-2026-117458](https://github.com/l00neyhacker/CVE-2026-117458) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-117458.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-117458.svg)


## CVE-2026-10698
This issue affects MOVEit Transfer: from 2025.0.0 before 2025.0.8, from 2025.1.0 before 2025.1.4, from 2026.0.0 before 2026.0.1.

- [https://github.com/l00neyhacker/CVE-2026-106983](https://github.com/l00neyhacker/CVE-2026-106983) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-106983.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-106983.svg)
- [https://github.com/l00neyhacker/CVE-2026-106984](https://github.com/l00neyhacker/CVE-2026-106984) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-106984.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-106984.svg)


## CVE-2026-10697
This issue affects MOVEit Transfer: before 2025.1.5, from 2026.0.0 before 2026.0.3.

- [https://github.com/l00neyhacker/CVE-2026-106976](https://github.com/l00neyhacker/CVE-2026-106976) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-106976.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-106976.svg)
- [https://github.com/l00neyhacker/CVE-2026-106979](https://github.com/l00neyhacker/CVE-2026-106979) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-106979.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-106979.svg)
- [https://github.com/l00neyhacker/CVE-2026-106977](https://github.com/l00neyhacker/CVE-2026-106977) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-106977.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-106977.svg)


## CVE-2026-6471
 Missing authorization in PostgreSQL logical decoding allows a non-superuser holding REPLICATION privilege to dlopen any file visible to the operating system account running the server, via the choice of logical decoding plugin.  This in turn runs arbitrary code as that account.  Versions before PostgreSQL 18.6, 17.11, 16.15, 15.19, and 14.24 are affected.

- [https://github.com/Mahgal/pg-patch-check](https://github.com/Mahgal/pg-patch-check) :  ![starts](https://img.shields.io/github/stars/Mahgal/pg-patch-check.svg) ![forks](https://img.shields.io/github/forks/Mahgal/pg-patch-check.svg)


## CVE-2026-6460
 Type confusion in PostgreSQL allows an object creator to execute arbitrary code as the operating system user running the database, via ALTER ... SET DATA TYPE primarily.  Other DDL attack routes exist, such as "ALTER TABLE ... ADD COLUMN; ROLLBACK; ALTER TABLE ... ADD COLUMN".  The system had inadequate tracking of typed values, and values were not self-identifying.  Stale values could appear in data dictionary entries, PL/pgSQL variables, and many other parts of the system.  PostgreSQL Versions before PostgreSQL 18.7, 17.12, 16.16, 15.20, and 14.25 are affected.

- [https://github.com/chor4o/CVE-2026-6460-POC](https://github.com/chor4o/CVE-2026-6460-POC) :  ![starts](https://img.shields.io/github/stars/chor4o/CVE-2026-6460-POC.svg) ![forks](https://img.shields.io/github/forks/chor4o/CVE-2026-6460-POC.svg)
- [https://github.com/slabbdev/postgresql-type-confusion-cve-2026-6460](https://github.com/slabbdev/postgresql-type-confusion-cve-2026-6460) :  ![starts](https://img.shields.io/github/stars/slabbdev/postgresql-type-confusion-cve-2026-6460.svg) ![forks](https://img.shields.io/github/forks/slabbdev/postgresql-type-confusion-cve-2026-6460.svg)


## CVE-2026-1292
 Tanium addressed an insertion of sensitive information into log file vulnerability in Trends.

- [https://github.com/Usama-Hanif131/CVE-2026-129254](https://github.com/Usama-Hanif131/CVE-2026-129254) :  ![starts](https://img.shields.io/github/stars/Usama-Hanif131/CVE-2026-129254.svg) ![forks](https://img.shields.io/github/forks/Usama-Hanif131/CVE-2026-129254.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/debugactiveprocess/CVE-2026-109618](https://github.com/debugactiveprocess/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/debugactiveprocess/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/debugactiveprocess/CVE-2026-109618.svg)
- [https://github.com/skydwn/CVE-2026-109618](https://github.com/skydwn/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/skydwn/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/skydwn/CVE-2026-109618.svg)


## CVE-2025-67898
 MJML through 4.18.0 allows mj-include directory traversal to test file existence and (in the type="css" case) read files. NOTE: this issue exists because of an incomplete fix for CVE-2020-12827.

- [https://github.com/justmumu/CVE-2025-67898](https://github.com/justmumu/CVE-2025-67898) :  ![starts](https://img.shields.io/github/stars/justmumu/CVE-2025-67898.svg) ![forks](https://img.shields.io/github/forks/justmumu/CVE-2025-67898.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/donggle0802/cve-2025-57819](https://github.com/donggle0802/cve-2025-57819) :  ![starts](https://img.shields.io/github/stars/donggle0802/cve-2025-57819.svg) ![forks](https://img.shields.io/github/forks/donggle0802/cve-2025-57819.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/alinaclark672377250/CVE-2025-53770](https://github.com/alinaclark672377250/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/alinaclark672377250/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/alinaclark672377250/CVE-2025-53770.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/xssdoctor/muse-git-cve-2025-48384-parent-20261113](https://github.com/xssdoctor/muse-git-cve-2025-48384-parent-20261113) :  ![starts](https://img.shields.io/github/stars/xssdoctor/muse-git-cve-2025-48384-parent-20261113.svg) ![forks](https://img.shields.io/github/forks/xssdoctor/muse-git-cve-2025-48384-parent-20261113.svg)
- [https://github.com/xssdoctor/muse-git-cve-2025-48384-sub-20261113](https://github.com/xssdoctor/muse-git-cve-2025-48384-sub-20261113) :  ![starts](https://img.shields.io/github/stars/xssdoctor/muse-git-cve-2025-48384-sub-20261113.svg) ![forks](https://img.shields.io/github/forks/xssdoctor/muse-git-cve-2025-48384-sub-20261113.svg)


## CVE-2025-31131
 YesWiki is a wiki system written in PHP. The squelette parameter is vulnerable to path traversal attacks, enabling read access to arbitrary files on the server. This vulnerability is fixed in 4.5.2.

- [https://github.com/alinaclark672377250/CVE-2025-31131](https://github.com/alinaclark672377250/CVE-2025-31131) :  ![starts](https://img.shields.io/github/stars/alinaclark672377250/CVE-2025-31131.svg) ![forks](https://img.shields.io/github/forks/alinaclark672377250/CVE-2025-31131.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/alinaclark672377250/CVE-2025-29927-POC](https://github.com/alinaclark672377250/CVE-2025-29927-POC) :  ![starts](https://img.shields.io/github/stars/alinaclark672377250/CVE-2025-29927-POC.svg) ![forks](https://img.shields.io/github/forks/alinaclark672377250/CVE-2025-29927-POC.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/alinaclark672377250/CVE-2025-24813](https://github.com/alinaclark672377250/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/alinaclark672377250/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/alinaclark672377250/CVE-2025-24813.svg)


## CVE-2025-24799
 GLPI is a free asset and IT management software package. An unauthenticated user can perform a SQL injection through the inventory endpoint. This vulnerability is fixed in 10.0.18.

- [https://github.com/alinaclark672377250/CVE-2025-24799](https://github.com/alinaclark672377250/CVE-2025-24799) :  ![starts](https://img.shields.io/github/stars/alinaclark672377250/CVE-2025-24799.svg) ![forks](https://img.shields.io/github/forks/alinaclark672377250/CVE-2025-24799.svg)


## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

- [https://github.com/alinaclark672377250/CVE-2025-24016](https://github.com/alinaclark672377250/CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/alinaclark672377250/CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/alinaclark672377250/CVE-2025-24016.svg)


## CVE-2025-4606
 The Sala - Startup & SaaS WordPress Theme theme for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 1.1.4. This is due to the theme not properly validating a user's identity prior to updating their details like password. This makes it possible for unauthenticated attackers to change arbitrary user's passwords, including administrators, and leverage that to gain access to their account.

- [https://github.com/0xCyp1337/CVE-2025-4606](https://github.com/0xCyp1337/CVE-2025-4606) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2025-4606.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2025-4606.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/darklotuskdb/nextjs-CVE-2025-29927-hunter](https://github.com/darklotuskdb/nextjs-CVE-2025-29927-hunter) :  ![starts](https://img.shields.io/github/stars/darklotuskdb/nextjs-CVE-2025-29927-hunter.svg) ![forks](https://img.shields.io/github/forks/darklotuskdb/nextjs-CVE-2025-29927-hunter.svg)


## CVE-2025-1661
 The HUSKY – Products Filter Professional for WooCommerce plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 1.3.6.5 via the 'template' parameter of the woof_text_search AJAX action. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/alinaclark672377250/CVE-2025-1661](https://github.com/alinaclark672377250/CVE-2025-1661) :  ![starts](https://img.shields.io/github/stars/alinaclark672377250/CVE-2025-1661.svg) ![forks](https://img.shields.io/github/forks/alinaclark672377250/CVE-2025-1661.svg)


## CVE-2024-36991
 In Splunk Enterprise on Windows versions below 9.2.2, 9.1.5, and 9.0.10, an attacker could perform a path traversal on the /modules/messaging/ endpoint in Splunk Enterprise on Windows. This vulnerability should only affect Splunk Enterprise on Windows.

- [https://github.com/wintxx/CVE-2024-36991-Splunk](https://github.com/wintxx/CVE-2024-36991-Splunk) :  ![starts](https://img.shields.io/github/stars/wintxx/CVE-2024-36991-Splunk.svg) ![forks](https://img.shields.io/github/forks/wintxx/CVE-2024-36991-Splunk.svg)


## CVE-2024-9465
 An SQL injection vulnerability in Palo Alto Networks Expedition allows an unauthenticated attacker to reveal Expedition database contents, such as password hashes, usernames, device configurations, and device API keys. With this, attackers can also create and read arbitrary files on the Expedition system.

- [https://github.com/0-9g/CVE-2024-9465](https://github.com/0-9g/CVE-2024-9465) :  ![starts](https://img.shields.io/github/stars/0-9g/CVE-2024-9465.svg) ![forks](https://img.shields.io/github/forks/0-9g/CVE-2024-9465.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/HadesNull123/CVE-2024-6387_Check](https://github.com/HadesNull123/CVE-2024-6387_Check) :  ![starts](https://img.shields.io/github/stars/HadesNull123/CVE-2024-6387_Check.svg) ![forks](https://img.shields.io/github/forks/HadesNull123/CVE-2024-6387_Check.svg)


## CVE-2023-33107
 Memory corruption in Graphics Linux while assigning shared virtual memory region during IOCTL call.

- [https://github.com/miyoubi/Fracture](https://github.com/miyoubi/Fracture) :  ![starts](https://img.shields.io/github/stars/miyoubi/Fracture.svg) ![forks](https://img.shields.io/github/forks/miyoubi/Fracture.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS = v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/qrxnz/CVE-2023-4220](https://github.com/qrxnz/CVE-2023-4220) :  ![starts](https://img.shields.io/github/stars/qrxnz/CVE-2023-4220.svg) ![forks](https://img.shields.io/github/forks/qrxnz/CVE-2023-4220.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/mlucianoeze/linux-backport-CVE-2022-0847](https://github.com/mlucianoeze/linux-backport-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/mlucianoeze/linux-backport-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/mlucianoeze/linux-backport-CVE-2022-0847.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/sotiak/CVE-2021-41773](https://github.com/sotiak/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-41773.svg)
- [https://github.com/R3leant/CVE-2021-41773](https://github.com/R3leant/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/R3leant/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/R3leant/CVE-2021-41773.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/Mohammad-Anon/CVE-2020-1938](https://github.com/Mohammad-Anon/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/Mohammad-Anon/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/Mohammad-Anon/CVE-2020-1938.svg)


## CVE-2020-1472
When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/mynga17/zerologon-security-lab](https://github.com/mynga17/zerologon-security-lab) :  ![starts](https://img.shields.io/github/stars/mynga17/zerologon-security-lab.svg) ![forks](https://img.shields.io/github/forks/mynga17/zerologon-security-lab.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/mlucianoeze/linux-backport-CVE-2016-5195](https://github.com/mlucianoeze/linux-backport-CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/mlucianoeze/linux-backport-CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/mlucianoeze/linux-backport-CVE-2016-5195.svg)

