# Update 2026-10-16
## CVE-2026-110447
 Collabora Online Built-in CODE Server before 26.4.303 (richdocumentscode), a Nextcloud app, allows remote code execution, as exploited in the wild in September and October 2026, a different vulnerability than CVE-2025-66208. This is an OS command injection in proxy.php when the CODE server isn't running (e.g., the product was recently restarted). The vulnerability is not present in standalone Collabora Online servers; only this deployment with CODE Server is affected.

- [https://github.com/adriyansyah-mf/cve-2026-110447](https://github.com/adriyansyah-mf/cve-2026-110447) :  ![starts](https://img.shields.io/github/stars/adriyansyah-mf/cve-2026-110447.svg) ![forks](https://img.shields.io/github/forks/adriyansyah-mf/cve-2026-110447.svg)


## CVE-2026-109506
settings.

- [https://github.com/lukaspalm/CVE-2026-109506](https://github.com/lukaspalm/CVE-2026-109506) :  ![starts](https://img.shields.io/github/stars/lukaspalm/CVE-2026-109506.svg) ![forks](https://img.shields.io/github/forks/lukaspalm/CVE-2026-109506.svg)


## CVE-2026-107821
 MariaDB server is a community developed fork of MySQL server. From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2, MariaDB insufficiently validated counts, offsets, lengths, and field boundaries in FRM metadata while opening binary FRM files. An attacker able to place a crafted FRM file in the data directory could trigger out-of-bounds reads or writes, crash the server, or potentially execute code. This issue is fixed in versions 10.6.28, 10.11.19, 11.4.13, 11.8.9, 12.3.3, and 13.0.2.

- [https://github.com/pinebudweiser/CVE-2026-107821-PoC](https://github.com/pinebudweiser/CVE-2026-107821-PoC) :  ![starts](https://img.shields.io/github/stars/pinebudweiser/CVE-2026-107821-PoC.svg) ![forks](https://img.shields.io/github/forks/pinebudweiser/CVE-2026-107821-PoC.svg)


## CVE-2026-107181
 Telegram Desktop before 7.2.9 contains an IPC record-separator injection vulnerability in Core::Sandbox that allows remote attackers to inject OPEN: records via crafted tg:// links containing unescaped semicolons. Attackers can reach the interpret: scheme handler to upload local files, including tdata session keys, to an attacker channel, enabling account takeover.

- [https://github.com/abdugafforov-bobur/cve-2026-107181-poc](https://github.com/abdugafforov-bobur/cve-2026-107181-poc) :  ![starts](https://img.shields.io/github/stars/abdugafforov-bobur/cve-2026-107181-poc.svg) ![forks](https://img.shields.io/github/forks/abdugafforov-bobur/cve-2026-107181-poc.svg)


## CVE-2026-105445
 An Incorrect Privilege Assignment vulnerability in Docker Hub's account-to-organization conversion feature allowed an authenticated attacker to reassign a personal access token (PAT) they controlled to another Docker Hub user without rotating or revoking the token secret. The unchanged PAT then authenticated to the registry as the recipient and could pull, push, or delete images, within its scopes, in repositories accessible to that user, including organization repositories.

- [https://github.com/Mothchui/CVE-2026-105445](https://github.com/Mothchui/CVE-2026-105445) :  ![starts](https://img.shields.io/github/stars/Mothchui/CVE-2026-105445.svg) ![forks](https://img.shields.io/github/forks/Mothchui/CVE-2026-105445.svg)


## CVE-2026-105134
 A flaw has been found in Ahsay AhsayCBS up to 10.3.2. This vulnerability affects unknown code of the file /rps/api/json/UpdateReceivers.do of the component Replication Receiver. Executing a manipulation of the argument random can lead to os command injection. It is possible to launch the attack remotely. The exploit has been published and may be used. Upgrading to version 10.3.4 is able to resolve this issue. Upgrading the affected component is advised.

- [https://github.com/horizon3ai/AhsayCBS-Auth-Bypass-RCE](https://github.com/horizon3ai/AhsayCBS-Auth-Bypass-RCE) :  ![starts](https://img.shields.io/github/stars/horizon3ai/AhsayCBS-Auth-Bypass-RCE.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/AhsayCBS-Auth-Bypass-RCE.svg)


## CVE-2026-105133
 A vulnerability was detected in Ahsay AhsayCBS up to 10.3.2. This affects the function checkSysPwd of the file com/ahsay/obs/api/ApiStructsAction.java of the component API. Performing a manipulation of the argument random results in improper authentication. It is possible to initiate the attack remotely. The exploit is now public and may be used. Upgrading to version 10.3.4 is able to mitigate this issue. It is recommended to upgrade the affected component.

- [https://github.com/horizon3ai/AhsayCBS-Auth-Bypass-RCE](https://github.com/horizon3ai/AhsayCBS-Auth-Bypass-RCE) :  ![starts](https://img.shields.io/github/stars/horizon3ai/AhsayCBS-Auth-Bypass-RCE.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/AhsayCBS-Auth-Bypass-RCE.svg)


## CVE-2026-104748
 The SimpleForm – Form Maker to Chat Apps with Quiz, Poll and Multi Lead Notifications plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 3.10.0 This is due to the `wp_ajax_nopriv_simpleform_wp_register` AJAX action lacking any capability check for role assignment and the `save_custom_fields_to_user_meta()` function using an exclusion list that omits `wp_capabilities`, combined with `get_form_settings()` returning a hard-coded defaults array that unconditionally enables meta writing regardless of the supplied `form_id`. This makes it possible for unauthenticated attackers to create a new Administrator-level WordPress account by supplying `wp_capabilities[administrator]=1` alongside standard registration fields. The nonce required by the endpoint is publicly emitted into the `front_end_data` JavaScript object on every front-end page via `wp_enqueue_scripts`, making it trivially obtainable by any unauthenticated visitor before submitting the malicious request.

- [https://github.com/joshuavanderpoll/CVE-2026-104748](https://github.com/joshuavanderpoll/CVE-2026-104748) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2026-104748.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2026-104748.svg)
- [https://github.com/MrjHaxcore/CVE-2026-104748](https://github.com/MrjHaxcore/CVE-2026-104748) :  ![starts](https://img.shields.io/github/stars/MrjHaxcore/CVE-2026-104748.svg) ![forks](https://img.shields.io/github/forks/MrjHaxcore/CVE-2026-104748.svg)


## CVE-2026-104711
Users are recommended to upgrade to version 6.12.0 or 7.4.0, which fixes the issue.

- [https://github.com/uday952/CVE-2026-104711-POC---Brand-New](https://github.com/uday952/CVE-2026-104711-POC---Brand-New) :  ![starts](https://img.shields.io/github/stars/uday952/CVE-2026-104711-POC---Brand-New.svg) ![forks](https://img.shields.io/github/forks/uday952/CVE-2026-104711-POC---Brand-New.svg)


## CVE-2026-104110
 FileRise is a self-hosted web-based file manager with multi-file upload, editing, and batch operations. Prior to 3.24.0, FileRise Pro /api/pro/portals/get.php returns a configured client portal's full internal record to an unauthenticated caller who knows or guesses the portal slug. The response includes the internal storage folder path, client contact email, form settings, and upload-policy details, while the separate publicMeta.php endpoint intentionally exposes only curated branding data. Exploitation requires the Pro add-on and at least one configured portal. This issue is fixed in version 3.24.0.

- [https://github.com/pervinzahidli/CVE-2026-104110](https://github.com/pervinzahidli/CVE-2026-104110) :  ![starts](https://img.shields.io/github/stars/pervinzahidli/CVE-2026-104110.svg) ![forks](https://img.shields.io/github/forks/pervinzahidli/CVE-2026-104110.svg)


## CVE-2026-103977
 FileRise is a self-hosted web-based file manager with multi-file upload, editing, and batch operations. Prior to 3.23.0, FileRise stores failed TOTP verification attempts in $_SESSION. An attacker who already possesses a target account's valid primary credential can restart the login workflow in a new session and restore the second-factor attempt allowance, permitting continued online TOTP guessing beyond the intended five-attempt limit. The pending-login TOTP handlers did not share a durable account-wide limit. This issue is fixed in version 3.23.0.

- [https://github.com/pervinzahidli/CVE-2026-103977](https://github.com/pervinzahidli/CVE-2026-103977) :  ![starts](https://img.shields.io/github/stars/pervinzahidli/CVE-2026-103977.svg) ![forks](https://img.shields.io/github/forks/pervinzahidli/CVE-2026-103977.svg)


## CVE-2026-97657
 The Abandoned Cart Pro for WooCommerce plugin for WordPress is vulnerable to Authentication Bypass via Malleable Encryption and Bypassable HMAC in all versions up to, and including, 10.8.0. This is due to the use of MAC-free AES-CTR encryption for cart-recovery link tokens — where the 8-byte CTR nonce is carried inside the ciphertext blob and the encryption key is looked up using the attacker-supplied `user_email` GET parameter — combined with an HMAC nonce check in `wcap_email_track_links()` that is only enforced when the `wcap_nonce` parameter is non-empty, allowing complete bypass by omission, and an insecure direct object reference on the decrypted `abandoned_id` with no ownership verification confirming the cart belongs to the email used for decryption. This makes it possible for unauthenticated attackers who possess a single legitimate cart-recovery link (obtained from their own reminder email) to recover the keystream, forge a ciphertext that decrypts to any victim's cart ID, and trigger a call to `wp_set_auth_cookie()` for the victim user — achieving full account takeover of any user who has ever abandoned a cart, including administrators. The auto-login feature defaults to enabled and is forced on during plugin upgrades, meaning all affected installations are exploitable without any additional configuration.

- [https://github.com/murrez/CVE-2026-97657](https://github.com/murrez/CVE-2026-97657) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-97657.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-97657.svg)


## CVE-2026-96230
 Improper neutralization of input during web page generation ('cross-site scripting') in ASP.NET Core allows an unauthorized attacker to execute code over a network.

- [https://github.com/codevalai/microsoft-security-advisory-cv](https://github.com/codevalai/microsoft-security-advisory-cv) :  ![starts](https://img.shields.io/github/stars/codevalai/microsoft-security-advisory-cv.svg) ![forks](https://img.shields.io/github/forks/codevalai/microsoft-security-advisory-cv.svg)


## CVE-2026-92392
free of a `struct Curl_easy` object.

- [https://github.com/ashu7ank/CVE-2026-92392](https://github.com/ashu7ank/CVE-2026-92392) :  ![starts](https://img.shields.io/github/stars/ashu7ank/CVE-2026-92392.svg) ![forks](https://img.shields.io/github/forks/ashu7ank/CVE-2026-92392.svg)


## CVE-2026-91159
 Discourse is an open-source discussion platform. Prior to 2026.9.0, 2026.8.1, 2026.7.3, and 2026.1.9, oEmbed processing treated an entire attacker-controlled HTML fragment as trusted when the fragment contained an iframe whose source matched the configured allowlist. A user with posting permission who controlled a public webpage and its oEmbed response could combine an allowlisted iframe with unrelated sibling HTML or CSS, causing stored visual overlays or other styled content to appear in post content and enabling misleading or fraudulent user interfaces. Exploitation requires a posting account, control of the fetched webpage and oEmbed response, and an allowlisted iframe source. The issue affects content integrity but does not expose restricted data, disrupt availability, or require interaction with Discourse Content Security Policy. This issue is fixed in versions 2026.9.0, 2026.8.1, 2026.7.3, and 2026.1.9.

- [https://github.com/sl4x0/autheo-cve-2026-91159-poc](https://github.com/sl4x0/autheo-cve-2026-91159-poc) :  ![starts](https://img.shields.io/github/stars/sl4x0/autheo-cve-2026-91159-poc.svg) ![forks](https://img.shields.io/github/forks/sl4x0/autheo-cve-2026-91159-poc.svg)


## CVE-2026-89026
 The Issabel Framework, the web framework supporting Issabel PBX software, before commit b97dbaf contains a hard-coded HS256 JWT signing key in the pbxapi index.php file that is identical across every installation, allowing unauthenticated remote attackers to forge valid bearer tokens. Attackers can use the forged token to call the manager originate endpoint with the System application parameter, causing Asterisk to execute arbitrary OS commands as the Asterisk user. Exploitation evidence was first observed by the Shadowserver Foundation on 2026-09-09.

- [https://github.com/im-hanzou/CVE-2026-89026](https://github.com/im-hanzou/CVE-2026-89026) :  ![starts](https://img.shields.io/github/stars/im-hanzou/CVE-2026-89026.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/CVE-2026-89026.svg)


## CVE-2026-86950
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.1 and iPadOS 26.7.1, macOS Sequoia 15.8.1, macOS Tahoe 26.7.1. Processing a maliciously crafted file may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 27.

- [https://github.com/java99999/CVE-2026-86950-POC](https://github.com/java99999/CVE-2026-86950-POC) :  ![starts](https://img.shields.io/github/stars/java99999/CVE-2026-86950-POC.svg) ![forks](https://img.shields.io/github/forks/java99999/CVE-2026-86950-POC.svg)


## CVE-2026-85097
 The Bricksforge plugin for WordPress is vulnerable to unauthenticated arbitrary file upload in versions up to, and including, 3.1.8.9. This is due to insufficient validation of the attacker-controlled URL field in the 'temporaryFileUploads' parameter during form submission. An unauthenticated attacker can first obtain a valid nonce via the bricksforge_regenerate_nonce AJAX endpoint, then upload a GIF/PHP polyglot file to the temporary upload directory where MIME type validation is correctly performed. Subsequently, the attacker can submit a form with a crafted 'temporaryFileUploads' parameter where the server-side file path points to the validated GIF file, but the attacker-controlled url field ends with a .php extension. This makes it possible for unauthenticated attackers to upload and execute arbitrary PHP code on the server.

- [https://github.com/Tarangj07/Wordpress-Lab-CVE-2026-85097](https://github.com/Tarangj07/Wordpress-Lab-CVE-2026-85097) :  ![starts](https://img.shields.io/github/stars/Tarangj07/Wordpress-Lab-CVE-2026-85097.svg) ![forks](https://img.shields.io/github/forks/Tarangj07/Wordpress-Lab-CVE-2026-85097.svg)


## CVE-2026-85046
 Type confusion in V8 in Google Chrome prior to 152.0.7977.82 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/jamezx32/CVE-2026-85046](https://github.com/jamezx32/CVE-2026-85046) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2026-85046.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2026-85046.svg)


## CVE-2026-83834
 Use after free in Windows Kernel-Mode Drivers allows an authorized attacker to elevate privileges locally.

- [https://github.com/wkpwn/CVE-2026-83834](https://github.com/wkpwn/CVE-2026-83834) :  ![starts](https://img.shields.io/github/stars/wkpwn/CVE-2026-83834.svg) ![forks](https://img.shields.io/github/forks/wkpwn/CVE-2026-83834.svg)


## CVE-2026-77770
 The miniOrange 2FA  WordPress plugin before 6.3.1, miniOrange 2FA  WordPress plugin before 19.3 does not require a validated transaction before deleting site options whose names come from unauthenticated request input, allowing any visitor to delete arbitrary options, which can lock every administrator out of the dashboard or deactivate every miniOrange 2FA  WordPress plugin before 6.3.1, miniOrange 2FA  WordPress plugin before 19.3 on the site.

- [https://github.com/gmh5225/CVE-2026-77770](https://github.com/gmh5225/CVE-2026-77770) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2026-77770.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2026-77770.svg)


## CVE-2026-76519
This vulnerability is due to improper handling of email attachments when the file reputation service is enabled. An attacker could exploit this vulnerability by sending an email that contains a crafted attachment through an affected device. A successful exploit could allow the attacker to write arbitrary files and execute commands with&nbsp;root privileges on the underlying operating system.

- [https://github.com/Mickysalivan/CVE-2026-76519-POC](https://github.com/Mickysalivan/CVE-2026-76519-POC) :  ![starts](https://img.shields.io/github/stars/Mickysalivan/CVE-2026-76519-POC.svg) ![forks](https://img.shields.io/github/forks/Mickysalivan/CVE-2026-76519-POC.svg)


## CVE-2026-74580
addresses are pushed back through iotlb_access_ok()'s slow path.

- [https://github.com/ABC00012345/CVE-2026-74580](https://github.com/ABC00012345/CVE-2026-74580) :  ![starts](https://img.shields.io/github/stars/ABC00012345/CVE-2026-74580.svg) ![forks](https://img.shields.io/github/forks/ABC00012345/CVE-2026-74580.svg)
- [https://github.com/techupdate24/linux-kernel-cve-2026-74580-vghost](https://github.com/techupdate24/linux-kernel-cve-2026-74580-vghost) :  ![starts](https://img.shields.io/github/stars/techupdate24/linux-kernel-cve-2026-74580-vghost.svg) ![forks](https://img.shields.io/github/forks/techupdate24/linux-kernel-cve-2026-74580-vghost.svg)


## CVE-2026-74041
 Wazuh 4.14.3 before 4.14.8 contains a case-sensitivity mismatch between the ossec.conf validator and wazuh-logcollector that bypasses remote-command validation. Authenticated users with manager:update_config can inject an uppercase LOG_FORMAT command localfile that the collector runs as root on reload.

- [https://github.com/roninreilly/wazuh-unauth-chain](https://github.com/roninreilly/wazuh-unauth-chain) :  ![starts](https://img.shields.io/github/stars/roninreilly/wazuh-unauth-chain.svg) ![forks](https://img.shields.io/github/forks/roninreilly/wazuh-unauth-chain.svg)


## CVE-2026-74034
 Wazuh from 4.1.0 before 4.14.8 contains a missing origin check in wm_agent_upgrade that allows enrolled agents to issue upgrade_custom commands with attacker-controlled file_path. Attackers can inject an upgrade_custom message over the agent channel to read arbitrary files as root, exfiltrating /etc/shadow and client.keys.

- [https://github.com/roninreilly/wazuh-unauth-chain](https://github.com/roninreilly/wazuh-unauth-chain) :  ![starts](https://img.shields.io/github/stars/roninreilly/wazuh-unauth-chain.svg) ![forks](https://img.shields.io/github/forks/roninreilly/wazuh-unauth-chain.svg)


## CVE-2026-69191
 FileRise is a self-hosted web-based file manager with multi-file upload, editing, and batch operations. Prior to 3.21.0, FileRise enforces disableFormLogin, disableBasicAuth, and disableOIDCLogin in the client interface but not consistently in the corresponding server-side authentication flows. A user with otherwise valid credentials for a disabled method can call its backend endpoint directly and authenticate despite the administrator's login-method policy. The flaw does not permit credential-free authentication. This issue is fixed in version 3.21.0.

- [https://github.com/fahimalshihab/CVE-2026-69191-FileRise-Authentication-Bypass](https://github.com/fahimalshihab/CVE-2026-69191-FileRise-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/fahimalshihab/CVE-2026-69191-FileRise-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/fahimalshihab/CVE-2026-69191-FileRise-Authentication-Bypass.svg)


## CVE-2026-67281
 RouterOS WebFig contains an unauthenticated file-read vulnerability in the /jsproxy path where a newly allocated session retains a stale uninitialized principal pointer used for file authorization. An unauthenticated attacker can prepare the allocator so that the file-serving path dereferences this pointer with sufficient rights, then supply parent-directory components in an encrypted URI to escape the WebFig file namespace and disclose root-owned files, including configuration stores containing credentials.This issue affects only 7.x branch was fixed in versions: 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/sohel160/Webfig-jsproxy-unauthenticated-file-read-CVE-2026-67281-](https://github.com/sohel160/Webfig-jsproxy-unauthenticated-file-read-CVE-2026-67281-) :  ![starts](https://img.shields.io/github/stars/sohel160/Webfig-jsproxy-unauthenticated-file-read-CVE-2026-67281-.svg) ![forks](https://img.shields.io/github/forks/sohel160/Webfig-jsproxy-unauthenticated-file-read-CVE-2026-67281-.svg)


## CVE-2026-65343
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 26.6.1 and iPadOS 26.6.1, macOS Tahoe 26.6.2, tvOS 27, visionOS 27, watchOS 27. A remote attacker may be able to cause unexpected system termination.

- [https://github.com/lkop32788/iOS26.6-CVE-2026-65343](https://github.com/lkop32788/iOS26.6-CVE-2026-65343) :  ![starts](https://img.shields.io/github/stars/lkop32788/iOS26.6-CVE-2026-65343.svg) ![forks](https://img.shields.io/github/forks/lkop32788/iOS26.6-CVE-2026-65343.svg)


## CVE-2026-63223
 CodeIgniter is a PHP full-stack web framework. Prior to 4.7.4, the is_image and mime_in upload validation rules do not independently enforce a safe client filename extension, allowing a remote attacker to upload executable content when an application preserves the client filename and stores uploads in a web-accessible script-enabled directory. Applications are impacted when they validate uploads using is_image or mime_in without an independent safe extension check (such as ext_in on patched versions), save uploaded files using the client-supplied filename, and place uploads in a web-accessible directory where PHP files can execute. This issue is fixed in version 4.7.4.

- [https://github.com/myeongji1/cve-2026-63223-ctf](https://github.com/myeongji1/cve-2026-63223-ctf) :  ![starts](https://img.shields.io/github/stars/myeongji1/cve-2026-63223-ctf.svg) ![forks](https://img.shields.io/github/forks/myeongji1/cve-2026-63223-ctf.svg)


## CVE-2026-59774
 Gitea's Org-mode markup renderer processes INCLUDE directives supplied to the repository markup endpoint without preventing access to server-side files. An unauthenticated attacker can use a suitable public repository to read files accessible to the Gitea service account. If the disclosed files include app.ini and its INTERNAL_TOKEN, the attacker can chain the disclosure with internal logger access to modify a Git hook and execute commands as the Gitea service account.

- [https://github.com/FlowerWitch/CVE-2026-59774_docker](https://github.com/FlowerWitch/CVE-2026-59774_docker) :  ![starts](https://img.shields.io/github/stars/FlowerWitch/CVE-2026-59774_docker.svg) ![forks](https://img.shields.io/github/forks/FlowerWitch/CVE-2026-59774_docker.svg)


## CVE-2026-57850
 RustDesk before 1.4.9 does not enforce a session's authorized connection scope on the server side, so a peer granted a limited session type (FileTransfer, PortForward, ViewCamera, or Terminal) can send control messages and login options reserved for a full Remote session. An authenticated remote peer can exploit this missing scope check to act outside its granted scope, injecting out-of-scope control messages to observe and control the host beyond the permissions it was given.

- [https://github.com/sn0x-sharma/CVE-2026-57850](https://github.com/sn0x-sharma/CVE-2026-57850) :  ![starts](https://img.shields.io/github/stars/sn0x-sharma/CVE-2026-57850.svg) ![forks](https://img.shields.io/github/forks/sn0x-sharma/CVE-2026-57850.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/ushst/CVE-2026-54121-adcs-chase-nxc](https://github.com/ushst/CVE-2026-54121-adcs-chase-nxc) :  ![starts](https://img.shields.io/github/stars/ushst/CVE-2026-54121-adcs-chase-nxc.svg) ![forks](https://img.shields.io/github/forks/ushst/CVE-2026-54121-adcs-chase-nxc.svg)


## CVE-2026-53613
 util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

- [https://github.com/mohamedjawady/CVE-2026-53613-poc](https://github.com/mohamedjawady/CVE-2026-53613-poc) :  ![starts](https://img.shields.io/github/stars/mohamedjawady/CVE-2026-53613-poc.svg) ![forks](https://img.shields.io/github/forks/mohamedjawady/CVE-2026-53613-poc.svg)


## CVE-2026-52806
 Gogs is an open source self-hosted Git service. Prior to 0.14.3, Gogs allows authenticated users to achieve Remote Code Execution (RCE) on the server by creating a pull request with a specially crafted branch name that injects the --exec flag into the git rebase command during the "Rebase before merging" merge operation. This vulnerability is fixed in 0.14.3.

- [https://github.com/portbuster1337/CVE-2026-52806](https://github.com/portbuster1337/CVE-2026-52806) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-52806.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-52806.svg)


## CVE-2026-49878
 In wpas_handle_robust_av_scs_recv_action of robust_av.c, there is a possible out-of-bounds write due to a logic error in the code. This could lead to remote code execution with System execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/rdip40026-web/cve_2026_49878_verify.txt](https://github.com/rdip40026-web/cve_2026_49878_verify.txt) :  ![starts](https://img.shields.io/github/stars/rdip40026-web/cve_2026_49878_verify.txt.svg) ![forks](https://img.shields.io/github/forks/rdip40026-web/cve_2026_49878_verify.txt.svg)


## CVE-2026-46376
 FreePBX is an open source IP PBX. From 15.0.42 to before 16.0.45 and 17.0.7, unauthenticated users may be able to access the User Control Panel (UCP) using hard-coded initial template credentials if these were not immediately changed by the Administrator who enabled UCP. Authenticated access to ACP is required for the initial setup of UCP generic templates, but after that, without further steps by the admin, unauthenticated users may be able to gain access. This vulnerability is fixed in 16.0.45 and 17.0.7.

- [https://github.com/portbuster1337/CVE-2026-46376](https://github.com/portbuster1337/CVE-2026-46376) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-46376.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-46376.svg)


## CVE-2026-46243
spnego_cred to request the key.

- [https://github.com/Koshmare-Blossom/CIFSwitch-go](https://github.com/Koshmare-Blossom/CIFSwitch-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/CIFSwitch-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/CIFSwitch-go.svg)


## CVE-2026-44825
  *  Clusters where template users have been assigned strong passwords after bootstrap

- [https://github.com/q0524/cve-2026-44825-challenge](https://github.com/q0524/cve-2026-44825-challenge) :  ![starts](https://img.shields.io/github/stars/q0524/cve-2026-44825-challenge.svg) ![forks](https://img.shields.io/github/forks/q0524/cve-2026-44825-challenge.svg)


## CVE-2026-44401
 Typemill CMS version 2.x contains a persistent cross-site scripting vulnerability in the Markdown parser extension that allows authenticated users with theme-configuration access to inject malicious JavaScript URIs by supplying unsanitized href values in Markdown links. Attackers can craft Markdown links using the javascript: scheme through ParsedownExtension.php or TwigMarkdownExtension.php, storing a persistent payload that executes in the browser of every visitor who clicks the link, enabling session cookie theft, authenticated request forgery, and credential harvesting.

- [https://github.com/sn0x-sharma/CVE-2026-44401](https://github.com/sn0x-sharma/CVE-2026-44401) :  ![starts](https://img.shields.io/github/stars/sn0x-sharma/CVE-2026-44401.svg) ![forks](https://img.shields.io/github/forks/sn0x-sharma/CVE-2026-44401.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/Koshmare-Blossom/DirtyFrag-go](https://github.com/Koshmare-Blossom/DirtyFrag-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/DirtyFrag-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/DirtyFrag-go.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/Koshmare-Blossom/DirtyFrag-go](https://github.com/Koshmare-Blossom/DirtyFrag-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/DirtyFrag-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/DirtyFrag-go.svg)
- [https://github.com/SudoXDdX/DirtyFrag](https://github.com/SudoXDdX/DirtyFrag) :  ![starts](https://img.shields.io/github/stars/SudoXDdX/DirtyFrag.svg) ![forks](https://img.shields.io/github/forks/SudoXDdX/DirtyFrag.svg)


## CVE-2026-33712
 Typebot is a chatbot builder tool. In versions 3.15.2 and prior, the preview chat endpoint (POST /api/v1/typebots/{typebotId}/preview/startChat) allows unauthenticated users to achieve Server-Side Request Forgery (SSRF) by supplying a custom typebot definition with server-side code blocks. The fetch function exposed inside the isolated-vm sandbox calls Node.js native fetch without the SSRF validation (validateHttpReqUrl) that protects the HTTP Request block. This bypasses all SSRF mitigations added after GHSA-8gq9-rw7v-3jpr. Exploitation of this unauthenticated SSRF vulnerability can lead to cloud credential theft, internal network access and data exfiltration for any self-hosted Typebot deployments and hosted services. This issue has been fixed in version 3.16.0.

- [https://github.com/portbuster1337/CVE-2026-33712](https://github.com/portbuster1337/CVE-2026-33712) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-33712.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-33712.svg)


## CVE-2026-33137
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. XWiki Platform is a generic wiki platform. In versions starting with 15.10.6 and prior to 18.1.0-rc-1, 17.10.3, 17.4.9, and 16.10.17, the POST /wikis/{wikiName} API executes a XAR import without performing any authentication or authorization checks, allowing an unauthenticated attacker to create or update documents in the target wiki. This vulnerability has been patched in XWiki 16.10.17, 17.4.9, 17.10.3, 18.0.1 and 18.1.0-rc-1.

- [https://github.com/portbuster1337/CVE-2026-33137](https://github.com/portbuster1337/CVE-2026-33137) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-33137.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-33137.svg)


## CVE-2026-31635
Reject authenticator lengths that exceed the remaining packet payload.

- [https://github.com/Koshmare-Blossom/DirtyDecrypt-go](https://github.com/Koshmare-Blossom/DirtyDecrypt-go) :  ![starts](https://img.shields.io/github/stars/Koshmare-Blossom/DirtyDecrypt-go.svg) ![forks](https://img.shields.io/github/forks/Koshmare-Blossom/DirtyDecrypt-go.svg)


## CVE-2026-27771
 Gitea versions up to and including 1.26.1 have insufficient permission checks for Composer package source links, which can expose private or internal package source information.

- [https://github.com/portbuster1337/CVE-2026-27771](https://github.com/portbuster1337/CVE-2026-27771) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-27771.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-27771.svg)


## CVE-2026-20182
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to the affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.

- [https://github.com/portbuster1337/CVE-2026-20182](https://github.com/portbuster1337/CVE-2026-20182) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-20182.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-20182.svg)


## CVE-2026-18718
 Ghidra contains an arbitrary code execution vulnerability in the Swift demangler analyzer that allows an attacker to execute arbitrary binaries by supplying a malicious Ghidra project with a crafted Swift tool directory path. When a victim opens the attacker-supplied project, SwiftDemanglerAnalyzer restores the persisted Swift binary directory from project state and SwiftNativeDemangler executes the resolved binary without integrity or signature verification, causing attacker-controlled executables to run under the Ghidra process user with no prompt or confirmation.

- [https://github.com/sn0x-sharma/CVE-2026-18718](https://github.com/sn0x-sharma/CVE-2026-18718) :  ![starts](https://img.shields.io/github/stars/sn0x-sharma/CVE-2026-18718.svg) ![forks](https://img.shields.io/github/forks/sn0x-sharma/CVE-2026-18718.svg)


## CVE-2026-18116
 Concrete CMS 8.3.0 to 9.5.2 stored calendar event names without sanitization and rendered them without HTML escaping in the workflow approval and deletion notifications shown in the dashboard "Waiting For Me" block. A registered user permitted to add events to a calendar governed by an approval workflow could submit an event whose name contained a script payload, which then executed in an administrator's browser when the pending request was displayed and could be used to create a new administrator account. The Concrete CMS security team gave this vulnerability a CVSS v4.0 score of 7.3 with vector CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N. Thanks v01demort for reporting.

- [https://github.com/EndlssNightmare/CVE-2026-18116](https://github.com/EndlssNightmare/CVE-2026-18116) :  ![starts](https://img.shields.io/github/stars/EndlssNightmare/CVE-2026-18116.svg) ![forks](https://img.shields.io/github/forks/EndlssNightmare/CVE-2026-18116.svg)


## CVE-2026-10769
 Improper Neutralization of Input During Web Page Generation ("Cross-site Scripting") vulnerability in Drupal Commerce Core allows Stored XSS. This issue affects Commerce Core versions: from 3.3.0 to 3.3.6.

- [https://github.com/thewhatdohe/CVE-2026-107692](https://github.com/thewhatdohe/CVE-2026-107692) :  ![starts](https://img.shields.io/github/stars/thewhatdohe/CVE-2026-107692.svg) ![forks](https://img.shields.io/github/forks/thewhatdohe/CVE-2026-107692.svg)


## CVE-2026-10708
 This vulnerability enables large‑scale data harvesting without requiring app‑specific secrets. A single request to a minimal leaderboard component may return user records containing emails, UUIDs, and custom fields. The combination of wildcard CORS behavior, long‑lived twenty‑day JWTs, and the absence of token revocation allows attackers to gather sensitive personal information from any Adalo application.

- [https://github.com/Primandito/CVE-2026-107081](https://github.com/Primandito/CVE-2026-107081) :  ![starts](https://img.shields.io/github/stars/Primandito/CVE-2026-107081.svg) ![forks](https://img.shields.io/github/forks/Primandito/CVE-2026-107081.svg)


## CVE-2026-0768
. Was ZDI-CAN-27322.

- [https://github.com/opthandsome/langflow_diff_cve-2026-0768](https://github.com/opthandsome/langflow_diff_cve-2026-0768) :  ![starts](https://img.shields.io/github/stars/opthandsome/langflow_diff_cve-2026-0768.svg) ![forks](https://img.shields.io/github/forks/opthandsome/langflow_diff_cve-2026-0768.svg)


## CVE-2026-0320
Cloud NGFW and Prisma® Access are not affected by this vulnerability.

- [https://github.com/gduma-phData/patch-CVE-2026-03200](https://github.com/gduma-phData/patch-CVE-2026-03200) :  ![starts](https://img.shields.io/github/stars/gduma-phData/patch-CVE-2026-03200.svg) ![forks](https://img.shields.io/github/forks/gduma-phData/patch-CVE-2026-03200.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/K4m1diamond/Flowise-RCE](https://github.com/K4m1diamond/Flowise-RCE) :  ![starts](https://img.shields.io/github/stars/K4m1diamond/Flowise-RCE.svg) ![forks](https://img.shields.io/github/forks/K4m1diamond/Flowise-RCE.svg)


## CVE-2025-58434
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including a valid password reset `tempToken` without authentication or verification. This enables any attacker to generate a reset token for arbitrary users and directly reset their password, leading to a complete account takeover (ATO). This vulnerability applies to both the cloud service (`cloud.flowiseai.com`) and self-hosted/local Flowise deployments that expose the same API. Commit 9e178d68873eb876073846433a596590d3d9c863 in version 3.0.6 secures password reset endpoints. Several recommended remediation steps are available. Do not return reset tokens or sensitive account details in API responses. Tokens must only be delivered securely via the registered email channel. Ensure `forgot-password` responds with a generic success message regardless of input, to avoid user enumeration. Require strong validation of the `tempToken` (e.g., single-use, short expiry, tied to request origin, validated against email delivery). Apply the same fixes to both cloud and self-hosted/local deployments. Log and monitor password reset requests for suspicious activity. Consider multi-factor verification for sensitive accounts.

- [https://github.com/K4m1diamond/Flowise-RCE](https://github.com/K4m1diamond/Flowise-RCE) :  ![starts](https://img.shields.io/github/stars/K4m1diamond/Flowise-RCE.svg) ![forks](https://img.shields.io/github/forks/K4m1diamond/Flowise-RCE.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC](https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC.svg)


## CVE-2025-24801
 GLPI is a free asset and IT management software package. An authenticated user can upload and force the execution of *.php files located on the GLPI server. This vulnerability is fixed in 10.0.18.

- [https://github.com/PeaMatNgu/cve-2025-24801-glpi](https://github.com/PeaMatNgu/cve-2025-24801-glpi) :  ![starts](https://img.shields.io/github/stars/PeaMatNgu/cve-2025-24801-glpi.svg) ![forks](https://img.shields.io/github/forks/PeaMatNgu/cve-2025-24801-glpi.svg)


## CVE-2025-13224
 Type Confusion in V8 in Google Chrome prior to 142.0.7444.175 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/jamezx32/CVE-2025-13224](https://github.com/jamezx32/CVE-2025-13224) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2025-13224.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2025-13224.svg)


## CVE-2025-12433
 Inappropriate implementation in V8 in Google Chrome prior to 142.0.7444.59 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/jamezx32/CVE-2025-12433](https://github.com/jamezx32/CVE-2025-12433) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2025-12433.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2025-12433.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182](https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg)


## CVE-2024-23222
 A type confusion issue was addressed with improved checks. This issue is fixed in Safari 17.3, iOS 15.8.7 and iPadOS 15.8.7, iOS 16.7.5 and iPadOS 16.7.5, iOS 17.3 and iPadOS 17.3, macOS Monterey 12.7.3, macOS Sonoma 14.3, macOS Ventura 13.6.4, tvOS 17.3, visionOS 1.0.2. Processing maliciously crafted web content may lead to arbitrary code execution. This fix associated with the Coruna exploit was shipped in iOS 17.3 on January 22, 2024. This update brings that fix to devices that cannot update to the latest iOS version.

- [https://github.com/jamezx32/CVE-2024-23222](https://github.com/jamezx32/CVE-2024-23222) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2024-23222.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2024-23222.svg)


## CVE-2024-5274
 Type Confusion in V8 in Google Chrome prior to 125.0.6422.112 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/jamezx32/CVE-2024-5274](https://github.com/jamezx32/CVE-2024-5274) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2024-5274.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2024-5274.svg)


## CVE-2024-2887
 Type Confusion in WebAssembly in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to execute arbitrary code via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/jamezx32/CVE-2024-2887](https://github.com/jamezx32/CVE-2024-2887) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2024-2887.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2024-2887.svg)


## CVE-2023-41993
 The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14. Processing web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 16.7.

- [https://github.com/jamezx32/CVE-2023-41993](https://github.com/jamezx32/CVE-2023-41993) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2023-41993.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2023-41993.svg)


## CVE-2023-41991
 A certificate validation issue was addressed. This issue is fixed in macOS Ventura 13.6, iOS 16.7 and iPadOS 16.7. A malicious app may be able to bypass signature validation. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 16.7.

- [https://github.com/lambertse/MOcha](https://github.com/lambertse/MOcha) :  ![starts](https://img.shields.io/github/stars/lambertse/MOcha.svg) ![forks](https://img.shields.io/github/forks/lambertse/MOcha.svg)


## CVE-2023-2033
 Type confusion in V8 in Google Chrome prior to 112.0.5615.121 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/jamezx32/CVE-2023-2033](https://github.com/jamezx32/CVE-2023-2033) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2023-2033.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2023-2033.svg)


## CVE-2022-1364
 Type confusion in V8 Turbofan in Google Chrome prior to 100.0.4896.127 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/jamezx32/CVE-2022-1364](https://github.com/jamezx32/CVE-2022-1364) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2022-1364.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2022-1364.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mah4nzfr/CVE-2021-41773](https://github.com/mah4nzfr/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/mah4nzfr/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mah4nzfr/CVE-2021-41773.svg)
- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)


## CVE-2021-38003
 Inappropriate implementation in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/jamezx32/CVE-2021-38003](https://github.com/jamezx32/CVE-2021-38003) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2021-38003.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2021-38003.svg)


## CVE-2021-30517
 Type confusion in V8 in Google Chrome prior to 90.0.4430.212 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/jamezx32/CVE-2021-30517](https://github.com/jamezx32/CVE-2021-30517) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2021-30517.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2021-30517.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/redspy-sec/CVE-2021-41773](https://github.com/redspy-sec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/redspy-sec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/redspy-sec/CVE-2021-41773.svg)
- [https://github.com/tr3m0x/CVE-2021-41773](https://github.com/tr3m0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/tr3m0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/tr3m0x/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2021-1905
 Possible use after free due to improper handling of memory mapping of multiple processes simultaneously. in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

- [https://github.com/Gonvar/movistar-home-root-](https://github.com/Gonvar/movistar-home-root-) :  ![starts](https://img.shields.io/github/stars/Gonvar/movistar-home-root-.svg) ![forks](https://img.shields.io/github/forks/Gonvar/movistar-home-root-.svg)


## CVE-2020-25213
 The File Manager (wp-file-manager) plugin before 6.9 for WordPress allows remote attackers to upload and execute arbitrary PHP code because it renames an unsafe example elFinder connector file to have the .php extension. This, for example, allows attackers to run the elFinder upload (or mkfile and put) command to write PHP code into the wp-content/plugins/wp-file-manager/lib/files/ directory. This was exploited in the wild in August and September 2020.

- [https://github.com/Maalfer/CVE-2020-25213-exploit](https://github.com/Maalfer/CVE-2020-25213-exploit) :  ![starts](https://img.shields.io/github/stars/Maalfer/CVE-2020-25213-exploit.svg) ![forks](https://img.shields.io/github/forks/Maalfer/CVE-2020-25213-exploit.svg)


## CVE-2020-17103
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/dooodad/MiniPlasma](https://github.com/dooodad/MiniPlasma) :  ![starts](https://img.shields.io/github/stars/dooodad/MiniPlasma.svg) ![forks](https://img.shields.io/github/forks/dooodad/MiniPlasma.svg)


## CVE-2020-0688
 A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.

- [https://github.com/chudamax/CVE-2020-0688-Exchange2010](https://github.com/chudamax/CVE-2020-0688-Exchange2010) :  ![starts](https://img.shields.io/github/stars/chudamax/CVE-2020-0688-Exchange2010.svg) ![forks](https://img.shields.io/github/forks/chudamax/CVE-2020-0688-Exchange2010.svg)


## CVE-2019-0567
 A remote code execution vulnerability exists in the way that the Chakra scripting engine handles objects in memory in Microsoft Edge, aka "Chakra Scripting Engine Memory Corruption Vulnerability." This affects Microsoft Edge, ChakraCore. This CVE ID is unique from CVE-2019-0539, CVE-2019-0568.

- [https://github.com/jamezx32/CVE-2019-0567](https://github.com/jamezx32/CVE-2019-0567) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2019-0567.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2019-0567.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/SanCody/DC1-Penetration-Testing-Report](https://github.com/SanCody/DC1-Penetration-Testing-Report) :  ![starts](https://img.shields.io/github/stars/SanCody/DC1-Penetration-Testing-Report.svg) ![forks](https://img.shields.io/github/forks/SanCody/DC1-Penetration-Testing-Report.svg)


## CVE-2018-4125
 An issue was discovered in certain Apple products. iOS before 11.3 is affected. Safari before 11.1 is affected. iCloud before 7.4 on Windows is affected. iTunes before 12.7.4 on Windows is affected. tvOS before 11.3 is affected. watchOS before 4.3 is affected. The issue involves the "WebKit" component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.

- [https://github.com/jamezx32/CVE-2018-4125-4161-4162-4163](https://github.com/jamezx32/CVE-2018-4125-4161-4162-4163) :  ![starts](https://img.shields.io/github/stars/jamezx32/CVE-2018-4125-4161-4162-4163.svg) ![forks](https://img.shields.io/github/forks/jamezx32/CVE-2018-4125-4161-4162-4163.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/m7arm4n/CVE-2017-7921](https://github.com/m7arm4n/CVE-2017-7921) :  ![starts](https://img.shields.io/github/stars/m7arm4n/CVE-2017-7921.svg) ![forks](https://img.shields.io/github/forks/m7arm4n/CVE-2017-7921.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/Mr-Ochobot/CVE-2016-5195](https://github.com/Mr-Ochobot/CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/Mr-Ochobot/CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/Mr-Ochobot/CVE-2016-5195.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/0xTaoZ/Heartbleed-CSP-project](https://github.com/0xTaoZ/Heartbleed-CSP-project) :  ![starts](https://img.shields.io/github/stars/0xTaoZ/Heartbleed-CSP-project.svg) ![forks](https://img.shields.io/github/forks/0xTaoZ/Heartbleed-CSP-project.svg)


## CVE-2012-2459
 Unspecified vulnerability in bitcoind and Bitcoin-Qt before 0.4.6, 0.5.x before 0.5.5, 0.6.0.x before 0.6.0.7, and 0.6.x before 0.6.2 allows remote attackers to cause a denial of service (block-processing outage and incorrect block count) via unknown behavior on a Bitcoin network.

- [https://github.com/GJ504b123/merkle-lab](https://github.com/GJ504b123/merkle-lab) :  ![starts](https://img.shields.io/github/stars/GJ504b123/merkle-lab.svg) ![forks](https://img.shields.io/github/forks/GJ504b123/merkle-lab.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Nutsulejustine/pentest-metasploitable](https://github.com/Nutsulejustine/pentest-metasploitable) :  ![starts](https://img.shields.io/github/stars/Nutsulejustine/pentest-metasploitable.svg) ![forks](https://img.shields.io/github/forks/Nutsulejustine/pentest-metasploitable.svg)


## CVE-2002-0082
 The dbm and shm session cache code in mod_ssl before 2.8.7-1.3.23, and Apache-SSL before 1.3.22+1.46, does not properly initialize memory using the i2d_SSL_SESSION function, which allows remote attackers to use a buffer overflow to execute arbitrary code via a large client certificate that is signed by a trusted Certificate Authority (CA), which produces a large serialized session.

- [https://github.com/Nutsulejustine/pentest-kioptrix](https://github.com/Nutsulejustine/pentest-kioptrix) :  ![starts](https://img.shields.io/github/stars/Nutsulejustine/pentest-kioptrix.svg) ![forks](https://img.shields.io/github/forks/Nutsulejustine/pentest-kioptrix.svg)

