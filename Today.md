# Update 2026-09-29
## CVE-2026-100835
 Contrast before 1.16.0 is susceptible to remote attestation relay attacks. Contrast accepted any TEE attestation report that verified correctly and contained the expected firmware patch levels and software measurements, regardless of which machine produced it, so attestation was not bound to specific, physically trusted hardware. An attacker who can both intercept network traffic between the CLI and the Coordinator (or between the Coordinator and an attested component) and forge reports or extract secrets from any single TEE machine under their physical control can relay such a report to impersonate a Contrast Coordinator or a Contrast workload, defeating identity verification in Contrast's attested TLS (aTLS).

- [https://github.com/murrez/CVE-2026-100835](https://github.com/murrez/CVE-2026-100835) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-100835.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-100835.svg)


## CVE-2026-100740
 A vulnerability was detected in D-Link DIR-895L A1_102b07. Impacted is the function tunnel_set_params of the file tunnel.c of the component L2TP Control Channel Parser. Performing a manipulation results in out-of-bounds write. The attack may be initiated remotely. The exploit is now public and may be used.

- [https://github.com/murrez/CVE-2026-100740](https://github.com/murrez/CVE-2026-100740) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-100740.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-100740.svg)


## CVE-2026-100382
This issue affects Mediawiki - ExternalData Extension: from * before 3.7.

- [https://github.com/nth347/mediawiki-CVE-2026-100382](https://github.com/nth347/mediawiki-CVE-2026-100382) :  ![starts](https://img.shields.io/github/stars/nth347/mediawiki-CVE-2026-100382.svg) ![forks](https://img.shields.io/github/forks/nth347/mediawiki-CVE-2026-100382.svg)


## CVE-2026-93399
 The Bookly plugin for WordPress is vulnerable to Insecure Direct Object Reference in versions up to, and including, 28.2 via the 'bookly_get_form_id', 'bookly_render_complete', 'bookly_add_to_calendar' and 'bookly_rollback_order' AJAX actions. This is due to the 'bookly_get_form_id' handler blindly storing the attacker-controlled 'order_id' from the submitted form_data into a new booking session, which the 'bookly_render_complete' handler then trusts to look up and return the corresponding Order's secret token without verifying that the current session created that order. This makes it possible for unauthenticated attackers to enumerate sequential order IDs, disclose other customers' order tokens, retrieve calendar/appointment information via 'bookly_add_to_calendar' and permanently delete arbitrary non-completed bookings via 'bookly_rollback_order', which cascade-deletes the customer_appointment and (when no other customers are attached) the underlying appointment.

- [https://github.com/josemour8/CVE-2026-93399](https://github.com/josemour8/CVE-2026-93399) :  ![starts](https://img.shields.io/github/stars/josemour8/CVE-2026-93399.svg) ![forks](https://img.shields.io/github/forks/josemour8/CVE-2026-93399.svg)


## CVE-2026-88772
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to Remote Code Execution or Denial of Service

- [https://github.com/murrez/CVE-2026-88772](https://github.com/murrez/CVE-2026-88772) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-88772.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-88772.svg)


## CVE-2026-88008
 Traefik is an open source HTTP reverse proxy and load balancer. From 2.11.26 until 2.11.57 and 3.7.13, Traefik forwards a client-supplied Connection header requesting Upgrade, the Upgrade: h2c token, and HTTP2-Settings to a shared backend. If the backend accepts h2c and returns 101 Switching Protocols, Traefik enters a raw tunnel and no longer applies routers, BasicAuth, ForwardAuth, IPAllowList, RateLimit, access logging, metrics, or tracing to later HTTP/2 requests, allowing an unauthenticated request through an unprotected route to reach protected paths on the same backend. This issue is fixed in 2.11.57 and 3.7.13.

- [https://github.com/Boreas37/CVE-2026-88008-PoC](https://github.com/Boreas37/CVE-2026-88008-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-88008-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-88008-PoC.svg)


## CVE-2026-87902
 An unauthenticated attacker can make `get_page_template()` page-template resolution include a chosen readable local `.php` file outside the active theme directories. If relevant pre-conditions for both the server and the active theme are met, this can lead to RCE.

- [https://github.com/langz337/CVE-2026-87902](https://github.com/langz337/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/langz337/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/langz337/CVE-2026-87902.svg)
- [https://github.com/Maalfer/CVE-2026-87902-exploit](https://github.com/Maalfer/CVE-2026-87902-exploit) :  ![starts](https://img.shields.io/github/stars/Maalfer/CVE-2026-87902-exploit.svg) ![forks](https://img.shields.io/github/forks/Maalfer/CVE-2026-87902-exploit.svg)
- [https://github.com/abatsakidis/wp-cve-2026-87902-checker](https://github.com/abatsakidis/wp-cve-2026-87902-checker) :  ![starts](https://img.shields.io/github/stars/abatsakidis/wp-cve-2026-87902-checker.svg) ![forks](https://img.shields.io/github/forks/abatsakidis/wp-cve-2026-87902-checker.svg)


## CVE-2026-86060
path involving usernames that begin with a prohibited character, allowing for the trusted RouterOS policy mask to be changed, leading to privilege escalation. Exploitation requires an unauthenticated SSH session to reach the RouterOS login helper.This issue was fixed in versions: 6.49.21 (Long-term), 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/tc4dy/CVE-2026-67279-86060-Toolkit](https://github.com/tc4dy/CVE-2026-67279-86060-Toolkit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-67279-86060-Toolkit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-67279-86060-Toolkit.svg)


## CVE-2026-85706
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.7 before 18.11.12, 19.0 before 19.0.9, 19.1 before 19.1.8, 19.2 before 19.2.6, and 19.3 before 19.3.2 that, under certain conditions, an unauthenticated user could have read arbitrary files from the GitLab server due to improper path confinement and missing authentication enforcement in the repository commits API.

- [https://github.com/unh00k3d/cve-2026-85706](https://github.com/unh00k3d/cve-2026-85706) :  ![starts](https://img.shields.io/github/stars/unh00k3d/cve-2026-85706.svg) ![forks](https://img.shields.io/github/forks/unh00k3d/cve-2026-85706.svg)


## CVE-2026-83603
 Netdata is an open source observability tool. Prior to 2.10.4, the setuid-root ndsudo helper command fail2ban-client-status-socket in src/collectors/utils/ndsudo.c accepts a caller-controlled --socket_path from the low-privileged netdata service account. The account can direct root fail2ban-client to a malicious UNIX socket, and fail2ban/client/csocket.py CSocket.receive() passes the returned data to pickle.loads(), allowing attacker-controlled code to execute as root on systems with fail2ban-client installed. This issue is fixed in version 2.10.4 and nightly build 2.10.0-782-nightly.

- [https://github.com/OhWelp/CVE-2026-83603-LPE-PoC](https://github.com/OhWelp/CVE-2026-83603-LPE-PoC) :  ![starts](https://img.shields.io/github/stars/OhWelp/CVE-2026-83603-LPE-PoC.svg) ![forks](https://img.shields.io/github/forks/OhWelp/CVE-2026-83603-LPE-PoC.svg)


## CVE-2026-78159
 The The Events Calendar plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 6.17.3 via the parse_array function. This is due to insufficient validation of the widget 'classes' map, allowing a plain-array payload to bypass the is_safe_widget_instance() object check and reach the callable-invocation sink in Element_Classes::parse_array(). This makes it possible for unauthenticated attackers to execute code on the server. Exploitation requires that the targeted site has comments enabled on tribe_events posts and that at least one comment containing a crafted wp:legacy-widget block has been submitted, as the attack chain is triggered when do_blocks() processes the single-event HTML including the comment area.

- [https://github.com/antid00t/CVE-2026-78006-CVE-2026-78159](https://github.com/antid00t/CVE-2026-78006-CVE-2026-78159) :  ![starts](https://img.shields.io/github/stars/antid00t/CVE-2026-78006-CVE-2026-78159.svg) ![forks](https://img.shields.io/github/forks/antid00t/CVE-2026-78006-CVE-2026-78159.svg)


## CVE-2026-78006
 The The Events Calendar plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 6.17.4 via the is_safe_widget_instance function. This is due to insufficient protection in is_safe_widget_instance, which can be bypassed because PHP fires magic methods during its pre-parse, combined with enable_rendering_widget_copied() forging a valid wp_hash integrity attribute before unserialize() is reached. This makes it possible for unauthenticated attackers to execute code on the server. This is exploitable without authentication or approval because the plugin's V2 single-event template runs do_blocks() over buffered comment HTML, and WordPress returns a moderation-hash URL that allows an unauthenticated commenter to immediately view their own pending comment, delivering the injected block markup to the vulnerable code path before any moderation occurs. This does require comments to be enabled and visible on events.

- [https://github.com/antid00t/CVE-2026-78006-CVE-2026-78159](https://github.com/antid00t/CVE-2026-78006-CVE-2026-78159) :  ![starts](https://img.shields.io/github/stars/antid00t/CVE-2026-78006-CVE-2026-78159.svg) ![forks](https://img.shields.io/github/forks/antid00t/CVE-2026-78006-CVE-2026-78159.svg)


## CVE-2026-76547
 The User Profile Builder  WordPress plugin before 4.0.1 does not validate the type of data being deserialized when importing a configuration file, allowing high privilege users such as administrators to conduct PHP Object Injection. The affected feature is a free add-on which is disabled by default, and no POP chain is present in the User Profile Builder  WordPress plugin before 4.0.1 itself, so further impact requires a suitable gadget from another installed User Profile Builder  WordPress plugin before 4.0.1 or .

- [https://github.com/H4zaz/CVE-2026-76547](https://github.com/H4zaz/CVE-2026-76547) :  ![starts](https://img.shields.io/github/stars/H4zaz/CVE-2026-76547.svg) ![forks](https://img.shields.io/github/forks/H4zaz/CVE-2026-76547.svg)


## CVE-2026-71963
 Hermes Agent 0.18.2 through 0.21.0, fixed in commit f6234d0, contains a remote code execution vulnerability that allows attackers to execute arbitrary OS commands by supplying a malicious repository with a crafted .git/config that sets core.fsmonitor to an attacker-controlled command. When a user opens the malicious repository and sends any message, the agent triggers a git status index refresh which executes the injected command in the user's process context, exposing the full environment including configured provider API keys.

- [https://github.com/Boreas37/CVE-2026-71963-PoC](https://github.com/Boreas37/CVE-2026-71963-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-71963-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-71963-PoC.svg)


## CVE-2026-67279
 RouterOS SSH enters the connection protocol after a client-requested rekey even though user authentication was never attempted, allowing an unauthenticated client to open a session channel and send an exec request. On affected builds the server dispatches the command, enabling unauthenticated creation, overwrite, and reconstruction of files in the RouterOS managed file namespace, including support files containing configuration and diagnostic data.This issue was fixed in versions: 6.49.21 (Long-term), 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/tc4dy/CVE-2026-67279-86060-Toolkit](https://github.com/tc4dy/CVE-2026-67279-86060-Toolkit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-67279-86060-Toolkit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-67279-86060-Toolkit.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/jed-parsec/CVE-2026-63030-60137-wp2shell-lab](https://github.com/jed-parsec/CVE-2026-63030-60137-wp2shell-lab) :  ![starts](https://img.shields.io/github/stars/jed-parsec/CVE-2026-63030-60137-wp2shell-lab.svg) ![forks](https://img.shields.io/github/forks/jed-parsec/CVE-2026-63030-60137-wp2shell-lab.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/jed-parsec/CVE-2026-63030-60137-wp2shell-lab](https://github.com/jed-parsec/CVE-2026-63030-60137-wp2shell-lab) :  ![starts](https://img.shields.io/github/stars/jed-parsec/CVE-2026-63030-60137-wp2shell-lab.svg) ![forks](https://img.shields.io/github/forks/jed-parsec/CVE-2026-63030-60137-wp2shell-lab.svg)


## CVE-2026-60000
 sshd in OpenSSH before 10.4 allows remote attackers to cause a denial of service (resource consumption from excessive authentication attempts) because MaxAuthTries was mishandled for GSSAPIAuthentication.

- [https://github.com/ImperfectP/CVE-2026-600004](https://github.com/ImperfectP/CVE-2026-600004) :  ![starts](https://img.shields.io/github/stars/ImperfectP/CVE-2026-600004.svg) ![forks](https://img.shields.io/github/forks/ImperfectP/CVE-2026-600004.svg)


## CVE-2026-48842
 Roundcube Webmail 1.6.x before 1.6.16 and 1.7.x before 1.7.1 has Pre-authentication SQL injection in the virtuser_query plugin via a preg_replace() backslash escape bypass.

- [https://github.com/4minx/CVE-2026-48842](https://github.com/4minx/CVE-2026-48842) :  ![starts](https://img.shields.io/github/stars/4minx/CVE-2026-48842.svg) ![forks](https://img.shields.io/github/forks/4minx/CVE-2026-48842.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/YellowKeyBitLocker-CVE/YellowKey-BitLocker-CVE-2026-45585](https://github.com/YellowKeyBitLocker-CVE/YellowKey-BitLocker-CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/YellowKeyBitLocker-CVE/YellowKey-BitLocker-CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/YellowKeyBitLocker-CVE/YellowKey-BitLocker-CVE-2026-45585.svg)


## CVE-2026-44431
 urllib3 is an HTTP client library for Python. From 1.23 to before 2.7.0, cross-origin redirects followed from the low-level API via ProxyManager.connection_from_url().urlopen(..., assert_same_host=False) still forward these sensitive headers. This vulnerability is fixed in 2.7.0.

- [https://github.com/SSH-PuR66/cve-replay](https://github.com/SSH-PuR66/cve-replay) :  ![starts](https://img.shields.io/github/stars/SSH-PuR66/cve-replay.svg) ![forks](https://img.shields.io/github/forks/SSH-PuR66/cve-replay.svg)


## CVE-2026-44011
 Craft CMS is a content management system (CMS). From 4.0.0 to before 4.17.12 and 5.9.18, Craft CMS which contains an input-handling flaw in a Yii object creation path that let any authenticated user inject malicious configuration and execute arbitrary commands on the server. The request-controlled condition field layouts data is converted into a live FieldLayout object without a Component::cleanseConfig() boundary. Because Craft configures models before parent::__construct(), attacker-controlled special config keys can take effect during object creation, and FieldLayout initialization then triggers a same-request event. This vulnerability is fixed in 4.17.12 and 5.9.18.

- [https://github.com/4xura/CVE-2026-44011-craftcms-auth-rce](https://github.com/4xura/CVE-2026-44011-craftcms-auth-rce) :  ![starts](https://img.shields.io/github/stars/4xura/CVE-2026-44011-craftcms-auth-rce.svg) ![forks](https://img.shields.io/github/forks/4xura/CVE-2026-44011-craftcms-auth-rce.svg)
- [https://github.com/Cyberuser-hash/CVE-2026-44011-craft-rce-poc](https://github.com/Cyberuser-hash/CVE-2026-44011-craft-rce-poc) :  ![starts](https://img.shields.io/github/stars/Cyberuser-hash/CVE-2026-44011-craft-rce-poc.svg) ![forks](https://img.shields.io/github/forks/Cyberuser-hash/CVE-2026-44011-craft-rce-poc.svg)
- [https://github.com/khush-613/CVE-2026-44011-poc](https://github.com/khush-613/CVE-2026-44011-poc) :  ![starts](https://img.shields.io/github/stars/khush-613/CVE-2026-44011-poc.svg) ![forks](https://img.shields.io/github/forks/khush-613/CVE-2026-44011-poc.svg)
- [https://github.com/DENNISDGR/CVE-2026-44011-poc](https://github.com/DENNISDGR/CVE-2026-44011-poc) :  ![starts](https://img.shields.io/github/stars/DENNISDGR/CVE-2026-44011-poc.svg) ![forks](https://img.shields.io/github/forks/DENNISDGR/CVE-2026-44011-poc.svg)


## CVE-2026-43805
 A race condition was addressed with improved state handling. This issue is fixed in iOS 26.6 and iPadOS 26.6, macOS Sequoia 15.7.8, macOS Sonoma 14.8.8, macOS Tahoe 26.6, watchOS 26.6. An app may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/tls456/CVE-2026-43805-PoC](https://github.com/tls456/CVE-2026-43805-PoC) :  ![starts](https://img.shields.io/github/stars/tls456/CVE-2026-43805-PoC.svg) ![forks](https://img.shields.io/github/forks/tls456/CVE-2026-43805-PoC.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/cyberbalsa/GhostLock-NVIDIA-Shield-9.2.4](https://github.com/cyberbalsa/GhostLock-NVIDIA-Shield-9.2.4) :  ![starts](https://img.shields.io/github/stars/cyberbalsa/GhostLock-NVIDIA-Shield-9.2.4.svg) ![forks](https://img.shields.io/github/forks/cyberbalsa/GhostLock-NVIDIA-Shield-9.2.4.svg)
- [https://github.com/deancyl/s9180-rootmygalaxy](https://github.com/deancyl/s9180-rootmygalaxy) :  ![starts](https://img.shields.io/github/stars/deancyl/s9180-rootmygalaxy.svg) ![forks](https://img.shields.io/github/forks/deancyl/s9180-rootmygalaxy.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/a2333c/DFRoot](https://github.com/a2333c/DFRoot) :  ![starts](https://img.shields.io/github/stars/a2333c/DFRoot.svg) ![forks](https://img.shields.io/github/forks/a2333c/DFRoot.svg)


## CVE-2026-34990
 OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In versions 2.4.16 and prior, a local unprivileged user can coerce cupsd into authenticating to an attacker-controlled localhost IPP service with a reusable Authorization: Local ... token. That token is enough to drive /admin/ requests on localhost, and the attacker can combine CUPS-Create-Local-Printer with printer-is-shared=true to persist a file:///... queue even though the normal FileDevice policy rejects such URIs. Printing to that queue gives an arbitrary root file overwrite; the PoC below uses that primitive to drop a sudoers fragment and demonstrate root command execution. At time of publication, there are no publicly available patches.

- [https://github.com/DENNISDGR/CVE-2026-34990-poc](https://github.com/DENNISDGR/CVE-2026-34990-poc) :  ![starts](https://img.shields.io/github/stars/DENNISDGR/CVE-2026-34990-poc.svg) ![forks](https://img.shields.io/github/forks/DENNISDGR/CVE-2026-34990-poc.svg)
- [https://github.com/predyy/CVE-2026-34990](https://github.com/predyy/CVE-2026-34990) :  ![starts](https://img.shields.io/github/stars/predyy/CVE-2026-34990.svg) ![forks](https://img.shields.io/github/forks/predyy/CVE-2026-34990.svg)
- [https://github.com/gbuyssens/CVE-2026-34990](https://github.com/gbuyssens/CVE-2026-34990) :  ![starts](https://img.shields.io/github/stars/gbuyssens/CVE-2026-34990.svg) ![forks](https://img.shields.io/github/forks/gbuyssens/CVE-2026-34990.svg)
- [https://github.com/0xc4rc3l/CVE-2026-34990-poc](https://github.com/0xc4rc3l/CVE-2026-34990-poc) :  ![starts](https://img.shields.io/github/stars/0xc4rc3l/CVE-2026-34990-poc.svg) ![forks](https://img.shields.io/github/forks/0xc4rc3l/CVE-2026-34990-poc.svg)
- [https://github.com/khush-613/CVE-2026-34990-poc](https://github.com/khush-613/CVE-2026-34990-poc) :  ![starts](https://img.shields.io/github/stars/khush-613/CVE-2026-34990-poc.svg) ![forks](https://img.shields.io/github/forks/khush-613/CVE-2026-34990-poc.svg)


## CVE-2026-28695
 Craft is a content management system (CMS). There is an authenticated admin RCE in Craft CMS 5.8.21 via Server-Side Template Injection using the create() Twig function combined with a Symfony Process gadget chain. The create() Twig function exposes Craft::createObject(), which allows instantiation of arbitrary PHP classes with constructor arguments. Combined with the bundled symfony/process dependency, this enables RCE. This bypasses the fix implemented for CVE-2025-57811 (patched in 5.8.7). This vulnerability is fixed in 5.9.0-beta.1 and 4.17.0-beta.1.

- [https://github.com/predyy/CVE-2026-28695](https://github.com/predyy/CVE-2026-28695) :  ![starts](https://img.shields.io/github/stars/predyy/CVE-2026-28695.svg) ![forks](https://img.shields.io/github/forks/predyy/CVE-2026-28695.svg)
- [https://github.com/gbuyssens/CVE-2026-28695-craft-rce-bypass](https://github.com/gbuyssens/CVE-2026-28695-craft-rce-bypass) :  ![starts](https://img.shields.io/github/stars/gbuyssens/CVE-2026-28695-craft-rce-bypass.svg) ![forks](https://img.shields.io/github/forks/gbuyssens/CVE-2026-28695-craft-rce-bypass.svg)


## CVE-2026-14281
 The Automation Web Platform – Notifications and OTP for WooCommerce, Advanced Country Code plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 4.8.6. This is due to missing permission enforcement on the publicly accessible REST route `POST /wp-json/wawp/v1/signup/op` and the absence of a key allowlist in the `finish_registration_logic` function, which copies the attacker-controlled `wawp_custom_fields` parameter directly into `update_user_meta()` — allowing sensitive meta keys such as `wp_capabilities` and `wp_user_level` to be set by the caller. This makes it possible for unauthenticated attackers to register a new account with the administrator role and gain full administrative access to the site. When OTP verification is enabled at signup, the OTP session token (`otp_transient`) is returned in plaintext in the HTTP response body, and the `handle_magic_link_request()` handler marks that token as verified on any unauthenticated GET request containing it without ever checking the OTP code value — making the OTP step trivially bypassable with no inbox or SMS access required.

- [https://github.com/abatsakidis/CVE-2026-14281-check](https://github.com/abatsakidis/CVE-2026-14281-check) :  ![starts](https://img.shields.io/github/stars/abatsakidis/CVE-2026-14281-check.svg) ![forks](https://img.shields.io/github/forks/abatsakidis/CVE-2026-14281-check.svg)


## CVE-2026-12227
 The Visual Composer Website Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 45.16.0 via the `vcv-template` parameter. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/be-keb/CVE-2026-12227](https://github.com/be-keb/CVE-2026-12227) :  ![starts](https://img.shields.io/github/stars/be-keb/CVE-2026-12227.svg) ![forks](https://img.shields.io/github/forks/be-keb/CVE-2026-12227.svg)


## CVE-2026-8712
 Wyoming before 1.10.2 contains a server-side request forgery vulnerability that allows unauthenticated attackers with network access to force outbound connections to arbitrary targets by supplying a malicious `uri` query parameter to the HTTP API. Attackers can pass arbitrary `tcp://` or `unix://` URIs to affected endpoints including /api/info, /api/speech-to-text, and /api/text-to-speech to override the server-configured backend and redirect connections to attacker-chosen hosts.

- [https://github.com/rahulreddykarne/CVE-2026-8712-Wyoming](https://github.com/rahulreddykarne/CVE-2026-8712-Wyoming) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/CVE-2026-8712-Wyoming.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/CVE-2026-8712-Wyoming.svg)


## CVE-2026-8452
 Memory overflow vulnerability NetScaler ADC and NetScaler Gateway leading to unpredictable or erroneous behavior and Denial of Service if the appliance is configured as a Gateway (SSL VPN, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server

- [https://github.com/techupdate24/citrix-netscaler-cve-2026-8452-rce](https://github.com/techupdate24/citrix-netscaler-cve-2026-8452-rce) :  ![starts](https://img.shields.io/github/stars/techupdate24/citrix-netscaler-cve-2026-8452-rce.svg) ![forks](https://img.shields.io/github/forks/techupdate24/citrix-netscaler-cve-2026-8452-rce.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/RokuSec/FreePBX-SQLi-RCE](https://github.com/RokuSec/FreePBX-SQLi-RCE) :  ![starts](https://img.shields.io/github/stars/RokuSec/FreePBX-SQLi-RCE.svg) ![forks](https://img.shields.io/github/forks/RokuSec/FreePBX-SQLi-RCE.svg)


## CVE-2025-56005
 An undocumented and unsafe feature in the PLY (Python Lex-Yacc) library 3.11 allows Remote Code Execution (RCE) via the `picklefile` parameter in the `yacc()` function. This parameter accepts a `.pkl` file that is deserialized with `pickle.load()` without validation. Because `pickle` allows execution of embedded code via `__reduce__()`, an attacker can achieve code execution by passing a malicious pickle file. The parameter is not mentioned in official documentation or the GitHub repository, yet it is active in the PyPI version. This introduces a stealthy backdoor and persistence risk. NOTE: A third-party states that this vulnerability should be rejected because the proof of concept does not demonstrate arbitrary code execution and fails to complete successfully.

- [https://github.com/gdfurr98/ply-cve-2025-56005-lab](https://github.com/gdfurr98/ply-cve-2025-56005-lab) :  ![starts](https://img.shields.io/github/stars/gdfurr98/ply-cve-2025-56005-lab.svg) ![forks](https://img.shields.io/github/forks/gdfurr98/ply-cve-2025-56005-lab.svg)
- [https://github.com/gdfurr98/ply-safepickle](https://github.com/gdfurr98/ply-safepickle) :  ![starts](https://img.shields.io/github/stars/gdfurr98/ply-safepickle.svg) ![forks](https://img.shields.io/github/forks/gdfurr98/ply-safepickle.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/X-Bulow/Reproduce-CVE-2025-32433](https://github.com/X-Bulow/Reproduce-CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/X-Bulow/Reproduce-CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/X-Bulow/Reproduce-CVE-2025-32433.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/ferpalma21/nextjs-scanner](https://github.com/ferpalma21/nextjs-scanner) :  ![starts](https://img.shields.io/github/stars/ferpalma21/nextjs-scanner.svg) ![forks](https://img.shields.io/github/forks/ferpalma21/nextjs-scanner.svg)


## CVE-2025-11926
 The Related Posts Lite plugin for WordPress is vulnerable to Stored Cross-Site Scripting via admin settings in all versions up to, and including, 1.12 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/prabhatverma47/Wordpress-Related-Posts-Lite-plugin-XSS-PoC](https://github.com/prabhatverma47/Wordpress-Related-Posts-Lite-plugin-XSS-PoC) :  ![starts](https://img.shields.io/github/stars/prabhatverma47/Wordpress-Related-Posts-Lite-plugin-XSS-PoC.svg) ![forks](https://img.shields.io/github/forks/prabhatverma47/Wordpress-Related-Posts-Lite-plugin-XSS-PoC.svg)


## CVE-2025-11201
The specific flaw exists within the handling of model file paths. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to execute code in the context of the service account. Was ZDI-CAN-26921.

- [https://github.com/rmhowe425/POC-CVE-2025-11201](https://github.com/rmhowe425/POC-CVE-2025-11201) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2025-11201.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2025-11201.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2025-4802
 Untrusted LD_LIBRARY_PATH environment variable vulnerability in the GNU C Library version 2.27 to 2.38 allows attacker controlled loading of dynamically shared library in statically compiled setuid binaries that call dlopen (including internal dlopen calls after setlocale or calls to NSS functions such as getaddrinfo).

- [https://github.com/betizzel/CVE-2025-4802-Proof-of-Concept](https://github.com/betizzel/CVE-2025-4802-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/betizzel/CVE-2025-4802-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/betizzel/CVE-2025-4802-Proof-of-Concept.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/Alexandertanay/jenkins-cve-2024-23897-lab](https://github.com/Alexandertanay/jenkins-cve-2024-23897-lab) :  ![starts](https://img.shields.io/github/stars/Alexandertanay/jenkins-cve-2024-23897-lab.svg) ![forks](https://img.shields.io/github/forks/Alexandertanay/jenkins-cve-2024-23897-lab.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/stuara1/cpc-pdfjs-poc](https://github.com/stuara1/cpc-pdfjs-poc) :  ![starts](https://img.shields.io/github/stars/stuara1/cpc-pdfjs-poc.svg) ![forks](https://img.shields.io/github/forks/stuara1/cpc-pdfjs-poc.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)
- [https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe](https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/khanna419/cve-2021-43798-lab](https://github.com/khanna419/cve-2021-43798-lab) :  ![starts](https://img.shields.io/github/stars/khanna419/cve-2021-43798-lab.svg) ![forks](https://img.shields.io/github/forks/khanna419/cve-2021-43798-lab.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/Park123r/CVE-2021-41773](https://github.com/Park123r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Park123r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Park123r/CVE-2021-41773.svg)


## CVE-2020-14008
 Zoho ManageEngine Applications Manager 14710 and before allows an authenticated admin user to upload a vulnerable jar in a specific location, which leads to remote code execution.

- [https://github.com/raflesiait/CVE-2020-14008---ManageEngine](https://github.com/raflesiait/CVE-2020-14008---ManageEngine) :  ![starts](https://img.shields.io/github/stars/raflesiait/CVE-2020-14008---ManageEngine.svg) ![forks](https://img.shields.io/github/forks/raflesiait/CVE-2020-14008---ManageEngine.svg)

