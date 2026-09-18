# Update 2026-09-18
## CVE-2026-90782
 S2OPC through 1.7.3 contains a null pointer dereference in msg_subscription_publish_bs__alloc_notification_message_items() where a failed allocation for DataChangeNotification is overwritten by a successful allocation for EventNotificationList. Attackers can trigger heap allocation failures on sessions with both data-change and event notifications to cause the server process to terminate.

- [https://github.com/HarshRajSinghania/CVE-2026-90782-s2opc-status-clobber](https://github.com/HarshRajSinghania/CVE-2026-90782-s2opc-status-clobber) :  ![starts](https://img.shields.io/github/stars/HarshRajSinghania/CVE-2026-90782-s2opc-status-clobber.svg) ![forks](https://img.shields.io/github/forks/HarshRajSinghania/CVE-2026-90782-s2opc-status-clobber.svg)


## CVE-2026-90781
 alsa-lib through 1.2.16.1 contains a stack buffer overflow in the __snd_ctl_ascii_elem_id_parse() function that writes one byte past a 64-byte buffer when parsing a name= field with 64 or more characters. Attackers can supply a long control-element identifier string through saved state files or command-line arguments to overwrite adjacent stack memory and crash the calling process.

- [https://github.com/HarshRajSinghania/CVE-2026-90781-alsa-lib-oob](https://github.com/HarshRajSinghania/CVE-2026-90781-alsa-lib-oob) :  ![starts](https://img.shields.io/github/stars/HarshRajSinghania/CVE-2026-90781-alsa-lib-oob.svg) ![forks](https://img.shields.io/github/forks/HarshRajSinghania/CVE-2026-90781-alsa-lib-oob.svg)


## CVE-2026-89013
 Dolibarr 23.0.4 before 24.0.1 ontains an authorization bypass vulnerability that allows unauthenticated attackers to read arbitrary files through the document storage endpoints by supplying a crafted hashp parameter value. Attackers can send a request with hashp=shared to skip token validation while satisfying the authorization condition in htdocs/document.php and htdocs/viewimage.php, gaining access to application logs, uploaded business documents, database backups containing password hashes, and files belonging to other multicompany entities.

- [https://github.com/Faceless0x7/CVE-2026-89013](https://github.com/Faceless0x7/CVE-2026-89013) :  ![starts](https://img.shields.io/github/stars/Faceless0x7/CVE-2026-89013.svg) ![forks](https://img.shields.io/github/forks/Faceless0x7/CVE-2026-89013.svg)


## CVE-2026-89012
 Dolibarr 24.0.0 before 24.0.1 contains a case-sensitive denylist bypass vulnerability in the sqlfilters API query parameter that allows authenticated attackers to recover protected database fields by supplying uppercase variants of denylist-protected field names. Attackers can exploit the case-insensitive database column resolution against the case-sensitive denylist check in the core library to use prefix-matching predicates as a boolean oracle and extract full password hashes for any user account, including administrators.

- [https://github.com/Faceless0x7/CVE-2026-89012](https://github.com/Faceless0x7/CVE-2026-89012) :  ![starts](https://img.shields.io/github/stars/Faceless0x7/CVE-2026-89012.svg) ![forks](https://img.shields.io/github/forks/Faceless0x7/CVE-2026-89012.svg)


## CVE-2026-88861
 Capgo (Cap-go/capgo.app) contains an authentication bypass affecting all versions (no patched version available at time of publication). The Edge authorization path allows a password-only Supabase aal1 session to exercise privileged RBAC permissions even when the account has a verified MFA factor that has not been used for the session: the Edge JWT middleware (foundJWT() in supabase/functions/_backend/utils/hono_middleware.ts) accepts the JWT without validating its assurance level, and the direct RBAC path (checkPermission()/checkPermissionPg() in supabase/functions/_backend/utils/rbac.ts calling public.rbac_check_permission_direct()) authorizes by user ID without passing or checking the session aal, unlike the public.verify_mfa() control which correctly requires aal2. An attacker who knows only the victim's password can therefore authenticate, mint a persistent app-scoped app_admin API key that remains valid after the aal1 session is logged out, and perform privileged operations such as modifying production OTA channel configurations (validated by changing a public production channel from bundle 1.0.0 to 1.0.1), defeating the protection provided by MFA.

- [https://github.com/franklincg/secdim-assurance-drift-challenge](https://github.com/franklincg/secdim-assurance-drift-challenge) :  ![starts](https://img.shields.io/github/stars/franklincg/secdim-assurance-drift-challenge.svg) ![forks](https://img.shields.io/github/forks/franklincg/secdim-assurance-drift-challenge.svg)


## CVE-2026-87606
 Missing authorization in SiteIsolation in Google Chrome prior to 153.0.8010.36 allowed a remote attacker who had compromised the renderer process to bypass site isolation via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass.](https://github.com/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass.) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass..svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass..svg)


## CVE-2026-87575
 Incorrect authorization in Loader in Google Chrome prior to 153.0.8010.36 allowed a remote attacker leveraging social engineering to bypass system access restrictions via a crafted HTML page. (Chromium security severity: Low)

- [https://github.com/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass.](https://github.com/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass.) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass..svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass..svg)


## CVE-2026-87492
 Incorrect authorization in DevTools in Google Chrome prior to 153.0.8010.36 allowed a remote attacker to potentially execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/valencenavy/IsolatedAnarchy-Public](https://github.com/valencenavy/IsolatedAnarchy-Public) :  ![starts](https://img.shields.io/github/stars/valencenavy/IsolatedAnarchy-Public.svg) ![forks](https://img.shields.io/github/forks/valencenavy/IsolatedAnarchy-Public.svg)


## CVE-2026-87491
 Out of bounds write in V8 in Google Chrome prior to 153.0.8010.36 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass.](https://github.com/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass.) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass..svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass..svg)
- [https://github.com/SneakyNachos/CVE-2026-87491-and-CVE-2026-85046-the-bagel-fell-off-the-counter](https://github.com/SneakyNachos/CVE-2026-87491-and-CVE-2026-85046-the-bagel-fell-off-the-counter) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-87491-and-CVE-2026-85046-the-bagel-fell-off-the-counter.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-87491-and-CVE-2026-85046-the-bagel-fell-off-the-counter.svg)


## CVE-2026-86547
 mrubyc through 4.0.0 contains a null pointer dereference vulnerability in the op_enter() handler in src/vm.c when processing untrusted bytecode. Attackers can craft malicious .mrb bytecode files with OP_ENTER instructions at the top level to crash the embedding application and cause denial of service.

- [https://github.com/HarshRajSinghania/cve-2026-86547-mrubyc-op-enter](https://github.com/HarshRajSinghania/cve-2026-86547-mrubyc-op-enter) :  ![starts](https://img.shields.io/github/stars/HarshRajSinghania/cve-2026-86547-mrubyc-op-enter.svg) ![forks](https://img.shields.io/github/forks/HarshRajSinghania/cve-2026-86547-mrubyc-op-enter.svg)


## CVE-2026-86283
 MISP's UiBeta theme collection view (app/View/Themed/UiBeta/Collections/view.ctp) performed a secondary query of member events by UUID without applying the caller's access control list (ACL). The CollectionsController::view() action correctly resolved collection element UUIDs through Event::fetchSimpleEvents($user, ...), which enforces per-user event ACL. However, the view template independently re-queried the same UUIDs using only an Event.uuid IN (...) condition, omitting the createEventConditions() authorization filter. Because collection element UUIDs are stored without server-side authorization against the referenced event (CollectionElementsController::add() accepts whatever UUID the collection owner posts), an authenticated user with view access to a collection could retrieve full details of events they are not permitted to read. The exposed data included event identifiers, info, dates, timestamps, creator organization, all event tags, and galaxy clusters (the latter attached via a cluster-scoped rather than event-scoped ACL check). This constitutes an authorization bypass at the presentation layer, allowing horizontal privilege escalation across event boundaries within the MISP instance.

- [https://github.com/Freire007-byte/sentric-core](https://github.com/Freire007-byte/sentric-core) :  ![starts](https://img.shields.io/github/stars/Freire007-byte/sentric-core.svg) ![forks](https://img.shields.io/github/forks/Freire007-byte/sentric-core.svg)


## CVE-2026-86218
 N-central is vulnerable to a pre-auth remote code execution This issue affects N-central: before 2026.3.1.14.

- [https://github.com/jithinkrishnanrs/CVE-2026-86218-N-central-IOC-Toolkit](https://github.com/jithinkrishnanrs/CVE-2026-86218-N-central-IOC-Toolkit) :  ![starts](https://img.shields.io/github/stars/jithinkrishnanrs/CVE-2026-86218-N-central-IOC-Toolkit.svg) ![forks](https://img.shields.io/github/forks/jithinkrishnanrs/CVE-2026-86218-N-central-IOC-Toolkit.svg)


## CVE-2026-86060
path involving usernames that begin with a prohibited character, allowing for the trusted RouterOS policy mask to be changed, leading to privilege escalation. Exploitation requires an unauthenticated SSH session to reach the RouterOS login helper.This issue was fixed in versions: 6.49.21 (Long-term), 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/bahirul/cve-2026-86060](https://github.com/bahirul/cve-2026-86060) :  ![starts](https://img.shields.io/github/stars/bahirul/cve-2026-86060.svg) ![forks](https://img.shields.io/github/forks/bahirul/cve-2026-86060.svg)


## CVE-2026-85706
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.7 before 19.1.8, 19.2 before 19.2.6, and 19.3 before 19.3.2 that, under certain conditions, an unauthenticated user could have read arbitrary files from the GitLab server due to improper path confinement and missing authentication enforcement in the repository commits API.

- [https://github.com/guneykabel/cve-2026-85706](https://github.com/guneykabel/cve-2026-85706) :  ![starts](https://img.shields.io/github/stars/guneykabel/cve-2026-85706.svg) ![forks](https://img.shields.io/github/forks/guneykabel/cve-2026-85706.svg)
- [https://github.com/ynsmroztas/GitLabSniper](https://github.com/ynsmroztas/GitLabSniper) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/GitLabSniper.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/GitLabSniper.svg)
- [https://github.com/mhtsec/CVE-2026-85706](https://github.com/mhtsec/CVE-2026-85706) :  ![starts](https://img.shields.io/github/stars/mhtsec/CVE-2026-85706.svg) ![forks](https://img.shields.io/github/forks/mhtsec/CVE-2026-85706.svg)
- [https://github.com/FlowerWitch/CVE-2026-85706_docker_exp](https://github.com/FlowerWitch/CVE-2026-85706_docker_exp) :  ![starts](https://img.shields.io/github/stars/FlowerWitch/CVE-2026-85706_docker_exp.svg) ![forks](https://img.shields.io/github/forks/FlowerWitch/CVE-2026-85706_docker_exp.svg)
- [https://github.com/0xlyvio/cve-2026-85706-poc-exploit-gitlab](https://github.com/0xlyvio/cve-2026-85706-poc-exploit-gitlab) :  ![starts](https://img.shields.io/github/stars/0xlyvio/cve-2026-85706-poc-exploit-gitlab.svg) ![forks](https://img.shields.io/github/forks/0xlyvio/cve-2026-85706-poc-exploit-gitlab.svg)
- [https://github.com/jithinkrishnanrs/gitlab-cve-2026-85706-ioc](https://github.com/jithinkrishnanrs/gitlab-cve-2026-85706-ioc) :  ![starts](https://img.shields.io/github/stars/jithinkrishnanrs/gitlab-cve-2026-85706-ioc.svg) ![forks](https://img.shields.io/github/forks/jithinkrishnanrs/gitlab-cve-2026-85706-ioc.svg)
- [https://github.com/gagaltotal/CVE-2026-85706-gitlab-poc](https://github.com/gagaltotal/CVE-2026-85706-gitlab-poc) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-85706-gitlab-poc.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-85706-gitlab-poc.svg)
- [https://github.com/solivaquaant/CVE-2026-85706](https://github.com/solivaquaant/CVE-2026-85706) :  ![starts](https://img.shields.io/github/stars/solivaquaant/CVE-2026-85706.svg) ![forks](https://img.shields.io/github/forks/solivaquaant/CVE-2026-85706.svg)
- [https://github.com/gabrielunknown/CVE-2026-85706](https://github.com/gabrielunknown/CVE-2026-85706) :  ![starts](https://img.shields.io/github/stars/gabrielunknown/CVE-2026-85706.svg) ![forks](https://img.shields.io/github/forks/gabrielunknown/CVE-2026-85706.svg)
- [https://github.com/brigadeops32/CVE-2026-85706](https://github.com/brigadeops32/CVE-2026-85706) :  ![starts](https://img.shields.io/github/stars/brigadeops32/CVE-2026-85706.svg) ![forks](https://img.shields.io/github/forks/brigadeops32/CVE-2026-85706.svg)
- [https://github.com/plur1bu5/gitread](https://github.com/plur1bu5/gitread) :  ![starts](https://img.shields.io/github/stars/plur1bu5/gitread.svg) ![forks](https://img.shields.io/github/forks/plur1bu5/gitread.svg)


## CVE-2026-85612
 OpenPanel before 2.3.0 contains an unauthenticated server-side request forgery vulnerability in the /misc/favicon and /misc/og endpoints that accept an attacker-supplied url parameter with insufficient validation. Attackers can force the API to fetch arbitrary internal hosts and cloud metadata endpoints, with small responses returned verbatim enabling credential theft and internal service enumeration.

- [https://github.com/hotplugin0x01/CVE-2026-85612](https://github.com/hotplugin0x01/CVE-2026-85612) :  ![starts](https://img.shields.io/github/stars/hotplugin0x01/CVE-2026-85612.svg) ![forks](https://img.shields.io/github/forks/hotplugin0x01/CVE-2026-85612.svg)


## CVE-2026-85046
 Type confusion in V8 in Google Chrome prior to 152.0.7977.82 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass.](https://github.com/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass.) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass..svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-87575-CVE-2026-87606-CVE-2026-87491-and-CVE-2026-85046.-Escape-the-v8-carcass..svg)
- [https://github.com/SneakyNachos/CVE-2026-87491-and-CVE-2026-85046-the-bagel-fell-off-the-counter](https://github.com/SneakyNachos/CVE-2026-87491-and-CVE-2026-85046-the-bagel-fell-off-the-counter) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-87491-and-CVE-2026-85046-the-bagel-fell-off-the-counter.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-87491-and-CVE-2026-85046-the-bagel-fell-off-the-counter.svg)


## CVE-2026-83991
 Missing authentication for critical function in Windows Cloud Files Mini Filter Driver allows an authorized attacker to perform tampering locally.

- [https://github.com/ZeroDayVPN/CVE-2026-83991-WriteUP-and-PoC](https://github.com/ZeroDayVPN/CVE-2026-83991-WriteUP-and-PoC) :  ![starts](https://img.shields.io/github/stars/ZeroDayVPN/CVE-2026-83991-WriteUP-and-PoC.svg) ![forks](https://img.shields.io/github/forks/ZeroDayVPN/CVE-2026-83991-WriteUP-and-PoC.svg)


## CVE-2026-81861
 CWE-522: Insufficiently Protected Credentials vulnerability that could result in exposure of authentication information and unauthorized access to RTU functionality.

- [https://github.com/abhinavagarwal07/scadapack-secure-lock-poc](https://github.com/abhinavagarwal07/scadapack-secure-lock-poc) :  ![starts](https://img.shields.io/github/stars/abhinavagarwal07/scadapack-secure-lock-poc.svg) ![forks](https://img.shields.io/github/forks/abhinavagarwal07/scadapack-secure-lock-poc.svg)


## CVE-2026-80099
 Several Newfold plugins are vulnerable to Authentication Bypass. The vulnerability exists because the plugins bundle the wp-module-data module. In the module, the `authenticate()` method — registered on the `rest_authentication_errors` filter and therefore evaluated for every unauthenticated REST API request — performs an HMAC-style Bearer token comparison that degenerates when `HiiveConnection::get_auth_token()` returns `false`: PHP coerces `strrev(false)` to `strrev('')`, collapsing the secret salt to the publicly known constant `hash('sha256', '') = e3b0c44...`, while all remaining hash inputs (HTTP method, request URL, raw request body, and the `X-Timestamp` header) remain fully attacker-controlled. This makes it possible for unauthenticated attackers to compute a valid Bearer token entirely offline, pass the token equality check, and have `wp_set_current_user()` invoked against the first administrator returned by `get_users(['role' = 'administrator'])`, granting full administrator-level access and enabling arbitrary REST API operations such as creating new administrator accounts and achieving complete site takeover. Vulnerable versions are WP Plugin Crazy Domains (= 2.5.2), WP Plugin Web (= 2.3.4), WP Plugin Hostgator (= 3.1.0), WP Plugin Bluehost (= 4.17.1). The affected module is vulnerable in versions up to, and including, 2.9.4.

- [https://github.com/Wayang1337/CVE-2026-80099](https://github.com/Wayang1337/CVE-2026-80099) :  ![starts](https://img.shields.io/github/stars/Wayang1337/CVE-2026-80099.svg) ![forks](https://img.shields.io/github/forks/Wayang1337/CVE-2026-80099.svg)


## CVE-2026-78997
 UC Browser for Android (package com.UCMobile.intl, version 13.7.8.1314) contains a Universal Cross-Site Scripting vulnerability that allows an attacker to execute arbitrary JavaScript in the context of any origin. An attacker hosts a specially crafted URL on a UC-owned domain (via a reflected XSS) that leverages the browser's internal JavaScript bridge to register a deferred callback, navigate the tab to a victim site, and then execute attacker-controlled code on that site when a login dialog is dismissed.

- [https://github.com/Hunt-Benito/the-callback-that-outlived-the-page-cve-2026-78997-uc-browser-android-universal-xss](https://github.com/Hunt-Benito/the-callback-that-outlived-the-page-cve-2026-78997-uc-browser-android-universal-xss) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/the-callback-that-outlived-the-page-cve-2026-78997-uc-browser-android-universal-xss.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/the-callback-that-outlived-the-page-cve-2026-78997-uc-browser-android-universal-xss.svg)


## CVE-2026-78006
 The The Events Calendar plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 6.17.4 via the is_safe_widget_instance function. This is due to insufficient protection in is_safe_widget_instance, which can be bypassed because PHP fires magic methods during its pre-parse, combined with enable_rendering_widget_copied() forging a valid wp_hash integrity attribute before unserialize() is reached. This makes it possible for unauthenticated attackers to execute code on the server. This is exploitable without authentication or approval because the plugin's V2 single-event template runs do_blocks() over buffered comment HTML, and WordPress returns a moderation-hash URL that allows an unauthenticated commenter to immediately view their own pending comment, delivering the injected block markup to the vulnerable code path before any moderation occurs. This does require comments to be enabled and visible on events.

- [https://github.com/DeadExpl0it/CVE-2026-78006-POC](https://github.com/DeadExpl0it/CVE-2026-78006-POC) :  ![starts](https://img.shields.io/github/stars/DeadExpl0it/CVE-2026-78006-POC.svg) ![forks](https://img.shields.io/github/forks/DeadExpl0it/CVE-2026-78006-POC.svg)
- [https://github.com/user445213/CVE-2026-78006](https://github.com/user445213/CVE-2026-78006) :  ![starts](https://img.shields.io/github/stars/user445213/CVE-2026-78006.svg) ![forks](https://img.shields.io/github/forks/user445213/CVE-2026-78006.svg)


## CVE-2026-77771
 The miniOrange 2FA  WordPress plugin before 6.3.1, miniOrange 2FA  WordPress plugin before 19.3 does not scope its second-factor attempt limit to the account being attacked, keying it instead to an identifier the client supplies and can change at will, allowing an attacker who already knows a victim's password to make unlimited one-time-passcode guesses and defeat the second factor. A second validation endpoint applies no attempt limit at all.

- [https://github.com/pervinzahidli/CVE-2026-77771](https://github.com/pervinzahidli/CVE-2026-77771) :  ![starts](https://img.shields.io/github/stars/pervinzahidli/CVE-2026-77771.svg) ![forks](https://img.shields.io/github/forks/pervinzahidli/CVE-2026-77771.svg)


## CVE-2026-77770
 The miniOrange 2FA  WordPress plugin before 6.3.1, miniOrange 2FA  WordPress plugin before 19.3 does not require a validated transaction before deleting site options whose names come from unauthenticated request input, allowing any visitor to delete arbitrary options, which can lock every administrator out of the dashboard or deactivate every miniOrange 2FA  WordPress plugin before 6.3.1, miniOrange 2FA  WordPress plugin before 19.3 on the site.

- [https://github.com/cflowsec/CVE-2026-77770](https://github.com/cflowsec/CVE-2026-77770) :  ![starts](https://img.shields.io/github/stars/cflowsec/CVE-2026-77770.svg) ![forks](https://img.shields.io/github/forks/cflowsec/CVE-2026-77770.svg)


## CVE-2026-75650
 Adobe Commerce is affected by an Improper Neutralization of Special Elements Used in a Template Engine vulnerability that could result in arbitrary code execution in the context of the current user. An attacker could exploit this vulnerability to execute arbitrary code. Exploitation of this issue does not require user interaction. Scope is changed.

- [https://github.com/fortbridge/stylesmuggler](https://github.com/fortbridge/stylesmuggler) :  ![starts](https://img.shields.io/github/stars/fortbridge/stylesmuggler.svg) ![forks](https://img.shields.io/github/forks/fortbridge/stylesmuggler.svg)


## CVE-2026-73786
 A vulnerability in the web-based management interface of CPPM could allow an unauthenticated remote attacker to conduct a Denial-of-Service (DoS) attack. Successful exploitation could allow an attacker to cause instability and degrade performance of the vulnerable CPPM server.

- [https://github.com/promasu/CVE-2026-73786](https://github.com/promasu/CVE-2026-73786) :  ![starts](https://img.shields.io/github/stars/promasu/CVE-2026-73786.svg) ![forks](https://img.shields.io/github/forks/promasu/CVE-2026-73786.svg)


## CVE-2026-71294
 Cotonti CMS's Comments plugin deserializes user-supplied data without restricting the classes that may be instantiated. In plugins/comments/controllers/actions/CreateAction.php, a POST parameter obtained via (trim-only sanitization) is passed to with no restriction, reachable by any member with write access to comments (the default setting in plugins/comments/comments.setup.php).

- [https://github.com/HarshRajSinghania/cotonti-commentswidget-poc](https://github.com/HarshRajSinghania/cotonti-commentswidget-poc) :  ![starts](https://img.shields.io/github/stars/HarshRajSinghania/cotonti-commentswidget-poc.svg) ![forks](https://img.shields.io/github/forks/HarshRajSinghania/cotonti-commentswidget-poc.svg)


## CVE-2026-66804
 Improper access control in Windows Cross Device Service allows an authorized attacker to elevate privileges locally.

- [https://github.com/ZeroDayVPN/CVE-2026-66804-CrossDevice-Service-EoP](https://github.com/ZeroDayVPN/CVE-2026-66804-CrossDevice-Service-EoP) :  ![starts](https://img.shields.io/github/stars/ZeroDayVPN/CVE-2026-66804-CrossDevice-Service-EoP.svg) ![forks](https://img.shields.io/github/forks/ZeroDayVPN/CVE-2026-66804-CrossDevice-Service-EoP.svg)


## CVE-2026-65616
 Incorrect authorization validation in refresh token signature allows non-admin users to obtain a signed JFrog administrator token.

- [https://github.com/BL0odz/JFrog_CVE-2026-65615-ByGLM](https://github.com/BL0odz/JFrog_CVE-2026-65615-ByGLM) :  ![starts](https://img.shields.io/github/stars/BL0odz/JFrog_CVE-2026-65615-ByGLM.svg) ![forks](https://img.shields.io/github/forks/BL0odz/JFrog_CVE-2026-65615-ByGLM.svg)


## CVE-2026-65540
 Unauthenticated Cross Site Request Forgery (CSRF) in Popup for CF7 with Sweet Alert = 1.6.5 versions.

- [https://github.com/testardou/CVE-2026-65540](https://github.com/testardou/CVE-2026-65540) :  ![starts](https://img.shields.io/github/stars/testardou/CVE-2026-65540.svg) ![forks](https://img.shields.io/github/forks/testardou/CVE-2026-65540.svg)


## CVE-2026-63642
 MagicMirror² is an open source modular smart mirror platform. Prior to 2.37.0, checkArticleUrl in defaultmodules/newsfeed/node_helper.js accepts the CHECK_ARTICLE_URL notification through the unauthenticated Socket.IO namespace /newsfeed and performs fetch(url, { method: "HEAD" }) without validating the attacker-controlled URL. The helper returns ARTICLE_URL_STATUS containing the URL and framing result, providing a response and timing oracle that can identify internal hosts and ports and trigger side effects on services that react to HEAD requests. This issue is fixed in version 2.37.0.

- [https://github.com/hakaioffsec/CVE-2026-63642](https://github.com/hakaioffsec/CVE-2026-63642) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2026-63642.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2026-63642.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/ivanesk315/CVE-2026-60137-and-CVE-2026-63030](https://github.com/ivanesk315/CVE-2026-60137-and-CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2026-60137-and-CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2026-60137-and-CVE-2026-63030.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/ivanesk315/CVE-2026-60137-and-CVE-2026-63030](https://github.com/ivanesk315/CVE-2026-60137-and-CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2026-60137-and-CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2026-60137-and-CVE-2026-63030.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/ZeroDayEvil/CVE-2026-54121-Certighost](https://github.com/ZeroDayEvil/CVE-2026-54121-Certighost) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-54121-Certighost.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-54121-Certighost.svg)


## CVE-2026-53519
 Nezha Monitoring is a self-hostable, lightweight, servers and websites monitoring and O&M tool. Prior to version 2.0.13, fallbackToFrontend in the dashboard's NoRoute handler treats any URL whose raw string starts with /dashboard as an admin-frontend asset request. The check uses strings.HasPrefix, not a path-segment match, so the input /dashboard../data/config.yaml is accepted; strings.TrimPrefix leaves ../data/config.yaml; and path.Join("admin-dist", "../data/config.yaml") normalizes to data/config.yaml — which os.Stat finds and http.ServeFile returns. No authentication required. This issue has been patched in version 2.0.13.

- [https://github.com/ivanesk315/CVE-2026-53519](https://github.com/ivanesk315/CVE-2026-53519) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2026-53519.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2026-53519.svg)


## CVE-2026-50751
 A logic flow weakness in Remote Access and Mobile Access certificate validation in deprecated IKEv1 key exchange allows an unauthenticated remote attacker to bypass user authentication and establish a remote access VPN connection without a valid user password.

- [https://github.com/uLl0a/CVE-2026-50751](https://github.com/uLl0a/CVE-2026-50751) :  ![starts](https://img.shields.io/github/stars/uLl0a/CVE-2026-50751.svg) ![forks](https://img.shields.io/github/forks/uLl0a/CVE-2026-50751.svg)


## CVE-2026-50416
 Exposure of sensitive information to an unauthorized actor in Windows Win32K allows an authorized attacker to disclose information locally.

- [https://github.com/ZeroDayEvil/CVE-2026-50416-writeup-and-PoC](https://github.com/ZeroDayEvil/CVE-2026-50416-writeup-and-PoC) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-50416-writeup-and-PoC.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-50416-writeup-and-PoC.svg)


## CVE-2026-49865
 Kimai is an open-source time tracking application. Versions prior to 2.58.0 contain a server-side request forgery vulnerability in their invoice PDF preview and generation workflow. If an attacker can control Markdown content that is later rendered into an invoice PDF, such as `Customer.invoiceText`, the server-side PDF renderer will fetch remote image URLs embedded in Markdown image syntax. This allows the application server to issue outbound requests to attacker-controlled or internal targets during PDF rendering. The behavior can be used for internal network probing, server-side reachability checks, and potentially follow-on exploitation depending on deployment environment and accessible internal services. Version 2.58.0 patches the issue.

- [https://github.com/cyeezy08/Kimai-CVE-2026-49865-POC](https://github.com/cyeezy08/Kimai-CVE-2026-49865-POC) :  ![starts](https://img.shields.io/github/stars/cyeezy08/Kimai-CVE-2026-49865-POC.svg) ![forks](https://img.shields.io/github/forks/cyeezy08/Kimai-CVE-2026-49865-POC.svg)


## CVE-2026-49049
 The Helix3 plugin for Joomla exposes an ajax handler task, that allows unauthenticated attackers to delete arbitrary files, write arbitrary JSON files and update template parameters.

- [https://github.com/MataKucing-OFC/CVE-2026-49049](https://github.com/MataKucing-OFC/CVE-2026-49049) :  ![starts](https://img.shields.io/github/stars/MataKucing-OFC/CVE-2026-49049.svg) ![forks](https://img.shields.io/github/forks/MataKucing-OFC/CVE-2026-49049.svg)


## CVE-2026-49009
 Northern.tech Mender Server v4.1.0, v4.0.1 and below, and fixed in v4.1.1 and v4.0.2 allows Directory Traversal.

- [https://github.com/inteleon404/CVE-2026-49009](https://github.com/inteleon404/CVE-2026-49009) :  ![starts](https://img.shields.io/github/stars/inteleon404/CVE-2026-49009.svg) ![forks](https://img.shields.io/github/forks/inteleon404/CVE-2026-49009.svg)


## CVE-2026-47691
 Netty is a network application framework for development of protocol servers and clients. Prior to versions 4.1.135.Final and 4.2.15.Final, Netty's `DnsResolveContext` insufficiently validates the bailiwick of NS records, enabling DNS Cache Poisoning. An attacker controlling an authoritative name server for a subdomain can poison the cache for parent domains (like `.co.uk`). In `io.netty.resolver.dns.DnsResolveContext.AuthoritativeNameServerList#add` method accepts any NS record from the AUTHORITY section as long as the record's name is a suffix of the questionName. Subsequently, the `handleWithAdditional` method caches the associated A records from the ADDITIONAL section directly into the `authoritativeDnsServerCache` under the parent domain's key. This bypasses standard bailiwick rules, where a server authoritative for a subdomain should not be trusted to provide authoritative records for its parent. The poisoned cache is then used for all future resolutions under the parent domain's key. Versions 4.1.135.Final and 4.2.15.Final patch the issue.

- [https://github.com/xiaoqiMikko/netty-resolver-dns-check](https://github.com/xiaoqiMikko/netty-resolver-dns-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/netty-resolver-dns-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/netty-resolver-dns-check.svg)


## CVE-2026-45674
 Netty is a network application framework for development of protocol servers and clients. Prior to versions 4.1.135.Final and 4.2.15.Final, Netty's DnsResolveContext fails to validate the origin (bailiwick) of CNAME records in DNS responses. Versions 4.1.135.Final and 4.2.15.Final patch the issue.

- [https://github.com/xiaoqiMikko/netty-resolver-dns-check](https://github.com/xiaoqiMikko/netty-resolver-dns-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/netty-resolver-dns-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/netty-resolver-dns-check.svg)


## CVE-2026-45673
 Netty is a network application framework for development of protocol servers and clients. Prior to versions 4.1.135.Final and 4.2.15.Final, Netty's DNS resolver uses a predictable PRNG for generating DNS transaction IDs and defaults to a static UDP source port. This combination reduces the entropy of DNS queries, enabling DNS Cache Poisoning (Kaminsky attack). Versions 4.1.135.Final and 4.2.15.Final patch the issue.

- [https://github.com/xiaoqiMikko/netty-resolver-dns-check](https://github.com/xiaoqiMikko/netty-resolver-dns-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/netty-resolver-dns-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/netty-resolver-dns-check.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/1ndevelopment/ghostlock-s26](https://github.com/1ndevelopment/ghostlock-s26) :  ![starts](https://img.shields.io/github/stars/1ndevelopment/ghostlock-s26.svg) ![forks](https://img.shields.io/github/forks/1ndevelopment/ghostlock-s26.svg)
- [https://github.com/CamsShaft/IonStack-S22-cve-2026-43499](https://github.com/CamsShaft/IonStack-S22-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/CamsShaft/IonStack-S22-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/CamsShaft/IonStack-S22-cve-2026-43499.svg)
- [https://github.com/diyiqiuye/ghostlock-pfem10](https://github.com/diyiqiuye/ghostlock-pfem10) :  ![starts](https://img.shields.io/github/stars/diyiqiuye/ghostlock-pfem10.svg) ![forks](https://img.shields.io/github/forks/diyiqiuye/ghostlock-pfem10.svg)
- [https://github.com/SammyEnigma/CVE-2026-43499-S26](https://github.com/SammyEnigma/CVE-2026-43499-S26) :  ![starts](https://img.shields.io/github/stars/SammyEnigma/CVE-2026-43499-S26.svg) ![forks](https://img.shields.io/github/forks/SammyEnigma/CVE-2026-43499-S26.svg)


## CVE-2026-42978
 Concurrent execution using shared resource with improper synchronization ('race condition') in Windows Push Notifications allows an authorized attacker to elevate privileges locally.

- [https://github.com/SyntaxMethod/CVE-2026-42978-PoC-Research](https://github.com/SyntaxMethod/CVE-2026-42978-PoC-Research) :  ![starts](https://img.shields.io/github/stars/SyntaxMethod/CVE-2026-42978-PoC-Research.svg) ![forks](https://img.shields.io/github/forks/SyntaxMethod/CVE-2026-42978-PoC-Research.svg)
- [https://github.com/ZeroDayEvil/CVE-2026-42978-PoC-Research](https://github.com/ZeroDayEvil/CVE-2026-42978-PoC-Research) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-42978-PoC-Research.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-42978-PoC-Research.svg)


## CVE-2026-42613
 Grav is a file-based Web platform. Prior to 2.0.0-beta.2, the Login::register() method in the Login plugin accepts attacker-controlled groups and access fields from the registration POST data without server-side validation. When registration is enabled and groups or access are included in the configured allowed fields list, an unauthenticated user can self-register with admin.super privileges by injecting these fields into the registration request. This vulnerability is fixed in 2.0.0-beta.2.

- [https://github.com/ivanesk315/CVE-2026-42613](https://github.com/ivanesk315/CVE-2026-42613) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2026-42613.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2026-42613.svg)


## CVE-2026-42536
Users are recommended to upgrade to version 2.4.68, which fixes the issue.

- [https://github.com/erberkan/CVE-2026-42536-PoC](https://github.com/erberkan/CVE-2026-42536-PoC) :  ![starts](https://img.shields.io/github/stars/erberkan/CVE-2026-42536-PoC.svg) ![forks](https://img.shields.io/github/forks/erberkan/CVE-2026-42536-PoC.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/ivanesk315/CVE-2026-42533](https://github.com/ivanesk315/CVE-2026-42533) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2026-42533.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2026-42533.svg)


## CVE-2026-42018
 JFrog Artifactory could return an internal anonymous-user token to an unauthenticated caller when anonymous access is disabled, potentially exposing sensitive resources.

- [https://github.com/BL0odz/JFrog_CVE-2026-65615-ByGLM](https://github.com/BL0odz/JFrog_CVE-2026-65615-ByGLM) :  ![starts](https://img.shields.io/github/stars/BL0odz/JFrog_CVE-2026-65615-ByGLM.svg) ![forks](https://img.shields.io/github/forks/BL0odz/JFrog_CVE-2026-65615-ByGLM.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/dann3xplo1t/Cpanel](https://github.com/dann3xplo1t/Cpanel) :  ![starts](https://img.shields.io/github/stars/dann3xplo1t/Cpanel.svg) ![forks](https://img.shields.io/github/forks/dann3xplo1t/Cpanel.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/iapetus12/cohort-htb](https://github.com/iapetus12/cohort-htb) :  ![starts](https://img.shields.io/github/stars/iapetus12/cohort-htb.svg) ![forks](https://img.shields.io/github/forks/iapetus12/cohort-htb.svg)


## CVE-2026-41096
 Heap-based buffer overflow in Microsoft Windows DNS allows an unauthorized attacker to execute code over a network.

- [https://github.com/ZeroDayEvil/CVE-2026-41096-PoC](https://github.com/ZeroDayEvil/CVE-2026-41096-PoC) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-41096-PoC.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-41096-PoC.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/SyntaxMethod/CVE-2026-41089-Netlogon-RCE-PoC](https://github.com/SyntaxMethod/CVE-2026-41089-Netlogon-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/SyntaxMethod/CVE-2026-41089-Netlogon-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/SyntaxMethod/CVE-2026-41089-Netlogon-RCE-PoC.svg)
- [https://github.com/ZeroDayVPN/CVE-2026-41089-Netlogon](https://github.com/ZeroDayVPN/CVE-2026-41089-Netlogon) :  ![starts](https://img.shields.io/github/stars/ZeroDayVPN/CVE-2026-41089-Netlogon.svg) ![forks](https://img.shields.io/github/forks/ZeroDayVPN/CVE-2026-41089-Netlogon.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/julichaan/CVE-2026-39987_POC](https://github.com/julichaan/CVE-2026-39987_POC) :  ![starts](https://img.shields.io/github/stars/julichaan/CVE-2026-39987_POC.svg) ![forks](https://img.shields.io/github/forks/julichaan/CVE-2026-39987_POC.svg)
- [https://github.com/iapetus12/cohort-htb](https://github.com/iapetus12/cohort-htb) :  ![starts](https://img.shields.io/github/stars/iapetus12/cohort-htb.svg) ![forks](https://img.shields.io/github/forks/iapetus12/cohort-htb.svg)


## CVE-2026-36392
 FairSketch Rise CRM Version 3.9.6 is vulnerable to Cross Site Scripting (XSS). An authenticated administrator can inject arbitrary JavaScript into an item's title, which is stored server-side and executed in the browser of any client user who visits the store page, enabling session hijacking, account takeover, and phishing.

- [https://github.com/moksh-nfsu/CVE-2026-36392](https://github.com/moksh-nfsu/CVE-2026-36392) :  ![starts](https://img.shields.io/github/stars/moksh-nfsu/CVE-2026-36392.svg) ![forks](https://img.shields.io/github/forks/moksh-nfsu/CVE-2026-36392.svg)


## CVE-2026-35194
Users are recommended to upgrade to either version 1.20.4, 2.0.2, 2.1.2 or 2.2.1, which fixes this issue.

- [https://github.com/DexSemon/CVE-2026-35194](https://github.com/DexSemon/CVE-2026-35194) :  ![starts](https://img.shields.io/github/stars/DexSemon/CVE-2026-35194.svg) ![forks](https://img.shields.io/github/forks/DexSemon/CVE-2026-35194.svg)


## CVE-2026-33697
 Cocos AI is a confidential computing system for AI. The current implementation of attested TLS (aTLS) in CoCoS is vulnerable to a relay attack affecting all versions from v0.4.0 through v0.8.2. This vulnerability is present in both the AMD SEV-SNP and Intel TDX deployment targets supported by CoCoS. In the affected design, an attacker may be able to extract the ephemeral TLS private key used during the intra-handshake attestation. Because the attestation evidence is bound to the ephemeral key but not to the TLS channel, possession of that key is sufficient to relay or divert the attested TLS session. A client will accept the connection under false assumptions about the endpoint it is communicating with — the attestation report cannot distinguish the genuine attested service from the attacker's relay. This undermines the intended authentication guarantees of attested TLS. A successful attack may allow an attacker to impersonate an attested CoCoS service and access data or operations that the client intended to send only to the genuine attested endpoint. Exploitation requires the attacker to first extract the ephemeral TLS private key, which is possible through physical access to the server hardware, transient execution attacks, or side-channel attacks. Note that the aTLS implementation was fully redesigned in v0.7.0, but the redesign does not address this vulnerability. The relay attack weakness is architectural and affects all releases in the v0.4.0–v0.8.2 range. This vulnerability class was formally analyzed and demonstrated across multiple attested TLS implementations, including CoCoS, by researchers whose findings were disclosed to the IETF TLS Working Group. Formal verification was conducted using ProVerif. As of time of publication, there is no patch available. No complete workaround is available. The following hardening measures reduce but do not eliminate the risk: Keep TEE firmware and microcode up to date to reduce the key-extraction surface; define strict attestation policies that validate all available report fields, including firmware versions, TCB levels, and platform configuration registers; and/or enable mutual aTLS with CA-signed certificates where deployment architecture permits.

- [https://github.com/muhammad-usama-sardar/intra-handshake-fail](https://github.com/muhammad-usama-sardar/intra-handshake-fail) :  ![starts](https://img.shields.io/github/stars/muhammad-usama-sardar/intra-handshake-fail.svg) ![forks](https://img.shields.io/github/forks/muhammad-usama-sardar/intra-handshake-fail.svg)


## CVE-2026-33439
 Open Access Management (OpenAM) is an access management solution. Prior to 16.0.6, OpenIdentityPlatform OpenAM is vulnerable to pre-authentication Remote Code Execution (RCE) via unsafe Java deserialization of the jato.clientSession HTTP parameter. This bypasses the WhitelistObjectInputStream mitigation that was applied to the jato.pageSession parameter after CVE-2021-35464. An unauthenticated attacker can achieve arbitrary command execution on the server by sending a crafted serialized Java object as the jato.clientSession GET/POST parameter to any JATO ViewBean endpoint whose JSP contains jato:form tags (e.g., the Password Reset pages). This vulnerability is fixed in 16.0.6.

- [https://github.com/infernosalex/CVE-2026-33439-Python-PoC](https://github.com/infernosalex/CVE-2026-33439-Python-PoC) :  ![starts](https://img.shields.io/github/stars/infernosalex/CVE-2026-33439-Python-PoC.svg) ![forks](https://img.shields.io/github/forks/infernosalex/CVE-2026-33439-Python-PoC.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/MaximilianoMeyer/CVE-2026-33017](https://github.com/MaximilianoMeyer/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/MaximilianoMeyer/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/MaximilianoMeyer/CVE-2026-33017.svg)


## CVE-2026-32202
 Protection mechanism failure in Windows Shell allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/f0xox/CVE-2026-32202](https://github.com/f0xox/CVE-2026-32202) :  ![starts](https://img.shields.io/github/stars/f0xox/CVE-2026-32202.svg) ![forks](https://img.shields.io/github/forks/f0xox/CVE-2026-32202.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix](https://github.com/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix) :  ![starts](https://img.shields.io/github/stars/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix.svg) ![forks](https://img.shields.io/github/forks/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix.svg)


## CVE-2026-28496
 FOSSBilling is a free, open-source billing and client management system. Versions prior to 0.8.0 have a Server-Side Template Injection (SSTI) vulnerability in the template rendering system. Administrators with access to features that render Twig templates (email templates, mass mail campaigns, custom payment adapters, and the `string_render` API endpoint) can inject arbitrary Twig expressions, leading to information disclosure and remote code execution. The vulnerability exists because Twig templates are rendered without a sandbox, allowing access to the full Twig environment, API context, and the application's dependency injection container. Version 0.8.0 patches the issue. Some workarounds are available. Audit existing email templates for suspicious Twig expressions, rotate all admin and client API tokens, and/or block external access to /api/system/* at reverse proxy/WAF to mitigate chaining with GHSA-78x5-c8gw-8279.

- [https://github.com/ivanesk315/CVE-2026-28496](https://github.com/ivanesk315/CVE-2026-28496) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2026-28496.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2026-28496.svg)


## CVE-2026-25645
 Requests is a HTTP library. Prior to version 2.33.0, the `requests.utils.extract_zipped_paths()` utility function uses a predictable filename when extracting files from zip archives into the system temporary directory. If the target file already exists, it is reused without validation. A local attacker with write access to the temp directory could pre-create a malicious file that would be loaded in place of the legitimate one. Standard usage of the Requests library is not affected by this vulnerability. Only applications that call `extract_zipped_paths()` directly are impacted. Starting in version 2.33.0, the library extracts files to a non-deterministic location. If developers are unable to upgrade, they can set `TMPDIR` in their environment to a directory with restricted write access.

- [https://github.com/Jaycelation/CVE-2026-25645](https://github.com/Jaycelation/CVE-2026-25645) :  ![starts](https://img.shields.io/github/stars/Jaycelation/CVE-2026-25645.svg) ![forks](https://img.shields.io/github/forks/Jaycelation/CVE-2026-25645.svg)


## CVE-2026-25057
 MarkUs is a web application for the submission and grading of student assignments. Prior to 2.9.1, instructors are able to upload a zip file to create an assignment from an exported configuration (courses/:course_id/assignments/upload_config_files). The uploaded zip file entry names are used to create paths to write files to disk without checking these paths. This vulnerability is fixed in 2.9.1.

- [https://github.com/ustr/CVE-2026-25057](https://github.com/ustr/CVE-2026-25057) :  ![starts](https://img.shields.io/github/stars/ustr/CVE-2026-25057.svg) ![forks](https://img.shields.io/github/forks/ustr/CVE-2026-25057.svg)


## CVE-2026-24332
 Discord through 2026-01-16 allows gathering information about whether a user's client state is Invisible (and not actually offline) because the response to a WebSocket API request includes the user in the presences array (with "status": "offline"), whereas offline users are omitted from the presences array. This is arguably inconsistent with the UI description of Invisible as "You will appear offline." NOTE: a third-party report suggests that this was remediated later in 2026.

- [https://github.com/0cqb/CVE-2026-24332](https://github.com/0cqb/CVE-2026-24332) :  ![starts](https://img.shields.io/github/stars/0cqb/CVE-2026-24332.svg) ![forks](https://img.shields.io/github/forks/0cqb/CVE-2026-24332.svg)


## CVE-2026-24291
 Incorrect permission assignment for critical resource in Windows Accessibility Infrastructure (ATBroker.exe) allows an authorized attacker to elevate privileges locally.

- [https://github.com/ZeroDayVPN/CVE-2026-24291](https://github.com/ZeroDayVPN/CVE-2026-24291) :  ![starts](https://img.shields.io/github/stars/ZeroDayVPN/CVE-2026-24291.svg) ![forks](https://img.shields.io/github/forks/ZeroDayVPN/CVE-2026-24291.svg)


## CVE-2026-23980
Users are recommended to upgrade to version 6.0.0, which fixes the issue.

- [https://github.com/hyphenTBG/CVE-2026-23980](https://github.com/hyphenTBG/CVE-2026-23980) :  ![starts](https://img.shields.io/github/stars/hyphenTBG/CVE-2026-23980.svg) ![forks](https://img.shields.io/github/forks/hyphenTBG/CVE-2026-23980.svg)


## CVE-2026-22732
: from 5.7.0 through 5.7.21, from 5.8.0 through 5.8.23, from 6.3.0 through 6.3.14, from 6.4.0 through 6.4.14, from 6.5.0 through 6.5.8, from 7.0.0 through 7.0.3.

- [https://github.com/dylan-chainguard/cve-2026-22732-poc](https://github.com/dylan-chainguard/cve-2026-22732-poc) :  ![starts](https://img.shields.io/github/stars/dylan-chainguard/cve-2026-22732-poc.svg) ![forks](https://img.shields.io/github/forks/dylan-chainguard/cve-2026-22732-poc.svg)


## CVE-2026-22706
 Strapi is an open source headless content management system. In Strapi versions prior to 5.33.3, changing or resetting a user's password did not invalidate the user's existing refresh-token sessions by default. The refresh-token invalidation step in the users-permissions and admin authentication controllers was conditional on a caller-supplied `deviceId`. When a password change or reset request did not include a `deviceId`, no refresh tokens were revoked, leaving every prior session active. An attacker who had previously obtained a refresh token could continue minting new access tokens after the legitimate user reset their password, allowing persistent unauthorized access for the lifetime of the refresh token (up to 30 days by default). Rotating credentials no longer terminated an active attacker session, defeating password reset as a containment measure. The patch in version 5.33.3 invalidates all refresh tokens associated with the user on every password change and password reset, regardless of whether a `deviceId` is supplied. A new device-scoped session is then issued to the caller as part of the response.

- [https://github.com/het-P301204/AfterLife](https://github.com/het-P301204/AfterLife) :  ![starts](https://img.shields.io/github/stars/het-P301204/AfterLife.svg) ![forks](https://img.shields.io/github/forks/het-P301204/AfterLife.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/ZeroDayEvil/CVE-2026-21858-n8n-FullChain](https://github.com/ZeroDayEvil/CVE-2026-21858-n8n-FullChain) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-21858-n8n-FullChain.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-21858-n8n-FullChain.svg)


## CVE-2026-21852
 Claude Code is an agentic coding tool. Prior to version 2.0.65, vulnerability in Claude Code's project-load flow allowed malicious repositories to exfiltrate data including Anthropic API keys before users confirmed trust. An attacker-controlled repository could include a settings file that sets ANTHROPIC_BASE_URL to an attacker-controlled endpoint and when the repository was opened, Claude Code would read the configuration and immediately issue API requests before showing the trust prompt, potentially leaking the user's API keys. Users on standard Claude Code auto-update have received this fix already. Users performing manual updates are advised to update to version 2.0.65, which contains a patch, or to the latest version.

- [https://github.com/abhishek2512mishra/claude-code-security-audit](https://github.com/abhishek2512mishra/claude-code-security-audit) :  ![starts](https://img.shields.io/github/stars/abhishek2512mishra/claude-code-security-audit.svg) ![forks](https://img.shields.io/github/forks/abhishek2512mishra/claude-code-security-audit.svg)


## CVE-2026-20805
 Exposure of sensitive information to an unauthorized actor in Desktop Windows Manager allows an authorized attacker to disclose information locally.

- [https://github.com/ZeroDayEvil/CVE-2026-20805-PoC](https://github.com/ZeroDayEvil/CVE-2026-20805-PoC) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-20805-PoC.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-20805-PoC.svg)


## CVE-2026-20516
 In MiracastService, there is a possible escalation of privilege due to a confused deputy. This could lead to local denial of service with User execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS11060069 / DTV04881615; Issue ID: MSV-7882.

- [https://github.com/Dingo97/CVE-2026-20516](https://github.com/Dingo97/CVE-2026-20516) :  ![starts](https://img.shields.io/github/stars/Dingo97/CVE-2026-20516.svg) ![forks](https://img.shields.io/github/forks/Dingo97/CVE-2026-20516.svg)


## CVE-2026-20253
 In Splunk Enterprise 10.2 versions below 10.2.4 and 10 versions below 10.0.7, an unauthenticated user could create or truncate arbitrary files through a PostgreSQL sidecar service endpoint. The vulnerability exists because the PostgreSQL sidecar service endpoint lacks authentication controls, allowing any network-reachable user to invoke file operations without credentials. Splunk Enterprise versions 9.4 and earlier are not affected. If you cannot immediately upgrade to a fixed version, you can mitigate this vulnerability by disabling the PostgreSQL sidecar service.

- [https://github.com/ivanesk315/CVE-2026-20253](https://github.com/ivanesk315/CVE-2026-20253) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2026-20253.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2026-20253.svg)


## CVE-2026-20079
This vulnerability is due to an improper system process that is created at boot time. An attacker could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute a variety of scripts and commands that allow&nbsp;root access to the device.&nbsp;

- [https://github.com/DiegoArias008/CVE-2026-20079-checker](https://github.com/DiegoArias008/CVE-2026-20079-checker) :  ![starts](https://img.shields.io/github/stars/DiegoArias008/CVE-2026-20079-checker.svg) ![forks](https://img.shields.io/github/forks/DiegoArias008/CVE-2026-20079-checker.svg)


## CVE-2026-19794
 The WP-Stats plugin for WordPress is vulnerable to Stored Cross-Site Scripting in all versions up to, and including, 2.56 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/testardou/CVE-2026-19794](https://github.com/testardou/CVE-2026-19794) :  ![starts](https://img.shields.io/github/stars/testardou/CVE-2026-19794.svg) ![forks](https://img.shields.io/github/forks/testardou/CVE-2026-19794.svg)


## CVE-2026-19490
This issue affects ADC: from 14.1 through 73.32 and from 13.1 through 63.21; Gateway: from 14.1 through 73.32 and from 13.1 through 63.21.

- [https://github.com/BishopFox/CVE-2026-19490-check](https://github.com/BishopFox/CVE-2026-19490-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2026-19490-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2026-19490-check.svg)


## CVE-2026-18963
 A flaw was found in the reset-credentials flow of the keycloak-services component, which is the core engine for identity and access management in Red Hat Build of Keycloak. The issue allows an unauthenticated attacker to force the password reset process for any user without needing to click the required email verification link. This can result in the attacker gaining full control over target user accounts by directly setting new credentials.

- [https://github.com/ivanesk315/CVE-2026-18963](https://github.com/ivanesk315/CVE-2026-18963) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2026-18963.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2026-18963.svg)


## CVE-2026-18351
 The Drag and Drop File Upload for Elementor Forms plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 1.6.0 via the elementor_file_upload function. This is due to insufficient file type validation in the is_file_type_valid() function, which uses the attacker-controlled 'type' parameter as regex keys in the MIME allowlist, allowing blacklist bypass via a crafted extension that sanitize_file_name() later normalizes to a PHP extension. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.

- [https://github.com/JohenLastGen-JLG/CVE-2026-18351](https://github.com/JohenLastGen-JLG/CVE-2026-18351) :  ![starts](https://img.shields.io/github/stars/JohenLastGen-JLG/CVE-2026-18351.svg) ![forks](https://img.shields.io/github/forks/JohenLastGen-JLG/CVE-2026-18351.svg)
- [https://github.com/ChiefYoru/Exploit-CVE-2026-18351](https://github.com/ChiefYoru/Exploit-CVE-2026-18351) :  ![starts](https://img.shields.io/github/stars/ChiefYoru/Exploit-CVE-2026-18351.svg) ![forks](https://img.shields.io/github/forks/ChiefYoru/Exploit-CVE-2026-18351.svg)


## CVE-2026-15667
 The Eventin – Event Calendar, Event Registration, Tickets & Booking (AI Powered) plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 4.1.22 via the 'event_layout' parameter parameter. This makes it possible for authenticated attackers, with contributor-level access and above, to include and execute arbitrary .php files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where .php file types can be uploaded and included. The etn_manage_event capability is assigned to Contributors by default, meaning any Contributor-level user can set the malicious event_layout value via the REST API without any additional configuration.

- [https://github.com/cflowsec/CVE-2026-15667](https://github.com/cflowsec/CVE-2026-15667) :  ![starts](https://img.shields.io/github/stars/cflowsec/CVE-2026-15667.svg) ![forks](https://img.shields.io/github/forks/cflowsec/CVE-2026-15667.svg)


## CVE-2026-15253
 The Easy Media Replace WordPress plugin through 0.2.0 does not sanitise and escape an attachment title before outputting it in an HTML attribute in the media library list view, allowing users with the Author role and above to inject arbitrary web scripts that are executed in the browser of a higher privileged user who views the media library.

- [https://github.com/testardou/CVE-2026-15253](https://github.com/testardou/CVE-2026-15253) :  ![starts](https://img.shields.io/github/stars/testardou/CVE-2026-15253.svg) ![forks](https://img.shields.io/github/forks/testardou/CVE-2026-15253.svg)


## CVE-2026-14962
 The ELEX WooCommerce Request a Quote WordPress plugin before 2.4.1 does not properly sanitise and escape a parameter before using it in a SQL query, allowing unauthenticated users to perform SQL injection attacks and extract arbitrary data from the database.

- [https://github.com/cflowsec/CVE-2026-14962](https://github.com/cflowsec/CVE-2026-14962) :  ![starts](https://img.shields.io/github/stars/cflowsec/CVE-2026-14962.svg) ![forks](https://img.shields.io/github/forks/cflowsec/CVE-2026-14962.svg)


## CVE-2026-13181
 In Progress® Telerik® UI for AJAX prior to v2026.2.708, forged upload metadata can influence AsyncUploadTypeName processing and trigger unsafe attacker-controlled type resolution, enabling remote code execution in affected deployments.

- [https://github.com/ivanesk315/CVE-2026-13181-Telerik](https://github.com/ivanesk315/CVE-2026-13181-Telerik) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2026-13181-Telerik.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2026-13181-Telerik.svg)


## CVE-2026-7929
 Use after free in MediaRecording in Google Chrome prior to 148.0.7778.96 allowed a remote attacker who convinced a user to engage in specific UI gestures to execute arbitrary code via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/TheMalwareGuardian/CVE-2026-79298](https://github.com/TheMalwareGuardian/CVE-2026-79298) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2026-79298.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2026-79298.svg)
- [https://github.com/MGTx2/CVE-2026-79294](https://github.com/MGTx2/CVE-2026-79294) :  ![starts](https://img.shields.io/github/stars/MGTx2/CVE-2026-79294.svg) ![forks](https://img.shields.io/github/forks/MGTx2/CVE-2026-79294.svg)


## CVE-2026-5199
This vulnerability also impacted Temporal Cloud when the attacker and victim namespaces were on the same cell, with the same preconditions as self-hosted clusters.

- [https://github.com/HORKimhab/CVE-2026-51990](https://github.com/HORKimhab/CVE-2026-51990) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-51990.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-51990.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Cxyofficial/x200-cve-2026-43499](https://github.com/Cxyofficial/x200-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/Cxyofficial/x200-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/Cxyofficial/x200-cve-2026-43499.svg)
- [https://github.com/pimpamebanihah/cve-2026-43499-app.so](https://github.com/pimpamebanihah/cve-2026-43499-app.so) :  ![starts](https://img.shields.io/github/stars/pimpamebanihah/cve-2026-43499-app.so.svg) ![forks](https://img.shields.io/github/forks/pimpamebanihah/cve-2026-43499-app.so.svg)
- [https://github.com/hui191/cve-2026-43499-aak-an00](https://github.com/hui191/cve-2026-43499-aak-an00) :  ![starts](https://img.shields.io/github/stars/hui191/cve-2026-43499-aak-an00.svg) ![forks](https://img.shields.io/github/forks/hui191/cve-2026-43499-aak-an00.svg)
- [https://github.com/huaguiqi/asus_i005-CVE-2026-43499](https://github.com/huaguiqi/asus_i005-CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/huaguiqi/asus_i005-CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/huaguiqi/asus_i005-CVE-2026-43499.svg)
- [https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40](https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40) :  ![starts](https://img.shields.io/github/stars/ccp-p/ghostlock-cve-2026-43499-4.19-k40.svg) ![forks](https://img.shields.io/github/forks/ccp-p/ghostlock-cve-2026-43499-4.19-k40.svg)


## CVE-2026-3869
 CWE-303 : Incorrect Implementation of Authentication Algorithm vulnerability exists that could cause loss of confidentiality, integrity and availability of the PLC provided an application project with a lower application level is running on the PLC.

- [https://github.com/vital-information-resource-under-siege/CVE-2026-38698-and-CVE-2026-38699](https://github.com/vital-information-resource-under-siege/CVE-2026-38698-and-CVE-2026-38699) :  ![starts](https://img.shields.io/github/stars/vital-information-resource-under-siege/CVE-2026-38698-and-CVE-2026-38699.svg) ![forks](https://img.shields.io/github/forks/vital-information-resource-under-siege/CVE-2026-38698-and-CVE-2026-38699.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/kvakirsanov/CVE-2026-31431-live-process-code-injection](https://github.com/kvakirsanov/CVE-2026-31431-live-process-code-injection) :  ![starts](https://img.shields.io/github/stars/kvakirsanov/CVE-2026-31431-live-process-code-injection.svg) ![forks](https://img.shields.io/github/forks/kvakirsanov/CVE-2026-31431-live-process-code-injection.svg)


## CVE-2026-2332
Note how the chunk extension does not close the double quotes, and it is able to inject a smuggled request.

- [https://github.com/xiaoqiMikko/jetty-line-check](https://github.com/xiaoqiMikko/jetty-line-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/jetty-line-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/jetty-line-check.svg)


## CVE-2026-0303
 A code execution vulnerability in Palo Alto Networks Checkov by Prisma® Cloud can allow arbitrary code execution when Checkov scans a directory that contains an attacker-controlled configuration file.

- [https://github.com/YonLiud/CVE-2026-0303](https://github.com/YonLiud/CVE-2026-0303) :  ![starts](https://img.shields.io/github/stars/YonLiud/CVE-2026-0303.svg) ![forks](https://img.shields.io/github/forks/YonLiud/CVE-2026-0303.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/ZeroDayEvil/CVE-2026-21858-n8n-FullChain](https://github.com/ZeroDayEvil/CVE-2026-21858-n8n-FullChain) :  ![starts](https://img.shields.io/github/stars/ZeroDayEvil/CVE-2026-21858-n8n-FullChain.svg) ![forks](https://img.shields.io/github/forks/ZeroDayEvil/CVE-2026-21858-n8n-FullChain.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-60787
 MotionEye v0.43.1b4 and before is vulnerable to OS Command Injection in configuration parameters such as image_file_name. Unsanitized user input is written to Motion configuration files, allowing remote authenticated attackers with admin access to achieve code execution when Motion is restarted.

- [https://github.com/ledksv/cctv](https://github.com/ledksv/cctv) :  ![starts](https://img.shields.io/github/stars/ledksv/cctv.svg) ![forks](https://img.shields.io/github/forks/ledksv/cctv.svg)


## CVE-2025-54123
 Hoverfly is an open source API simulation tool. In versions 1.11.3 and prior, the middleware functionality in Hoverfly is vulnerable to command injection vulnerability at `/api/v2/hoverfly/middleware` endpoint due to insufficient validation and sanitization in user input. The vulnerability exists in the middleware management API endpoint `/api/v2/hoverfly/middleware`. This issue is born due to combination of three code level flaws: Insufficient Input Validation in middleware.go line 94-96; Unsafe Command Execution in local_middleware.go line 14-19; and Immediate Execution During Testing in hoverfly_service.go line 173. This allows an attacker to gain remote code execution (RCE) on any system running the vulnerable Hoverfly service. Since the input is directly passed to system commands without proper checks, an attacker can upload a malicious payload or directly execute arbitrary commands (including reverse shells) on the host server with the privileges of the Hoverfly process. Commit 17e60a9bc78826deb4b782dca1c1abd3dbe60d40 in version 1.12.0 disables the set middleware API by default, and subsequent changes to documentation make users aware of the security changes of exposing the set middleware API.

- [https://github.com/ledksv/devarea](https://github.com/ledksv/devarea) :  ![starts](https://img.shields.io/github/stars/ledksv/devarea.svg) ![forks](https://img.shields.io/github/forks/ledksv/devarea.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/ledksv/pterodactyl](https://github.com/ledksv/pterodactyl) :  ![starts](https://img.shields.io/github/stars/ledksv/pterodactyl.svg) ![forks](https://img.shields.io/github/forks/ledksv/pterodactyl.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/fishjojo1/devin-cve48384-1789318364-1162143-parent](https://github.com/fishjojo1/devin-cve48384-1789318364-1162143-parent) :  ![starts](https://img.shields.io/github/stars/fishjojo1/devin-cve48384-1789318364-1162143-parent.svg) ![forks](https://img.shields.io/github/forks/fishjojo1/devin-cve48384-1789318364-1162143-parent.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/ledksv/wingdata](https://github.com/ledksv/wingdata) :  ![starts](https://img.shields.io/github/stars/ledksv/wingdata.svg) ![forks](https://img.shields.io/github/forks/ledksv/wingdata.svg)


## CVE-2025-38502
using any of the cgroup local storage maps.

- [https://github.com/abraxas/CVE-2025-38502-Linux-LPE](https://github.com/abraxas/CVE-2025-38502-Linux-LPE) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2025-38502-Linux-LPE.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2025-38502-Linux-LPE.svg)


## CVE-2025-38352
anyway in this case.

- [https://github.com/longwasu/CVE-2025-38352-PoC](https://github.com/longwasu/CVE-2025-38352-PoC) :  ![starts](https://img.shields.io/github/stars/longwasu/CVE-2025-38352-PoC.svg) ![forks](https://img.shields.io/github/forks/longwasu/CVE-2025-38352-PoC.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/e5dfdd568a75282b712b6d93a7a18e12/CVE-2025-32432](https://github.com/e5dfdd568a75282b712b6d93a7a18e12/CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/e5dfdd568a75282b712b6d93a7a18e12/CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/e5dfdd568a75282b712b6d93a7a18e12/CVE-2025-32432.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/SebastianMautner/nuclei-CVE-2025-24813](https://github.com/SebastianMautner/nuclei-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/SebastianMautner/nuclei-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/SebastianMautner/nuclei-CVE-2025-24813.svg)
- [https://github.com/Mega-Starmie/tomcat-cve-2025-24813-lab](https://github.com/Mega-Starmie/tomcat-cve-2025-24813-lab) :  ![starts](https://img.shields.io/github/stars/Mega-Starmie/tomcat-cve-2025-24813-lab.svg) ![forks](https://img.shields.io/github/forks/Mega-Starmie/tomcat-cve-2025-24813-lab.svg)


## CVE-2025-24367
 Cacti is an open source performance and fault management framework. An authenticated Cacti user can abuse graph creation and graph template functionality to create arbitrary PHP scripts in the web root of the application, leading to remote code execution on the server. This vulnerability is fixed in 1.2.29.

- [https://github.com/ledksv/monitorsfour](https://github.com/ledksv/monitorsfour) :  ![starts](https://img.shields.io/github/stars/ledksv/monitorsfour.svg) ![forks](https://img.shields.io/github/forks/ledksv/monitorsfour.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/BardLaudian/CVE-2025-24071](https://github.com/BardLaudian/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/BardLaudian/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/BardLaudian/CVE-2025-24071.svg)


## CVE-2025-14659
 A vulnerability was detected in D-Link DIR-860LB1 and DIR-868LB1 203b01/203b03. Affected is an unknown function of the component DHCP Daemon. The manipulation of the argument Hostname results in command injection. It is possible to launch the attack remotely. The exploit is now public and may be used.

- [https://github.com/PeterLinccl/Vulnerability-DLink-CVE-2025-14659](https://github.com/PeterLinccl/Vulnerability-DLink-CVE-2025-14659) :  ![starts](https://img.shields.io/github/stars/PeterLinccl/Vulnerability-DLink-CVE-2025-14659.svg) ![forks](https://img.shields.io/github/forks/PeterLinccl/Vulnerability-DLink-CVE-2025-14659.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/ledksv/monitorsfour](https://github.com/ledksv/monitorsfour) :  ![starts](https://img.shields.io/github/stars/ledksv/monitorsfour.svg) ![forks](https://img.shields.io/github/forks/ledksv/monitorsfour.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/wqsv/ThrottleStopPoC](https://github.com/wqsv/ThrottleStopPoC) :  ![starts](https://img.shields.io/github/stars/wqsv/ThrottleStopPoC.svg) ![forks](https://img.shields.io/github/forks/wqsv/ThrottleStopPoC.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/ledksv/pterodactyl](https://github.com/ledksv/pterodactyl) :  ![starts](https://img.shields.io/github/stars/ledksv/pterodactyl.svg) ![forks](https://img.shields.io/github/forks/ledksv/pterodactyl.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/ledksv/pterodactyl](https://github.com/ledksv/pterodactyl) :  ![starts](https://img.shields.io/github/stars/ledksv/pterodactyl.svg) ![forks](https://img.shields.io/github/forks/ledksv/pterodactyl.svg)


## CVE-2025-4030
 A vulnerability was found in PHPGurukul COVID19 Testing Management System 1.0. It has been classified as critical. This affects an unknown part of the file /search-report-result.php. The manipulation of the argument serachdata leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/JunZ-Leo/CVE](https://github.com/JunZ-Leo/CVE) :  ![starts](https://img.shields.io/github/stars/JunZ-Leo/CVE.svg) ![forks](https://img.shields.io/github/forks/JunZ-Leo/CVE.svg)


## CVE-2025-4028
 A vulnerability has been found in PHPGurukul COVID19 Testing Management System 1.0 and classified as critical. Affected by this vulnerability is an unknown functionality of the file /profile.php. The manipulation of the argument mobilenumber leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.

- [https://github.com/JunZ-Leo/CVE](https://github.com/JunZ-Leo/CVE) :  ![starts](https://img.shields.io/github/stars/JunZ-Leo/CVE.svg) ![forks](https://img.shields.io/github/forks/JunZ-Leo/CVE.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)


## CVE-2025-0133
For GlobalProtect users with Clientless VPN enabled, there is a limited impact on confidentiality due to inherent risks of Clientless VPN that facilitate credential theft. You can read more about this risk in the informational bulletin  PAN-SA-2025-0005 https://security.paloaltonetworks.com/PAN-SA-2025-0005   https://security.paloaltonetworks.com/PAN-SA-2025-0005 . There is no impact to confidentiality for GlobalProtect users if you did not enable (or you disable) Clientless VPN.

- [https://github.com/inteleon404/CVE-2025-0133](https://github.com/inteleon404/CVE-2025-0133) :  ![starts](https://img.shields.io/github/stars/inteleon404/CVE-2025-0133.svg) ![forks](https://img.shields.io/github/forks/inteleon404/CVE-2025-0133.svg)


## CVE-2024-57610
 A rate limiting issue in Sylius v2.0.2 allows a remote attacker to perform unrestricted brute-force attacks on user accounts, significantly increasing the risk of account compromise and denial of service for legitimate users. The Supplier's position is that the Sylius core software is not intended to address brute-force attacks; instead, customers deploying a Sylius-based system are supposed to use "firewalls, rate-limiting middleware, or authentication providers" for that functionality.

- [https://github.com/H4ckM3-png/CVE-2024-57610](https://github.com/H4ckM3-png/CVE-2024-57610) :  ![starts](https://img.shields.io/github/stars/H4ckM3-png/CVE-2024-57610.svg) ![forks](https://img.shields.io/github/forks/H4ckM3-png/CVE-2024-57610.svg)


## CVE-2024-51482
 ZoneMinder is a free, open source closed-circuit television software application. ZoneMinder v1.37.* = 1.37.64 is vulnerable to boolean-based SQL Injection in function of web/ajax/event.php. This is fixed in 1.37.65.

- [https://github.com/ledksv/cctv](https://github.com/ledksv/cctv) :  ![starts](https://img.shields.io/github/stars/ledksv/cctv.svg) ![forks](https://img.shields.io/github/forks/ledksv/cctv.svg)


## CVE-2024-51324
 An issue in the BdApiUtil driver of Baidu Antivirus v5.2.3.116083 allows attackers to terminate arbitrary process via executing a BYOVD (Bring Your Own Vulnerable Driver) attack.

- [https://github.com/uLl0a/bdapiutil-bydov](https://github.com/uLl0a/bdapiutil-bydov) :  ![starts](https://img.shields.io/github/stars/uLl0a/bdapiutil-bydov.svg) ![forks](https://img.shields.io/github/forks/uLl0a/bdapiutil-bydov.svg)


## CVE-2024-32019
 Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/ayub0x7/cve-2024-32019-PoC](https://github.com/ayub0x7/cve-2024-32019-PoC) :  ![starts](https://img.shields.io/github/stars/ayub0x7/cve-2024-32019-PoC.svg) ![forks](https://img.shields.io/github/forks/ayub0x7/cve-2024-32019-PoC.svg)


## CVE-2024-31666
 An issue in flusity-CMS v.2.33 allows a remote attacker to execute arbitrary code via a crafted script to the edit_addon_post.php component.

- [https://github.com/Shijx1024/CVE-2024-31666](https://github.com/Shijx1024/CVE-2024-31666) :  ![starts](https://img.shields.io/github/stars/Shijx1024/CVE-2024-31666.svg) ![forks](https://img.shields.io/github/forks/Shijx1024/CVE-2024-31666.svg)


## CVE-2024-30350
The specific flaw exists within the handling of Annotation objects. The issue results from the lack of proper validation of user-supplied data, which can result in a read past the end of an allocated buffer. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of the current process. Was ZDI-CAN-22708.

- [https://github.com/lmx-071028/cve-2024-30350-research-notes](https://github.com/lmx-071028/cve-2024-30350-research-notes) :  ![starts](https://img.shields.io/github/stars/lmx-071028/cve-2024-30350-research-notes.svg) ![forks](https://img.shields.io/github/forks/lmx-071028/cve-2024-30350-research-notes.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/shauryarathore357-hub/thm-Moniker-Link-cve-2024-21413-writeup](https://github.com/shauryarathore357-hub/thm-Moniker-Link-cve-2024-21413-writeup) :  ![starts](https://img.shields.io/github/stars/shauryarathore357-hub/thm-Moniker-Link-cve-2024-21413-writeup.svg) ![forks](https://img.shields.io/github/forks/shauryarathore357-hub/thm-Moniker-Link-cve-2024-21413-writeup.svg)


## CVE-2024-7344
 Howyar UEFI Application "Reloader"  (32-bit and 64-bit)  is vulnerable to execution of unsigned software in a hardcoded path.

- [https://github.com/TheMalwareGuardian/CVE-2026-79298](https://github.com/TheMalwareGuardian/CVE-2026-79298) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2026-79298.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2026-79298.svg)
- [https://github.com/TheMalwareGuardian/UEFI-Security-Research-Howyar-SysReturn-NetCopy](https://github.com/TheMalwareGuardian/UEFI-Security-Research-Howyar-SysReturn-NetCopy) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/UEFI-Security-Research-Howyar-SysReturn-NetCopy.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/UEFI-Security-Research-Howyar-SysReturn-NetCopy.svg)


## CVE-2024-2044
 pgAdmin = 8.3 is affected by a path-traversal vulnerability while deserializing users’ sessions in the session handling code. If the server is running on Windows, an unauthenticated attacker can load and deserialize remote pickle objects and gain code execution. If the server is running on POSIX/Linux, an authenticated attacker can upload pickle objects, deserialize them, and gain code execution.

- [https://github.com/hanzzly/CVE-2024-2044](https://github.com/hanzzly/CVE-2024-2044) :  ![starts](https://img.shields.io/github/stars/hanzzly/CVE-2024-2044.svg) ![forks](https://img.shields.io/github/forks/hanzzly/CVE-2024-2044.svg)


## CVE-2023-43208
 NextGen Healthcare Mirth Connect before version 4.4.1 is vulnerable to unauthenticated remote code execution. Note that this vulnerability is caused by the incomplete patch of CVE-2023-37679.

- [https://github.com/ledksv/Interpreter-HackTheBox](https://github.com/ledksv/Interpreter-HackTheBox) :  ![starts](https://img.shields.io/github/stars/ledksv/Interpreter-HackTheBox.svg) ![forks](https://img.shields.io/github/forks/ledksv/Interpreter-HackTheBox.svg)


## CVE-2023-33107
 Memory corruption in Graphics Linux while assigning shared virtual memory region during IOCTL call.

- [https://github.com/Xorriath/lg-velvet-eu-bootloader-unlock](https://github.com/Xorriath/lg-velvet-eu-bootloader-unlock) :  ![starts](https://img.shields.io/github/stars/Xorriath/lg-velvet-eu-bootloader-unlock.svg) ![forks](https://img.shields.io/github/forks/Xorriath/lg-velvet-eu-bootloader-unlock.svg)


## CVE-2023-22515
Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/Borsch-Appreciator/SOC235---Atlassian-Confluence-Broken-Access-Control-0-Day-CVE-2023-22515](https://github.com/Borsch-Appreciator/SOC235---Atlassian-Confluence-Broken-Access-Control-0-Day-CVE-2023-22515) :  ![starts](https://img.shields.io/github/stars/Borsch-Appreciator/SOC235---Atlassian-Confluence-Broken-Access-Control-0-Day-CVE-2023-22515.svg) ![forks](https://img.shields.io/github/forks/Borsch-Appreciator/SOC235---Atlassian-Confluence-Broken-Access-Control-0-Day-CVE-2023-22515.svg)


## CVE-2023-1326
 A privilege escalation attack was found in apport-cli 2.26.0 and earlier which is similar to CVE-2023-26604. If a system is specially configured to allow unprivileged users to run sudo apport-cli, less is configured as the pager, and the terminal size can be set: a local attacker can escalate privilege. It is extremely unlikely that a system administrator would configure sudo to allow unprivileged users to perform this class of exploit.

- [https://github.com/R3fr4kt/DEVVORTEX](https://github.com/R3fr4kt/DEVVORTEX) :  ![starts](https://img.shields.io/github/stars/R3fr4kt/DEVVORTEX.svg) ![forks](https://img.shields.io/github/forks/R3fr4kt/DEVVORTEX.svg)


## CVE-2022-46364
 A SSRF vulnerability in parsing the href attribute of XOP:Include in MTOM requests in versions of Apache CXF before 3.5.5 and 3.4.10 allows an attacker to perform SSRF style attacks on webservices that take at least one parameter of any type. 

- [https://github.com/ledksv/devarea](https://github.com/ledksv/devarea) :  ![starts](https://img.shields.io/github/stars/ledksv/devarea.svg) ![forks](https://img.shields.io/github/forks/ledksv/devarea.svg)


## CVE-2022-41404
 An issue in the fetch() method in the BasicProfile class of org.ini4j through version v0.5.4 allows attackers to cause a Denial of Service (DoS) via unspecified vectors.

- [https://github.com/fdjy1234/CVE-2022-41404-DoS-Protection](https://github.com/fdjy1234/CVE-2022-41404-DoS-Protection) :  ![starts](https://img.shields.io/github/stars/fdjy1234/CVE-2022-41404-DoS-Protection.svg) ![forks](https://img.shields.io/github/forks/fdjy1234/CVE-2022-41404-DoS-Protection.svg)


## CVE-2022-38181
 The Arm Mali GPU kernel driver allows unprivileged users to access freed memory because GPU memory operations are mishandled. This affects Bifrost r0p0 through r38p1, and r39p0; Valhall r19p0 through r38p1, and r39p0; and Midgard r4p0 through r32p0.

- [https://github.com/artur9010/amazon-mustang-hack](https://github.com/artur9010/amazon-mustang-hack) :  ![starts](https://img.shields.io/github/stars/artur9010/amazon-mustang-hack.svg) ![forks](https://img.shields.io/github/forks/artur9010/amazon-mustang-hack.svg)


## CVE-2022-34303
 A flaw was found in Eurosoft bootloaders before 2022-06-01. An attacker may use this bootloader to bypass or tamper with Secure Boot protections. In order to load and execute arbitrary code in the pre-boot stage, an attacker simply needs to replace the existing signed bootloader currently in use with this bootloader. Access to the EFI System Partition is required for booting using external media.

- [https://github.com/TheMalwareGuardian/CVE-2022-34303](https://github.com/TheMalwareGuardian/CVE-2022-34303) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2022-34303.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2022-34303.svg)
- [https://github.com/TheMalwareGuardian/CVE-2022-34301](https://github.com/TheMalwareGuardian/CVE-2022-34301) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2022-34301.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2022-34301.svg)


## CVE-2022-34302
 A flaw was found in New Horizon Datasys bootloaders before 2022-06-01. An attacker may use this bootloader to bypass or tamper with Secure Boot protections. In order to load and execute arbitrary code in the pre-boot stage, an attacker simply needs to replace the existing signed bootloader currently in use with this bootloader. Access to the EFI System Partition is required for booting using external media.

- [https://github.com/TheMalwareGuardian/CVE-2022-34302](https://github.com/TheMalwareGuardian/CVE-2022-34302) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2022-34302.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2022-34302.svg)


## CVE-2022-34301
 A flaw was found in CryptoPro Secure Disk bootloaders before 2022-06-01. An attacker may use this bootloader to bypass or tamper with Secure Boot protections. In order to load and execute arbitrary code in the pre-boot stage, an attacker simply needs to replace the existing signed bootloader currently in use with this bootloader. Access to the EFI System Partition is required for booting using external media.

- [https://github.com/TheMalwareGuardian/CVE-2022-34301](https://github.com/TheMalwareGuardian/CVE-2022-34301) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2022-34301.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2022-34301.svg)


## CVE-2021-35394
 Realtek Jungle SDK version v2.x up to v3.4.14B provides a diagnostic tool called 'MP Daemon' that is usually compiled as 'UDPServer' binary. The binary is affected by multiple memory corruption vulnerabilities and an arbitrary command injection vulnerability that can be exploited by remote unauthenticated attackers.

- [https://github.com/graphworlok/cve-2021-35394-ecosystem](https://github.com/graphworlok/cve-2021-35394-ecosystem) :  ![starts](https://img.shields.io/github/stars/graphworlok/cve-2021-35394-ecosystem.svg) ![forks](https://img.shields.io/github/forks/graphworlok/cve-2021-35394-ecosystem.svg)


## CVE-2021-28664
 The Arm Mali GPU kernel driver allows privilege escalation or a denial of service (memory corruption) because an unprivileged user can achieve read/write access to read-only pages. This affects Bifrost r0p0 through r29p0 before r30p0, Valhall r19p0 through r29p0 before r30p0, and Midgard r8p0 through r30p0 before r31p0.

- [https://github.com/woaphone/CVE-2021-28664-PoC](https://github.com/woaphone/CVE-2021-28664-PoC) :  ![starts](https://img.shields.io/github/stars/woaphone/CVE-2021-28664-PoC.svg) ![forks](https://img.shields.io/github/forks/woaphone/CVE-2021-28664-PoC.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/racoon-rac/CVE-2021-44228](https://github.com/racoon-rac/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/racoon-rac/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/racoon-rac/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/Park123r/CVE-2021-41773](https://github.com/Park123r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Park123r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Park123r/CVE-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/wangqian06/CVE-2021-3156](https://github.com/wangqian06/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/wangqian06/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/wangqian06/CVE-2021-3156.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/saaedimam/sony-bravia-root-toolkit](https://github.com/saaedimam/sony-bravia-root-toolkit) :  ![starts](https://img.shields.io/github/stars/saaedimam/sony-bravia-root-toolkit.svg) ![forks](https://img.shields.io/github/forks/saaedimam/sony-bravia-root-toolkit.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/ronankongala/metasploit-pentest-report](https://github.com/ronankongala/metasploit-pentest-report) :  ![starts](https://img.shields.io/github/stars/ronankongala/metasploit-pentest-report.svg) ![forks](https://img.shields.io/github/forks/ronankongala/metasploit-pentest-report.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/vudangducminh/CVE-2016-5195](https://github.com/vudangducminh/CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/vudangducminh/CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/vudangducminh/CVE-2016-5195.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/JohnRyk/ICMPShock3](https://github.com/JohnRyk/ICMPShock3) :  ![starts](https://img.shields.io/github/stars/JohnRyk/ICMPShock3.svg) ![forks](https://img.shields.io/github/forks/JohnRyk/ICMPShock3.svg)


## CVE-2014-3704
 The expandArguments function in the database abstraction API in Drupal core 7.x before 7.32 does not properly construct prepared statements, which allows remote attackers to conduct SQL injection attacks via an array containing crafted keys.

- [https://github.com/adfortunato/metasploitable3-pentest-writeup](https://github.com/adfortunato/metasploitable3-pentest-writeup) :  ![starts](https://img.shields.io/github/stars/adfortunato/metasploitable3-pentest-writeup.svg) ![forks](https://img.shields.io/github/forks/adfortunato/metasploitable3-pentest-writeup.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/L1LF1NG3R/heartbleed-vulnerability-exploitation](https://github.com/L1LF1NG3R/heartbleed-vulnerability-exploitation) :  ![starts](https://img.shields.io/github/stars/L1LF1NG3R/heartbleed-vulnerability-exploitation.svg) ![forks](https://img.shields.io/github/forks/L1LF1NG3R/heartbleed-vulnerability-exploitation.svg)
- [https://github.com/Ayushsinha322/heartbleed-lab](https://github.com/Ayushsinha322/heartbleed-lab) :  ![starts](https://img.shields.io/github/stars/Ayushsinha322/heartbleed-lab.svg) ![forks](https://img.shields.io/github/forks/Ayushsinha322/heartbleed-lab.svg)


## CVE-2012-0754
 Adobe Flash Player before 10.3.183.15 and 11.x before 11.1.102.62 on Windows, Mac OS X, Linux, and Solaris; before 11.1.111.6 on Android 2.x and 3.x; and before 11.1.115.6 on Android 4.x allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors.

- [https://github.com/mbeweoo/flash-exploit-defense-system](https://github.com/mbeweoo/flash-exploit-defense-system) :  ![starts](https://img.shields.io/github/stars/mbeweoo/flash-exploit-defense-system.svg) ![forks](https://img.shields.io/github/forks/mbeweoo/flash-exploit-defense-system.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/ronankongala/metasploit-pentest-report](https://github.com/ronankongala/metasploit-pentest-report) :  ![starts](https://img.shields.io/github/stars/ronankongala/metasploit-pentest-report.svg) ![forks](https://img.shields.io/github/forks/ronankongala/metasploit-pentest-report.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/zales2004/sunset-noontide-pentesting](https://github.com/zales2004/sunset-noontide-pentesting) :  ![starts](https://img.shields.io/github/stars/zales2004/sunset-noontide-pentesting.svg) ![forks](https://img.shields.io/github/forks/zales2004/sunset-noontide-pentesting.svg)


## CVE-2009-2265
 Multiple directory traversal vulnerabilities in FCKeditor before 2.6.4.1 allow remote attackers to create executable files in arbitrary directories via directory traversal sequences in the input to unspecified connector modules, as exploited in the wild for remote code execution in July 2009, related to the file browser and the editor/filemanager/connectors/ directory.

- [https://github.com/hd-exe/CVE-2009-2265-fix](https://github.com/hd-exe/CVE-2009-2265-fix) :  ![starts](https://img.shields.io/github/stars/hd-exe/CVE-2009-2265-fix.svg) ![forks](https://img.shields.io/github/forks/hd-exe/CVE-2009-2265-fix.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/ronankongala/metasploit-pentest-report](https://github.com/ronankongala/metasploit-pentest-report) :  ![starts](https://img.shields.io/github/stars/ronankongala/metasploit-pentest-report.svg) ![forks](https://img.shields.io/github/forks/ronankongala/metasploit-pentest-report.svg)

