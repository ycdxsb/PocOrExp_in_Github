# Update 2026-11-28
## CVE-2026-137390
 Mail2000 developed by Openfind has an OS Command Injection vulnerability.Authenticated remote attackers can inject arbitrary OS commands and execute them on the server.

- [https://github.com/googlesky/CVE-2026-137390](https://github.com/googlesky/CVE-2026-137390) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137390.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137390.svg)


## CVE-2026-137389
 MailGates/MailAudit developed by Openfind has a Command Injection vulnerability.Authenticated remote attackers can inject commands and execute them on the server.

- [https://github.com/googlesky/CVE-2026-137389](https://github.com/googlesky/CVE-2026-137389) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137389.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137389.svg)


## CVE-2026-137327
 GNU mtools through 4.0.50 contains a divide-by-zero vulnerability that allows attackers to crash mtools commands by supplying a FAT image with a zero sectors-per-cluster byte. Attackers can craft a FAT image that, when opened with mdir, minfo or mtype, triggers a SIGFPE in calc_num_clus() on x86, causing denial of service.

- [https://github.com/googlesky/CVE-2026-137327](https://github.com/googlesky/CVE-2026-137327) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137327.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137327.svg)


## CVE-2026-137309
 Friendica through 2026.05-1 contains an incorrect authorization vulnerability in item_edit() that allows authenticated local users to edit other authors' posts by submitting their own stored copy's post_id. Attackers can POST to /item to delete attachments and overwrite the shared body, title and content warning, which is shown under the original author's name.

- [https://github.com/googlesky/CVE-2026-137309](https://github.com/googlesky/CVE-2026-137309) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137309.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137309.svg)


## CVE-2026-137308
 markdownify-mcp before 1.2.0 contains a server-side request forgery vulnerability that allows attackers to bypass URL validation by supplying DNS names, bracketed IPv6 literals, or IPv4-mapped IPv6 addresses. Attackers can influence URLs passed to webpage-to-markdown or git-repo-to-markdown through prompt injection to fetch loopback services, internal hosts, and cloud metadata endpoints.

- [https://github.com/googlesky/CVE-2026-137308](https://github.com/googlesky/CVE-2026-137308) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137308.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137308.svg)


## CVE-2026-137307
 wpa_supplicant 2.7 through 2.12 with the wolfSSL backend contains an EAP-FAST server authentication bypass in tls_sess_sec_cb() that skips master secret derivation for oversized PAC-Opaque tickets. Adjacent attackers running a rogue authenticator can complete the handshake with an all-zero master secret to capture MS-CHAPv2 responses for offline cracking and replace the stored PAC.

- [https://github.com/googlesky/CVE-2026-137307](https://github.com/googlesky/CVE-2026-137307) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137307.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137307.svg)


## CVE-2026-137306
 Grav Admin plugin before 1.10.65 contains a password reset poisoning vulnerability in LoginController::taskForgot() that ignores the Require Trusted Host setting when building reset links. Unauthenticated attackers who know an administrator's username can submit the forgot-password form with a forged Host header, capturing the reset token when clicked to take over accounts.

- [https://github.com/googlesky/CVE-2026-137306](https://github.com/googlesky/CVE-2026-137306) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137306.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137306.svg)


## CVE-2026-137305
 Grav Form plugin before 9.2.4 contains a code injection vulnerability that allows page authors to write uploads into Twig template folders by setting an unchecked file field destination in Form::uploadFiles(). Attackers can upload .txt or .svg files containing Twig and have them rendered as trusted templates outside the sandbox, executing code as the web server user.

- [https://github.com/googlesky/CVE-2026-137305](https://github.com/googlesky/CVE-2026-137305) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137305.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137305.svg)


## CVE-2026-137080
 libical 4.0.0 before 4.0.7 contains an infinite loop vulnerability in icalrecur_iterator_set_range() that allows attackers to cause denial of service by supplying crafted recurrence rules. Attackers can provide a calendar whose recurrence rule is iterated over a reverse range, causing the loop to never terminate and spin the calling thread at full CPU indefinitely.

- [https://github.com/googlesky/CVE-2026-137080](https://github.com/googlesky/CVE-2026-137080) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137080.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137080.svg)


## CVE-2026-137070
 GEOS 3.13.0 before 3.15.1 contains an uncontrolled recursion vulnerability in RectangleContains::isContainedInBoundary that recurses indefinitely on curved geometries returned by getGeometryN. Attackers can supply crafted WKT or WKB CircularString, CompoundCurve, or CurvePolygon geometries tested via PreparedGeometry::contains or GEOSPreparedContains against a prepared rectangle to crash the process with a stack overflow.

- [https://github.com/googlesky/CVE-2026-137070](https://github.com/googlesky/CVE-2026-137070) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137070.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137070.svg)


## CVE-2026-137064
 Chatwoot before 4.20.0 contains a missing authentication vulnerability in the Bandwidth SMS webhook endpoint POST /webhooks/sms/:phone_number that allows unauthenticated attackers to submit forged SMS events. Attackers who know an inbox phone number can set the 'to' field to inject inbound messages with forged sender numbers or forge delivery status updates.

- [https://github.com/googlesky/CVE-2026-137064](https://github.com/googlesky/CVE-2026-137064) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137064.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137064.svg)


## CVE-2026-137062
 BookStack before 26.09.3 contains an incorrect authorization vulnerability that allows authenticated Editors to permanently delete recycle bin content by converting chapters to books or books to shelves. Attackers can trigger TrashCan::destroyEntity() through the conversion actions to force-delete soft-deleted children, revisions and attachments, including content deleted by other users, preventing restoration.

- [https://github.com/googlesky/CVE-2026-137062](https://github.com/googlesky/CVE-2026-137062) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137062.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137062.svg)


## CVE-2026-137057
 llama.cpp from b7118 before b12604 contains an integer underflow vulnerability in llama_grammar_parser::parse_sequence() that allows unauthenticated remote attackers to cause denial of service by supplying GBNF repetitions with max lower than min. Attackers can send a grammar like {5,2} in the grammar field of a llama-server /completion request, wrapping n_opt to generate endless repetition rules that hang the process and exhaust memory.

- [https://github.com/googlesky/CVE-2026-137057](https://github.com/googlesky/CVE-2026-137057) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137057.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137057.svg)


## CVE-2026-137043
 A security vulnerability has been detected in TOTOLINK N350RT 9.3.5u.6468_B20250827/9.3.5u.6466_B20250825. The affected element is the function setLanguageCfg of the file /cgi-bin/cstecgi.cgi. Such manipulation of the argument lang leads to authorization bypass. The attack can be executed remotely. The exploit has been disclosed publicly and may be used.

- [https://github.com/googlesky/CVE-2026-137043](https://github.com/googlesky/CVE-2026-137043) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137043.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137043.svg)


## CVE-2026-137036
 A flaw was found in bootc. On a sealed composefs boot, a failed bootc-root-setup.service does not fail initrd-root-fs.target, so the initramfs can switch root into the unverified physical root under the original signed UKI.

- [https://github.com/googlesky/CVE-2026-137036](https://github.com/googlesky/CVE-2026-137036) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137036.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137036.svg)


## CVE-2026-137035
 A flaw was found in bootc. On a sealed composefs boot with a strict composefs digest on the kernel command line, the initramfs derives fs-verity enforcement from unsigned repository metadata and can mount an image under images/refs without measuring it against that digest. An attacker with offline write access to the root filesystem can boot a modified root under a legitimately signed UKI.

- [https://github.com/googlesky/CVE-2026-137035](https://github.com/googlesky/CVE-2026-137035) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-137035.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-137035.svg)


## CVE-2026-136991
 A weakness has been identified in Spotweb up to 1.5.8. This issue affects the function redirect of the file lib/SpotTemplateHelper.php of the component Login. Executing a manipulation of the argument http_referer can lead to open redirect. It is possible to launch the attack remotely. The exploit has been made available to the public and could be used for attacks. This patch is called 0853d646d615225b35f466a960976d1492b786a9. Applying a patch is advised to resolve this issue.

- [https://github.com/googlesky/CVE-2026-136991](https://github.com/googlesky/CVE-2026-136991) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-136991.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-136991.svg)


## CVE-2026-136950
 A security vulnerability has been detected in Ghostty up to 1.3.1. The impacted element is an unknown function of the component macOS OSC 8 Hyperlink Handler. Such manipulation leads to injection. The attack can be launched remotely. Upgrading to version 1.4.0 is sufficient to resolve this issue. The name of the patch is 54fe8e188552977249a084db687e75aee6bf12e9. Upgrading the affected component is advised.

- [https://github.com/googlesky/CVE-2026-136950](https://github.com/googlesky/CVE-2026-136950) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-136950.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-136950.svg)


## CVE-2026-136716
 Improper Check for Unusual or Exceptional Conditions vulnerability in Drupal Drupal core allows Forceful Browsing. This issue affects Drupal core versions: from 0.0.0 to 10.6.23, from 11.0.0 to 11.3.23, from 11.4.0 to 11.4.14.

- [https://github.com/googlesky/CVE-2026-136716](https://github.com/googlesky/CVE-2026-136716) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-136716.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-136716.svg)


## CVE-2026-135797
 A vulnerability was identified in Volans NGFW Next-Generation Firewall r5.1. Impacted is the function exec of the file sslvpn/sslvpn_client.php of the component SSLVPN Client. Such manipulation of the argument img leads to os command injection. The attack can be executed remotely. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/D3crypT0r/CVE-2026-135797](https://github.com/D3crypT0r/CVE-2026-135797) :  ![starts](https://img.shields.io/github/stars/D3crypT0r/CVE-2026-135797.svg) ![forks](https://img.shields.io/github/forks/D3crypT0r/CVE-2026-135797.svg)


## CVE-2026-135690
 CivetWeb through 1.16 built with USE_HTTP2 and enable_http2 contains a heap out-of-bounds read vulnerability in hpack_decode() in src/http2.inl. Unauthenticated remote attackers can send a crafted HEADERS frame ending with a Huffman-coded string over TLS-negotiated HTTP/2 to read one byte past the heap frame buffer.

- [https://github.com/heilig-682/CVE-2026-135690](https://github.com/heilig-682/CVE-2026-135690) :  ![starts](https://img.shields.io/github/stars/heilig-682/CVE-2026-135690.svg) ![forks](https://img.shields.io/github/forks/heilig-682/CVE-2026-135690.svg)


## CVE-2026-134815
 simple-git before 4.1.0 contains an argument injection vulnerability that allows attackers to bypass the allowUnsafePack guard by supplying the --exec option to non-push git operations. Attackers who influence arguments passed to listRemote() or raw() can inject --exec for ls-remote, archive, fetch-pack or send-pack to execute commands on the host.

- [https://github.com/tc4dy/CVE-2026-134815-PoC-Exploit](https://github.com/tc4dy/CVE-2026-134815-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-134815-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-134815-PoC-Exploit.svg)


## CVE-2026-133968
 monailabel (aka MONAI Label) before 0.8.6 allows directory traversal, with resultant remote code execution, via the image parameter to the PUT /datastore/image endpoint, as exploited in the wild starting in September 2026.

- [https://github.com/evenomn/CVE-2026-133968](https://github.com/evenomn/CVE-2026-133968) :  ![starts](https://img.shields.io/github/stars/evenomn/CVE-2026-133968.svg) ![forks](https://img.shields.io/github/forks/evenomn/CVE-2026-133968.svg)


## CVE-2026-133525
 Deserialization of Untrusted Data vulnerability in ThemeFusion Fusion Builder fusion-builder allows Object Injection.This issue affects Fusion Builder: from n/a before 3.17.1.

- [https://github.com/googlesky/CVE-2026-133525](https://github.com/googlesky/CVE-2026-133525) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133525.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133525.svg)


## CVE-2026-133341
 Joomla Extension - vi-solutions - Missing SQL statement permission check in Maxsubmissions plugin in Visforms extension 1.0.0-5.6.5, 6.0.0-6.2.2 - The SQL statement permission was not enforced when saving, importing or batch copying forms with Maxsubmissions plugin settings, allowing backend users without this permission to store arbitrary SQL statements.

- [https://github.com/googlesky/CVE-2026-133341](https://github.com/googlesky/CVE-2026-133341) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133341.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133341.svg)


## CVE-2026-133340
 Joomla Extension - vi-solutions - Missing data export permission check in administrative form export in Visforms extension 1.0.0-5.6.5, 6.0.0-6.2.2 - The administrative form export did not check the data export permission when copying form data, allowing backend users without this permission to export submitted form data.

- [https://github.com/googlesky/CVE-2026-133340](https://github.com/googlesky/CVE-2026-133340) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133340.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133340.svg)


## CVE-2026-133339
 Joomla Extension - vi-solutions - SQL injection via form IDs in administrative form export in Visforms extension 1.0.0-5.6.5, 6.0.0-6.2.2 - Form IDs passed to the administrative form export were not cast to integers before being added to SQL queries, allowing SQL injection by backend users.

- [https://github.com/googlesky/CVE-2026-133339](https://github.com/googlesky/CVE-2026-133339) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133339.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133339.svg)


## CVE-2026-133338
 Joomla Extension - chronoengine.com - Unauthenticated stored XSS in DB Table cells in ChronoForms extension 8.0.0-8.0.53 - Values rendered in the cells of the DB Table widget are not escaped, allowing unauthenticated users to store JavaScript through form submissions that is executed when the listing is viewed. Fixed in 8.0.54.

- [https://github.com/googlesky/CVE-2026-133338](https://github.com/googlesky/CVE-2026-133338) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133338.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133338.svg)


## CVE-2026-133337
 Joomla Extension - chronoengine.com - Unauthenticated SQL injection in table sorting in ChronoForms extension 8.0.0-8.0.53 - The order_by request parameter used for sorting DB Table and Read Data listings is insufficiently sanitized before being added to the ORDER BY clause, allowing unauthenticated users to inject SQL expressions. Fixed in 8.0.54.

- [https://github.com/googlesky/CVE-2026-133337](https://github.com/googlesky/CVE-2026-133337) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133337.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133337.svg)


## CVE-2026-133336
 Joomla Extension - chronoengine.com - Unauthenticated arbitrary file upload in ChronoForms extension 8.0.0-8.0.53 - When the Filename Provider option of a file field is used, the file extension check is performed against the original client filename instead of the final stored filename, allowing unauthenticated users to upload files with dangerous extensions. Fixed in 8.0.54.

- [https://github.com/googlesky/CVE-2026-133336](https://github.com/googlesky/CVE-2026-133336) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133336.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133336.svg)


## CVE-2026-133323
 A vulnerability in the Audio, Web, and Video Conferencing (AWV) component of Mitel MiCollab through 10.3 (10.3.0.18) could allow an unauthenticated attacker to conduct a blind command injection attack due to insufficient parameter sanitization. A successful exploit could allow an attacker to execute arbitrary commands within the context of the system. This is MTLVULN-1864.

- [https://github.com/foxcornlab/mitel-micollab-scanner](https://github.com/foxcornlab/mitel-micollab-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/mitel-micollab-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/mitel-micollab-scanner.svg)


## CVE-2026-133211
 In Revive Adserver through 6.0.9, the ct0 request parameter of the delivery scripts is only required to start with http:// or https:// and is prepended unescaped to banner click URLs. An unauthenticated attacker can craft a delivery URL that executes JavaScript in the delivery origin when a visitor follows it. An active banner using the raw {clickurl} macro is required.

- [https://github.com/googlesky/CVE-2026-133211](https://github.com/googlesky/CVE-2026-133211) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133211.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133211.svg)


## CVE-2026-133210
 In Revive Adserver through 6.0.9, the zone banner-linking page (zone-include.php) does not cast the keys of the includebanner request array to integers. An authenticated manager, or a trafficker with the zone-linking permission, who owns the submitted website and zone can place SQL in an array key, which is concatenated unquoted into the banner-lookup query, resulting in time-based blind SQL injection bounded by the privileges of the application's database account.

- [https://github.com/googlesky/CVE-2026-133210](https://github.com/googlesky/CVE-2026-133210) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133210.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133210.svg)


## CVE-2026-133209
 In Revive Adserver through 6.0.9, deleting an agency, advertiser, or publisher through affected API paths can leave the associated account and user session active because the deletion path does not load the entity's account identifier before cleanup. A user whose entity has been deleted can continue accessing pages of the orphaned account. Access to data belonging to another agency was not demonstrated.

- [https://github.com/googlesky/CVE-2026-133209](https://github.com/googlesky/CVE-2026-133209) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133209.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133209.svg)


## CVE-2026-133208
 In Revive Adserver through 6.0.9, unauthenticated request parameters in ad delivery can cause reflected cross-site scripting. A crafted delivery URL places a macro token in the source or target parameter and malicious markup in the referer parameter. Macro replacement after initial input encoding can insert the unescaped markup into generated banner output, causing JavaScript execution in the delivery origin when a visitor follows the URL. An active banner is required.

- [https://github.com/googlesky/CVE-2026-133208](https://github.com/googlesky/CVE-2026-133208) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133208.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133208.svg)


## CVE-2026-133207
 In Revive Adserver through 6.0.9, user-controlled entity names in XLS report exports can be interpreted as spreadsheet formulas. A user with permission to rename a zone can place a formula in the zone name, which is then included in another user's Conversion Tracking report. Opening the affected spreadsheet can evaluate the formula and alter displayed report contents.

- [https://github.com/googlesky/CVE-2026-133207](https://github.com/googlesky/CVE-2026-133207) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133207.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133207.svg)


## CVE-2026-133206
 In Revive Adserver through 6.0.9, an advertiser can put XML syntax in fields of its own video creative. Unescaped MediaFile attributes and CDATA terminators allow the advertiser to inject elements into VAST responses served for a publisher's zone. A crafted TrackingEvents block can suppress the ad server's video playback event records and redirect tracking requests to an attacker-controlled endpoint.

- [https://github.com/googlesky/CVE-2026-133206](https://github.com/googlesky/CVE-2026-133206) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133206.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133206.svg)


## CVE-2026-133205
 In Revive Adserver through 6.0.9, an authenticated manager can supply another agency's advertiser or website identifier as a report scope and obtain that entity's name in an XLS report header. Submitted scope identifiers are not checked against the manager's permitted selections. The demonstrated disclosure is limited to entity names.

- [https://github.com/googlesky/CVE-2026-133205](https://github.com/googlesky/CVE-2026-133205) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133205.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133205.svg)


## CVE-2026-133204
 In Revive Adserver through 6.0.9, the zone-linking page can disclose campaign and banner names and identifiers belonging to another agency. An authenticated manager, or a website user with permission to link banners to zones, can supply another agency's advertiser and campaign identifiers because the selection lists are not restricted to the agency owning the zone.

- [https://github.com/googlesky/CVE-2026-133204](https://github.com/googlesky/CVE-2026-133204) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133204.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133204.svg)


## CVE-2026-133203
 In Revive Adserver through 6.0.9, the public conversion-variable endpoint does not verify that a caller-supplied conversion belongs to the supplied tracker. An unauthenticated attacker can submit a unique variable for a different tracker's conversion, causing that conversion to be classified as a duplicate and excluded from conversion reports.

- [https://github.com/googlesky/CVE-2026-133203](https://github.com/googlesky/CVE-2026-133203) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133203.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133203.svg)


## CVE-2026-133202
 In Revive Adserver through 6.0.9, an authenticated manager with access to two advertisers can associate a conversion tracker owned by one advertiser with a campaign owned by the other. The tracker-campaign page checks access to each object but does not verify that their actual owners match. The resulting association can expose the first advertiser's tracker name and identifier in the second advertiser's restricted conversion report.

- [https://github.com/googlesky/CVE-2026-133202](https://github.com/googlesky/CVE-2026-133202) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133202.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133202.svg)


## CVE-2026-132165
 Missing Authentication for Critical Function vulnerability in Drupal Drupal core allows Exploiting Incorrectly Configured Access Control Security Levels. This issue affects Drupal core versions: from 0.0.0 to 10.6.22, from 11.0.0 to 11.3.22, from 11.4.0 to 11.4.13.

- [https://github.com/abraxas/drupal-install-takeover](https://github.com/abraxas/drupal-install-takeover) :  ![starts](https://img.shields.io/github/stars/abraxas/drupal-install-takeover.svg) ![forks](https://img.shields.io/github/forks/abraxas/drupal-install-takeover.svg)
- [https://github.com/lxdwnpiper/CVE-2026-132165-Drupal](https://github.com/lxdwnpiper/CVE-2026-132165-Drupal) :  ![starts](https://img.shields.io/github/stars/lxdwnpiper/CVE-2026-132165-Drupal.svg) ![forks](https://img.shields.io/github/forks/lxdwnpiper/CVE-2026-132165-Drupal.svg)
- [https://github.com/ashrafzaryouh/CVE-2026-132165](https://github.com/ashrafzaryouh/CVE-2026-132165) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-132165.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-132165.svg)
- [https://github.com/googlesky/CVE-2026-132165](https://github.com/googlesky/CVE-2026-132165) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-132165.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-132165.svg)
- [https://github.com/malloryai/cve-2026-132165-drupal-installer-check](https://github.com/malloryai/cve-2026-132165-drupal-installer-check) :  ![starts](https://img.shields.io/github/stars/malloryai/cve-2026-132165-drupal-installer-check.svg) ![forks](https://img.shields.io/github/forks/malloryai/cve-2026-132165-drupal-installer-check.svg)
- [https://github.com/foxcornlab/drupal-installer-scanner](https://github.com/foxcornlab/drupal-installer-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/drupal-installer-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/drupal-installer-scanner.svg)


## CVE-2026-131916
 GENAI Web provided by Digital Agency contains a server-side request forgery (SSRF) vulnerability. An attacker may be able to obtain information about which ports are open on devices located on the same network as the affected product.

- [https://github.com/googlesky/CVE-2026-131916](https://github.com/googlesky/CVE-2026-131916) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-131916.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-131916.svg)


## CVE-2026-129991
 Dokploy is a free, self-hostable Platform as a Service (PaaS). Prior to 0.31.1, the backup prefix field is only checked for a nonempty value, and normalizeS3Path preserves shell metacharacters before the prefix is interpolated into rclone upload and retention-cleanup command strings. An authenticated organization member with backup permission for a service can execute arbitrary commands as root on the Dokploy host or configured remote server when a PostgreSQL, MySQL, MariaDB, MongoDB, libSQL, Compose, or web-server backup runs manually, on schedule, or performs retention cleanup. This issue is fixed in version 0.31.1.

- [https://github.com/The-G0lden/CVE-2026-129991-dokploy](https://github.com/The-G0lden/CVE-2026-129991-dokploy) :  ![starts](https://img.shields.io/github/stars/The-G0lden/CVE-2026-129991-dokploy.svg) ![forks](https://img.shields.io/github/forks/The-G0lden/CVE-2026-129991-dokploy.svg)


## CVE-2026-129496
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/ys0816/php56-php2shell-rpm](https://github.com/ys0816/php56-php2shell-rpm) :  ![starts](https://img.shields.io/github/stars/ys0816/php56-php2shell-rpm.svg) ![forks](https://img.shields.io/github/forks/ys0816/php56-php2shell-rpm.svg)


## CVE-2026-129481
This issue affects PHP versions 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/googlesky/CVE-2026-129481](https://github.com/googlesky/CVE-2026-129481) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129481.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129481.svg)


## CVE-2026-129474
This issue affects PHP versions 8.5.* before 8.5.13.

- [https://github.com/googlesky/CVE-2026-129474](https://github.com/googlesky/CVE-2026-129474) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129474.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129474.svg)


## CVE-2026-129291
This issue affects PHP versions from 8.1.20 through 8.1.34, from 8.2.7 before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/googlesky/CVE-2026-129291](https://github.com/googlesky/CVE-2026-129291) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129291.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129291.svg)


## CVE-2026-129289
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/googlesky/CVE-2026-129289](https://github.com/googlesky/CVE-2026-129289) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129289.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129289.svg)
- [https://github.com/ys0816/php56-php2shell-rpm](https://github.com/ys0816/php56-php2shell-rpm) :  ![starts](https://img.shields.io/github/stars/ys0816/php56-php2shell-rpm.svg) ![forks](https://img.shields.io/github/forks/ys0816/php56-php2shell-rpm.svg)


## CVE-2026-129182
This issue affects PHP versions 8.5.* before 8.5.13.

- [https://github.com/googlesky/CVE-2026-129182](https://github.com/googlesky/CVE-2026-129182) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129182.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129182.svg)


## CVE-2026-128064
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/wild0ni0n/CVE-2026-128064-PoC](https://github.com/wild0ni0n/CVE-2026-128064-PoC) :  ![starts](https://img.shields.io/github/stars/wild0ni0n/CVE-2026-128064-PoC.svg) ![forks](https://img.shields.io/github/forks/wild0ni0n/CVE-2026-128064-PoC.svg)
- [https://github.com/googlesky/CVE-2026-128064](https://github.com/googlesky/CVE-2026-128064) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-128064.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-128064.svg)
- [https://github.com/ys0816/php56-php2shell-rpm](https://github.com/ys0816/php56-php2shell-rpm) :  ![starts](https://img.shields.io/github/stars/ys0816/php56-php2shell-rpm.svg) ![forks](https://img.shields.io/github/forks/ys0816/php56-php2shell-rpm.svg)


## CVE-2026-126747
 Missing Authorization vulnerability in Drupal File Resumable Upload allows Forceful Browsing. This issue affects File Resumable Upload versions: from 0.0.0 to 2.0.6.

- [https://github.com/googlesky/CVE-2026-126747](https://github.com/googlesky/CVE-2026-126747) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126747.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126747.svg)


## CVE-2026-126746
 Incorrect Authorization vulnerability in Drupal S3 File System CORS Upload allows Forceful Browsing. This issue affects S3 File System CORS Upload versions: from 0.0.0 to 1.4.0.

- [https://github.com/googlesky/CVE-2026-126746](https://github.com/googlesky/CVE-2026-126746) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126746.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126746.svg)


## CVE-2026-126745
 Improper Neutralization of Special Elements Used in a Template Engine vulnerability in Drupal Real Name allows Code Injection. This issue affects Real Name versions: from 0.0.0 to 2.0.1.

- [https://github.com/googlesky/CVE-2026-126745](https://github.com/googlesky/CVE-2026-126745) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126745.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126745.svg)


## CVE-2026-126744
 Improper Neutralization of Input During Web Page Generation ("Cross-site Scripting") vulnerability in Drupal Layout Builder iFrame Modal allows Cross-Site Scripting (XSS). This issue affects Layout Builder iFrame Modal versions: from 0.0.0 to 1.3.9.

- [https://github.com/googlesky/CVE-2026-126744](https://github.com/googlesky/CVE-2026-126744) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126744.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126744.svg)


## CVE-2026-126742
 Incorrect Authorization vulnerability in Drupal Commerce sermepa allows Forceful Browsing. This issue affects Commerce sermepa versions: from 0.0.0 to 2.5.0.

- [https://github.com/googlesky/CVE-2026-126742](https://github.com/googlesky/CVE-2026-126742) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126742.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126742.svg)


## CVE-2026-126740
 Missing Authorization vulnerability in Drupal Download Count allows Forceful Browsing. This issue affects Download Count versions: from 0.0.0 to 2.2.5, from 3.0.0 to 3.0.2.

- [https://github.com/googlesky/CVE-2026-126740](https://github.com/googlesky/CVE-2026-126740) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126740.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126740.svg)


## CVE-2026-126739
 Cross-Site Request Forgery (CSRF) vulnerability in Drupal Page Manager allows Cross Site Request Forgery. This issue affects Page Manager versions: from 0.0.0 to 4.1.0.

- [https://github.com/googlesky/CVE-2026-126739](https://github.com/googlesky/CVE-2026-126739) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126739.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126739.svg)


## CVE-2026-126738
 Insertion of Sensitive Information Into Sent Data vulnerability in Drupal Mollie for Drupal allows Forceful Browsing. This issue affects Mollie for Drupal versions: from 0.0.0 to 2.3.2.

- [https://github.com/googlesky/CVE-2026-126738](https://github.com/googlesky/CVE-2026-126738) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126738.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126738.svg)


## CVE-2026-126737
 Incorrect Authorization vulnerability in Drupal Mollie for Drupal allows Forceful Browsing. This issue affects Mollie for Drupal versions: from 0.0.0 to 2.3.2.

- [https://github.com/googlesky/CVE-2026-126737](https://github.com/googlesky/CVE-2026-126737) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126737.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126737.svg)


## CVE-2026-126736
 Insertion of Sensitive Information Into Sent Data vulnerability in Drupal Entity Print allows Forceful Browsing. This issue affects Entity Print versions: from 0.0.0 to 2.20.0.

- [https://github.com/googlesky/CVE-2026-126736](https://github.com/googlesky/CVE-2026-126736) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126736.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126736.svg)


## CVE-2026-126735
 Cross-Site Request Forgery (CSRF) vulnerability in Drupal Campaign Monitor allows Cross Site Request Forgery. This issue affects Campaign Monitor versions: from 0.0.0 to 3.0.3.

- [https://github.com/googlesky/CVE-2026-126735](https://github.com/googlesky/CVE-2026-126735) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126735.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126735.svg)


## CVE-2026-126733
 Incorrect Authorization vulnerability in Drupal Commerce License allows Forceful Browsing. This issue affects Commerce License versions: from 0.0.0 to 3.1.2.

- [https://github.com/googlesky/CVE-2026-126733](https://github.com/googlesky/CVE-2026-126733) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126733.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126733.svg)


## CVE-2026-126732
 Incorrect Authorization vulnerability in Drupal Commerce License allows Forceful Browsing. This issue affects Commerce License versions: from 0.0.0 to 3.1.2.

- [https://github.com/googlesky/CVE-2026-126732](https://github.com/googlesky/CVE-2026-126732) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126732.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126732.svg)


## CVE-2026-126731
 Authentication Bypass Using an Alternate Path or Channel vulnerability in Drupal Authenticator Login Plus (2FA) allows Authentication Bypass. This issue affects Authenticator Login Plus (2FA) versions: from 0.0.0 to 1.0.3.

- [https://github.com/googlesky/CVE-2026-126731](https://github.com/googlesky/CVE-2026-126731) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126731.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126731.svg)


## CVE-2026-126730
 Authentication Bypass Using an Alternate Path or Channel vulnerability in Drupal Authenticator Login Plus (2FA) allows Authentication Bypass. This issue affects Authenticator Login Plus (2FA) versions: from 0.0.0 to 1.0.3.

- [https://github.com/googlesky/CVE-2026-126730](https://github.com/googlesky/CVE-2026-126730) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126730.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126730.svg)


## CVE-2026-126729
 Authentication Bypass Using an Alternate Path or Channel vulnerability in Drupal Authenticator Login Plus (2FA) allows Authentication Bypass. This issue affects Authenticator Login Plus (2FA) versions: from 0.0.0 to 1.0.3.

- [https://github.com/googlesky/CVE-2026-126729](https://github.com/googlesky/CVE-2026-126729) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126729.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126729.svg)


## CVE-2026-126728
 Cross-Site Request Forgery (CSRF) vulnerability in Drupal Texts: key-based strings and translations allows Cross Site Request Forgery. This issue affects Texts: key-based strings and translations versions: from 1.0.13 to 1.0.17.

- [https://github.com/googlesky/CVE-2026-126728](https://github.com/googlesky/CVE-2026-126728) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126728.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126728.svg)


## CVE-2026-126726
 Missing Authorization vulnerability in Drupal Paragraphs Edit allows Forceful Browsing. This issue affects Paragraphs Edit versions: from 0.0.0 to 3.0.2.

- [https://github.com/googlesky/CVE-2026-126726](https://github.com/googlesky/CVE-2026-126726) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126726.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126726.svg)


## CVE-2026-126725
 Incorrect Authorization vulnerability in Drupal GraphQL Core Schema allows Forceful Browsing. This issue affects GraphQL Core Schema versions: from 0.0.0 to 1.0.29.

- [https://github.com/googlesky/CVE-2026-126725](https://github.com/googlesky/CVE-2026-126725) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126725.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126725.svg)


## CVE-2026-126714
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/ys0816/php56-php2shell-rpm](https://github.com/ys0816/php56-php2shell-rpm) :  ![starts](https://img.shields.io/github/stars/ys0816/php56-php2shell-rpm.svg) ![forks](https://img.shields.io/github/forks/ys0816/php56-php2shell-rpm.svg)


## CVE-2026-125180
 FFmpeg 8.1 through 9.0.2 contains a memory exhaustion vulnerability in the libavcodec/exif.c parser that allows attackers to amplify allocations by pointing many IFD entries at overlapping payloads. Attackers can embed a small crafted EXIF block in TIFF, JPEG, PNG or WebP images to trigger quadratic memory allocation, causing denial of service in decoding applications.

- [https://github.com/XChen446/cve-2026-125180-demo](https://github.com/XChen446/cve-2026-125180-demo) :  ![starts](https://img.shields.io/github/stars/XChen446/cve-2026-125180-demo.svg) ![forks](https://img.shields.io/github/forks/XChen446/cve-2026-125180-demo.svg)


## CVE-2026-123903
VMware Telco Cloud Infrastructure 3.0: fixed in KB463501

- [https://github.com/dinosn/CVE-2026-123903](https://github.com/dinosn/CVE-2026-123903) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-123903.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-123903.svg)
- [https://github.com/Hann1bl3L3ct3r/CVE-2026-123903](https://github.com/Hann1bl3L3ct3r/CVE-2026-123903) :  ![starts](https://img.shields.io/github/stars/Hann1bl3L3ct3r/CVE-2026-123903.svg) ![forks](https://img.shields.io/github/forks/Hann1bl3L3ct3r/CVE-2026-123903.svg)


## CVE-2026-123633
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/googlesky/CVE-2026-123633](https://github.com/googlesky/CVE-2026-123633) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-123633.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-123633.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/iotsec-in/sshole-cve-2026-123158](https://github.com/iotsec-in/sshole-cve-2026-123158) :  ![starts](https://img.shields.io/github/stars/iotsec-in/sshole-cve-2026-123158.svg) ![forks](https://img.shields.io/github/forks/iotsec-in/sshole-cve-2026-123158.svg)
- [https://github.com/asvorg/CVE-2026-123158-SSHole-poc](https://github.com/asvorg/CVE-2026-123158-SSHole-poc) :  ![starts](https://img.shields.io/github/stars/asvorg/CVE-2026-123158-SSHole-poc.svg) ![forks](https://img.shields.io/github/forks/asvorg/CVE-2026-123158-SSHole-poc.svg)


## CVE-2026-123007
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/googlesky/CVE-2026-123007](https://github.com/googlesky/CVE-2026-123007) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-123007.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-123007.svg)


## CVE-2026-122083
 Privilege Defined With Unsafe Actions vulnerability in Drupal AdobeAnalytics allows Stored XSS. This issue affects AdobeAnalytics versions: from 0.0.0 to 1.1.0.

- [https://github.com/googlesky/CVE-2026-122083](https://github.com/googlesky/CVE-2026-122083) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122083.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122083.svg)


## CVE-2026-122082
 Insertion of Sensitive Information Into Sent Data vulnerability in Drupal Mime Mail allows Forceful Browsing. This issue affects Mime Mail versions: from 0.0.0 to 2.0.4.

- [https://github.com/googlesky/CVE-2026-122082](https://github.com/googlesky/CVE-2026-122082) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122082.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122082.svg)


## CVE-2026-122081
 Incorrect Authorization vulnerability in Drupal Islandora  allows Forceful Browsing. This issue affects Islandora  versions: from 0.0.0 to 2.19.1.

- [https://github.com/googlesky/CVE-2026-122081](https://github.com/googlesky/CVE-2026-122081) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122081.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122081.svg)


## CVE-2026-122077
 Incorrect Authorization vulnerability in Drupal Allowed Languages allows Forceful Browsing. This issue affects Allowed Languages versions: from 0.0.0 to 2.0.3.

- [https://github.com/googlesky/CVE-2026-122077](https://github.com/googlesky/CVE-2026-122077) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122077.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122077.svg)


## CVE-2026-122076
 Unverified Password Change vulnerability in Drupal Password Separate Form allows Functionality Bypass. This issue affects Password Separate Form versions: from 0.0.0 to 2.0.3.

- [https://github.com/googlesky/CVE-2026-122076](https://github.com/googlesky/CVE-2026-122076) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122076.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122076.svg)


## CVE-2026-122075
 Incorrect Authorization vulnerability in Drupal Scheduler allows Forceful Browsing. This issue affects Scheduler versions: from 0.0.0 to 1.7.0, from 2.2.0 to 2.2.3, from 0.0.0 to 2.0.*, from 0.0.0 to 2.1.*, from 2.3.0 to 2.3.1.

- [https://github.com/googlesky/CVE-2026-122075](https://github.com/googlesky/CVE-2026-122075) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122075.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122075.svg)


## CVE-2026-122074
 Incorrect Authorization vulnerability in Drupal Reset Password Email/SMS OTP allows Forceful Browsing. This issue affects Reset Password Email/SMS OTP versions: from 0.0.0 to 1.0.5.

- [https://github.com/googlesky/CVE-2026-122074](https://github.com/googlesky/CVE-2026-122074) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122074.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122074.svg)


## CVE-2026-122072
 Incorrect Authorization vulnerability in Drupal Forum Access allows Forceful Browsing. This issue affects Forum Access versions: from 0.0.0 to 2.0.3.

- [https://github.com/googlesky/CVE-2026-122072](https://github.com/googlesky/CVE-2026-122072) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122072.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122072.svg)


## CVE-2026-122071
 Improper Verification of Cryptographic Signature vulnerability in Drupal Commerce Escrow allows Signature Spoof. This issue affects Commerce Escrow versions: from 0.0.0 to 1.1.0.

- [https://github.com/googlesky/CVE-2026-122071](https://github.com/googlesky/CVE-2026-122071) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122071.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122071.svg)


## CVE-2026-122070
 Missing Authorization vulnerability in Drupal Commerce Product Alternative allows Forceful Browsing. This issue affects Commerce Product Alternative versions: from 0.0.0 to 1.0.1.

- [https://github.com/googlesky/CVE-2026-122070](https://github.com/googlesky/CVE-2026-122070) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122070.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122070.svg)


## CVE-2026-122069
 Improper Verification of Cryptographic Signature vulnerability in Drupal AlternativeCommerce PayPal Checkout allows Signature Spoof. This issue affects AlternativeCommerce PayPal Checkout versions: from 0.0.0 to 1.1.1.

- [https://github.com/googlesky/CVE-2026-122069](https://github.com/googlesky/CVE-2026-122069) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122069.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122069.svg)


## CVE-2026-122067
 Authentication Bypass Using an Alternate Path or Channel vulnerability in Drupal REST & JSON API Authentication for Drupal allows Authentication Bypass. This issue affects REST & JSON API Authentication for Drupal versions: from 0.0.0 to 3.2.1.

- [https://github.com/googlesky/CVE-2026-122067](https://github.com/googlesky/CVE-2026-122067) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122067.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122067.svg)


## CVE-2026-122066
 Missing Authorization vulnerability in Drupal Workflow Notifications allows Forceful Browsing. This issue affects Workflow Notifications versions: from 0.0.0 to 3.0.3.

- [https://github.com/googlesky/CVE-2026-122066](https://github.com/googlesky/CVE-2026-122066) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122066.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122066.svg)


## CVE-2026-122058
 Incorrect Authorization vulnerability in Drupal Simple OAuth (OAuth2) & OpenID Connect allows Forceful Browsing. This issue affects Simple OAuth (OAuth2) & OpenID Connect versions: from 0.0.0 to 5.2.6, from 6.0.0 to 6.0.10, from 6.1.0 to 6.1.4.

- [https://github.com/googlesky/CVE-2026-122058](https://github.com/googlesky/CVE-2026-122058) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122058.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122058.svg)


## CVE-2026-122057
 Missing Authorization vulnerability in Drupal S3 File System CORS Upload allows Forceful Browsing. This issue affects S3 File System CORS Upload versions: from 0.0.0 to 1.3.0.

- [https://github.com/googlesky/CVE-2026-122057](https://github.com/googlesky/CVE-2026-122057) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-122057.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-122057.svg)


## CVE-2026-119977
 WordPress Core is vulnerable to Remote Code Execution in versions 4.7 through 7.1.3. This is due to predictable, web-accessible staging paths used during full-package core upgrades. This makes it possible for unauthenticated attackers to execute code on the server during the upgrade window.

- [https://github.com/googlesky/CVE-2026-119977](https://github.com/googlesky/CVE-2026-119977) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-119977.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-119977.svg)


## CVE-2026-118547
 Deserialization of Untrusted Data vulnerability in Drupal Content Synchronizer allows Object Injection. This issue affects Content Synchronizer versions: from 0.0.0 to 4.1.1.

- [https://github.com/googlesky/CVE-2026-118547](https://github.com/googlesky/CVE-2026-118547) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-118547.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-118547.svg)


## CVE-2026-115560
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/ys0816/php56-php2shell-rpm](https://github.com/ys0816/php56-php2shell-rpm) :  ![starts](https://img.shields.io/github/stars/ys0816/php56-php2shell-rpm.svg) ![forks](https://img.shields.io/github/forks/ys0816/php56-php2shell-rpm.svg)


## CVE-2026-112326
 GitLab has remediated an issue in GitLab EE affecting all versions from 17.8 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, could have allowed an authenticated user with read-only permissions to permanently delete existing vulnerability records due to improper cleanup logic that failed to distinguish between pre-existing records from newly created ones during error handling.

- [https://github.com/googlesky/CVE-2026-112326](https://github.com/googlesky/CVE-2026-112326) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-112326.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-112326.svg)


## CVE-2026-112212
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.3 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, an unauthenticated user could have poisoned a shared cache's OAuth/OIDC discovery document to redirect certain flows to an externally controlled server, due to improper trust of user-supplied values when constructing endpoint URLs in cached discovery responses.

- [https://github.com/googlesky/CVE-2026-112212](https://github.com/googlesky/CVE-2026-112212) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-112212.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-112212.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/OrnisLab/2shell-advisories](https://github.com/OrnisLab/2shell-advisories) :  ![starts](https://img.shields.io/github/stars/OrnisLab/2shell-advisories.svg) ![forks](https://img.shields.io/github/forks/OrnisLab/2shell-advisories.svg)
- [https://github.com/eduxcode/node2shell-lab](https://github.com/eduxcode/node2shell-lab) :  ![starts](https://img.shields.io/github/stars/eduxcode/node2shell-lab.svg) ![forks](https://img.shields.io/github/forks/eduxcode/node2shell-lab.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/ihsansencan/Php2Shell-Lab](https://github.com/ihsansencan/Php2Shell-Lab) :  ![starts](https://img.shields.io/github/stars/ihsansencan/Php2Shell-Lab.svg) ![forks](https://img.shields.io/github/forks/ihsansencan/Php2Shell-Lab.svg)


## CVE-2026-105777
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 17.6.5 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, an unauthenticated user could have retrieved sensitive internal server credentials due to improper filtering of internal response headers.

- [https://github.com/googlesky/CVE-2026-105777](https://github.com/googlesky/CVE-2026-105777) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-105777.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-105777.svg)


## CVE-2026-103383
 In Eclipse MWE = 2.27.0 if you debug mwe workflows a remote attacker can cause arbitrary classes with an zero arg constructor from your mwe classpath to be instantiated in a timed attack

- [https://github.com/googlesky/CVE-2026-103383](https://github.com/googlesky/CVE-2026-103383) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-103383.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-103383.svg)


## CVE-2026-99567
down to the collapse and inserts one more key.

- [https://github.com/Rat5ak/CVE-2026-99567-ASSOC_ARRAY_SHORTCUT-CHAIN-EoP](https://github.com/Rat5ak/CVE-2026-99567-ASSOC_ARRAY_SHORTCUT-CHAIN-EoP) :  ![starts](https://img.shields.io/github/stars/Rat5ak/CVE-2026-99567-ASSOC_ARRAY_SHORTCUT-CHAIN-EoP.svg) ![forks](https://img.shields.io/github/forks/Rat5ak/CVE-2026-99567-ASSOC_ARRAY_SHORTCUT-CHAIN-EoP.svg)


## CVE-2026-99362
an error returned from SEQUENCE.

- [https://github.com/ashrafzaryouh/CVE-2026-99362](https://github.com/ashrafzaryouh/CVE-2026-99362) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-99362.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-99362.svg)


## CVE-2026-99233
file-event_call before adjusting se-ref.

- [https://github.com/Aoki-Shinshi/CVE-2026-99233](https://github.com/Aoki-Shinshi/CVE-2026-99233) :  ![starts](https://img.shields.io/github/stars/Aoki-Shinshi/CVE-2026-99233.svg) ![forks](https://img.shields.io/github/forks/Aoki-Shinshi/CVE-2026-99233.svg)


## CVE-2026-88765
 GitLab has remediated an issue in GitLab EE affecting all versions from 12.3 to 19.1.8, 19.2 before 19.2.6, and 19.3 before 19.3.2 under certain conditions could allow an authenticated user to achieve remote code execution by importing a specially crafted Git project export to overflow the Unicode conversion buffer used in Advanced Search indexing.

- [https://github.com/googlesky/CVE-2026-88765](https://github.com/googlesky/CVE-2026-88765) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-88765.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-88765.svg)


## CVE-2026-87719
 GitLab has remediated an issue in GitLab EE affecting all versions from 18.3 before 18.11.12, 19.0 before 19.0.9, 19.1 before 19.1.8, 19.2 before 19.2.6, and 19.3 before 19.3.2 that under certain conditions could allow an authenticated user with Duo Chat access to obtain Advanced Search instance configurations and sensitive credentials using a specially crafted GraphQL subscription argument to bypass serialization and perform server object lookup.

- [https://github.com/googlesky/CVE-2026-87719](https://github.com/googlesky/CVE-2026-87719) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-87719.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-87719.svg)


## CVE-2026-81418
 Nmap before 7.992 contains an uncontrolled resource consumption vulnerability in the TLV.AUTH parser of the NSE eigrp.lua library, whose length arithmetic cancels out the running read position. An attacker on the same layer 2 segment can send a single crafted EIGRP Update of roughly 36 bytes over unauthenticated multicast, causing unbounded table growth that exhausts the memory of the Nmap process when broadcast-eigrp-discovery.nse is running.

- [https://github.com/googlesky/CVE-2026-81418](https://github.com/googlesky/CVE-2026-81418) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-81418.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-81418.svg)


## CVE-2026-81417
 Nmap before 7.992 contains an infinite loop vulnerability in the dispatcher of the NSE tftp.lua library, which removes completed coroutines but not ones that ended in an error, leaving a zero-yield spin. A malicious TFTP exchange reached by snmp-ios-config.nse after an SNMP write sequence can leave a dead coroutine that freezes the entire Nmap invocation, before port scanning begins for any target in the run; the hang is prevented when the script-timeout option is set.

- [https://github.com/googlesky/CVE-2026-81417](https://github.com/googlesky/CVE-2026-81417) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-81417.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-81417.svg)


## CVE-2026-81416
 Nmap before 7.992 contains an infinite loop vulnerability in the process_write function of the NSE tn3270.lua library, whose write loop does not advance when it processes a malformed Repeat to Address (RA) order. A malicious TN3270 server on a scanned host can embed a single 6-byte malformed RA order in an ordinary screen-write data stream after a normal negotiation, causing a permanent 100% CPU hang of the Nmap process when tn3270-screen.nse runs, which the script-timeout option does not interrupt.

- [https://github.com/googlesky/CVE-2026-81416](https://github.com/googlesky/CVE-2026-81416) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-81416.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-81416.svg)


## CVE-2026-78252
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 15.3 before 19.1.8, 19.2 before 19.2.6, and 19.3 before 19.3.2 that, under certain conditions, an authenticated user could have induced a targeted user to perform unintended state-changing HTTP requests due to improper sanitization of user-controlled data in the Markdown JSON table renderer.

- [https://github.com/googlesky/CVE-2026-78252](https://github.com/googlesky/CVE-2026-78252) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-78252.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-78252.svg)


## CVE-2026-77806
 SPIP before 4.4.21 allows unauthenticated remote attackers to execute arbitrary code, as exploited in the wild in August 2026. This is related to code injection via an X-Spip-Filtre HTTP request header that is mishandled by analyse_resultat_skel.

- [https://github.com/NiteeshPujari/cve-2026-77806-spip-x-spip-filtre-rce](https://github.com/NiteeshPujari/cve-2026-77806-spip-x-spip-filtre-rce) :  ![starts](https://img.shields.io/github/stars/NiteeshPujari/cve-2026-77806-spip-x-spip-filtre-rce.svg) ![forks](https://img.shields.io/github/forks/NiteeshPujari/cve-2026-77806-spip-x-spip-filtre-rce.svg)


## CVE-2026-76904
 GeoTools is an open source Java library that provides tools for geospatial data. Starting in version 30.5 and prior to versions 33.6, 34.5, and 33.6, an SQL Injection Vulnerability is present when executing OGC Filters with PostGIS DataStore implementation: `jsonArrayContains` function; Requires PostGIS 12 or greater with a String or JSON field. For PostGIS 12 and greater `jsonArrayContains(column, pointer, value)` function writes `value` into generated SQL without escaping. Patches are available in versions 33.6, 34.5, and 33.6. No known workaround is available. To limit scope of SQL Injection the PostGIS connection pool should be configured with limited rights.

- [https://github.com/himfatihoner/CVE-2026-76904](https://github.com/himfatihoner/CVE-2026-76904) :  ![starts](https://img.shields.io/github/stars/himfatihoner/CVE-2026-76904.svg) ![forks](https://img.shields.io/github/forks/himfatihoner/CVE-2026-76904.svg)


## CVE-2026-65106
 NVIDIA Transformer Engine for Linux contains a vulnerability where a user could cause deserialization by loading  untrusted data. A successful exploit of this vulnerability might lead to code execution, information disclosure, and denial of service.

- [https://github.com/alert-k/checkpoint-deser-rules](https://github.com/alert-k/checkpoint-deser-rules) :  ![starts](https://img.shields.io/github/stars/alert-k/checkpoint-deser-rules.svg) ![forks](https://img.shields.io/github/forks/alert-k/checkpoint-deser-rules.svg)


## CVE-2026-61725
 sevenz-rust2 is a Rust-native 7z compressor and `decompress`or. Prior to 0.21.1, extracting an attacker-supplied 7z archive can write or overwrite files outside the destination directory. In `src/util/decompress.rs`, `decompress_impl` computes each destination with `dest.join(entry.name())` without normalizing the archive's UTF-16 entry name or verifying containment, and `default_entry_extract_fn` writes to it with `File::create`. Parent-directory components escape the extraction root, and an absolute entry path makes the join discard the destination entirely. The convenience entry points `decompress`, `decompress_file`, `decompress_with_password`, and `decompress_file_with_password` all use this default path. Overwriting writable configuration, startup, cron, or build files can lead to code execution or persistence. The archive bytes are the attacker-controlled trust boundary, including for applications that automatically unpack uploaded or otherwise untrusted archives. This issue is fixed in version 0.21.1.

- [https://github.com/pluto-chou/CVE-2026-61725_sevenz-rust2](https://github.com/pluto-chou/CVE-2026-61725_sevenz-rust2) :  ![starts](https://img.shields.io/github/stars/pluto-chou/CVE-2026-61725_sevenz-rust2.svg) ![forks](https://img.shields.io/github/forks/pluto-chou/CVE-2026-61725_sevenz-rust2.svg)


## CVE-2026-53361
Let's set gc_in_progress to true in unix_gc().

- [https://github.com/Aoki-Shinshi/CVE-2026-53361](https://github.com/Aoki-Shinshi/CVE-2026-53361) :  ![starts](https://img.shields.io/github/stars/Aoki-Shinshi/CVE-2026-53361.svg) ![forks](https://img.shields.io/github/forks/Aoki-Shinshi/CVE-2026-53361.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/YUE546/IQOO-neo7-ghostlock-43499](https://github.com/YUE546/IQOO-neo7-ghostlock-43499) :  ![starts](https://img.shields.io/github/stars/YUE546/IQOO-neo7-ghostlock-43499.svg) ![forks](https://img.shields.io/github/forks/YUE546/IQOO-neo7-ghostlock-43499.svg)


## CVE-2026-34197
Users are recommended to upgrade to version 5.19.4 or 6.2.3, which fixes the issue

- [https://github.com/PRODEVCORP/CVE-2026-34197](https://github.com/PRODEVCORP/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/PRODEVCORP/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/PRODEVCORP/CVE-2026-34197.svg)


## CVE-2026-24239
 NVIDIA NeMo Speech for all platforms contains a vulnerability where malicious data created by an attacker could cause remote code execution. A successful exploit of this vulnerability might lead to code execution, information disclosure, and data tampering.

- [https://github.com/alert-k/checkpoint-deser-rules](https://github.com/alert-k/checkpoint-deser-rules) :  ![starts](https://img.shields.io/github/stars/alert-k/checkpoint-deser-rules.svg) ![forks](https://img.shields.io/github/forks/alert-k/checkpoint-deser-rules.svg)


## CVE-2026-17633
 IBM Langflow OSS 1.0.0 through 1.10.3 could allow a remote authenticated attacker to execute arbitrary code due to code injection.

- [https://github.com/joaovicdev/EXPLOIT-CVE-2026-17633](https://github.com/joaovicdev/EXPLOIT-CVE-2026-17633) :  ![starts](https://img.shields.io/github/stars/joaovicdev/EXPLOIT-CVE-2026-17633.svg) ![forks](https://img.shields.io/github/forks/joaovicdev/EXPLOIT-CVE-2026-17633.svg)


## CVE-2026-17194
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 16.7.0 before 19.4.11, 19.5 before 19.5.9, and 19.6 before 19.6.2 that under certain conditions could have allowed an authenticated user with developer-role permissions to merge code changes into protected branches without triggering approval resets due to the use of a weak hash function in the merge request approval change detection mechanism.

- [https://github.com/googlesky/CVE-2026-17194](https://github.com/googlesky/CVE-2026-17194) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-17194.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-17194.svg)


## CVE-2026-15723
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 10.1 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, when OmniAuth SAML and LDAP auto-linking were both enabled, an authenticated user could have taken over an existing LDAP-backed account without any interaction from the targeted user, due to improper input sanitization in the LDAP email lookup path used during OmniAuth identity linking.

- [https://github.com/googlesky/CVE-2026-15723](https://github.com/googlesky/CVE-2026-15723) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-15723.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-15723.svg)


## CVE-2026-12664
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.2 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, could have allowed an authenticated user with a read_api-scoped token to retrieve a project's incoming email address and create work items, bypassing the token's restrictions, due to insufficient scope enforcement on a GraphQL field.

- [https://github.com/googlesky/CVE-2026-12664](https://github.com/googlesky/CVE-2026-12664) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-12664.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-12664.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618](https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/cloudducoeur/ansible-playbook-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cloudducoeur/ansible-playbook-CVE-2026-109618.svg)
- [https://github.com/anldori/CVE-2026-109618](https://github.com/anldori/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/anldori/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/anldori/CVE-2026-109618.svg)


## CVE-2026-6224
 A security flaw has been discovered in nocobase plugin-workflow-javascript up to 2.0.23. This issue affects the function createSafeConsole of the file packages/plugins/@nocobase/plugin-workflow-javascript/src/server/Vm.js. Performing a manipulation results in sandbox issue. The attack can be initiated remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/Yxuan18/nocobase-cve-2026-6224](https://github.com/Yxuan18/nocobase-cve-2026-6224) :  ![starts](https://img.shields.io/github/stars/Yxuan18/nocobase-cve-2026-6224.svg) ![forks](https://img.shields.io/github/forks/Yxuan18/nocobase-cve-2026-6224.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Github-Oriented-Programmer/GhostLock-CVE-2026-43499-ZTE_A2322_4.19](https://github.com/Github-Oriented-Programmer/GhostLock-CVE-2026-43499-ZTE_A2322_4.19) :  ![starts](https://img.shields.io/github/stars/Github-Oriented-Programmer/GhostLock-CVE-2026-43499-ZTE_A2322_4.19.svg) ![forks](https://img.shields.io/github/forks/Github-Oriented-Programmer/GhostLock-CVE-2026-43499-ZTE_A2322_4.19.svg)


## CVE-2026-1286
 CWE-502: Deserialization of untrusted data vulnerability exists that could lead to loss of confidentiality, integrity and potential remote code execution on workstation when an admin authenticated user opens a malicious project file.

- [https://github.com/langz337/CVE-2026-128616](https://github.com/langz337/CVE-2026-128616) :  ![starts](https://img.shields.io/github/stars/langz337/CVE-2026-128616.svg) ![forks](https://img.shields.io/github/forks/langz337/CVE-2026-128616.svg)


## CVE-2025-60709
 Out-of-bounds read in Windows Common Log File System Driver allows an authorized attacker to elevate privileges locally.

- [https://github.com/PRODEVCORP/CVE-2025-60709](https://github.com/PRODEVCORP/CVE-2025-60709) :  ![starts](https://img.shields.io/github/stars/PRODEVCORP/CVE-2025-60709.svg) ![forks](https://img.shields.io/github/forks/PRODEVCORP/CVE-2025-60709.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/gabrielchv/seguranca-informacao-cve-2025-29927](https://github.com/gabrielchv/seguranca-informacao-cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/gabrielchv/seguranca-informacao-cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/gabrielchv/seguranca-informacao-cve-2025-29927.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/NuhHozar/Moniker-Link-CVE-2024-21413-TRYHACKME-WALKTROUGH-](https://github.com/NuhHozar/Moniker-Link-CVE-2024-21413-TRYHACKME-WALKTROUGH-) :  ![starts](https://img.shields.io/github/stars/NuhHozar/Moniker-Link-CVE-2024-21413-TRYHACKME-WALKTROUGH-.svg) ![forks](https://img.shields.io/github/forks/NuhHozar/Moniker-Link-CVE-2024-21413-TRYHACKME-WALKTROUGH-.svg)


## CVE-2023-40129
 In build_read_multi_rsp of gatt_sr.cc, there is a possible out of bounds write due to a heap buffer overflow. This could lead to remote (proximal/adjacent) code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Pavanb2609/FLUORIDEX](https://github.com/Pavanb2609/FLUORIDEX) :  ![starts](https://img.shields.io/github/stars/Pavanb2609/FLUORIDEX.svg) ![forks](https://img.shields.io/github/forks/Pavanb2609/FLUORIDEX.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/googlesky/CVE-2023-38831](https://github.com/googlesky/CVE-2023-38831) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2023-38831.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2023-38831.svg)


## CVE-2023-35673
 In build_read_multi_rsp of gatt_sr.cc, there is a possible out of bounds write due to an integer overflow. This could lead to remote (proximal/adjacent) code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Pavanb2609/FLUORIDEX](https://github.com/Pavanb2609/FLUORIDEX) :  ![starts](https://img.shields.io/github/stars/Pavanb2609/FLUORIDEX.svg) ![forks](https://img.shields.io/github/forks/Pavanb2609/FLUORIDEX.svg)


## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/googlesky/CVE-2023-34362](https://github.com/googlesky/CVE-2023-34362) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2023-34362.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2023-34362.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/googlesky/CVE-2023-23397](https://github.com/googlesky/CVE-2023-23397) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2023-23397.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2023-23397.svg)


## CVE-2023-3519
 Unauthenticated remote code execution

- [https://github.com/googlesky/CVE-2023-3519](https://github.com/googlesky/CVE-2023-3519) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2023-3519.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2023-3519.svg)


## CVE-2023-0264
 A flaw was found in Keycloaks OpenID Connect user authentication, which may incorrectly authenticate requests. An authenticated attacker who could obtain information from a user request within the same realm could use that data to impersonate the victim and generate new session tokens. This issue could impact confidentiality, integrity, and availability.

- [https://github.com/iam-s21-caece/PoC-CVE-2023-0264](https://github.com/iam-s21-caece/PoC-CVE-2023-0264) :  ![starts](https://img.shields.io/github/stars/iam-s21-caece/PoC-CVE-2023-0264.svg) ![forks](https://img.shields.io/github/forks/iam-s21-caece/PoC-CVE-2023-0264.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/googlesky/CVE-2022-30190](https://github.com/googlesky/CVE-2022-30190) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2022-30190.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2022-30190.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.

- [https://github.com/googlesky/CVE-2022-29464](https://github.com/googlesky/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2022-29464.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/googlesky/CVE-2022-22965](https://github.com/googlesky/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2022-22965.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/googlesky/CVE-2022-22954](https://github.com/googlesky/CVE-2022-22954) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2022-22954.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2022-22954.svg)


## CVE-2022-2296
 Use after free in Chrome OS Shell in Google Chrome on Chrome OS prior to 103.0.5060.114 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via direct UI interactions.

- [https://github.com/felisha-elmer/Sandbox-Challenge-Spring4Shell-CVE-2022-22965-](https://github.com/felisha-elmer/Sandbox-Challenge-Spring4Shell-CVE-2022-22965-) :  ![starts](https://img.shields.io/github/stars/felisha-elmer/Sandbox-Challenge-Spring4Shell-CVE-2022-22965-.svg) ![forks](https://img.shields.io/github/forks/felisha-elmer/Sandbox-Challenge-Spring4Shell-CVE-2022-22965-.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/googlesky/CVE-2022-1388](https://github.com/googlesky/CVE-2022-1388) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2022-1388.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2022-1388.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/googlesky/CVE-2022-0847](https://github.com/googlesky/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2022-0847.svg)


## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

- [https://github.com/googlesky/CVE-2021-45105](https://github.com/googlesky/CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2021-45105.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/googlesky/CVE-2021-45046](https://github.com/googlesky/CVE-2021-45046) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2021-45046.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2021-45046.svg)


## CVE-2021-34527
Note that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as “PrintNightmare”, documented in CVE-2021-34527.

- [https://github.com/googlesky/CVE-2021-34527](https://github.com/googlesky/CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2021-34527.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/googlesky/CVE-2021-26855](https://github.com/googlesky/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2021-26855.svg)


## CVE-2021-25329
 The fix for CVE-2020-9484 was incomplete. When using Apache Tomcat 10.0.0-M1 to 10.0.0, 9.0.0.M1 to 9.0.41, 8.5.0 to 8.5.61 or 7.0.0. to 7.0.107 with a configuration edge case that was highly unlikely to be used, the Tomcat instance was still vulnerable to CVE-2020-9494. Note that both the previously published prerequisites for CVE-2020-9484 and the previously published mitigations for CVE-2020-9484 also apply to this issue.

- [https://github.com/googlesky/CVE-2021-25329](https://github.com/googlesky/CVE-2021-25329) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2021-25329.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2021-25329.svg)


## CVE-2021-22986
 On BIG-IP versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x before 14.1.4, 13.1.x before 13.1.3.6, and 12.1.x before 12.1.5.3 amd BIG-IQ 7.1.0.x before 7.1.0.3 and 7.0.0.x before 7.0.0.2, the iControl REST interface has an unauthenticated remote command execution vulnerability. Note: Software versions which have reached End of Software Development (EoSD) are not evaluated.

- [https://github.com/googlesky/CVE-2021-22986](https://github.com/googlesky/CVE-2021-22986) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2021-22986.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2021-22986.svg)


## CVE-2021-21985
 The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.

- [https://github.com/googlesky/CVE-2021-21985](https://github.com/googlesky/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2021-21985.svg)


## CVE-2021-20329
 Specific cstrings input may not be properly validated in the MongoDB Go Driver when marshalling Go objects into BSON. A malicious user could use a Go object with specific string to potentially inject additional fields into marshalled documents. This issue affects all MongoDB GO Drivers prior to and including 1.5.0.

- [https://github.com/hugo19941994/CVE-2021-20329-bson-injection](https://github.com/hugo19941994/CVE-2021-20329-bson-injection) :  ![starts](https://img.shields.io/github/stars/hugo19941994/CVE-2021-20329-bson-injection.svg) ![forks](https://img.shields.io/github/forks/hugo19941994/CVE-2021-20329-bson-injection.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/googlesky/CVE-2021-3156](https://github.com/googlesky/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2021-3156.svg)


## CVE-2020-11989
 Apache Shiro before 1.5.3, when using Apache Shiro with Spring dynamic controllers, a specially crafted request may cause an authentication bypass.

- [https://github.com/googlesky/CVE-2020-11989](https://github.com/googlesky/CVE-2020-11989) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2020-11989.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2020-11989.svg)


## CVE-2020-9484
 When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter="null" (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.

- [https://github.com/googlesky/CVE-2020-9484](https://github.com/googlesky/CVE-2020-9484) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2020-9484.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2020-9484.svg)
- [https://github.com/CrieHeiki/Apache-Tomcat-CVE-2020-9484](https://github.com/CrieHeiki/Apache-Tomcat-CVE-2020-9484) :  ![starts](https://img.shields.io/github/stars/CrieHeiki/Apache-Tomcat-CVE-2020-9484.svg) ![forks](https://img.shields.io/github/forks/CrieHeiki/Apache-Tomcat-CVE-2020-9484.svg)
- [https://github.com/googlesky/CVE-2021-25329](https://github.com/googlesky/CVE-2021-25329) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2021-25329.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2021-25329.svg)


## CVE-2020-9402
 Django 1.11 before 1.11.29, 2.2 before 2.2.11, and 3.0 before 3.0.4 allows SQL Injection if untrusted data is used as a tolerance parameter in GIS functions and aggregates on Oracle. By passing a suitably crafted tolerance to GIS functions and aggregates on Oracle, it was possible to break escaping and inject malicious SQL.

- [https://github.com/googlesky/CVE-2020-9402](https://github.com/googlesky/CVE-2020-9402) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2020-9402.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2020-9402.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/googlesky/CVE-2020-5902](https://github.com/googlesky/CVE-2020-5902) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2020-5902.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2020-5902.svg)


## CVE-2020-2555
 Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/googlesky/CVE-2020-2555](https://github.com/googlesky/CVE-2020-2555) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2020-2555.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2020-2555.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/googlesky/CVE-2020-1938](https://github.com/googlesky/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2020-1938.svg)


## CVE-2020-1935
 In Apache Tomcat 9.0.0.M1 to 9.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99 the HTTP header parsing code used an approach to end-of-line parsing that allowed some invalid HTTP headers to be parsed as valid. This led to a possibility of HTTP Request Smuggling if Tomcat was located behind a reverse proxy that incorrectly handled the invalid Transfer-Encoding header in a particular manner. Such a reverse proxy is considered unlikely.

- [https://github.com/googlesky/CVE-2020-1935](https://github.com/googlesky/CVE-2020-1935) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2020-1935.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2020-1935.svg)


## CVE-2020-1472
When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/googlesky/CVE-2020-1472](https://github.com/googlesky/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2020-1472.svg)


## CVE-2020-0688
 A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.

- [https://github.com/googlesky/CVE-2020-0688](https://github.com/googlesky/CVE-2020-0688) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2020-0688.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2020-0688.svg)


## CVE-2020-0601
 A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates.An attacker could exploit the vulnerability by using a spoofed code-signing certificate to sign a malicious executable, making it appear the file was from a trusted, legitimate source, aka 'Windows CryptoAPI Spoofing Vulnerability'.

- [https://github.com/googlesky/CVE-2020-0601](https://github.com/googlesky/CVE-2020-0601) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2020-0601.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2020-0601.svg)


## CVE-2019-19844
 Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover. A suitably crafted email address (that is equal to an existing user's email address after case transformation of Unicode characters) would allow an attacker to be sent a password reset token for the matched user account. (One mitigation in the new releases is to send password reset tokens only to the registered user email address.)

- [https://github.com/googlesky/CVE-2019-19844](https://github.com/googlesky/CVE-2019-19844) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2019-19844.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2019-19844.svg)


## CVE-2019-19781
 An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. They allow Directory Traversal.

- [https://github.com/googlesky/CVE-2019-19781](https://github.com/googlesky/CVE-2019-19781) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2019-19781.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2019-19781.svg)


## CVE-2019-17571
 Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget when listening to untrusted network traffic for log data. This affects Log4j versions up to 1.2 up to 1.2.17.

- [https://github.com/googlesky/CVE-2019-17571](https://github.com/googlesky/CVE-2019-17571) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2019-17571.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2019-17571.svg)


## CVE-2019-17563
 When using FORM authentication with Apache Tomcat 9.0.0.M1 to 9.0.29, 8.5.0 to 8.5.49 and 7.0.0 to 7.0.98 there was a narrow window where an attacker could perform a session fixation attack. The window was considered too narrow for an exploit to be practical but, erring on the side of caution, this issue has been treated as a security vulnerability.

- [https://github.com/googlesky/CVE-2019-17563](https://github.com/googlesky/CVE-2019-17563) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2019-17563.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2019-17563.svg)


## CVE-2019-17558
 Apache Solr 5.0.0 to Apache Solr 8.3.1 are vulnerable to a Remote Code Execution through the VelocityResponseWriter. A Velocity template can be provided through Velocity templates in a configset `velocity/` directory or as a parameter. A user defined configset could contain renderable, potentially malicious, templates. Parameter provided templates are disabled by default, but can be enabled by setting `params.resource.loader.enabled` by defining a response writer with that setting set to `true`. Defining a response writer requires configuration API access. Solr 8.4 removed the params resource loader entirely, and only enables the configset-provided template rendering when the configset is `trusted` (has been uploaded by an authenticated user).

- [https://github.com/googlesky/CVE-2019-17558](https://github.com/googlesky/CVE-2019-17558) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2019-17558.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2019-17558.svg)


## CVE-2019-13272
 In the Linux kernel before 5.1.17, ptrace_link in kernel/ptrace.c mishandles the recording of the credentials of a process that wants to create a ptrace relationship, which allows local users to obtain root access by leveraging certain scenarios with a parent-child process relationship, where a parent drops privileges and calls execve (potentially allowing control by an attacker). One contributing factor is an object lifetime issue (which can also cause a panic). Another contributing factor is incorrect marking of a ptrace relationship as privileged, which is exploitable through (for example) Polkit's pkexec helper with PTRACE_TRACEME. NOTE: SELinux deny_ptrace might be a usable workaround in some environments.

- [https://github.com/googlesky/CVE-2019-13272](https://github.com/googlesky/CVE-2019-13272) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2019-13272.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2019-13272.svg)


## CVE-2019-12735
 getchar.c in Vim before 8.1.1365 and Neovim before 0.3.6 allows remote attackers to execute arbitrary OS commands via the :source! command in a modeline, as demonstrated by execute in Vim, and assert_fails or nvim_input in Neovim.

- [https://github.com/eltociear/vimplugin-audit](https://github.com/eltociear/vimplugin-audit) :  ![starts](https://img.shields.io/github/stars/eltociear/vimplugin-audit.svg) ![forks](https://img.shields.io/github/forks/eltociear/vimplugin-audit.svg)


## CVE-2019-2725
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/googlesky/CVE-2019-2725](https://github.com/googlesky/CVE-2019-2725) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2019-2725.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2019-2725.svg)


## CVE-2019-1040
The update addresses the vulnerability by hardening NTLM MIC protection on the server-side.

- [https://github.com/googlesky/CVE-2019-1040](https://github.com/googlesky/CVE-2019-1040) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2019-1040.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2019-1040.svg)


## CVE-2019-0232
 When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache Tomcat 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 is vulnerable to Remote Code Execution due to a bug in the way the JRE passes command line arguments to Windows. The CGI Servlet is disabled by default. The CGI option enableCmdLineArguments is disable by default in Tomcat 9.0.x (and will be disabled by default in all versions in response to this vulnerability). For a detailed explanation of the JRE behaviour, see Markus Wulftange's blog (https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-windows.html) and this archived MSDN blog (https://web.archive.org/web/20161228144344/https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/).

- [https://github.com/googlesky/CVE-2019-0232](https://github.com/googlesky/CVE-2019-0232) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2019-0232.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2019-0232.svg)


## CVE-2019-0199
 The HTTP/2 implementation in Apache Tomcat 9.0.0.M1 to 9.0.14 and 8.5.0 to 8.5.37 accepted streams with excessive numbers of SETTINGS frames and also permitted clients to keep streams open without reading/writing request/response data. By keeping streams open for requests that utilised the Servlet API's blocking I/O, clients were able to cause server-side threads to block eventually leading to thread exhaustion and a DoS.

- [https://github.com/googlesky/CVE-2019-0199](https://github.com/googlesky/CVE-2019-0199) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2019-0199.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2019-0199.svg)


## CVE-2019-0193
 In Apache Solr, the DataImportHandler, an optional but popular module to pull in data from databases and other sources, has a feature in which the whole DIH configuration can come from a request's "dataConfig" parameter. The debug mode of the DIH admin screen uses this to allow convenient debugging / development of a DIH config. Since a DIH config can contain scripts, this parameter is a security risk. Starting with version 8.2.0 of Solr, use of this parameter requires setting the Java System property "enable.dih.dataConfigParam" to true.

- [https://github.com/googlesky/CVE-2019-0193](https://github.com/googlesky/CVE-2019-0193) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2019-0193.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2019-0193.svg)


## CVE-2018-1000861
 A code execution vulnerability exists in the Stapler web framework used by Jenkins 2.153 and earlier, LTS 2.138.3 and earlier in stapler/core/src/main/java/org/kohsuke/stapler/MetaClass.java that allows attackers to invoke some methods on Java objects by accessing crafted URLs that were not intended to be invoked this way.

- [https://github.com/googlesky/CVE-2018-1000861](https://github.com/googlesky/CVE-2018-1000861) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2018-1000861.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2018-1000861.svg)


## CVE-2018-11776
 Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.

- [https://github.com/googlesky/CVE-2018-11776](https://github.com/googlesky/CVE-2018-11776) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2018-11776.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2018-11776.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/Abdullah-Racip/detection-lab](https://github.com/Abdullah-Racip/detection-lab) :  ![starts](https://img.shields.io/github/stars/Abdullah-Racip/detection-lab.svg) ![forks](https://img.shields.io/github/forks/Abdullah-Racip/detection-lab.svg)


## CVE-2018-1336
 An improper handing of overflow in the UTF-8 decoder with supplementary characters can lead to an infinite loop in the decoder causing a Denial of Service. Versions Affected: Apache Tomcat 9.0.0.M9 to 9.0.7, 8.5.0 to 8.5.30, 8.0.0.RC1 to 8.0.51, and 7.0.28 to 7.0.86.

- [https://github.com/googlesky/CVE-2018-1336](https://github.com/googlesky/CVE-2018-1336) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2018-1336.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2018-1336.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/googlesky/CVE-2018-1273](https://github.com/googlesky/CVE-2018-1273) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2018-1273.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2018-1273.svg)


## CVE-2017-20291
 An XML External Entity (XXE) injection vulnerability in the Federation Web Services component (/affwebservices/router/session) of Broadcom SiteMinder (CA Single Sign-On) Secure Proxy Server / Access Gateway R12.52 SP1 prior to R12.52 SP1 CR6 allows a remote attacker to submit crafted SOAP requests to the exposed Apache-SOAP RPC Router servlet (org.apache.soap.server.http.RPCRouterServlet). Successful exploitation could result in unauthorized disclosure of local files or sensitive data, server-side request forgery (SSRF), or denial of service. The issue is resolved in R12.52 SP1 CR6 (and does not affect R12.8 or R12.9) by removing the router servlet mapping so requests to the endpoint return HTTP 404.

- [https://github.com/googlesky/CVE-2017-20291](https://github.com/googlesky/CVE-2017-20291) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2017-20291.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2017-20291.svg)


## CVE-2017-12629
 Remote code execution occurs in Apache Solr before 7.1 with Apache Lucene before 7.1 by exploiting XXE in conjunction with use of a Config API add-listener command to reach the RunExecutableListener class. Elasticsearch, although it uses Lucene, is NOT vulnerable to this. Note that the XML external entity expansion vulnerability occurs in the XML Query Parser which is available, by default, for any query request with parameters deftype=xmlparser and can be exploited to upload malicious data to the /upload request handler or as Blind XXE using ftp wrapper in order to read arbitrary local files from the Solr server. Note also that the second vulnerability relates to remote code execution using the RunExecutableListener available on all affected versions of Solr.

- [https://github.com/googlesky/CVE-2017-12629](https://github.com/googlesky/CVE-2017-12629) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2017-12629.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2017-12629.svg)


## CVE-2017-12617
 When running Apache Tomcat versions 9.0.0.M1 to 9.0.0, 8.5.0 to 8.5.22, 8.0.0.RC1 to 8.0.46 and 7.0.0 to 7.0.81 with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default servlet to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/googlesky/CVE-2017-12617](https://github.com/googlesky/CVE-2017-12617) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2017-12617.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2017-12617.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/googlesky/CVE-2017-12615](https://github.com/googlesky/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2017-12615.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka "Microsoft Office Memory Corruption Vulnerability". This CVE ID is unique from CVE-2017-11884.

- [https://github.com/googlesky/CVE-2017-11882](https://github.com/googlesky/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2017-11882.svg)


## CVE-2017-9805
 The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.

- [https://github.com/googlesky/CVE-2017-9805](https://github.com/googlesky/CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2017-9805.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/Mipa97/CVE-2017-7529](https://github.com/Mipa97/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/Mipa97/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/Mipa97/CVE-2017-7529.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/googlesky/CVE-2017-5638](https://github.com/googlesky/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2017-5638.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/googlesky/CVE-2017-0144](https://github.com/googlesky/CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2017-0144.svg)


## CVE-2016-10033
 The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \" (backslash double quote) in a crafted Sender property.

- [https://github.com/googlesky/CVE-2016-10033](https://github.com/googlesky/CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2016-10033.svg)


## CVE-2016-8735
 Remote code execution is possible with Apache Tomcat before 6.0.48, 7.x before 7.0.73, 8.x before 8.0.39, 8.5.x before 8.5.7, and 9.x before 9.0.0.M12 if JmxRemoteLifecycleListener is used and an attacker can reach JMX ports. The issue exists because this listener wasn't updated for consistency with the CVE-2016-3427 Oracle patch that affected credential types.

- [https://github.com/googlesky/CVE-2016-8735](https://github.com/googlesky/CVE-2016-8735) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2016-8735.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2016-8735.svg)


## CVE-2016-6816
 The code in Apache Tomcat 9.0.0.M1 to 9.0.0.M11, 8.5.0 to 8.5.6, 8.0.0.RC1 to 8.0.38, 7.0.0 to 7.0.72, and 6.0.0 to 6.0.47 that parsed the HTTP request line permitted invalid characters. This could be exploited, in conjunction with a proxy that also permitted the invalid characters but with a different interpretation, to inject data into the HTTP response. By manipulating the HTTP response the attacker could poison a web-cache, perform an XSS attack and/or obtain sensitive information from requests other then their own.

- [https://github.com/googlesky/CVE-2016-6816](https://github.com/googlesky/CVE-2016-6816) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2016-6816.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2016-6816.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/googlesky/CVE-2016-5195](https://github.com/googlesky/CVE-2016-5195) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2016-5195.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2016-5195.svg)


## CVE-2016-4437
 Apache Shiro before 1.2.5, when a cipher key has not been configured for the "remember me" feature, allows remote attackers to execute arbitrary code or bypass intended access restrictions via an unspecified request parameter.

- [https://github.com/googlesky/CVE-2016-4437](https://github.com/googlesky/CVE-2016-4437) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2016-4437.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2016-4437.svg)


## CVE-2015-4852
 The WLS Security component in Oracle WebLogic Server 10.3.6.0, 12.1.2.0, 12.1.3.0, and 12.2.1.0 allows remote attackers to execute arbitrary commands via a crafted serialized Java object in T3 protocol traffic to TCP port 7001, related to oracle_common/modules/com.bea.core.apache.commons.collections.jar. NOTE: the scope of this CVE is limited to the WebLogic Server product.

- [https://github.com/googlesky/CVE-2015-4852](https://github.com/googlesky/CVE-2015-4852) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2015-4852.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2015-4852.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/googlesky/CVE-2014-0160](https://github.com/googlesky/CVE-2014-0160) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2014-0160.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2014-0160.svg)


## CVE-2012-1675
 The TNS Listener, as used in Oracle Database 11g 11.1.0.7, 11.2.0.2, and 11.2.0.3, and 10g 10.2.0.3, 10.2.0.4, and 10.2.0.5, as used in Oracle Fusion Middleware, Enterprise Manager, E-Business Suite, and possibly other products, allows remote attackers to execute arbitrary database commands by performing a remote registration of a database (1) instance or (2) service name that already exists, then conducting a man-in-the-middle (MITM) attack to hijack database connections, aka "TNS Poison."

- [https://github.com/0xwarwolf/Oracle-Security-Alert-CVE-2012-1675](https://github.com/0xwarwolf/Oracle-Security-Alert-CVE-2012-1675) :  ![starts](https://img.shields.io/github/stars/0xwarwolf/Oracle-Security-Alert-CVE-2012-1675.svg) ![forks](https://img.shields.io/github/forks/0xwarwolf/Oracle-Security-Alert-CVE-2012-1675.svg)

