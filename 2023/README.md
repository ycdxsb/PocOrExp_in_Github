## CVE-2023-22671
 Ghidra/RuntimeScripts/Linux/support/launch.sh in NSA Ghidra through 10.2.2 passes user-provided input into eval, leading to command injection when calling analyzeHeadless with untrusted input.



- [https://github.com/Live-Hack-CVE/CVE-2023-22671](https://github.com/Live-Hack-CVE/CVE-2023-22671) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22671.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22671.svg)

## CVE-2023-22626
 PgHero before 3.1.0 allows Information Disclosure via EXPLAIN because query results may be present in an error message. (Depending on database user privileges, this may only be information from the database, or may be information from file contents on the database server.)



- [https://github.com/Live-Hack-CVE/CVE-2023-22626](https://github.com/Live-Hack-CVE/CVE-2023-22626) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22626.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22626.svg)

## CVE-2023-22551
 The FTP (aka &quot;Implementation of a simple FTP client and server&quot;) project through 96c1a35 allows remote attackers to cause a denial of service (memory consumption) by engaging in client activity, such as establishing and then terminating a connection. This occurs because malloc is used but free is not.



- [https://github.com/Live-Hack-CVE/CVE-2023-22551](https://github.com/Live-Hack-CVE/CVE-2023-22551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22551.svg)

## CVE-2023-22475
 Canarytokens is an open source tool which helps track activity and actions on your network. A Cross-Site Scripting vulnerability was identified in the history page of triggered Canarytokens prior to sha-fb61290. An attacker who discovers an HTTP-based Canarytoken (a URL) can use this to execute Javascript in the Canarytoken's trigger history page (domain: canarytokens.org) when the history page is later visited by the Canarytoken's creator. This vulnerability could be used to disable or delete the affected Canarytoken, or view its activation history. It might also be used as a stepping stone towards revealing more information about the Canarytoken's creator to the attacker. For example, an attacker could recover the email address tied to the Canarytoken, or place Javascript on the history page that redirect the creator towards an attacker-controlled Canarytoken to show the creator's network location. This vulnerability is similar to CVE-2022-31113, but affected parameters reported differently from the Canarytoken trigger request. An attacker could only act on the discovered Canarytoken. This issue did not expose other Canarytokens or other Canarytoken creators. Canarytokens Docker images sha-fb61290 and later contain a patch for this issue.



- [https://github.com/Live-Hack-CVE/CVE-2023-22475](https://github.com/Live-Hack-CVE/CVE-2023-22475) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22475.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22475.svg)

## CVE-2023-22472
 Deck is a kanban style organization tool aimed at personal planning and project organization for teams integrated with Nextcloud. It is possible to make a user send any POST request with an arbitrary body given they click on a malicious deep link on a Windows computer. (e.g. in an email, chat link, etc). There are currently no known workarounds. It is recommended that the Nextcloud Desktop client is upgraded to 3.6.2.



- [https://github.com/Live-Hack-CVE/CVE-2023-22472](https://github.com/Live-Hack-CVE/CVE-2023-22472) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22472.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22472.svg)

## CVE-2023-22467
 Luxon is a library for working with dates and times in JavaScript. On the 1.x branch prior to 1.38.1, the 2.x branch prior to 2.5.2, and the 3.x branch on 3.2.1, Luxon's `DateTime.fromRFC2822() has quadratic (N^2) complexity on some specific inputs. This causes a noticeable slowdown for inputs with lengths above 10k characters. Users providing untrusted data to this method are therefore vulnerable to (Re)DoS attacks. This issue also appears in Moment as CVE-2022-31129. Versions 1.38.1, 2.5.2, and 3.2.1 contain patches for this issue. As a workaround, limit the length of the input.



- [https://github.com/Live-Hack-CVE/CVE-2023-22467](https://github.com/Live-Hack-CVE/CVE-2023-22467) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22467.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22467.svg)

## CVE-2023-22466
 Tokio is a runtime for writing applications with Rust. Starting with version 1.7.0 and prior to versions 1.18.4, 1.20.3, and 1.23.1, when configuring a Windows named pipe server, setting `pipe_mode` will reset `reject_remote_clients` to `false`. If the application has previously configured `reject_remote_clients` to `true`, this effectively undoes the configuration. Remote clients may only access the named pipe if the named pipe's associated path is accessible via a publicly shared folder (SMB). Versions 1.23.1, 1.20.3, and 1.18.4 have been patched. The fix will also be present in all releases starting from version 1.24.0. Named pipes were introduced to Tokio in version 1.7.0, so releases older than 1.7.0 are not affected. As a workaround, ensure that `pipe_mode` is set first after initializing a `ServerOptions`.



- [https://github.com/Live-Hack-CVE/CVE-2023-22466](https://github.com/Live-Hack-CVE/CVE-2023-22466) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22466.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22466.svg)

## CVE-2023-22463
 KubePi is a k8s panel. The jwt authentication function of KubePi through version 1.6.2 uses hard-coded Jwtsigkeys, resulting in the same Jwtsigkeys for all online projects. This means that an attacker can forge any jwt token to take over the administrator account of any online project. Furthermore, they may use the administrator to take over the k8s cluster of the target enterprise. `session.go`, the use of hard-coded JwtSigKey, allows an attacker to use this value to forge jwt tokens arbitrarily. The JwtSigKey is confidential and should not be hard-coded in the code. The vulnerability has been fixed in 1.6.3. In the patch, JWT key is specified in app.yml. If the user leaves it blank, a random key will be used. There are no workarounds aside from upgrading.



- [https://github.com/Live-Hack-CVE/CVE-2023-22463](https://github.com/Live-Hack-CVE/CVE-2023-22463) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22463.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22463.svg)

## CVE-2023-22456
 ViewVC, a browser interface for CVS and Subversion version control repositories, as a cross-site scripting vulnerability that affects versions prior to 1.2.2 and 1.1.29. The impact of this vulnerability is mitigated by the need for an attacker to have commit privileges to a Subversion repository exposed by an otherwise trusted ViewVC instance. The attack vector involves files with unsafe names (names that, when embedded into an HTML stream, would cause the browser to run unwanted code), which themselves can be challenging to create. Users should update to at least version 1.2.2 (if they are using a 1.2.x version of ViewVC) or 1.1.29 (if they are using a 1.1.x version). ViewVC 1.0.x is no longer supported, so users of that release lineage should implement a workaround. Users can edit their ViewVC EZT view templates to manually HTML-escape changed paths during rendering. Locate in your template set's `revision.ezt` file references to those changed paths, and wrap them with `[format &quot;html&quot;]` and `[end]`. For most users, that means that references to `[changes.path]` will become `[format &quot;html&quot;][changes.path][end]`. (This workaround should be reverted after upgrading to a patched version of ViewVC, else changed path names will be doubly escaped.)



- [https://github.com/Live-Hack-CVE/CVE-2023-22456](https://github.com/Live-Hack-CVE/CVE-2023-22456) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22456.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22456.svg)

## CVE-2023-22454
 Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 3.0.0.beta16 on the `beta` and `tests-passed` branches, pending post titles can be used for cross-site scripting attacks. Pending posts can be created by unprivileged users when a category has the &quot;require moderator approval of all new topics&quot; setting set. This vulnerability can lead to a full XSS on sites which have modified or disabled Discourse&#8217;s default Content Security Policy. A patch is available in versions 2.8.14 and 3.0.0.beta16.



- [https://github.com/Live-Hack-CVE/CVE-2023-22454](https://github.com/Live-Hack-CVE/CVE-2023-22454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22454.svg)

## CVE-2023-22453
 Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 3.0.0.beta16 on the `beta` and `tests-passed` branches, the number of times a user posted in an arbitrary topic is exposed to unauthorized users through the `/u/username.json` endpoint. The issue is patched in version 2.8.14 and 3.0.0.beta16. There is no known workaround.



- [https://github.com/Live-Hack-CVE/CVE-2023-22453](https://github.com/Live-Hack-CVE/CVE-2023-22453) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22453.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22453.svg)

## CVE-2023-22452
 kenny2automate is a Discord bot. In the web interface for server settings, form elements were generated with Discord channel IDs as part of input names. Prior to commit a947d7c, no validation was performed to ensure that the channel IDs submitted actually belonged to the server being configured. Thus anyone who has access to the channel ID they wish to change settings for and the server settings panel for any server could change settings for the requested channel no matter which server it belonged to. Commit a947d7c resolves the issue and has been deployed to the official instance of the bot. The only workaround that exists is to disable the web config entirely by changing it to run on localhost. Note that a workaround is only necessary for those who run their own instance of the bot.



- [https://github.com/Live-Hack-CVE/CVE-2023-22452](https://github.com/Live-Hack-CVE/CVE-2023-22452) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22452.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22452.svg)

## CVE-2023-22451
 Kiwi TCMS is an open source test management system. In version 11.6 and prior, when users register new accounts and/or change passwords, there is no validation in place which would prevent them from picking an easy to guess password. This issue is resolved by providing defaults for the `AUTH_PASSWORD_VALIDATORS` configuration setting. As of version 11.7, the password can&#8217;t be too similar to other personal information, must contain at least 10 characters, can&#8217;t be a commonly used password, and can&#8217;t be entirely numeric. As a workaround, an administrator may reset all passwords in Kiwi TCMS if they think a weak password may have been chosen.



- [https://github.com/Live-Hack-CVE/CVE-2023-22451](https://github.com/Live-Hack-CVE/CVE-2023-22451) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22451.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22451.svg)

## CVE-2023-0125
 A vulnerability was found in Control iD Panel. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the component Web Interface. The manipulation of the argument Nome leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-217717 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0125](https://github.com/Live-Hack-CVE/CVE-2023-0125) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0125.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0125.svg)

## CVE-2023-0114
 A vulnerability was found in Netis Netcore Router. It has been rated as problematic. Affected by this issue is some unknown functionality of the file param.file.tgz of the component Backup Handler. The manipulation leads to cleartext storage in a file or on disk. Local access is required to approach this attack. The identifier of this vulnerability is VDB-217592.



- [https://github.com/Live-Hack-CVE/CVE-2023-0114](https://github.com/Live-Hack-CVE/CVE-2023-0114) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0114.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0114.svg)

## CVE-2023-0113
 A vulnerability was found in Netis Netcore Router. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file param.file.tgz of the component Backup Handler. The manipulation leads to information disclosure. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-217591.



- [https://github.com/Live-Hack-CVE/CVE-2023-0113](https://github.com/Live-Hack-CVE/CVE-2023-0113) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0113.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0113.svg)

## CVE-2023-0112
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0112](https://github.com/Live-Hack-CVE/CVE-2023-0112) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0112.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0112.svg)

## CVE-2023-0111
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0111](https://github.com/Live-Hack-CVE/CVE-2023-0111) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0111.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0111.svg)

## CVE-2023-0110
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0110](https://github.com/Live-Hack-CVE/CVE-2023-0110) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0110.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0110.svg)

## CVE-2023-0108
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0108](https://github.com/Live-Hack-CVE/CVE-2023-0108) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0108.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0108.svg)

## CVE-2023-0107
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0107](https://github.com/Live-Hack-CVE/CVE-2023-0107) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0107.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0107.svg)

## CVE-2023-0106
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/Live-Hack-CVE/CVE-2023-0106](https://github.com/Live-Hack-CVE/CVE-2023-0106) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0106.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0106.svg)

## CVE-2023-0088
 The Swifty Page Manager plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 3.0.1. This is due to missing or incorrect nonce validation on several AJAX actions handling page creation and deletion among other things. This makes it possible for unauthenticated attackers to invoke those functions, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/Live-Hack-CVE/CVE-2023-0088](https://github.com/Live-Hack-CVE/CVE-2023-0088) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0088.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0088.svg)

## CVE-2023-0087
 The Swifty Page Manager plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the &#8216;spm_plugin_options_page_tree_max_width&#8217; parameter in versions up to, and including, 3.0.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.



- [https://github.com/Live-Hack-CVE/CVE-2023-0087](https://github.com/Live-Hack-CVE/CVE-2023-0087) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0087.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0087.svg)

## CVE-2023-0086
 The JetWidgets for Elementor plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 1.0.12. This is due to missing nonce validation on the save() function. This makes it possible for unauthenticated attackers to to modify the plugin's settings via a forged request granted they can trick a site administrator into performing an action such as clicking on a link. This can be used to enable SVG uploads that could make Cross-Site Scripting possible.



- [https://github.com/Live-Hack-CVE/CVE-2023-0086](https://github.com/Live-Hack-CVE/CVE-2023-0086) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0086.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0086.svg)

## CVE-2023-0077
 Integer overflow or wraparound vulnerability in CGI component in Synology Router Manager (SRM) before 1.2.5-8227-6 and 1.3.1-9346-3 allows remote attackers to overflow buffers via unspecified vectors.



- [https://github.com/Live-Hack-CVE/CVE-2023-0077](https://github.com/Live-Hack-CVE/CVE-2023-0077) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0077.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0077.svg)

## CVE-2023-0055
 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute in GitHub repository pyload/pyload prior to 0.5.0b3.dev32.



- [https://github.com/Live-Hack-CVE/CVE-2023-0055](https://github.com/Live-Hack-CVE/CVE-2023-0055) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0055.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0055.svg)

## CVE-2023-0054
 Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1145.



- [https://github.com/Live-Hack-CVE/CVE-2023-0054](https://github.com/Live-Hack-CVE/CVE-2023-0054) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0054.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0054.svg)

## CVE-2023-0049
 Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143.



- [https://github.com/Live-Hack-CVE/CVE-2023-0049](https://github.com/Live-Hack-CVE/CVE-2023-0049) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0049.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0049.svg)

## CVE-2023-0048
 Code Injection in GitHub repository lirantal/daloradius prior to master-branch.



- [https://github.com/Live-Hack-CVE/CVE-2023-0048](https://github.com/Live-Hack-CVE/CVE-2023-0048) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0048.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0048.svg)

## CVE-2023-0046
 Improper Restriction of Names for Files and Other Resources in GitHub repository lirantal/daloradius prior to master-branch.



- [https://github.com/Live-Hack-CVE/CVE-2023-0046](https://github.com/Live-Hack-CVE/CVE-2023-0046) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0046.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0046.svg)

## CVE-2023-0039
 The User Post Gallery - UPG plugin for WordPress is vulnerable to authorization bypass which leads to remote command execution due to the use of a nopriv AJAX action and user supplied function calls and parameters in versions up to, and including 2.19. This makes it possible for unauthenticated attackers to call arbitrary PHP functions and perform actions like adding new files that can be webshells and updating the site's options to allow anyone to register as an administrator.



- [https://github.com/Live-Hack-CVE/CVE-2023-0039](https://github.com/Live-Hack-CVE/CVE-2023-0039) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0039.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0039.svg)

## CVE-2023-0038
 The &quot;Survey Maker &#8211; Best WordPress Survey Plugin&quot; plugin for WordPress is vulnerable to Stored Cross-Site Scripting via survey answers in versions up to, and including, 3.1.3 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts when submitting quizzes that will execute whenever a user accesses the submissions page.



- [https://github.com/Live-Hack-CVE/CVE-2023-0038](https://github.com/Live-Hack-CVE/CVE-2023-0038) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0038.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0038.svg)

## CVE-2023-0036
 platform_callback_stub in misc subsystem within OpenHarmony-v3.0.5 and prior versions has an authentication bypass vulnerability which allows an &quot;SA relay attack&quot;.Local attackers can bypass authentication and attack other SAs with high privilege.



- [https://github.com/Live-Hack-CVE/CVE-2023-0036](https://github.com/Live-Hack-CVE/CVE-2023-0036) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0036.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0036.svg)

## CVE-2023-0035
 softbus_client_stub in communication subsystem within OpenHarmony-v3.0.5 and prior versions has an authentication bypass vulnerability which allows an &quot;SA relay attack&quot;.Local attackers can bypass authentication and attack other SAs with high privilege.



- [https://github.com/Live-Hack-CVE/CVE-2023-0035](https://github.com/Live-Hack-CVE/CVE-2023-0035) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0035.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0035.svg)

## CVE-2023-0029
 A vulnerability was found in Multilaser RE708 RE1200R4GC-2T2R-V3_v3411b_MUL029B. It has been rated as problematic. This issue affects some unknown processing of the component Telnet Service. The manipulation leads to denial of service. The attack may be initiated remotely. The identifier VDB-217169 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0029](https://github.com/Live-Hack-CVE/CVE-2023-0029) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0029.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0029.svg)

## CVE-2023-0028
 Cross-site Scripting (XSS) - Stored in GitHub repository linagora/twake prior to 2023.Q1.1200+.



- [https://github.com/Live-Hack-CVE/CVE-2023-0028](https://github.com/Live-Hack-CVE/CVE-2023-0028) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0028.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0028.svg)
