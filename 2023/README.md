## CVE-2023-22551
 The FTP (aka &quot;Implementation of a simple FTP client and server&quot;) project through 96c1a35 allows remote attackers to cause a denial of service (memory consumption) by engaging in client activity, such as establishing and then terminating a connection. This occurs because malloc is used but free is not.



- [https://github.com/Live-Hack-CVE/CVE-2023-22551](https://github.com/Live-Hack-CVE/CVE-2023-22551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22551.svg)

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

## CVE-2023-22452
 kenny2automate is a Discord bot. In the web interface for server settings, form elements were generated with Discord channel IDs as part of input names. Prior to commit a947d7c, no validation was performed to ensure that the channel IDs submitted actually belonged to the server being configured. Thus anyone who has access to the channel ID they wish to change settings for and the server settings panel for any server could change settings for the requested channel no matter which server it belonged to. Commit a947d7c resolves the issue and has been deployed to the official instance of the bot. The only workaround that exists is to disable the web config entirely by changing it to run on localhost. Note that a workaround is only necessary for those who run their own instance of the bot.



- [https://github.com/Live-Hack-CVE/CVE-2023-22452](https://github.com/Live-Hack-CVE/CVE-2023-22452) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22452.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22452.svg)

## CVE-2023-22451
 Kiwi TCMS is an open source test management system. In version 11.6 and prior, when users register new accounts and/or change passwords, there is no validation in place which would prevent them from picking an easy to guess password. This issue is resolved by providing defaults for the `AUTH_PASSWORD_VALIDATORS` configuration setting. As of version 11.7, the password can&#8217;t be too similar to other personal information, must contain at least 10 characters, can&#8217;t be a commonly used password, and can&#8217;t be entirely numeric. As a workaround, an administrator may reset all passwords in Kiwi TCMS if they think a weak password may have been chosen.



- [https://github.com/Live-Hack-CVE/CVE-2023-22451](https://github.com/Live-Hack-CVE/CVE-2023-22451) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22451.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22451.svg)

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

## CVE-2023-0029
 A vulnerability was found in Multilaser RE708 RE1200R4GC-2T2R-V3_v3411b_MUL029B. It has been rated as problematic. This issue affects some unknown processing of the component Telnet Service. The manipulation leads to denial of service. The attack may be initiated remotely. The identifier VDB-217169 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0029](https://github.com/Live-Hack-CVE/CVE-2023-0029) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0029.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0029.svg)
