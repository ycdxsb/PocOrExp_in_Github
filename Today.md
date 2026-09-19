# Update 2026-09-19
## CVE-2026-92805
 UVdesk Community Skeleton through 1.1.8 fails to authenticate or validate installation state on wizard endpoints in ConfigureHelpdesk controller actions. Unauthenticated attackers can repoint the database and create super administrator accounts by submitting crafted requests to wizard endpoints, gaining full control of the instance.

- [https://github.com/cflowsec/CVE-2026-92805](https://github.com/cflowsec/CVE-2026-92805) :  ![starts](https://img.shields.io/github/stars/cflowsec/CVE-2026-92805.svg) ![forks](https://img.shields.io/github/forks/cflowsec/CVE-2026-92805.svg)


## CVE-2026-92247
 A security vulnerability has been detected in synaptikcms synaptik-cms up to 1.3.4.4. This affects the function rename of the file admin/file-manager.php of the component Admin File Manager. The manipulation leads to unrestricted upload. The attack can be initiated remotely. The exploit has been disclosed publicly and may be used. Upgrading to version 1.3.5 is able to mitigate this issue. It is suggested to upgrade the affected component.

- [https://github.com/d1n3sh-0x3/CVE-2026-92247](https://github.com/d1n3sh-0x3/CVE-2026-92247) :  ![starts](https://img.shields.io/github/stars/d1n3sh-0x3/CVE-2026-92247.svg) ![forks](https://img.shields.io/github/forks/d1n3sh-0x3/CVE-2026-92247.svg)


## CVE-2026-91843
 A stack overflow during the unauthenticated login process may allow an attacker to run arbitrary code remotely with root privileges.

- [https://github.com/HORKimhab/CVE-2026-91843](https://github.com/HORKimhab/CVE-2026-91843) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-91843.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-91843.svg)


## CVE-2026-89026
 The Issabel Framework, the web framework supporting Issabel PBX software, before commit b97dbaf contains a hard-coded HS256 JWT signing key in the pbxapi index.php file that is identical across every installation, allowing unauthenticated remote attackers to forge valid bearer tokens. Attackers can use the forged token to call the manager originate endpoint with the System application parameter, causing Asterisk to execute arbitrary OS commands as the Asterisk user. Exploitation evidence was first observed by the Shadowserver Foundation on 2026-09-09.

- [https://github.com/cflowsec/CVE-2026-89026](https://github.com/cflowsec/CVE-2026-89026) :  ![starts](https://img.shields.io/github/stars/cflowsec/CVE-2026-89026.svg) ![forks](https://img.shields.io/github/forks/cflowsec/CVE-2026-89026.svg)


## CVE-2026-88899
 knowns versions before 0.31.0 fail to properly validate the x-opencode-directory request header in the /api/opencode proxy endpoint. Remote attackers can supply arbitrary directory paths to execute file operations outside the project root on the host system.

- [https://github.com/uziii2208/CVE-2026-88899](https://github.com/uziii2208/CVE-2026-88899) :  ![starts](https://img.shields.io/github/stars/uziii2208/CVE-2026-88899.svg) ![forks](https://img.shields.io/github/forks/uziii2208/CVE-2026-88899.svg)


## CVE-2026-87930
 MaxSite CMS through 109.6 passes the ci_session cookie to unserialize() without class restrictions, allowing unauthenticated attackers to inject PHP objects. Attackers can forge valid session cookies using the hardcoded encryption key to trigger magic methods and corrupt application state or achieve code execution if gadget classes exist.

- [https://github.com/winrarzipsexploit/CVE-2026-87930](https://github.com/winrarzipsexploit/CVE-2026-87930) :  ![starts](https://img.shields.io/github/stars/winrarzipsexploit/CVE-2026-87930.svg) ![forks](https://img.shields.io/github/forks/winrarzipsexploit/CVE-2026-87930.svg)


## CVE-2026-87796
 The Multi Uploader for Gravity Forms plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 1.1.9 via the move_file function. This is due to insufficient file type validation during chunked upload handling. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/abraxas/CVE-2026-87796](https://github.com/abraxas/CVE-2026-87796) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-87796.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-87796.svg)


## CVE-2026-86259
 OpenMAIC before 1.0.1 skips server-side request forgery validation in non-production builds, allowing unauthenticated attackers to reach cloud instance metadata services. Attackers can supply arbitrary provider URLs via the x-base-url header or baseUrl parameter to access sensitive cloud credentials and metadata.

- [https://github.com/uziii2208/CVE-2026-86259](https://github.com/uziii2208/CVE-2026-86259) :  ![starts](https://img.shields.io/github/stars/uziii2208/CVE-2026-86259.svg) ![forks](https://img.shields.io/github/forks/uziii2208/CVE-2026-86259.svg)


## CVE-2026-86218
 N-central is vulnerable to a pre-auth remote code execution This issue affects N-central: before 2026.3.1.14.

- [https://github.com/Udyz/CVE-2026-86218](https://github.com/Udyz/CVE-2026-86218) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2026-86218.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2026-86218.svg)


## CVE-2026-85706
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.7 before 19.1.8, 19.2 before 19.2.6, and 19.3 before 19.3.2 that, under certain conditions, an unauthenticated user could have read arbitrary files from the GitLab server due to improper path confinement and missing authentication enforcement in the repository commits API.

- [https://github.com/tc4dy/CVE-2026-85706-PoC-Toolkit](https://github.com/tc4dy/CVE-2026-85706-PoC-Toolkit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-85706-PoC-Toolkit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-85706-PoC-Toolkit.svg)
- [https://github.com/0xenesbayram/cve-2026-85706](https://github.com/0xenesbayram/cve-2026-85706) :  ![starts](https://img.shields.io/github/stars/0xenesbayram/cve-2026-85706.svg) ![forks](https://img.shields.io/github/forks/0xenesbayram/cve-2026-85706.svg)


## CVE-2026-85048
 Use after free in Compositing in Google Chrome prior to 152.0.7977.82 allowed a remote attacker who had compromised the renderer process to execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/SneakyNachos/CVE-2026-85048-the-gpu-died](https://github.com/SneakyNachos/CVE-2026-85048-the-gpu-died) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-85048-the-gpu-died.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-85048-the-gpu-died.svg)


## CVE-2026-85045
 Race condition in V8 in Google Chrome prior to 152.0.7977.82 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/SneakyNachos/CVE-2026-85045](https://github.com/SneakyNachos/CVE-2026-85045) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-85045.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-85045.svg)


## CVE-2026-84616
 A type confusion issue was addressed with improved memory handling. This issue is fixed in iOS 26.7 and iPadOS 26.7, iOS 27 and iPadOS 27, macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7, tvOS 27, visionOS 27, watchOS 27. An app may be able to cause unexpected system termination.

- [https://github.com/Ping-2o/ios.CVE-2026-84616-84607](https://github.com/Ping-2o/ios.CVE-2026-84616-84607) :  ![starts](https://img.shields.io/github/stars/Ping-2o/ios.CVE-2026-84616-84607.svg) ![forks](https://img.shields.io/github/forks/Ping-2o/ios.CVE-2026-84616-84607.svg)


## CVE-2026-84607
 A race condition was addressed with improved state management. This issue is fixed in iOS 26.7 and iPadOS 26.7, iOS 27 and iPadOS 27, macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7, tvOS 27, visionOS 27, watchOS 27. A sandboxed app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/Ping-2o/ios.CVE-2026-84616-84607](https://github.com/Ping-2o/ios.CVE-2026-84616-84607) :  ![starts](https://img.shields.io/github/stars/Ping-2o/ios.CVE-2026-84616-84607.svg) ![forks](https://img.shields.io/github/forks/Ping-2o/ios.CVE-2026-84616-84607.svg)


## CVE-2026-84600
 An authorization issue was addressed with improved state management. This issue is fixed in iOS 27 and iPadOS 27, macOS Golden Gate 27, tvOS 27, visionOS 27, watchOS 27. A malicious shortcut may be able to send messages without user confirmation.

- [https://github.com/OwenPawl/CVE-2026-84600](https://github.com/OwenPawl/CVE-2026-84600) :  ![starts](https://img.shields.io/github/stars/OwenPawl/CVE-2026-84600.svg) ![forks](https://img.shields.io/github/forks/OwenPawl/CVE-2026-84600.svg)


## CVE-2026-82329
 JFrog Artifactory contains an authentication weakness that, under default configuration, may allow an unauthenticated attacker with network access to obtain administrative privileges.

- [https://github.com/tc4dy/CVE-2026-82329-PoC-Exploit](https://github.com/tc4dy/CVE-2026-82329-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-82329-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-82329-PoC-Exploit.svg)


## CVE-2026-82090
 Pocket through 8.33.0.0 allows XSS because "Save to Pocket" injects external HTML into the DOM.  JavaScript code can alter the application state via native bridge methods.

- [https://github.com/FUNFACTOR1/CVE-2026-82090-18-Years-All-Versions-CVSS-9.2-CRITICAL-The-Pocket-Forever-Day](https://github.com/FUNFACTOR1/CVE-2026-82090-18-Years-All-Versions-CVSS-9.2-CRITICAL-The-Pocket-Forever-Day) :  ![starts](https://img.shields.io/github/stars/FUNFACTOR1/CVE-2026-82090-18-Years-All-Versions-CVSS-9.2-CRITICAL-The-Pocket-Forever-Day.svg) ![forks](https://img.shields.io/github/forks/FUNFACTOR1/CVE-2026-82090-18-Years-All-Versions-CVSS-9.2-CRITICAL-The-Pocket-Forever-Day.svg)


## CVE-2026-80521
Let's unlink scc_entry before freeing the vertex in unix_del_edge().

- [https://github.com/Markakd/Container_escape](https://github.com/Markakd/Container_escape) :  ![starts](https://img.shields.io/github/stars/Markakd/Container_escape.svg) ![forks](https://img.shields.io/github/forks/Markakd/Container_escape.svg)


## CVE-2026-80467
 The Advanced Custom Fields: Extended WordPress plugin before 0.9.2.7 does not restrict the role submitted through its front-end user forms to the roles the form actually offers, and its safeguard against privileged roles is incomplete, allowing unauthenticated visitors to register an account with elevated capabilities and then escalate it to administrator.

- [https://github.com/SangSenimanWartefak/CVE-2026-80467](https://github.com/SangSenimanWartefak/CVE-2026-80467) :  ![starts](https://img.shields.io/github/stars/SangSenimanWartefak/CVE-2026-80467.svg) ![forks](https://img.shields.io/github/forks/SangSenimanWartefak/CVE-2026-80467.svg)


## CVE-2026-80428
 ILIAS before versions 9.22, 10.10, and 11.3 contains an unauthenticated PHP object injection vulnerability that allows unauthenticated attackers to execute arbitrary code by injecting serialized objects through the LTI authentication endpoint and triggering deserialization via the Shibboleth back-channel logout endpoint. Attackers can write arbitrary serialized objects into session storage, then exploit an available POP gadget through the logout endpoint's unrestricted deserialization to write attacker-controlled PHP content to a web-accessible path and achieve remote code execution as the web server user.

- [https://github.com/shivammittal2403/cve-2026-80428-ctf](https://github.com/shivammittal2403/cve-2026-80428-ctf) :  ![starts](https://img.shields.io/github/stars/shivammittal2403/cve-2026-80428-ctf.svg) ![forks](https://img.shields.io/github/forks/shivammittal2403/cve-2026-80428-ctf.svg)


## CVE-2026-79551
 Tenda Technology Co., Ltd NVR_4H CH3 v2.1 V27.5.58.6 was discovered to contain a hardcoded cryptographic key.

- [https://github.com/snyi001/CVE-2026-79551-Tenda](https://github.com/snyi001/CVE-2026-79551-Tenda) :  ![starts](https://img.shields.io/github/stars/snyi001/CVE-2026-79551-Tenda.svg) ![forks](https://img.shields.io/github/forks/snyi001/CVE-2026-79551-Tenda.svg)


## CVE-2026-79303
 kaiten from 57.192.20 to before 57.214.26 is vulnerable to SQL Injection. Dynamic SQL statements are generated without the required data validation and without using parameterized statements or stored procedures.

- [https://github.com/4ybrick/CVE-2026-79303](https://github.com/4ybrick/CVE-2026-79303) :  ![starts](https://img.shields.io/github/stars/4ybrick/CVE-2026-79303.svg) ![forks](https://img.shields.io/github/forks/4ybrick/CVE-2026-79303.svg)


## CVE-2026-79298
 An issue in Howyar Technologies Inc SysReturn Versions prior to 11.3.034 and fixed in v.11.3.0.34 allows a local attcker to execute arbitrary code via the BOOTia32.efi and a crafted cloak32.dat file on the ESP.

- [https://github.com/TheMalwareGuardian/CVE-2026-79298](https://github.com/TheMalwareGuardian/CVE-2026-79298) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2026-79298.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2026-79298.svg)
- [https://github.com/TheMalwareGuardian/UEFI-Security-Research-Howyar-SysReturn-NetCopy](https://github.com/TheMalwareGuardian/UEFI-Security-Research-Howyar-SysReturn-NetCopy) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/UEFI-Security-Research-Howyar-SysReturn-NetCopy.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/UEFI-Security-Research-Howyar-SysReturn-NetCopy.svg)


## CVE-2026-77179
 On macOS, the virtio-fs host server used by Docker Sandboxes improperly follows symlinks when reopening an unlinked file from a stored path. A malicious guest can replace a parent directory with a symlink, escape the shared workspace, and read or modify arbitrary host files as the VMM user, potentially achieving host code execution.

- [https://github.com/HORKimhab/CVE-2026-77179](https://github.com/HORKimhab/CVE-2026-77179) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-77179.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-77179.svg)


## CVE-2026-76461
This vulnerability is due to insufficient validation in the email parsing logic. An attacker could exploit this vulnerability by sending a crafted email message that contains malicious SQL statements through an affected device. A successful exploit could allow the attacker to execute arbitrary SQL statements, leading to command execution with root privileges on the underlying operating system.

- [https://github.com/S3v3n-JG/CVE-2026-76461](https://github.com/S3v3n-JG/CVE-2026-76461) :  ![starts](https://img.shields.io/github/stars/S3v3n-JG/CVE-2026-76461.svg) ![forks](https://img.shields.io/github/forks/S3v3n-JG/CVE-2026-76461.svg)
- [https://github.com/0xBlackash/CVE-2026-76461](https://github.com/0xBlackash/CVE-2026-76461) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-76461.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-76461.svg)
- [https://github.com/HORKimhab/CVE-2026-76461](https://github.com/HORKimhab/CVE-2026-76461) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-76461.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-76461.svg)
- [https://github.com/fevar54/CVE-2026-76461-Detection-Kit-](https://github.com/fevar54/CVE-2026-76461-Detection-Kit-) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-76461-Detection-Kit-.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-76461-Detection-Kit-.svg)


## CVE-2026-76460
This vulnerability is due to insufficient authentication control on an API endpoint. An attacker could exploit this vulnerability by sending a crafted request to an affected API endpoint. A successful exploit could allow the attacker to gain unauthorized access to the affected device by bypassing the web-based management interface.

- [https://github.com/S3v3n-JG/CVE-2026-76460](https://github.com/S3v3n-JG/CVE-2026-76460) :  ![starts](https://img.shields.io/github/stars/S3v3n-JG/CVE-2026-76460.svg) ![forks](https://img.shields.io/github/forks/S3v3n-JG/CVE-2026-76460.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/34zY/CVE-2026-72898](https://github.com/34zY/CVE-2026-72898) :  ![starts](https://img.shields.io/github/stars/34zY/CVE-2026-72898.svg) ![forks](https://img.shields.io/github/forks/34zY/CVE-2026-72898.svg)


## CVE-2026-72710
 SPIP before 4.4.18 contains a mass assignment vulnerability in the editer_objet action that allows unauthenticated attackers to write arbitrary rows to any SQL table lacking a champs_editables allowlist by supplying an attacker-controlled arg parameter resolving to internal database tables. Attackers can insert a malicious row into the spip_jobs queue with a controlled PHP function and arguments, which is then dynamically executed when the cron processes the queue, resulting in remote code execution.

- [https://github.com/ambionics/spip-exploits](https://github.com/ambionics/spip-exploits) :  ![starts](https://img.shields.io/github/stars/ambionics/spip-exploits.svg) ![forks](https://img.shields.io/github/forks/ambionics/spip-exploits.svg)


## CVE-2026-72709
 SPIP before version 4.4.18 contains a missing authorization vulnerability in sensitive actions under ecrire/action/ that allows unauthenticated attackers to invoke privileged actions by supplying only a valid CSRF nonce without any server-side permission check. Attackers can bypass template-level authorization guards through direct HTTP requests to invoke actions such as editer_auteur, enabling arbitrary account password rewrites including administrator accounts and resulting in full account takeover.

- [https://github.com/ambionics/spip-exploits](https://github.com/ambionics/spip-exploits) :  ![starts](https://img.shields.io/github/stars/ambionics/spip-exploits.svg) ![forks](https://img.shields.io/github/forks/ambionics/spip-exploits.svg)


## CVE-2026-72708
 SPIP before 4.4.18 contains an unauthenticated blind SQL injection vulnerability in the SQL escaping layer that allows unauthenticated attackers to inject arbitrary SQL by supplying a crafted annee parameter value matching a word character followed by an open parenthesis, which bypasses escaping for date-type columns across MySQL, SQLite, and PostgreSQL backends. Attackers can exploit the always-present sitemap.xml.html template's annee criterion to embed unescaped time-based or boolean payloads into database queries, enabling extraction of arbitrary database content including the alea_ephemere secret used to sign SPIP action nonces.

- [https://github.com/ambionics/spip-exploits](https://github.com/ambionics/spip-exploits) :  ![starts](https://img.shields.io/github/stars/ambionics/spip-exploits.svg) ![forks](https://img.shields.io/github/forks/ambionics/spip-exploits.svg)


## CVE-2026-69328
 Untrusted search path in Windows Storage allows an authorized attacker to elevate privileges locally.

- [https://github.com/0xf9b6a41ec/CVE-2026-69328](https://github.com/0xf9b6a41ec/CVE-2026-69328) :  ![starts](https://img.shields.io/github/stars/0xf9b6a41ec/CVE-2026-69328.svg) ![forks](https://img.shields.io/github/forks/0xf9b6a41ec/CVE-2026-69328.svg)


## CVE-2026-69212
 Http4s is a Scala interface for HTTP services. Prior to 0.23.35 and 1.0.0-M47, The FollowRedirect client middleware strips Authorization and Cookie headers only when a redirect changes authority, but authority comparison excludes the URI scheme. A same-authority redirect from HTTPS to HTTP therefore preserves credentials and transmits them over a plaintext connection. An attacker who can induce the downgrade and observe the network can capture those sensitive headers from applications using FollowRedirect. This issue is fixed in versions 0.23.35 and 1.0.0-M47.

- [https://github.com/c0gnit00/CVE-2026-69212](https://github.com/c0gnit00/CVE-2026-69212) :  ![starts](https://img.shields.io/github/stars/c0gnit00/CVE-2026-69212.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/CVE-2026-69212.svg)


## CVE-2026-67401
 A vulnerability in cPanel allows a mail-enabled account to achieve remote code execution as root through SQLi in EmailTrack component

- [https://github.com/imbas007/CVE-2026-67401](https://github.com/imbas007/CVE-2026-67401) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2026-67401.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2026-67401.svg)


## CVE-2026-65616
 Incorrect authorization validation in refresh token signature allows non-admin users to obtain a signed JFrog administrator token.

- [https://github.com/alixiacf/rep-openai-artifactory](https://github.com/alixiacf/rep-openai-artifactory) :  ![starts](https://img.shields.io/github/stars/alixiacf/rep-openai-artifactory.svg) ![forks](https://img.shields.io/github/forks/alixiacf/rep-openai-artifactory.svg)


## CVE-2026-65374
 A memory corruption issue was addressed with improved validation. This issue is fixed in macOS Golden Gate 27, macOS Sequoia 15.8, macOS Tahoe 26.7. Connecting to a malicious WebDAV server may result in code execution.

- [https://github.com/HORKimhab/CVE-2026-65374](https://github.com/HORKimhab/CVE-2026-65374) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-65374.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-65374.svg)


## CVE-2026-65343
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 26.6.1 and iPadOS 26.6.1, macOS Tahoe 26.6.2, tvOS 27, visionOS 27, watchOS 27. A remote attacker may be able to cause unexpected system termination.

- [https://github.com/hidayat-tanjung/CVE-2026-65343-e7eb2ed](https://github.com/hidayat-tanjung/CVE-2026-65343-e7eb2ed) :  ![starts](https://img.shields.io/github/stars/hidayat-tanjung/CVE-2026-65343-e7eb2ed.svg) ![forks](https://img.shields.io/github/forks/hidayat-tanjung/CVE-2026-65343-e7eb2ed.svg)


## CVE-2026-65330
 The issue was addressed with improved memory handling. This issue is fixed in iOS 26.6.1 and iPadOS 26.6.1, macOS Sequoia 15.8, macOS Tahoe 26.6.2, tvOS 27, visionOS 27, watchOS 27. An app may be able to cause unexpected system termination or corrupt kernel memory.

- [https://github.com/csrXamfi/CVE-2026-65330](https://github.com/csrXamfi/CVE-2026-65330) :  ![starts](https://img.shields.io/github/stars/csrXamfi/CVE-2026-65330.svg) ![forks](https://img.shields.io/github/forks/csrXamfi/CVE-2026-65330.svg)


## CVE-2026-65013
 Onlook through 0.2.32, fixed in commit 423e2e9, contains a broken object level authorization vulnerability that allows authenticated attackers to access and manipulate other users' resources by supplying arbitrary UUID values to tRPC API procedures including project.get, member.remove, and chat.conversation.delete. Attackers can provide arbitrary projectId or conversationId values without authorization validation to read, modify, and delete other users' project data, members, and conversation history.

- [https://github.com/isaca0315/CVE-2026-65013-BOLA-IDOR](https://github.com/isaca0315/CVE-2026-65013-BOLA-IDOR) :  ![starts](https://img.shields.io/github/stars/isaca0315/CVE-2026-65013-BOLA-IDOR.svg) ![forks](https://img.shields.io/github/forks/isaca0315/CVE-2026-65013-BOLA-IDOR.svg)


## CVE-2026-60004
 Gitea before 1.27.1 allows remote code execution via the diffpatch API through Git hook installation.

- [https://github.com/erberkan/CVE-2026-60004-PoC](https://github.com/erberkan/CVE-2026-60004-PoC) :  ![starts](https://img.shields.io/github/stars/erberkan/CVE-2026-60004-PoC.svg) ![forks](https://img.shields.io/github/forks/erberkan/CVE-2026-60004-PoC.svg)


## CVE-2026-59827
 Metabase is an open-source business intelligence and embedded analytics tool. Prior to 1.58.15, 1.59.12, 1.60.6.3, and 1.61.1.4, Metabase instances with an H2 database connection, including the default sample database, deserialize arbitrary Java objects returned in H2 native query result columns of type OTHER without validation, allowing an authenticated user who can run native H2 queries to execute code on the Metabase server. This issue is fixed in versions 1.58.15, 1.59.12, 1.60.6.3, and 1.61.1.4.

- [https://github.com/shivammittal2403/cve-2026-59827-metabase-cyber-range](https://github.com/shivammittal2403/cve-2026-59827-metabase-cyber-range) :  ![starts](https://img.shields.io/github/stars/shivammittal2403/cve-2026-59827-metabase-cyber-range.svg) ![forks](https://img.shields.io/github/forks/shivammittal2403/cve-2026-59827-metabase-cyber-range.svg)


## CVE-2026-59550
 Unauthenticated SQL Injection in AWP Classifieds = 4.4.7 versions.

- [https://github.com/FLX-0x00/CVE-2026-59550](https://github.com/FLX-0x00/CVE-2026-59550) :  ![starts](https://img.shields.io/github/stars/FLX-0x00/CVE-2026-59550.svg) ![forks](https://img.shields.io/github/forks/FLX-0x00/CVE-2026-59550.svg)


## CVE-2026-56096
 The extension passes the user-supplied search query parameter to Apache Solr without restricting advanced Solr query syntax such as wildcards, field selectors and range queries. A remote, unauthenticated attacker can use this syntax to enumerate indexed field names and extract their stored values through boolean- and range-based blind extraction techniques, independent of any site-specific configuration.

- [https://github.com/yairHinkis/CVE-2026-56096](https://github.com/yairHinkis/CVE-2026-56096) :  ![starts](https://img.shields.io/github/stars/yairHinkis/CVE-2026-56096.svg) ![forks](https://img.shields.io/github/forks/yairHinkis/CVE-2026-56096.svg)


## CVE-2026-55781
 NanaZip is the 7-Zip derivative intended for the modern Windows experience. Prior to 6.5.1749.0, NanaZip's UFS and FFS image handler in NanaZip.Codecs.Archive.Ufs.cpp validates the superblock block size only against the MINBSIZE lower bound and does not validate the fs_fsize fragment size, allowing attacker-controlled 32-bit fields to flow into indirect-block, directory, and extraction buffer allocations. A tiny crafted UFS image can force multi-gigabyte allocations during open or extraction, causing memory exhaustion or process termination. This issue is fixed in version 6.5.1749.0.

- [https://github.com/g17hubH4ck/CVE-2026-55781-poc](https://github.com/g17hubH4ck/CVE-2026-55781-poc) :  ![starts](https://img.shields.io/github/stars/g17hubH4ck/CVE-2026-55781-poc.svg) ![forks](https://img.shields.io/github/forks/g17hubH4ck/CVE-2026-55781-poc.svg)


## CVE-2026-54597
 ITFlow provides an IT documentation, ticketing and accounting system for small managed service providers. Prior to version 26.07, an authenticated user with module_support write permission and access to a credential record can perform time-based blind SQL injection through the expires parameter of the share_generate_link handler in agent/ajax.php. sanitizeInput applies string-context escaping, but expires is inserted unquoted into the item_expire_at MySQL INTERVAL expression, allowing a crafted expression and interval unit to execute conditional database queries whose results are inferred from response delays. This can expose password hashes, SMTP credentials, API keys, encrypted vault data, and database metadata and support administrative takeover after credential cracking. This issue is fixed in version 26.07.

- [https://github.com/iltosec/CVE-2026-54597](https://github.com/iltosec/CVE-2026-54597) :  ![starts](https://img.shields.io/github/stars/iltosec/CVE-2026-54597.svg) ![forks](https://img.shields.io/github/forks/iltosec/CVE-2026-54597.svg)


## CVE-2026-54596
 ITFlow provides an IT documentation, ticketing and accounting system for small managed service providers. Prior to version 26.07, an authenticated Technician or higher with access to at least one client invoice can inject SQL through the frequency parameter handled by agent/post/recurring_invoice.php. The handler passes recurring_invoice_frequency through sanitizeInput but interpolates it unquoted into DATE_ADD, allowing SQL syntax to escape the interval expression, assign additional INSERT columns, store subquery results in recurring_invoice_note, and expose those results through agent/recurring_invoice.php. The persisted recurring_invoice_frequency can execute again when Force Recurring uses it in a later UPDATE, allowing another legitimate user to trigger the second-order injection. This can expose password hashes, SMTP credentials, user records, and database metadata, modify database fields, and enable administrative takeover after credential cracking. This issue is fixed in version 26.07.

- [https://github.com/iltosec/CVE-2026-54596](https://github.com/iltosec/CVE-2026-54596) :  ![starts](https://img.shields.io/github/stars/iltosec/CVE-2026-54596.svg) ![forks](https://img.shields.io/github/forks/iltosec/CVE-2026-54596.svg)


## CVE-2026-54520
 AI Agent Automation is a modular AI agent workflow automation platform with schedulers, tools, and observability. Prior to 0.9.1, the executeStep file-step implementation in backend/src/agents/executor.js passes the user-controlled step.path value through path.resolve with process.cwd() and then uses the resulting path for read or write operations without checking that it remains in an approved workflow directory. An authenticated user who can create or modify workflow file steps can supply traversal segments to escape the intended workspace and read sensitive files or write and overwrite files accessible to the backend process, including application-adjacent files when process permissions allow. This issue is fixed in version 0.9.1.

- [https://github.com/chaitanyagarware/CVE-2026-54520](https://github.com/chaitanyagarware/CVE-2026-54520) :  ![starts](https://img.shields.io/github/stars/chaitanyagarware/CVE-2026-54520.svg) ![forks](https://img.shields.io/github/forks/chaitanyagarware/CVE-2026-54520.svg)


## CVE-2026-54519
 AI Agent Automation is a modular AI agent workflow automation platform with schedulers, tools, and observability. Prior to 0.9.1, backend/src/controllers/memory.controller.js authenticates requests but listMemories, deleteMemory, and clearAgentMemory use a caller-supplied agentId or memory _id without verifying through the related Agent that the record belongs to req.user. An authenticated attacker who knows or obtains another user's identifiers can read victim AgentMemory content, including conversation history, agent context, task data, embeddings, and metadata, delete an individual victim memory, or clear all memory belonging to a victim agent. This breaks tenant isolation and causes unauthorized disclosure and data loss. This issue is fixed in version 0.9.1.

- [https://github.com/chaitanyagarware/CVE-2026-54519](https://github.com/chaitanyagarware/CVE-2026-54519) :  ![starts](https://img.shields.io/github/stars/chaitanyagarware/CVE-2026-54519.svg) ![forks](https://img.shields.io/github/forks/chaitanyagarware/CVE-2026-54519.svg)


## CVE-2026-54512
 jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. From 2.10.0 until 2.18.8, 2.21.4, and 3.1.4, jackson-databind's PolymorphicTypeValidator (PTV) is the primary safety mechanism guarding polymorphic deserialization. When polymorphic typing is enabled and a type identifier contains generic parameters (i.e. the type ID string contains ), DatabindContext._resolveAndValidateGeneric() validates only the raw container class name (the substring before ) against the configured PTV. If the container type is approved, the method parses the full canonical type string via TypeFactory.constructFromCanonical() and returns the fully parameterized type without ever validating the nested type arguments against the PTV. The nested type arguments are then resolved, instantiated, and populated as beans during deserialization. An attacker who controls the type ID can therefore place a denied class as a generic type parameter of an allowed container — for example java.util.ArrayListcom.evil.Gadget when only java.util.ArrayList is allow-listed. The container passes the PTV check; com.evil.Gadget is loaded via Class.forName(name, true, loader), instantiated, and its properties are set from attacker-controlled JSON. This completely bypasses an explicitly configured PTV allow-list. This vulnerability is fixed in 2.18.8, 2.21.4, and 3.1.4.

- [https://github.com/avergnaud/flight-sql-jdbc-driver-cve-2026-54512](https://github.com/avergnaud/flight-sql-jdbc-driver-cve-2026-54512) :  ![starts](https://img.shields.io/github/stars/avergnaud/flight-sql-jdbc-driver-cve-2026-54512.svg) ![forks](https://img.shields.io/github/forks/avergnaud/flight-sql-jdbc-driver-cve-2026-54512.svg)
- [https://github.com/cklinisme/doris-spark-connector-cve](https://github.com/cklinisme/doris-spark-connector-cve) :  ![starts](https://img.shields.io/github/stars/cklinisme/doris-spark-connector-cve.svg) ![forks](https://img.shields.io/github/forks/cklinisme/doris-spark-connector-cve.svg)


## CVE-2026-54337
 Fireshare facilitates self-hosted media and link sharing. Prior to version 1.6.14, an argument Injection in the video upload function allows unauthenticated attacker to write/overwrite system files. Version 1.6.14 fixes the issue.

- [https://github.com/4qu4r1um/CVE-2026-54337-PoC](https://github.com/4qu4r1um/CVE-2026-54337-PoC) :  ![starts](https://img.shields.io/github/stars/4qu4r1um/CVE-2026-54337-PoC.svg) ![forks](https://img.shields.io/github/forks/4qu4r1um/CVE-2026-54337-PoC.svg)


## CVE-2026-52910
---truncated---

- [https://github.com/yolkfull/cve-2026-52910-poc](https://github.com/yolkfull/cve-2026-52910-poc) :  ![starts](https://img.shields.io/github/stars/yolkfull/cve-2026-52910-poc.svg) ![forks](https://img.shields.io/github/forks/yolkfull/cve-2026-52910-poc.svg)
- [https://github.com/Markakd/Container_escape](https://github.com/Markakd/Container_escape) :  ![starts](https://img.shields.io/github/stars/Markakd/Container_escape.svg) ![forks](https://img.shields.io/github/forks/Markakd/Container_escape.svg)


## CVE-2026-52824
 Kimai is an open-source time tracking application. Prior to 2.58.0, the official Docker image sets APP_SECRET to the public value change_this_to_something_unique in Dockerfile, and .docker/entrypoint.sh neither replaces nor rejects that value before Symfony uses it as kernel.secret. An unauthenticated attacker who reaches a deployment that did not override APP_SECRET, knows a username, correctly guesses the account ID associated with that username, and targets an account without active two-factor authentication can forge HMAC-protected authentication artifacts, including KIMAI_REMEMBER cookies and login links, to access the account without its password. The updated entrypoint generates and persists a random secret when no safe operator-provided value exists. This issue is fixed in version 2.58.0.

- [https://github.com/AzureADTrent/CVE-2026-52824](https://github.com/AzureADTrent/CVE-2026-52824) :  ![starts](https://img.shields.io/github/stars/AzureADTrent/CVE-2026-52824.svg) ![forks](https://img.shields.io/github/forks/AzureADTrent/CVE-2026-52824.svg)
- [https://github.com/cyeezy08/Kimai-CVE-2026-49865-POC](https://github.com/cyeezy08/Kimai-CVE-2026-49865-POC) :  ![starts](https://img.shields.io/github/stars/cyeezy08/Kimai-CVE-2026-49865-POC.svg) ![forks](https://img.shields.io/github/forks/cyeezy08/Kimai-CVE-2026-49865-POC.svg)


## CVE-2026-51990
 An issue in Sogou Sogou Input Method  16.3.0.3498 (fixed in 16.3.0.3498) allows a remote attacker to execute arbitrary code via the biz_helper.exe component

- [https://github.com/HORKimhab/CVE-2026-51990](https://github.com/HORKimhab/CVE-2026-51990) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-51990.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-51990.svg)


## CVE-2026-49975
This issue affects Apache HTTP Server: from 2.4.17 through 2.4.67.

- [https://github.com/naheeju/POC-CVE-2026-49975](https://github.com/naheeju/POC-CVE-2026-49975) :  ![starts](https://img.shields.io/github/stars/naheeju/POC-CVE-2026-49975.svg) ![forks](https://img.shields.io/github/forks/naheeju/POC-CVE-2026-49975.svg)


## CVE-2026-49268
Upgrade to Apache Shiro 2.2.1 or 3.0.0-alpha-2 or later, which fixes the issue.

- [https://github.com/sassoftware/shiro](https://github.com/sassoftware/shiro) :  ![starts](https://img.shields.io/github/stars/sassoftware/shiro.svg) ![forks](https://img.shields.io/github/forks/sassoftware/shiro.svg)


## CVE-2026-49179
 Improper neutralization of special elements used in a command ('command injection') in Windows Active Directory allows an unauthorized attacker to execute code over a network.

- [https://github.com/overgrowncarrot1/CVE-2026-49179-Active-Directory-WriteSPNScript-Command-Injection](https://github.com/overgrowncarrot1/CVE-2026-49179-Active-Directory-WriteSPNScript-Command-Injection) :  ![starts](https://img.shields.io/github/stars/overgrowncarrot1/CVE-2026-49179-Active-Directory-WriteSPNScript-Command-Injection.svg) ![forks](https://img.shields.io/github/forks/overgrowncarrot1/CVE-2026-49179-Active-Directory-WriteSPNScript-Command-Injection.svg)


## CVE-2026-48908
 A vulnerability in SP Page Builder for Joomla allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.

- [https://github.com/winrarzipsexploit/CVE-2026-48908](https://github.com/winrarzipsexploit/CVE-2026-48908) :  ![starts](https://img.shields.io/github/stars/winrarzipsexploit/CVE-2026-48908.svg) ![forks](https://img.shields.io/github/forks/winrarzipsexploit/CVE-2026-48908.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/NONAME-ELV/CVE-2026-48907](https://github.com/NONAME-ELV/CVE-2026-48907) :  ![starts](https://img.shields.io/github/stars/NONAME-ELV/CVE-2026-48907.svg) ![forks](https://img.shields.io/github/forks/NONAME-ELV/CVE-2026-48907.svg)


## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/theendofabbys/pedit-cow](https://github.com/theendofabbys/pedit-cow) :  ![starts](https://img.shields.io/github/stars/theendofabbys/pedit-cow.svg) ![forks](https://img.shields.io/github/forks/theendofabbys/pedit-cow.svg)


## CVE-2026-44840
 Dgraph is an open source distributed GraphQL database. Prior to version 25.3.4, the `checkUserPassword` GraphQL query in Dgraph is vulnerable to DQL (Dgraph Query Language) injection. User-supplied password values are interpolated directly into a DQL `checkpwd()` query via `fmt.Sprintf` without any escaping or parameterization. An attacker can inject a password containing a double-quote character to break out of the DQL string literal and append arbitrary DQL query blocks. Version 25.3.4 patches the issue.

- [https://github.com/isaca0315/CVE-2026-44840-poc](https://github.com/isaca0315/CVE-2026-44840-poc) :  ![starts](https://img.shields.io/github/stars/isaca0315/CVE-2026-44840-poc.svg) ![forks](https://img.shields.io/github/forks/isaca0315/CVE-2026-44840-poc.svg)


## CVE-2026-44351
 fast-jwt provides fast JSON Web Token (JWT) implementation. Prior to 6.2.4, a critical authentication-bypass vulnerability in fast-jwt's async key-resolver flow allows any unauthenticated attacker to forge arbitrary JWTs that are accepted as authentic. When the application's key resolver returns an empty string (''), for example via the common keys[decoded.header.kid] || '' JWKS-style fallback, fast-jwt converts it to a zero-length Buffer, hands it to crypto.createSecretKey, derives allowedAlgorithms = ['HS256','HS384','HS512'] from it, and then verifies the token's signature against an empty-key HMAC. The attacker simply computes HMAC-SHA256(key='', input='${header}.${payload}'), which Node accepts without complaint — and the verifier returns the attacker-chosen payload (sub, admin, scopes, etc.) as authentic. This vulnerability is fixed in 6.2.4.

- [https://github.com/isaca0315/CVE-2026-44351-poc](https://github.com/isaca0315/CVE-2026-44351-poc) :  ![starts](https://img.shields.io/github/stars/isaca0315/CVE-2026-44351-poc.svg) ![forks](https://img.shields.io/github/forks/isaca0315/CVE-2026-44351-poc.svg)


## CVE-2026-44246
 nnU-Net is a semantic segmentation framework that automatically adapts its pipeline to a dataset. Prior to 2.4.1, the nnU-Net Issue Triage workflow in .github/workflows/issue-triage.yml is vulnerable to Agentic Workflow Injection. The workflow sets allowed_non_write_users: ${{ github.event.issue.user.login }}, which means any logged-in GitHub user who opens an issue can reach this agentic workflow with attacker-controlled content. Untrusted issue title and body content are embedded directly into the prompt of anthropics/claude-code-action, and the workflow then runs a command-capable Claude agent with permission to comment on and relabel the current issue via gh. Because this workflow is triggered automatically on issues.opened, an external attacker can submit a crafted issue that steers the agent beyond its intended issue-triage purpose and influences authenticated issue actions. This vulnerability is fixed in 2.4.1.

- [https://github.com/sushant-me/agentic-workflow-injection](https://github.com/sushant-me/agentic-workflow-injection) :  ![starts](https://img.shields.io/github/stars/sushant-me/agentic-workflow-injection.svg) ![forks](https://img.shields.io/github/forks/sushant-me/agentic-workflow-injection.svg)


## CVE-2026-43783
 A race condition was addressed with improved locking. This issue is fixed in macOS Tahoe 26.6. A malicious app may be able to gain root privileges.

- [https://github.com/andrd3v/CVE-2026-43783](https://github.com/andrd3v/CVE-2026-43783) :  ![starts](https://img.shields.io/github/stars/andrd3v/CVE-2026-43783.svg) ![forks](https://img.shields.io/github/forks/andrd3v/CVE-2026-43783.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/zhubaohe123/ghostlock-kit](https://github.com/zhubaohe123/ghostlock-kit) :  ![starts](https://img.shields.io/github/stars/zhubaohe123/ghostlock-kit.svg) ![forks](https://img.shields.io/github/forks/zhubaohe123/ghostlock-kit.svg)
- [https://github.com/k-o-n-t-o-r/ghostlock-sabrina](https://github.com/k-o-n-t-o-r/ghostlock-sabrina) :  ![starts](https://img.shields.io/github/stars/k-o-n-t-o-r/ghostlock-sabrina.svg) ![forks](https://img.shields.io/github/forks/k-o-n-t-o-r/ghostlock-sabrina.svg)
- [https://github.com/hui191/cve-2026-43499-aak-an00](https://github.com/hui191/cve-2026-43499-aak-an00) :  ![starts](https://img.shields.io/github/stars/hui191/cve-2026-43499-aak-an00.svg) ![forks](https://img.shields.io/github/forks/hui191/cve-2026-43499-aak-an00.svg)
- [https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40](https://github.com/ccp-p/ghostlock-cve-2026-43499-4.19-k40) :  ![starts](https://img.shields.io/github/stars/ccp-p/ghostlock-cve-2026-43499-4.19-k40.svg) ![forks](https://img.shields.io/github/forks/ccp-p/ghostlock-cve-2026-43499-4.19-k40.svg)
- [https://github.com/kurtulusakyuz/IonStack_S21](https://github.com/kurtulusakyuz/IonStack_S21) :  ![starts](https://img.shields.io/github/stars/kurtulusakyuz/IonStack_S21.svg) ![forks](https://img.shields.io/github/forks/kurtulusakyuz/IonStack_S21.svg)
- [https://github.com/ymh001/meizu21-ghostlock-root](https://github.com/ymh001/meizu21-ghostlock-root) :  ![starts](https://img.shields.io/github/stars/ymh001/meizu21-ghostlock-root.svg) ![forks](https://img.shields.io/github/forks/ymh001/meizu21-ghostlock-root.svg)
- [https://github.com/mouseos/aquos-r6-ghostlock](https://github.com/mouseos/aquos-r6-ghostlock) :  ![starts](https://img.shields.io/github/stars/mouseos/aquos-r6-ghostlock.svg) ![forks](https://img.shields.io/github/forks/mouseos/aquos-r6-ghostlock.svg)
- [https://github.com/cyberbalsa/GhostLock-NVIDIA-Shield-9.2.4](https://github.com/cyberbalsa/GhostLock-NVIDIA-Shield-9.2.4) :  ![starts](https://img.shields.io/github/stars/cyberbalsa/GhostLock-NVIDIA-Shield-9.2.4.svg) ![forks](https://img.shields.io/github/forks/cyberbalsa/GhostLock-NVIDIA-Shield-9.2.4.svg)
- [https://github.com/genksome/ghost-hoock](https://github.com/genksome/ghost-hoock) :  ![starts](https://img.shields.io/github/stars/genksome/ghost-hoock.svg) ![forks](https://img.shields.io/github/forks/genksome/ghost-hoock.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/ctdal/cve-2026-41940-PoC](https://github.com/ctdal/cve-2026-41940-PoC) :  ![starts](https://img.shields.io/github/stars/ctdal/cve-2026-41940-PoC.svg) ![forks](https://img.shields.io/github/forks/ctdal/cve-2026-41940-PoC.svg)


## CVE-2026-38526
 An authenticated arbitrary file upload vulnerability in the /admin/tinymce/upload endpoint of Webkul Krayin CRM v2.2.x allows attackers to execute arbitrary code via uploading a crafted PHP file.

- [https://github.com/Shirouuu/Gitea-template-sync-Path-Traversal-Privilege-Escalation-CVE-2026-38526-](https://github.com/Shirouuu/Gitea-template-sync-Path-Traversal-Privilege-Escalation-CVE-2026-38526-) :  ![starts](https://img.shields.io/github/stars/Shirouuu/Gitea-template-sync-Path-Traversal-Privilege-Escalation-CVE-2026-38526-.svg) ![forks](https://img.shields.io/github/forks/Shirouuu/Gitea-template-sync-Path-Traversal-Privilege-Escalation-CVE-2026-38526-.svg)
- [https://github.com/Ish3ng0m4/CVE-2026-38526-KrayinCRM](https://github.com/Ish3ng0m4/CVE-2026-38526-KrayinCRM) :  ![starts](https://img.shields.io/github/stars/Ish3ng0m4/CVE-2026-38526-KrayinCRM.svg) ![forks](https://img.shields.io/github/forks/Ish3ng0m4/CVE-2026-38526-KrayinCRM.svg)


## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.

- [https://github.com/Oieua/CVE-2026-33017](https://github.com/Oieua/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/Oieua/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/Oieua/CVE-2026-33017.svg)


## CVE-2026-32996
 This vulnerability in Veeam Agent for Microsoft Windows allows for Local Privilege Escalation.

- [https://github.com/suce0155/CVE-2026-32996](https://github.com/suce0155/CVE-2026-32996) :  ![starts](https://img.shields.io/github/stars/suce0155/CVE-2026-32996.svg) ![forks](https://img.shields.io/github/forks/suce0155/CVE-2026-32996.svg)


## CVE-2026-32604
 Spinnaker is an open source, multi-cloud continuous delivery platform. In versions prior to 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2, a bad actor can execute arbitrary commands very simply on the clouddriver pods. This can expose credentials, remove files, or inject resources easily. Versions 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2 contain a patch. As a workaround, disable the gitrepo artifact types.

- [https://github.com/K3ysTr0K3R/CVE-2026-32604](https://github.com/K3ysTr0K3R/CVE-2026-32604) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2026-32604.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2026-32604.svg)


## CVE-2026-31278
 An issue in the /api/v2/setting/adserversetting endpoint of Suprema BioStar 2 before 2.9.12 and and BioStar X before 1.0.2 allows attackers to obtain Active Directory service account credentials in cleartext by supplying a crafted GET request.

- [https://github.com/mda1r/CVE-2026-31278](https://github.com/mda1r/CVE-2026-31278) :  ![starts](https://img.shields.io/github/stars/mda1r/CVE-2026-31278.svg) ![forks](https://img.shields.io/github/forks/mda1r/CVE-2026-31278.svg)


## CVE-2026-27739
 The Angular SSR is a server-rise rendering tool for Angular applications. Versions prior to 21.2.0-rc.1, 21.1.5, 20.3.17, and 19.2.21 have a Server-Side Request Forgery (SSRF) vulnerability in the Angular SSR request handling pipeline. The vulnerability exists because Angular’s internal URL reconstruction logic directly trusts and consumes user-controlled HTTP headers specifically the Host and `X-Forwarded-*` family to determine the application's base origin without any validation of the destination domain. Specifically, the framework didn't have checks for the host domain, path and character sanitization, and port validation. This vulnerability manifests in two primary ways: implicit relative URL resolution and explicit manual construction. When successfully exploited, this vulnerability allows for arbitrary internal request steering. This can lead to credential exfiltration, internal network probing, and a confidentiality breach. In order to be vulnerable, the victim application must use Angular SSR (Server-Side Rendering), the application must perform `HttpClient` requests using relative URLs OR manually construct URLs using the unvalidated `Host` / `X-Forwarded-*` headers using the `REQUEST` object, the application server must be reachable by an attacker who can influence these headers without strict validation from a front-facing proxy, and the infrastructure (Cloud, CDN, or Load Balancer) must not sanitize or validate incoming headers. Versions 21.2.0-rc.1, 21.1.5, 20.3.17, and 19.2.21 contain a patch. Some workarounds are available. Avoid using `req.headers` for URL construction. Instead, use trusted variables for base API paths. Those who cannot upgrade immediately should implement a middleware in their `server.ts` to enforce numeric ports and validated hostnames.

- [https://github.com/mr-redoo7/CVE-2026-27739-POC](https://github.com/mr-redoo7/CVE-2026-27739-POC) :  ![starts](https://img.shields.io/github/stars/mr-redoo7/CVE-2026-27739-POC.svg) ![forks](https://img.shields.io/github/forks/mr-redoo7/CVE-2026-27739-POC.svg)


## CVE-2026-27540
 Unrestricted Upload of File with Dangerous Type vulnerability in Rymera Web Co Pty Ltd. Woocommerce Wholesale Lead Capture woocommerce-wholesale-lead-capture allows Using Malicious Files.This issue affects Woocommerce Wholesale Lead Capture: from n/a through = 2.0.3.1.

- [https://github.com/winrarzipsexploit/CVE-2026-27540](https://github.com/winrarzipsexploit/CVE-2026-27540) :  ![starts](https://img.shields.io/github/stars/winrarzipsexploit/CVE-2026-27540.svg) ![forks](https://img.shields.io/github/forks/winrarzipsexploit/CVE-2026-27540.svg)


## CVE-2026-24733
Users are recommended to upgrade to version 11.0.15 or later, 10.1.50 or later or 9.0.113 or later, which fixes the issue.

- [https://github.com/Darabium/CVE-2026-24733](https://github.com/Darabium/CVE-2026-24733) :  ![starts](https://img.shields.io/github/stars/Darabium/CVE-2026-24733.svg) ![forks](https://img.shields.io/github/forks/Darabium/CVE-2026-24733.svg)


## CVE-2026-22686
 Enclave is a secure JavaScript sandbox designed for safe AI agent code execution. Prior to 2.7.0, there is a critical sandbox escape vulnerability in enclave-vm that allows untrusted, sandboxed JavaScript code to execute arbitrary code in the host Node.js runtime. When a tool invocation fails, enclave-vm exposes a host-side Error object to sandboxed code. This Error object retains its host realm prototype chain, which can be traversed to reach the host Function constructor. An attacker can intentionally trigger a host error, then climb the prototype chain. Using the host Function constructor, arbitrary JavaScript can be compiled and executed in the host context, fully bypassing the sandbox and granting access to sensitive resources such as process.env, filesystem, and network. This breaks enclave-vm’s core security guarantee of isolating untrusted code. This vulnerability is fixed in 2.7.0.

- [https://github.com/moi404/CVE-2026-22686-RemoteCodeExecution-RCE-PoC](https://github.com/moi404/CVE-2026-22686-RemoteCodeExecution-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/moi404/CVE-2026-22686-RemoteCodeExecution-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/moi404/CVE-2026-22686-RemoteCodeExecution-RCE-PoC.svg)


## CVE-2026-19975
 A weakness has been identified in Azuriom CMS up to 1.2.12. This issue affects the function transferMoney of the file app/Http/Controllers/ProfileController.php of the component Money Transfer Handler. This manipulation causes time-of-check time-of-use. The attack may be initiated remotely. A high degree of complexity is needed for the attack. The exploitability is assessed as difficult. Upgrading to version 1.2.13 is capable of addressing this issue. Patch name: ae5596a9548e010a8a79838806eff60ef9554539. Upgrading the affected component is advised. The vendor was contacted early about this disclosure.

- [https://github.com/HORKimhab/CVE-2026-19975](https://github.com/HORKimhab/CVE-2026-19975) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-19975.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-19975.svg)


## CVE-2026-17633
 IBM Langflow OSS 1.0.0 through 1.10.3 could allow a remote authenticated attacker to execute arbitrary code due to code injection.

- [https://github.com/Oscar-Collado/langflow-CVE-2026-17633-PoC](https://github.com/Oscar-Collado/langflow-CVE-2026-17633-PoC) :  ![starts](https://img.shields.io/github/stars/Oscar-Collado/langflow-CVE-2026-17633-PoC.svg) ![forks](https://img.shields.io/github/forks/Oscar-Collado/langflow-CVE-2026-17633-PoC.svg)


## CVE-2026-17632
 IBM Langflow OSS 1.0.0 through 1.10.3 could allow a remote authenticated attacker to execute arbitrary code due to improper validation of Python code during AST-based security scanning.

- [https://github.com/Oscar-Collado/langflow-CVE-2026-17633-PoC](https://github.com/Oscar-Collado/langflow-CVE-2026-17633-PoC) :  ![starts](https://img.shields.io/github/stars/Oscar-Collado/langflow-CVE-2026-17633-PoC.svg) ![forks](https://img.shields.io/github/forks/Oscar-Collado/langflow-CVE-2026-17633-PoC.svg)


## CVE-2026-15316
service recovers.

- [https://github.com/HORKimhab/CVE-2026-15315](https://github.com/HORKimhab/CVE-2026-15315) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-15315.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-15315.svg)


## CVE-2026-15315
condition.

- [https://github.com/HORKimhab/CVE-2026-15315](https://github.com/HORKimhab/CVE-2026-15315) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-15315.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-15315.svg)


## CVE-2026-12944
 IBM Langflow OSS 1.0.0 through 1.10.0 can allow attackers to execute arbitrary Python code with root privileges (UID=0) on the Langflow server by submitting components containing socket or urllib imports. This enables: (1) AWS credential theft via IMDSv1 SSRF with full IAM role permissions, (2) arbitrary file exfiltration from the container filesystem, and (3) lateral movement to internal services (PostgreSQL, Redis) within the Docker network. The scanner incorrectly returns "validated": true, providing a false security signal.

- [https://github.com/cflowsec/CVE-2026-12944](https://github.com/cflowsec/CVE-2026-12944) :  ![starts](https://img.shields.io/github/stars/cflowsec/CVE-2026-12944.svg) ![forks](https://img.shields.io/github/forks/cflowsec/CVE-2026-12944.svg)
- [https://github.com/ShadowForge-Cyber/CVE-2026-12944](https://github.com/ShadowForge-Cyber/CVE-2026-12944) :  ![starts](https://img.shields.io/github/stars/ShadowForge-Cyber/CVE-2026-12944.svg) ![forks](https://img.shields.io/github/forks/ShadowForge-Cyber/CVE-2026-12944.svg)


## CVE-2026-12793
 The JetFormBuilder — Dynamic Blocks Form Builder plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 3.6.2. This is due to the plugin not validating that a submitted form ID belongs to a JetFormBuilder form before parsing the referenced post's content as form schema and executing an Advanced Validation server-side callback. This makes it possible for unauthenticated attackers to create a new administrator-level user account.

- [https://github.com/murrez/CVE-2026-12793](https://github.com/murrez/CVE-2026-12793) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-12793.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-12793.svg)
- [https://github.com/rootxn/CVE-2026-12793](https://github.com/rootxn/CVE-2026-12793) :  ![starts](https://img.shields.io/github/stars/rootxn/CVE-2026-12793.svg) ![forks](https://img.shields.io/github/forks/rootxn/CVE-2026-12793.svg)
- [https://github.com/abraxas/CVE-2026-12793](https://github.com/abraxas/CVE-2026-12793) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-12793.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-12793.svg)


## CVE-2026-9794
 A flaw was found in Keycloak. A remote, unauthenticated attacker can exploit this vulnerability by sending specially crafted SOAP requests to the SAML ECP (Security Assertion Markup Language Enhanced Client or Proxy) endpoint with varying client IDs. By observing distinct faultstrings in the responses, the attacker can determine the client's protocol type, leading to information disclosure.

- [https://github.com/MuhammedHussein17/keycloak](https://github.com/MuhammedHussein17/keycloak) :  ![starts](https://img.shields.io/github/stars/MuhammedHussein17/keycloak.svg) ![forks](https://img.shields.io/github/forks/MuhammedHussein17/keycloak.svg)


## CVE-2026-9216
 An insufficient input validation vulnerability in the listed NETGEAR RAX series models allows a network-adjacent attacker having network access (such as WiFi credentials) to crash the router's management UI. There is no confidentiality or integrity impact. A crash of the router's management UI does not impact the availability of the router's core services like WiFi network.

- [https://github.com/0xSemizzz/CVE-2026-92162](https://github.com/0xSemizzz/CVE-2026-92162) :  ![starts](https://img.shields.io/github/stars/0xSemizzz/CVE-2026-92162.svg) ![forks](https://img.shields.io/github/forks/0xSemizzz/CVE-2026-92162.svg)


## CVE-2026-8853
 The MW WP Form plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'memo' parameter in all versions up to, and including, 5.1.3 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with editor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. Because the memo value is stored via update_post_meta() rather than wp_insert_post(), WordPress's built-in kses and unfiltered_html protections do not apply, allowing attackers to break out of the textarea element via injected closing tags regardless of role-based content filtering.

- [https://github.com/HEMLOCK-LYK/CVE-2026-88533](https://github.com/HEMLOCK-LYK/CVE-2026-88533) :  ![starts](https://img.shields.io/github/stars/HEMLOCK-LYK/CVE-2026-88533.svg) ![forks](https://img.shields.io/github/forks/HEMLOCK-LYK/CVE-2026-88533.svg)


## CVE-2026-6179
 Stored Cross Site Scripting in NightWolf Penetration Testing Platform allows attack trigger and run malicious script in user's browser

- [https://github.com/itres-labs/CVE-2026-61797](https://github.com/itres-labs/CVE-2026-61797) :  ![starts](https://img.shields.io/github/stars/itres-labs/CVE-2026-61797.svg) ![forks](https://img.shields.io/github/forks/itres-labs/CVE-2026-61797.svg)


## CVE-2026-5934
 The WP Rocket plugin for WordPress is vulnerable to Stored Cross-Site Scripting in versions up to, and including, 3.21.0.1. This is due to insufficient input sanitization and output escaping of user-supplied data via the rocket_beacon AJAX endpoint. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/0xCyberstan/CVE-2026-59346-POC](https://github.com/0xCyberstan/CVE-2026-59346-POC) :  ![starts](https://img.shields.io/github/stars/0xCyberstan/CVE-2026-59346-POC.svg) ![forks](https://img.shields.io/github/forks/0xCyberstan/CVE-2026-59346-POC.svg)


## CVE-2026-5430
Successful exploitation of this vulnerability may result in unauthorized access to the system, including the potential compromise of administrative accounts and full account takeover. The CVSS score is adjusted to 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) in single-tenant deployments, reflecting that the impact is contained within a single security authority boundary.

- [https://github.com/HORKimhab/CVE-2026-5430](https://github.com/HORKimhab/CVE-2026-5430) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-5430.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-5430.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/HORKimhab/CVE-2026-43499](https://github.com/HORKimhab/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-43499.svg)
- [https://github.com/caspy123/CVE-2026-43499](https://github.com/caspy123/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/caspy123/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/caspy123/CVE-2026-43499.svg)
- [https://github.com/CatXiaoShi/cve-2026-43499](https://github.com/CatXiaoShi/cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/CatXiaoShi/cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/CatXiaoShi/cve-2026-43499.svg)
- [https://github.com/justsoman/CVE-2026-43499-jinghu](https://github.com/justsoman/CVE-2026-43499-jinghu) :  ![starts](https://img.shields.io/github/stars/justsoman/CVE-2026-43499-jinghu.svg) ![forks](https://img.shields.io/github/forks/justsoman/CVE-2026-43499-jinghu.svg)
- [https://github.com/dorlow/hazel-cve-2026-43499](https://github.com/dorlow/hazel-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/dorlow/hazel-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/dorlow/hazel-cve-2026-43499.svg)
- [https://github.com/fusiondrive/CVE-2026-43499-ZFOLD4](https://github.com/fusiondrive/CVE-2026-43499-ZFOLD4) :  ![starts](https://img.shields.io/github/stars/fusiondrive/CVE-2026-43499-ZFOLD4.svg) ![forks](https://img.shields.io/github/forks/fusiondrive/CVE-2026-43499-ZFOLD4.svg)
- [https://github.com/SammyEnigma/CVE-2026-43499-S26](https://github.com/SammyEnigma/CVE-2026-43499-S26) :  ![starts](https://img.shields.io/github/stars/SammyEnigma/CVE-2026-43499-S26.svg) ![forks](https://img.shields.io/github/forks/SammyEnigma/CVE-2026-43499-S26.svg)
- [https://github.com/huaguiqi/asus-i005-cve-2026-43499](https://github.com/huaguiqi/asus-i005-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/huaguiqi/asus-i005-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/huaguiqi/asus-i005-cve-2026-43499.svg)
- [https://github.com/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup](https://github.com/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup) :  ![starts](https://img.shields.io/github/stars/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup.svg) ![forks](https://img.shields.io/github/forks/accessmodifier364/cve-2026-43499-firetv-sheldonp-writeup.svg)
- [https://github.com/Bobikl/CVE-2026-43499-T807D](https://github.com/Bobikl/CVE-2026-43499-T807D) :  ![starts](https://img.shields.io/github/stars/Bobikl/CVE-2026-43499-T807D.svg) ![forks](https://img.shields.io/github/forks/Bobikl/CVE-2026-43499-T807D.svg)
- [https://github.com/CamsShaft/IonStack-S22-cve-2026-43499](https://github.com/CamsShaft/IonStack-S22-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/CamsShaft/IonStack-S22-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/CamsShaft/IonStack-S22-cve-2026-43499.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/maniakh/CVE-2026-31431---Copy-Fail-PoC](https://github.com/maniakh/CVE-2026-31431---Copy-Fail-PoC) :  ![starts](https://img.shields.io/github/stars/maniakh/CVE-2026-31431---Copy-Fail-PoC.svg) ![forks](https://img.shields.io/github/forks/maniakh/CVE-2026-31431---Copy-Fail-PoC.svg)


## CVE-2026-1961
 A flaw was found in Foreman. A remote attacker could exploit a command injection vulnerability in Foreman's WebSocket proxy implementation. This vulnerability arises from the system's use of unsanitized hostname values from compute resource providers when constructing shell commands. By operating a malicious compute resource server, an attacker could achieve remote code execution on the Foreman server when a user accesses VM VNC console functionality. This could lead to the compromise of sensitive credentials and the entire managed infrastructure.

- [https://github.com/kalnux/CVE-2026-1961-foreman-poc](https://github.com/kalnux/CVE-2026-1961-foreman-poc) :  ![starts](https://img.shields.io/github/stars/kalnux/CVE-2026-1961-foreman-poc.svg) ![forks](https://img.shields.io/github/forks/kalnux/CVE-2026-1961-foreman-poc.svg)


## CVE-2026-0994
Due to missing recursion depth accounting inside the internal Any-handling logic, an attacker can supply deeply nested Any structures that bypass the intended recursion limit, eventually exhausting Python’s recursion stack and causing a RecursionError.

- [https://github.com/Vardhan0257/upb-any-recursion-audit](https://github.com/Vardhan0257/upb-any-recursion-audit) :  ![starts](https://img.shields.io/github/stars/Vardhan0257/upb-any-recursion-audit.svg) ![forks](https://img.shields.io/github/forks/Vardhan0257/upb-any-recursion-audit.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-64512
 Pdfminer.six is a community maintained fork of the original PDFMiner, a tool for extracting information from PDF documents. Prior to version 20251107, pdfminer.six will execute arbitrary code from a malicious pickle file if provided with a malicious PDF file. The `CMapDB._load_data()` function in pdfminer.six uses `pickle.loads()` to deserialize pickle files. These pickle files are supposed to be part of the pdfminer.six distribution stored in the `cmap/` directory, but a malicious PDF can specify an alternative directory and filename as long as the filename ends in `.pickle.gz`. A malicious, zipped pickle file can then contain code which will automatically execute when the PDF is processed. Version 20251107 fixes the issue.

- [https://github.com/Jinook-Kim/CVE-2025-64512_PoC](https://github.com/Jinook-Kim/CVE-2025-64512_PoC) :  ![starts](https://img.shields.io/github/stars/Jinook-Kim/CVE-2025-64512_PoC.svg) ![forks](https://img.shields.io/github/forks/Jinook-Kim/CVE-2025-64512_PoC.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/shivammittal2403/cve-2025-57819-freepbx-range](https://github.com/shivammittal2403/cve-2025-57819-freepbx-range) :  ![starts](https://img.shields.io/github/stars/shivammittal2403/cve-2025-57819-freepbx-range.svg) ![forks](https://img.shields.io/github/forks/shivammittal2403/cve-2025-57819-freepbx-range.svg)


## CVE-2025-57231
 Path Traversal in avatar attachments in Docmost v0.21.0 allows an unauthenticated malicious actor to disclose local files via a POST Request in a public url.

- [https://github.com/anirbala98/CVE-2025-57231](https://github.com/anirbala98/CVE-2025-57231) :  ![starts](https://img.shields.io/github/stars/anirbala98/CVE-2025-57231.svg) ![forks](https://img.shields.io/github/forks/anirbala98/CVE-2025-57231.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/P34NUT2/CVE-2025-32432-exploit-by-P34NUT](https://github.com/P34NUT2/CVE-2025-32432-exploit-by-P34NUT) :  ![starts](https://img.shields.io/github/stars/P34NUT2/CVE-2025-32432-exploit-by-P34NUT.svg) ![forks](https://img.shields.io/github/forks/P34NUT2/CVE-2025-32432-exploit-by-P34NUT.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/e5dfdd568a75282b712b6d93a7a18e12/CVE-2025-24813](https://github.com/e5dfdd568a75282b712b6d93a7a18e12/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/e5dfdd568a75282b712b6d93a7a18e12/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/e5dfdd568a75282b712b6d93a7a18e12/CVE-2025-24813.svg)
- [https://github.com/Affapple/CVE-2025-24813-POC](https://github.com/Affapple/CVE-2025-24813-POC) :  ![starts](https://img.shields.io/github/stars/Affapple/CVE-2025-24813-POC.svg) ![forks](https://img.shields.io/github/forks/Affapple/CVE-2025-24813-POC.svg)


## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

- [https://github.com/xjoker/lenovo_y700_tb320fc_on_CVE-2025-21479](https://github.com/xjoker/lenovo_y700_tb320fc_on_CVE-2025-21479) :  ![starts](https://img.shields.io/github/stars/xjoker/lenovo_y700_tb320fc_on_CVE-2025-21479.svg) ![forks](https://img.shields.io/github/forks/xjoker/lenovo_y700_tb320fc_on_CVE-2025-21479.svg)
- [https://github.com/7678837-glitch/lenovo_y700_tb320fc_on_CVE-2025-21479](https://github.com/7678837-glitch/lenovo_y700_tb320fc_on_CVE-2025-21479) :  ![starts](https://img.shields.io/github/stars/7678837-glitch/lenovo_y700_tb320fc_on_CVE-2025-21479.svg) ![forks](https://img.shields.io/github/forks/7678837-glitch/lenovo_y700_tb320fc_on_CVE-2025-21479.svg)
- [https://github.com/RamenFast/zenfone9-root](https://github.com/RamenFast/zenfone9-root) :  ![starts](https://img.shields.io/github/stars/RamenFast/zenfone9-root.svg) ![forks](https://img.shields.io/github/forks/RamenFast/zenfone9-root.svg)


## CVE-2025-8191
 A vulnerability, which was classified as problematic, was found in macrozheng mall up to 1.0.3. Affected is an unknown function of the file /swagger-ui/index.html of the component Swagger UI. The manipulation of the argument configUrl leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor deleted the GitHub issue for this vulnerability without any explanation. Afterwards the vendor was contacted early about this disclosure via email but did not respond in any way.

- [https://github.com/d154573r-4v3r73d/CVE-2025-8191](https://github.com/d154573r-4v3r73d/CVE-2025-8191) :  ![starts](https://img.shields.io/github/stars/d154573r-4v3r73d/CVE-2025-8191.svg) ![forks](https://img.shields.io/github/forks/d154573r-4v3r73d/CVE-2025-8191.svg)


## CVE-2025-8061
 A potential insufficient access control vulnerability was reported in the Lenovo Dispatcher 3.0 and Dispatcher 3.1 drivers used by some Lenovo consumer notebooks that could allow an authenticated local user to execute code with elevated privileges. The Lenovo Dispatcher 3.2 driver is not affected. This vulnerability does not affect systems when the Windows feature Core Isolation Memory Integrity is enabled. Lenovo systems preloaded with Windows 11 have this feature enabled by default.

- [https://github.com/uLl0a/MSRMapper](https://github.com/uLl0a/MSRMapper) :  ![starts](https://img.shields.io/github/stars/uLl0a/MSRMapper.svg) ![forks](https://img.shields.io/github/forks/uLl0a/MSRMapper.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-5548
 A vulnerability, which was classified as critical, was found in FreeFloat FTP Server 1.0. Affected is an unknown function of the component NOOP Command Handler. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/M4Rc0s-S3c/CVE-2025-5548-FreeFloat-FTP-Lab](https://github.com/M4Rc0s-S3c/CVE-2025-5548-FreeFloat-FTP-Lab) :  ![starts](https://img.shields.io/github/stars/M4Rc0s-S3c/CVE-2025-5548-FreeFloat-FTP-Lab.svg) ![forks](https://img.shields.io/github/forks/M4Rc0s-S3c/CVE-2025-5548-FreeFloat-FTP-Lab.svg)


## CVE-2025-3194
 Versions of the package bigint-buffer from 0.0.0 are vulnerable to Buffer Overflow in the toBigIntLE() function. Attackers can exploit this to crash the application.

- [https://github.com/disley15-collab/bigint-buffer-js](https://github.com/disley15-collab/bigint-buffer-js) :  ![starts](https://img.shields.io/github/stars/disley15-collab/bigint-buffer-js.svg) ![forks](https://img.shields.io/github/forks/disley15-collab/bigint-buffer-js.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)


## CVE-2025-0401
 A vulnerability classified as critical has been found in 1902756969 reggie 1.0. Affected is the function download of the file src/main/java/com/itheima/reggie/controller/CommonController.java. The manipulation of the argument name leads to path traversal. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/JoasASantos/CVE-2025-0401](https://github.com/JoasASantos/CVE-2025-0401) :  ![starts](https://img.shields.io/github/stars/JoasASantos/CVE-2025-0401.svg) ![forks](https://img.shields.io/github/forks/JoasASantos/CVE-2025-0401.svg)


## CVE-2024-49138
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/FabianCH20/SOC335---CVE-2024-49138-Exploitation-Detected](https://github.com/FabianCH20/SOC335---CVE-2024-49138-Exploitation-Detected) :  ![starts](https://img.shields.io/github/stars/FabianCH20/SOC335---CVE-2024-49138-Exploitation-Detected.svg) ![forks](https://img.shields.io/github/forks/FabianCH20/SOC335---CVE-2024-49138-Exploitation-Detected.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/raniaemran/cve-2024-36401-security-simulator](https://github.com/raniaemran/cve-2024-36401-security-simulator) :  ![starts](https://img.shields.io/github/stars/raniaemran/cve-2024-36401-security-simulator.svg) ![forks](https://img.shields.io/github/forks/raniaemran/cve-2024-36401-security-simulator.svg)


## CVE-2024-31317
 In multiple functions of ZygoteProcess.java, there is a possible way to achieve code execution as any app via WRITE_SECURE_SETTINGS due to unsafe deserialization. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/bapesupreme/portal-de-metaification](https://github.com/bapesupreme/portal-de-metaification) :  ![starts](https://img.shields.io/github/stars/bapesupreme/portal-de-metaification.svg) ![forks](https://img.shields.io/github/forks/bapesupreme/portal-de-metaification.svg)


## CVE-2024-27815
 An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in iOS 17.5 and iPadOS 17.5, macOS Sonoma 14.5, tvOS 17.5, visionOS 1.2, watchOS 10.5. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/nomnomheapnom/CVE-2024-27815](https://github.com/nomnomheapnom/CVE-2024-27815) :  ![starts](https://img.shields.io/github/stars/nomnomheapnom/CVE-2024-27815.svg) ![forks](https://img.shields.io/github/forks/nomnomheapnom/CVE-2024-27815.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/Michel-DV/xz-utils-backdoor-case-study](https://github.com/Michel-DV/xz-utils-backdoor-case-study) :  ![starts](https://img.shields.io/github/stars/Michel-DV/xz-utils-backdoor-case-study.svg) ![forks](https://img.shields.io/github/forks/Michel-DV/xz-utils-backdoor-case-study.svg)


## CVE-2024-2026
 The Passster plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's content_protector shortcode in all versions up to, and including, 4.2.6.4 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Ishanoshada/Ollama-Hunter](https://github.com/Ishanoshada/Ollama-Hunter) :  ![starts](https://img.shields.io/github/stars/Ishanoshada/Ollama-Hunter.svg) ![forks](https://img.shields.io/github/forks/Ishanoshada/Ollama-Hunter.svg)


## CVE-2024-0670
 Privilege escalation in windows agent plugin in Checkmk before 2.2.0p23, 2.1.0p40 and 2.0.0 (EOL) allows local user to escalate privileges

- [https://github.com/taktak0x/HTB-NanoCorp-CVE-2024-0670](https://github.com/taktak0x/HTB-NanoCorp-CVE-2024-0670) :  ![starts](https://img.shields.io/github/stars/taktak0x/HTB-NanoCorp-CVE-2024-0670.svg) ![forks](https://img.shields.io/github/forks/taktak0x/HTB-NanoCorp-CVE-2024-0670.svg)


## CVE-2022-45442
 Sinatra is a domain-specific language for creating web applications in Ruby. An issue was discovered in Sinatra 2.0 before 2.2.3 and 3.0 before 3.0.4. An application is vulnerable to a reflected file download (RFD) attack that sets the Content-Disposition header of a response when the filename is derived from user-supplied input. Version 2.2.3 and 3.0.4 contain patches for this issue.

- [https://github.com/boost-legal/refile](https://github.com/boost-legal/refile) :  ![starts](https://img.shields.io/github/stars/boost-legal/refile.svg) ![forks](https://img.shields.io/github/forks/boost-legal/refile.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/redzrush101/zte-blade-v40-vita-unlock](https://github.com/redzrush101/zte-blade-v40-vita-unlock) :  ![starts](https://img.shields.io/github/stars/redzrush101/zte-blade-v40-vita-unlock.svg) ![forks](https://img.shields.io/github/forks/redzrush101/zte-blade-v40-vita-unlock.svg)


## CVE-2022-22715
 Named Pipe File System Elevation of Privilege Vulnerability

- [https://github.com/vportal/CVE-2022-22715](https://github.com/vportal/CVE-2022-22715) :  ![starts](https://img.shields.io/github/stars/vportal/CVE-2022-22715.svg) ![forks](https://img.shields.io/github/forks/vportal/CVE-2022-22715.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/Squ1shification/Grafana-Plugin-Enumerator-CVE-2021-43798](https://github.com/Squ1shification/Grafana-Plugin-Enumerator-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/Squ1shification/Grafana-Plugin-Enumerator-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/Squ1shification/Grafana-Plugin-Enumerator-CVE-2021-43798.svg)


## CVE-2021-43290
 An issue was discovered in ThoughtWorks GoCD before 21.3.0. An attacker who has compromised a GoCD agent can upload a malicious file into a directory of a GoCD server. They can control the filename but the directory is placed inside of a directory that they can't control.

- [https://github.com/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack](https://github.com/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack) :  ![starts](https://img.shields.io/github/stars/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack.svg) ![forks](https://img.shields.io/github/forks/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack.svg)


## CVE-2021-43289
 An issue was discovered in ThoughtWorks GoCD before 21.3.0. An attacker who has compromised a GoCD agent can upload a malicious file into an arbitrary directory of a GoCD server, but does not control the filename.

- [https://github.com/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack](https://github.com/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack) :  ![starts](https://img.shields.io/github/stars/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack.svg) ![forks](https://img.shields.io/github/forks/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack.svg)


## CVE-2021-43288
 An issue was discovered in ThoughtWorks GoCD before 21.3.0. An attacker in control of a GoCD Agent can plant malicious JavaScript into a failed Job Report.

- [https://github.com/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack](https://github.com/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack) :  ![starts](https://img.shields.io/github/stars/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack.svg) ![forks](https://img.shields.io/github/forks/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack.svg)


## CVE-2021-43287
 An issue was discovered in ThoughtWorks GoCD before 21.3.0. The business continuity add-on, which is enabled by default, leaks all secrets known to the GoCD server to unauthenticated attackers.

- [https://github.com/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack](https://github.com/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack) :  ![starts](https://img.shields.io/github/stars/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack.svg) ![forks](https://img.shields.io/github/forks/HigorGabrielDCF/GoCD_PoC_Supply_Chain_Attack.svg)


## CVE-2021-33045
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/thebadinteger/p2pwn](https://github.com/thebadinteger/p2pwn) :  ![starts](https://img.shields.io/github/stars/thebadinteger/p2pwn.svg) ![forks](https://img.shields.io/github/forks/thebadinteger/p2pwn.svg)


## CVE-2021-33044
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/thebadinteger/p2pwn](https://github.com/thebadinteger/p2pwn) :  ![starts](https://img.shields.io/github/stars/thebadinteger/p2pwn.svg) ![forks](https://img.shields.io/github/forks/thebadinteger/p2pwn.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/Kashyapghodasara/Public_Exploit-1--Wordpress-CVE-2021-29447](https://github.com/Kashyapghodasara/Public_Exploit-1--Wordpress-CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/Kashyapghodasara/Public_Exploit-1--Wordpress-CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/Kashyapghodasara/Public_Exploit-1--Wordpress-CVE-2021-29447.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-3030
 Cute Editor for ASP.NET 6.4 is vulnerable to reflected cross-site scripting caused by improper validation of the Theme GET parameter in colorpicker_more.aspx. A remote, unauthenticated attacker can craft a URL that, once opened by a victim in a browser session authenticated to a site running the vulnerable component, executes arbitrary JavaScript in the security context of that site.

- [https://github.com/athosgonzaga/CVE-2021-3030](https://github.com/athosgonzaga/CVE-2021-3030) :  ![starts](https://img.shields.io/github/stars/athosgonzaga/CVE-2021-3030.svg) ![forks](https://img.shields.io/github/forks/athosgonzaga/CVE-2021-3030.svg)


## CVE-2020-1948
 This vulnerability can affect all Dubbo users stay on version 2.7.6 or lower. An attacker can send RPC requests with unrecognized service name or method name along with some malicious parameter payloads. When the malicious parameter is deserialized, it will execute some malicious code. More details can be found below.

- [https://github.com/keloke/Dubbo-deserialization](https://github.com/keloke/Dubbo-deserialization) :  ![starts](https://img.shields.io/github/stars/keloke/Dubbo-deserialization.svg) ![forks](https://img.shields.io/github/forks/keloke/Dubbo-deserialization.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/cyberexpert111/Blind-SSRF-to-Remote-Code-Execution-Shellshock-Professional-Bug-Bounty-Report](https://github.com/cyberexpert111/Blind-SSRF-to-Remote-Code-Execution-Shellshock-Professional-Bug-Bounty-Report) :  ![starts](https://img.shields.io/github/stars/cyberexpert111/Blind-SSRF-to-Remote-Code-Execution-Shellshock-Professional-Bug-Bounty-Report.svg) ![forks](https://img.shields.io/github/forks/cyberexpert111/Blind-SSRF-to-Remote-Code-Execution-Shellshock-Professional-Bug-Bounty-Report.svg)


## CVE-2009-3103
 Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2, Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location, aka "SMBv2 Negotiation Vulnerability." NOTE: some of these details are obtained from third party information.

- [https://github.com/bytejmp/MS09-050](https://github.com/bytejmp/MS09-050) :  ![starts](https://img.shields.io/github/stars/bytejmp/MS09-050.svg) ![forks](https://img.shields.io/github/forks/bytejmp/MS09-050.svg)

