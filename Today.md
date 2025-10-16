# Update 2025-10-16
## CVE-2025-60374
 Stored Cross-Site Scripting (XSS) in Perfex CRM chatbot before 3.3.1 allows attackers to inject arbitrary HTML/JavaScript. The payload is executed in the browsers of users viewing the chat, resulting in client-side code execution, potential session token theft, and other malicious actions. A different vulnerability than CVE-2024-8867.

- [https://github.com/ajansha/CVE-2025-60374](https://github.com/ajansha/CVE-2025-60374) :  ![starts](https://img.shields.io/github/stars/ajansha/CVE-2025-60374.svg) ![forks](https://img.shields.io/github/forks/ajansha/CVE-2025-60374.svg)


## CVE-2025-56803
 Figma Desktop for Windows version 125.6.5 contains a command injection vulnerability in the local plugin loader. An attacker can execute arbitrary OS commands by setting a crafted build field in the plugin's manifest.json. This field is passed to child_process.exec without validation, leading to possible RCE. NOTE: this is disputed by the Supplier because the behavior only allows a local user to attack himself via a local plugin. The local build procedure, which is essential to the attack, is not executed for plugins shared to the Figma Community.

- [https://github.com/shinyColumn/CVE-2025-56803](https://github.com/shinyColumn/CVE-2025-56803) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-56803.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-56803.svg)


## CVE-2025-50944
 An issue was discovered in the method push.lite.avtech.com.MySSLSocketFactoryNew.checkServerTrusted in AVTECH EagleEyes 2.0.0. The custom X509TrustManager used in checkServerTrusted only checks the certificate's expiration date, skipping proper TLS chain validation.

- [https://github.com/shinyColumn/CVE-2025-50944](https://github.com/shinyColumn/CVE-2025-50944) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-50944.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-50944.svg)


## CVE-2025-50110
 An issue was discovered in the method push.lite.avtech.com.AvtechLib.GetHttpsResponse in AVTECH EagleEyes Lite 2.0.0, the GetHttpsResponse method transmits sensitive information - including internal server URLs, account IDs, passwords, and device tokens - as plaintext query parameters over HTTPS

- [https://github.com/shinyColumn/CVE-2025-50110](https://github.com/shinyColumn/CVE-2025-50110) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-50110.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-50110.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/angelusrivera/CVE-2025-49844](https://github.com/angelusrivera/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/angelusrivera/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/angelusrivera/CVE-2025-49844.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/mukesh-610/cve-2025-48384](https://github.com/mukesh-610/cve-2025-48384) :  ![starts](https://img.shields.io/github/stars/mukesh-610/cve-2025-48384.svg) ![forks](https://img.shields.io/github/forks/mukesh-610/cve-2025-48384.svg)
- [https://github.com/mukesh-610/cve-2025-48384-exploit](https://github.com/mukesh-610/cve-2025-48384-exploit) :  ![starts](https://img.shields.io/github/stars/mukesh-610/cve-2025-48384-exploit.svg) ![forks](https://img.shields.io/github/forks/mukesh-610/cve-2025-48384-exploit.svg)


## CVE-2025-46408
 An issue was discovered in the methods push.lite.avtech.com.AvtechLib.GetHttpsResponse and push.lite.avtech.com.Push_HttpService.getNewHttpClient in AVTECH EagleEyes 2.0.0. The methods set ALLOW_ALL_HOSTNAME_VERIFIER, bypassing domain validation.

- [https://github.com/shinyColumn/CVE-2025-46408](https://github.com/shinyColumn/CVE-2025-46408) :  ![starts](https://img.shields.io/github/stars/shinyColumn/CVE-2025-46408.svg) ![forks](https://img.shields.io/github/forks/shinyColumn/CVE-2025-46408.svg)


## CVE-2025-39682
zero length.

- [https://github.com/khoatran107/cve-2025-39682](https://github.com/khoatran107/cve-2025-39682) :  ![starts](https://img.shields.io/github/stars/khoatran107/cve-2025-39682.svg) ![forks](https://img.shields.io/github/forks/khoatran107/cve-2025-39682.svg)


## CVE-2025-25198
 mailcow: dockerized is an open source groupware/email suite based on docker. Prior to version 2025-01a, a vulnerability in mailcow's password reset functionality allows an attacker to manipulate the `Host HTTP` header to generate a password reset link pointing to an attacker-controlled domain. This can lead to account takeover if a user clicks the poisoned link. Version 2025-01a contains a patch. As a workaround, deactivate the password reset functionality by clearing `Notification email sender` and `Notification email subject` under System - Configuration - Options - Password Settings.

- [https://github.com/Groppoxx/CVE-2025-25198-PoC](https://github.com/Groppoxx/CVE-2025-25198-PoC) :  ![starts](https://img.shields.io/github/stars/Groppoxx/CVE-2025-25198-PoC.svg) ![forks](https://img.shields.io/github/forks/Groppoxx/CVE-2025-25198-PoC.svg)
- [https://github.com/enzocipher/CVE-2025-25198-PoC](https://github.com/enzocipher/CVE-2025-25198-PoC) :  ![starts](https://img.shields.io/github/stars/enzocipher/CVE-2025-25198-PoC.svg) ![forks](https://img.shields.io/github/forks/enzocipher/CVE-2025-25198-PoC.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/ThHardvester/CVE-2025-24813](https://github.com/ThHardvester/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/ThHardvester/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/ThHardvester/CVE-2025-24813.svg)


## CVE-2025-10720
 The WP Private Content Plus through 3.6.2 provides a global content protection feature that requires a password. However, the access control check is based only on the presence of an unprotected client-side cookie. As a result, an unauthenticated attacker can completely bypass the password protection by manually setting the cookie value in their browser.

- [https://github.com/lorenzocamilli/CVE-2025-10720-PoC](https://github.com/lorenzocamilli/CVE-2025-10720-PoC) :  ![starts](https://img.shields.io/github/stars/lorenzocamilli/CVE-2025-10720-PoC.svg) ![forks](https://img.shields.io/github/forks/lorenzocamilli/CVE-2025-10720-PoC.svg)


## CVE-2025-9196
 The Trinity Audio – Text to Speech AI audio player to convert content into audio plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 5.21.0 via the ~/admin/inc/phpinfo.php file that gets created on install. This makes it possible for unauthenticated attackers to extract sensitive data including configuration data.

- [https://github.com/godfatherofexps/CVE-2025-9196-PoC](https://github.com/godfatherofexps/CVE-2025-9196-PoC) :  ![starts](https://img.shields.io/github/stars/godfatherofexps/CVE-2025-9196-PoC.svg) ![forks](https://img.shields.io/github/forks/godfatherofexps/CVE-2025-9196-PoC.svg)


## CVE-2025-7441
 The StoryChief plugin for WordPress is vulnerable to arbitrary file uploads in all versions up to, and including, 1.0.42. This vulnerability occurs through the /wp-json/storychief/webhook REST-API endpoint that does not have sufficient filetype validation. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Pwdnx1337/CVE-2025-7441](https://github.com/Pwdnx1337/CVE-2025-7441) :  ![starts](https://img.shields.io/github/stars/Pwdnx1337/CVE-2025-7441.svg) ![forks](https://img.shields.io/github/forks/Pwdnx1337/CVE-2025-7441.svg)


## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/jopraveen/CVE-2025-6554](https://github.com/jopraveen/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/jopraveen/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/jopraveen/CVE-2025-6554.svg)


## CVE-2025-6145
 A vulnerability was found in TOTOLINK EX1200T 4.1.2cu.5232_B20210713 and classified as critical. Affected by this issue is some unknown functionality of the file /boafrm/formSysLog of the component HTTP POST Request Handler. The manipulation of the argument submit-url leads to buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/tansique-17/CVE-2025-61454](https://github.com/tansique-17/CVE-2025-61454) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-61454.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-61454.svg)
- [https://github.com/tansique-17/CVE-2025-61456](https://github.com/tansique-17/CVE-2025-61456) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-61456.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-61456.svg)
- [https://github.com/tansique-17/CVE-2025-61455](https://github.com/tansique-17/CVE-2025-61455) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-61455.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-61455.svg)


## CVE-2025-5622
 A vulnerability was found in D-Link DIR-816 1.10CNB05 and classified as critical. Affected by this issue is the function wirelessApcli_5g of the file /goform/wirelessApcli_5g. The manipulation of the argument apcli_mode_5g/apcli_enc_5g/apcli_default_key_5g leads to stack-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/saykino/CVE-2025-56221](https://github.com/saykino/CVE-2025-56221) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56221.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56221.svg)
- [https://github.com/saykino/CVE-2025-56223](https://github.com/saykino/CVE-2025-56223) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56223.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56223.svg)
- [https://github.com/saykino/CVE-2025-56224](https://github.com/saykino/CVE-2025-56224) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56224.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56224.svg)


## CVE-2025-5621
 A vulnerability has been found in D-Link DIR-816 1.10CNB05 and classified as critical. Affected by this vulnerability is the function qosClassifier of the file /goform/qosClassifier. The manipulation of the argument dip_address/sip_address leads to os command injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/saykino/CVE-2025-56218](https://github.com/saykino/CVE-2025-56218) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56218.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56218.svg)
- [https://github.com/saykino/CVE-2025-56219](https://github.com/saykino/CVE-2025-56219) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56219.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56219.svg)


## CVE-2025-4123
The default Content-Security-Policy (CSP) in Grafana will block the XSS though the `connect-src` directive.

- [https://github.com/MorphyKutay/CVE-2025-4123-Exploit](https://github.com/MorphyKutay/CVE-2025-4123-Exploit) :  ![starts](https://img.shields.io/github/stars/MorphyKutay/CVE-2025-4123-Exploit.svg) ![forks](https://img.shields.io/github/forks/MorphyKutay/CVE-2025-4123-Exploit.svg)


## CVE-2025-0886
 An incorrect permissions vulnerability was reported in Elliptic Labs Virtual Lock Sensor that could allow a local, authenticated user to escalate privileges.

- [https://github.com/JNDataRT/VirtualLockSensorLPE](https://github.com/JNDataRT/VirtualLockSensorLPE) :  ![starts](https://img.shields.io/github/stars/JNDataRT/VirtualLockSensorLPE.svg) ![forks](https://img.shields.io/github/forks/JNDataRT/VirtualLockSensorLPE.svg)


## CVE-2024-58239
did some work.

- [https://github.com/khoatran107/cve-2025-39682](https://github.com/khoatran107/cve-2025-39682) :  ![starts](https://img.shields.io/github/stars/khoatran107/cve-2025-39682.svg) ![forks](https://img.shields.io/github/forks/khoatran107/cve-2025-39682.svg)


## CVE-2024-36971
This old bug became visible after the blamed commit, using UDP sockets.

- [https://github.com/Kronk-imp/CVE-2024-36971](https://github.com/Kronk-imp/CVE-2024-36971) :  ![starts](https://img.shields.io/github/stars/Kronk-imp/CVE-2024-36971.svg) ![forks](https://img.shields.io/github/forks/Kronk-imp/CVE-2024-36971.svg)


## CVE-2022-41678
A more restrictive Jolokia configuration has been defined in default ActiveMQ distribution. We encourage users to upgrade to ActiveMQ distributions version including updated Jolokia configuration: 5.16.6, 5.17.4, 5.18.0, 6.0.0.

- [https://github.com/URJACK2025/CVE-2022-41678](https://github.com/URJACK2025/CVE-2022-41678) :  ![starts](https://img.shields.io/github/stars/URJACK2025/CVE-2022-41678.svg) ![forks](https://img.shields.io/github/forks/URJACK2025/CVE-2022-41678.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/RizqiSec/CVE-2021-41773](https://github.com/RizqiSec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RizqiSec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RizqiSec/CVE-2021-41773.svg)
- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2021-26291
 Apache Maven will follow repositories that are defined in a dependency’s Project Object Model (pom) which may be surprising to some users, resulting in potential risk if a malicious actor takes over that repository or is able to insert themselves into a position to pretend to be that repository. Maven is changing the default behavior in 3.8.1+ to no longer follow http (non-SSL) repository references by default. More details available in the referenced urls. If you are currently using a repository manager to govern the repositories used by your builds, you are unaffected by the risks present in the legacy behavior, and are unaffected by this vulnerability and change to default behavior. See this link for more information about repository management: https://maven.apache.org/repository-management.html

- [https://github.com/jpmartins/MinimalReproducer](https://github.com/jpmartins/MinimalReproducer) :  ![starts](https://img.shields.io/github/stars/jpmartins/MinimalReproducer.svg) ![forks](https://img.shields.io/github/forks/jpmartins/MinimalReproducer.svg)


## CVE-2021-22941
 Improper Access Control in Citrix ShareFile storage zones controller before 5.11.20 may allow an unauthenticated attacker to remotely compromise the storage zones controller.

- [https://github.com/hoav18/CVE-2021-22941](https://github.com/hoav18/CVE-2021-22941) :  ![starts](https://img.shields.io/github/stars/hoav18/CVE-2021-22941.svg) ![forks](https://img.shields.io/github/forks/hoav18/CVE-2021-22941.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/tachote/CVE-2021-4034](https://github.com/tachote/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/tachote/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/tachote/CVE-2021-4034.svg)


## CVE-2017-10271
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/seoyoung-kang/CVE-2017-10271](https://github.com/seoyoung-kang/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/seoyoung-kang/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/seoyoung-kang/CVE-2017-10271.svg)

