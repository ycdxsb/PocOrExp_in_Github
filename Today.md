# Update 2021-06-03
## CVE-2021-33790
 The RebornCore library before 4.7.3 allows remote code execution because it deserializes untrusted data in ObjectInputStream.readObject as part of reborncore.common.network.ExtendedPacketBuffer. An attacker can instantiate any class on the classpath with any data. A class usable for exploitation might or might not be present, depending on what Minecraft modifications are installed.

- [https://github.com/JamesGeee/CVE-2021-33790](https://github.com/JamesGeee/CVE-2021-33790) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-33790.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-33790.svg)


## CVE-2021-33564
 An argument injection vulnerability in the Dragonfly gem before 1.4.0 for Ruby allows remote attackers to read and write to arbitrary files via a crafted URL when the verify_url option is disabled. This may lead to code execution. The problem occurs because the generate and process features mishandle use of the ImageMagick convert utility.

- [https://github.com/JamesGeee/CVE-2021-33564](https://github.com/JamesGeee/CVE-2021-33564) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-33564.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-33564.svg)


## CVE-2021-33477
 rxvt-unicode 9.22, rxvt 2.7.10, mrxvt 0.5.4, and Eterm 0.9.7 allow (potentially remote) code execution because of improper handling of certain escape sequences (ESC G Q). A response is terminated by a newline.

- [https://github.com/JamesGeee/CVE-2021-33477](https://github.com/JamesGeee/CVE-2021-33477) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-33477.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-33477.svg)


## CVE-2021-33038
 An issue was discovered in management/commands/hyperkitty_import.py in HyperKitty through 1.3.4. When importing a private mailing list's archives, these archives are publicly visible for the duration of the import. For example, sensitive information might be available on the web for an hour during a large migration from Mailman 2 to Mailman 3.

- [https://github.com/JamesGeee/CVE-2021-33038](https://github.com/JamesGeee/CVE-2021-33038) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-33038.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-33038.svg)


## CVE-2021-32657
 Nextcloud Server is a Nextcloud package that handles data storage. In versions of Nextcloud Server prior to 10.0.11, 20.0.10, and 21.0.2, a malicious user may be able to break the user administration page. This would disallow administrators to administrate users on the Nextcloud instance. The vulnerability is fixed in versions 19.0.11, 20.0.10, and 21.0.2. As a workaround, administrators can use the OCC command line tool to administrate the Nextcloud users.

- [https://github.com/JamesGeee/CVE-2021-32657](https://github.com/JamesGeee/CVE-2021-32657) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-32657.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-32657.svg)


## CVE-2021-32656
 Nextcloud Server is a Nextcloud package that handles data storage. A vulnerability in federated share exists in versions prior to 19.0.11, 20.0.10, and 21.0.2. An attacker can gain access to basic information about users of a server by accessing a public link that a legitimate server user added as a federated share. This happens because Nextcloud supports sharing registered users with other Nextcloud servers, which can be done automatically when selecting the &quot;Add server automatically once a federated share was created successfully&quot; setting. The vulnerability is patched in versions 19.0.11, 20.0.10, and 21.0.2 As a workaround, disable &quot;Add server automatically once a federated share was created successfully&quot; in the Nextcloud settings.

- [https://github.com/JamesGeee/CVE-2021-32656](https://github.com/JamesGeee/CVE-2021-32656) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-32656.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-32656.svg)


## CVE-2021-32620
 ### Impact A user disabled on a wiki using email verification for registration can re-activate himself by using the activation link provided for his registration. ### Patches The problem has been patched in the following versions of XWiki: 11.10.13, 12.6.7, 12.10.2, 13.0. ### Workarounds It's possible to workaround the issue by resetting the `validkey` property of the disabled XWiki users. This can be done by editing the user profile with object editor. ### References https://jira.xwiki.org/browse/XWIKI-17942 ### For more information If you have any questions or comments about this advisory: * Open an issue in [Jira](http://jira.xwiki.org) * Email us at [Security mailing-list](mailto:security@xwiki.org)

- [https://github.com/JamesGeee/CVE-2021-32620](https://github.com/JamesGeee/CVE-2021-32620) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-32620.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-32620.svg)


## CVE-2021-32617
 Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata of image files. An inefficient algorithm (quadratic complexity) was found in Exiv2 versions v0.27.3 and earlier. The inefficient algorithm is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they can trick the victim into running Exiv2 on a crafted image file. The bug is fixed in version v0.27.4. Note that this bug is only triggered when _writing_ the metadata, which is a less frequently used Exiv2 operation than _reading_ the metadata. For example, to trigger the bug in the Exiv2 command-line application, you need to add an extra command-line argument such as `rm`.

- [https://github.com/JamesGeee/CVE-2021-32617](https://github.com/JamesGeee/CVE-2021-32617) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-32617.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-32617.svg)


## CVE-2021-31703
 Frontier ichris through 5.18 allows users to upload malicious executable files that might later be downloaded and run by any client user.

- [https://github.com/JamesGeee/CVE-2021-31703](https://github.com/JamesGeee/CVE-2021-31703) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-31703.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-31703.svg)


## CVE-2021-31702
 Frontier ichris through 5.18 mishandles making a DNS request for the hostname in the HTTP Host header, as demonstrated by submitting 127.0.0.1 multiple times for DoS.

- [https://github.com/JamesGeee/CVE-2021-31702](https://github.com/JamesGeee/CVE-2021-31702) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-31702.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-31702.svg)


## CVE-2021-30498
 A flaw was found in libcaca. A heap buffer overflow in export.c in function export_tga might lead to memory corruption and other potential consequences.

- [https://github.com/JamesGeee/CVE-2021-30498](https://github.com/JamesGeee/CVE-2021-30498) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-30498.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-30498.svg)


## CVE-2021-30465
 runc before 1.0.0-rc95 allows a Container Filesystem Breakout via Directory Traversal. To exploit the vulnerability, an attacker must be able to create multiple containers with a fairly specific mount configuration. The problem occurs via a symlink-exchange attack that relies on a race condition.

- [https://github.com/JamesGeee/CVE-2021-30465](https://github.com/JamesGeee/CVE-2021-30465) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-30465.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-30465.svg)


## CVE-2021-30461
 A remote code execution issue was discovered in the web UI of VoIPmonitor before 24.61. When the recheck option is used, the user-supplied SPOOLDIR value (which might contain PHP code) is injected into config/configuration.php.

- [https://github.com/JamesGeee/CVE-2021-30461](https://github.com/JamesGeee/CVE-2021-30461) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-30461.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-30461.svg)


## CVE-2021-29623
 Exiv2 is a C++ library and a command-line utility to read, write, delete and modify Exif, IPTC, XMP and ICC image metadata. A read of uninitialized memory was found in Exiv2 versions v0.27.3 and earlier. Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata of image files. The read of uninitialized memory is triggered when Exiv2 is used to read the metadata of a crafted image file. An attacker could potentially exploit the vulnerability to leak a few bytes of stack memory, if they can trick the victim into running Exiv2 on a crafted image file. The bug is fixed in version v0.27.4.

- [https://github.com/JamesGeee/CVE-2021-29623](https://github.com/JamesGeee/CVE-2021-29623) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29623.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29623.svg)


## CVE-2021-29507
 ### Impact _What kind of vulnerability is it? Who is impacted?_ The vulnerable component could be crashed when the configuration file is intentionally/ unintentionally containing the special characters. All the applications which are using could fail to generate their dlt logs in system. ### Patches _Has the problem been patched? What versions should users upgrade to?_ There is solution for the problem but the patch is not integrated yet. ### Workarounds _Is there a way for users to fix or remediate the vulnerability without upgrading?_ Check the integrity of information in configuration file manually. ### References _Are there any links users can visit to find out more?_ N/A ### For more information If you have any questions or comments about this advisory: * Open an issue in [ GENIVI/dlt-daemon ](https://github.com/GENIVI/dlt-daemon/issues) * Email us at [Mailinglist](mailto:https://lists.genivi.org/mailman/listinfo/genivi-diagnostic-log-and-trace_lists.genivi.org)

- [https://github.com/JamesGeee/CVE-2021-29507](https://github.com/JamesGeee/CVE-2021-29507) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29507.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29507.svg)


## CVE-2021-29505
 ### Impact The vulnerability may allow a remote attacker has sufficient rights to execute commands of the host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. ### Patches If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.17. ### Workarounds See [workarounds](https://x-stream.github.io/security.html#workaround) for the different versions covering all CVEs. ### References See full information about the nature of the vulnerability and the steps to reproduce it in XStream's documentation for [CVE-2021-xxxxx](https://x-stream.github.io/CVE-2021-xxxxx.html). ### Credits V3geB1rd, white hat hacker from Tencent Security Response Center found and reported the issue to XStream and provided the required information to reproduce it. ### For more information If you have any questions or comments about this advisory: * Open an issue in [XStream](https://github.com/x-stream/xstream/issues) * Email us at [XStream Google Group](https://groups.google.com/group/xstream-user)

- [https://github.com/JamesGeee/CVE-2021-29505](https://github.com/JamesGeee/CVE-2021-29505) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29505.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29505.svg)


## CVE-2021-29492
 ### Description Envoy does not decode escaped slash sequences `%2F` and `%5C` in HTTP URL paths in versions 1.18.2 and before. A remote attacker may craft a path with escaped slashes, e.g. `/something%2F..%2Fadmin`, to bypass access control, e.g. a block on `/admin`. A backend server could then decode slash sequences and normalize path and provide an attacker access beyond the scope provided for by the access control policy. ### Impact Escalation of Privileges when using RBAC or JWT filters with enforcement based on URL path. Users with back end servers that interpret `%2F` and `/` and `%5C` and `\` interchangeably are impacted. ### Attack Vector URL paths containing escaped slash characters delivered by untrusted client. ### Patches Envoy versions 1.18.3, 1.17.3, 1.16.4, 1.15.5 contain new path normalization option to decode escaped slash characters. ### Workarounds If back end servers treat `%2F` and `/` and `%5C` and `\` interchangeably and a URL path based access control is configured, we recommend reconfiguring back end server to not treat `%2F` and `/` and `%5C` and `\` interchangeably if feasible. ### Credit Ruilin Yang (ruilin.yrl@gmail.com) ### References https://blog.envoyproxy.io https://github.com/envoyproxy/envoy/releases ### For more information If you have any questions or comments about this advisory: * Open an issue in [Envoy repo](https://github.com/envoyproxy/envoy/issues) * Email us at [envoy-security](mailto:envoy-security@googlegroups.com)

- [https://github.com/JamesGeee/CVE-2021-29492](https://github.com/JamesGeee/CVE-2021-29492) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29492.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29492.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/dnr6419/CVE-2021-29447](https://github.com/dnr6419/CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/dnr6419/CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/dnr6419/CVE-2021-29447.svg)


## CVE-2021-29252
 RSA Archer before 6.9 SP1 P1 (6.9.1.1) contains a stored XSS vulnerability. A remote authenticated malicious Archer user with access to modify link name fields could potentially exploit this vulnerability to execute code in a victim's browser.

- [https://github.com/JamesGeee/CVE-2021-29252](https://github.com/JamesGeee/CVE-2021-29252) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-29252.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-29252.svg)


## CVE-2021-23343
 All versions of package path-parse are vulnerable to Regular Expression Denial of Service (ReDoS) via splitDeviceRe, splitTailRe, and splitPathRe regular expressions. ReDoS exhibits polynomial worst-case time complexity.

- [https://github.com/JamesGeee/CVE-2021-23343](https://github.com/JamesGeee/CVE-2021-23343) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-23343.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-23343.svg)


## CVE-2021-23336
 The package python/cpython from 0 and before 3.6.13, from 3.7.0 and before 3.7.10, from 3.8.0 and before 3.8.8, from 3.9.0 and before 3.9.2 are vulnerable to Web Cache Poisoning via urllib.parse.parse_qsl and urllib.parse.parse_qs by using a vector called parameter cloaking. When the attacker can separate query parameters using a semicolon (;), they can cause a difference in the interpretation of the request between the proxy (running with default configuration) and the server. This can result in malicious requests being cached as completely safe ones, as the proxy would usually not see the semicolon as a separator, and therefore would not include it in a cache key of an unkeyed parameter.

- [https://github.com/JamesGeee/CVE-2021-23336](https://github.com/JamesGeee/CVE-2021-23336) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-23336.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-23336.svg)


## CVE-2021-21985
 The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.

- [https://github.com/onSec-fr/CVE-2021-21985-Checker](https://github.com/onSec-fr/CVE-2021-21985-Checker) :  ![starts](https://img.shields.io/github/stars/onSec-fr/CVE-2021-21985-Checker.svg) ![forks](https://img.shields.io/github/forks/onSec-fr/CVE-2021-21985-Checker.svg)
- [https://github.com/mauricelambert/CVE-2021-21985](https://github.com/mauricelambert/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/mauricelambert/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/mauricelambert/CVE-2021-21985.svg)


## CVE-2021-21424
 Symfony is a PHP framework for web and console applications and a set of reusable PHP components. The ability to enumerate users was possible without relevant permissions due to different handling depending on whether the user existed or not when attempting to use the switch users functionality. We now ensure that 403s are returned whether the user exists or not if a user cannot switch to a user or if the user does not exist. The patch for this issue is available for branch 3.4.

- [https://github.com/JamesGeee/CVE-2021-21424](https://github.com/JamesGeee/CVE-2021-21424) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-21424.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-21424.svg)


## CVE-2021-20254
 A flaw was found in samba. The Samba smbd file server must map Windows group identities (SIDs) into unix group ids (gids). The code that performs this had a flaw that could allow it to read data beyond the end of the array in the case where a negative cache entry had been added to the mapping cache. This could cause the calling code to return those values into the process token that stores the group membership for a user. The highest threat from this vulnerability is to data confidentiality and integrity.

- [https://github.com/JamesGeee/CVE-2021-20254](https://github.com/JamesGeee/CVE-2021-20254) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-20254.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-20254.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/JamesGeee/CVE-2021-3493](https://github.com/JamesGeee/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-3493.svg)


## CVE-2021-1871
 A logic issue was addressed with improved restrictions. This issue is fixed in macOS Big Sur 11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, iOS 14.4 and iPadOS 14.4. A remote attacker may be able to cause arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited..

- [https://github.com/JamesGeee/CVE-2021-1871](https://github.com/JamesGeee/CVE-2021-1871) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-1871.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-1871.svg)


## CVE-2021-1844
 A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 14.4.1 and iPadOS 14.4.1, Safari 14.0.3 (v. 14610.4.3.1.7 and 15610.4.3.1.7), watchOS 7.3.2, macOS Big Sur 11.2.3. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/JamesGeee/CVE-2021-1844](https://github.com/JamesGeee/CVE-2021-1844) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-1844.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-1844.svg)


## CVE-2021-1788
 A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur 11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, tvOS 14.4, watchOS 7.3, iOS 14.4 and iPadOS 14.4, Safari 14.0.3. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/JamesGeee/CVE-2021-1788](https://github.com/JamesGeee/CVE-2021-1788) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-1788.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-1788.svg)


## CVE-2021-1738
 An out-of-bounds write was addressed with improved input validation. This issue is fixed in macOS Big Sur 11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave. Processing a maliciously crafted image may lead to arbitrary code execution.

- [https://github.com/JamesGeee/CVE-2021-1738](https://github.com/JamesGeee/CVE-2021-1738) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-1738.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-1738.svg)


## CVE-2021-1737
 An out-of-bounds write was addressed with improved input validation. This issue is fixed in macOS Big Sur 11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave. Processing a maliciously crafted image may lead to arbitrary code execution.

- [https://github.com/JamesGeee/CVE-2021-1737](https://github.com/JamesGeee/CVE-2021-1737) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2021-1737.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2021-1737.svg)


## CVE-2020-36375
 Stack overflow vulnerability in parse_equality Cesanta MJS 1.20.1, allows remote attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/JamesGeee/CVE-2020-36375](https://github.com/JamesGeee/CVE-2020-36375) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-36375.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-36375.svg)


## CVE-2020-36374
 Stack overflow vulnerability in parse_comparison Cesanta MJS 1.20.1, allows remote attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/JamesGeee/CVE-2020-36374](https://github.com/JamesGeee/CVE-2020-36374) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-36374.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-36374.svg)


## CVE-2020-36373
 Stack overflow vulnerability in parse_shifts Cesanta MJS 1.20.1, allows remote attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/JamesGeee/CVE-2020-36373](https://github.com/JamesGeee/CVE-2020-36373) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-36373.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-36373.svg)


## CVE-2020-36372
 Stack overflow vulnerability in parse_plus_minus Cesanta MJS 1.20.1, allows remote attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/JamesGeee/CVE-2020-36372](https://github.com/JamesGeee/CVE-2020-36372) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-36372.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-36372.svg)


## CVE-2020-36371
 Stack overflow vulnerability in parse_mul_div_rem Cesanta MJS 1.20.1, allows remote attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/JamesGeee/CVE-2020-36371](https://github.com/JamesGeee/CVE-2020-36371) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-36371.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-36371.svg)


## CVE-2020-36370
 Stack overflow vulnerability in parse_unary Cesanta MJS 1.20.1, allows remote attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/JamesGeee/CVE-2020-36370](https://github.com/JamesGeee/CVE-2020-36370) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-36370.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-36370.svg)


## CVE-2020-36369
 Stack overflow vulnerability in parse_statement_list Cesanta MJS 1.20.1, allows remote attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/JamesGeee/CVE-2020-36369](https://github.com/JamesGeee/CVE-2020-36369) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-36369.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-36369.svg)


## CVE-2020-36368
 Stack overflow vulnerability in parse_statement Cesanta MJS 1.20.1, allows remote attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/JamesGeee/CVE-2020-36368](https://github.com/JamesGeee/CVE-2020-36368) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-36368.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-36368.svg)


## CVE-2020-36367
 Stack overflow vulnerability in parse_block Cesanta MJS 1.20.1, allows remote attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/JamesGeee/CVE-2020-36367](https://github.com/JamesGeee/CVE-2020-36367) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-36367.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-36367.svg)


## CVE-2020-36366
 Stack overflow vulnerability in parse_value Cesanta MJS 1.20.1, allows remote attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/JamesGeee/CVE-2020-36366](https://github.com/JamesGeee/CVE-2020-36366) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-36366.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-36366.svg)


## CVE-2020-27619
 In Python 3 through 3.9.0, the Lib/test/multibytecodec_support.py CJK codec tests call eval() on content retrieved via HTTP.

- [https://github.com/JamesGeee/CVE-2020-27619](https://github.com/JamesGeee/CVE-2020-27619) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-27619.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-27619.svg)


## CVE-2020-25710
 A flaw was found in OpenLDAP in versions before 2.4.56. This flaw allows an attacker who sends a malicious packet processed by OpenLDAP to force a failed assertion in csnNormalize23(). The highest threat from this vulnerability is to system availability.

- [https://github.com/JamesGeee/CVE-2020-25710](https://github.com/JamesGeee/CVE-2020-25710) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-25710.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-25710.svg)


## CVE-2020-18395
 A NULL-pointer deference issue was discovered in GNU_gama::set() in ellipsoid.h in Gama 2.04 which can lead to a denial of service (DOS) via segment faults caused by crafted inputs.

- [https://github.com/JamesGeee/CVE-2020-18395](https://github.com/JamesGeee/CVE-2020-18395) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-18395.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-18395.svg)


## CVE-2020-18392
 Stack overflow vulnerability in parse_array Cesanta MJS 1.20.1, allows remote attackers to cause a Denial of Service (DoS) via a crafted file.

- [https://github.com/JamesGeee/CVE-2020-18392](https://github.com/JamesGeee/CVE-2020-18392) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-18392.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-18392.svg)


## CVE-2020-13956
 Apache HttpClient versions prior to version 4.5.13 and 5.0.3 can misinterpret malformed authority component in request URIs passed to the library as java.net.URI object and pick the wrong target host for request execution.

- [https://github.com/JamesGeee/CVE-2020-13956](https://github.com/JamesGeee/CVE-2020-13956) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-13956.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-13956.svg)


## CVE-2020-12460
 OpenDMARC through 1.3.2 and 1.4.x through 1.4.0-Beta1 has improper null termination in the function opendmarc_xml_parse that can result in a one-byte heap overflow in opendmarc_xml when parsing a specially crafted DMARC aggregate report. This can cause remote memory corruption when a '\0' byte overwrites the heap metadata of the next chunk and its PREV_INUSE flag.

- [https://github.com/JamesGeee/CVE-2020-12460](https://github.com/JamesGeee/CVE-2020-12460) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-12460.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-12460.svg)


## CVE-2020-12272
 OpenDMARC through 1.3.2 and 1.4.x allows attacks that inject authentication results to provide false information about the domain that originated an e-mail message. This is caused by incorrect parsing and interpretation of SPF/DKIM authentication results, as demonstrated by the example.net(.example.com substring.

- [https://github.com/JamesGeee/CVE-2020-12272](https://github.com/JamesGeee/CVE-2020-12272) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-12272.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-12272.svg)


## CVE-2020-11978
 An issue was found in Apache Airflow versions 1.10.10 and below. A remote code/command injection vulnerability was discovered in one of the example DAGs shipped with Airflow which would allow any authenticated user to run arbitrary commands as the user running airflow worker/scheduler (depending on the executor in use). If you already have examples disabled by setting load_examples=False in the config then you are not vulnerable.

- [https://github.com/pberba/CVE-2020-11978](https://github.com/pberba/CVE-2020-11978) :  ![starts](https://img.shields.io/github/stars/pberba/CVE-2020-11978.svg) ![forks](https://img.shields.io/github/forks/pberba/CVE-2020-11978.svg)


## CVE-2020-10666
 The restapps (aka Rest Phone apps) module for Sangoma FreePBX and PBXact 13, 14, and 15 through 15.0.19.2 allows remote code execution via a URL variable to an AMI command.

- [https://github.com/JamesGeee/CVE-2020-10666](https://github.com/JamesGeee/CVE-2020-10666) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2020-10666.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2020-10666.svg)


## CVE-2019-10218
 A flaw was found in the samba client, all samba versions before samba 4.11.2, 4.10.10 and 4.9.15, where a malicious server can supply a pathname to the client with separators. This could allow the client to access files and folders outside of the SMB network pathnames. An attacker could use this vulnerability to create files outside of the current working directory using the privileges of the client user.

- [https://github.com/JamesGeee/CVE-2019-10218](https://github.com/JamesGeee/CVE-2019-10218) :  ![starts](https://img.shields.io/github/stars/JamesGeee/CVE-2019-10218.svg) ![forks](https://img.shields.io/github/forks/JamesGeee/CVE-2019-10218.svg)


## CVE-2018-16167
 LogonTracer 1.2.0 and earlier allows remote attackers to execute arbitrary OS commands via unspecified vectors.

- [https://github.com/dnr6419/CVE-2018-16167](https://github.com/dnr6419/CVE-2018-16167) :  ![starts](https://img.shields.io/github/stars/dnr6419/CVE-2018-16167.svg) ![forks](https://img.shields.io/github/forks/dnr6419/CVE-2018-16167.svg)


## CVE-2018-6905
 The page module in TYPO3 before 8.7.11, and 9.1.0, has XSS via $GLOBALS['TYPO3_CONF_VARS']['SYS']['sitename'], as demonstrated by an admin entering a crafted site name during the installation process.

- [https://github.com/dnr6419/CVE-2018-6905](https://github.com/dnr6419/CVE-2018-6905) :  ![starts](https://img.shields.io/github/stars/dnr6419/CVE-2018-6905.svg) ![forks](https://img.shields.io/github/forks/dnr6419/CVE-2018-6905.svg)

