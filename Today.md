# Update 2025-07-20
## CVE-2025-53367
 DjVuLibre is a GPL implementation of DjVu, a web-centric format for distributing documents and images. Prior to version 3.5.29, the MMRDecoder::scanruns method is affected by an OOB-write vulnerability, because it does not check that the xr pointer stays within the bounds of the allocated buffer. This can lead to writes beyond the allocated memory, resulting in a heap corruption condition. An out-of-bounds read with pr is also possible for the same reason. This issue has been patched in version 3.5.29.

- [https://github.com/kevinbackhouse/DjVuLibre-poc-CVE-2025-53367](https://github.com/kevinbackhouse/DjVuLibre-poc-CVE-2025-53367) :  ![starts](https://img.shields.io/github/stars/kevinbackhouse/DjVuLibre-poc-CVE-2025-53367.svg) ![forks](https://img.shields.io/github/forks/kevinbackhouse/DjVuLibre-poc-CVE-2025-53367.svg)


## CVE-2025-47176
 '.../...//' in Microsoft Office Outlook allows an authorized attacker to execute code locally.

- [https://github.com/mahyarx/CVE-2025-47176](https://github.com/mahyarx/CVE-2025-47176) :  ![starts](https://img.shields.io/github/stars/mahyarx/CVE-2025-47176.svg) ![forks](https://img.shields.io/github/forks/mahyarx/CVE-2025-47176.svg)


## CVE-2025-45157
 Insecure permissions in Splashin iOS v2.0 allow unauthorized attackers to access location data for specific users.

- [https://github.com/carterlasalle/splashin-cve-2025](https://github.com/carterlasalle/splashin-cve-2025) :  ![starts](https://img.shields.io/github/stars/carterlasalle/splashin-cve-2025.svg) ![forks](https://img.shields.io/github/forks/carterlasalle/splashin-cve-2025.svg)


## CVE-2025-45156
 Splashin iOS v2.0 fails to enforce server-side interval restrictions for location updates for free-tier users.

- [https://github.com/carterlasalle/splashin-cve-2025](https://github.com/carterlasalle/splashin-cve-2025) :  ![starts](https://img.shields.io/github/stars/carterlasalle/splashin-cve-2025.svg) ![forks](https://img.shields.io/github/forks/carterlasalle/splashin-cve-2025.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/MGunturG/CVE-2025-32463](https://github.com/MGunturG/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/MGunturG/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/MGunturG/CVE-2025-32463.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/incommatose/CVE-2025-27591-PoC](https://github.com/incommatose/CVE-2025-27591-PoC) :  ![starts](https://img.shields.io/github/stars/incommatose/CVE-2025-27591-PoC.svg) ![forks](https://img.shields.io/github/forks/incommatose/CVE-2025-27591-PoC.svg)


## CVE-2025-27210
This vulnerability affects Windows users of `path.join` API.

- [https://github.com/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit](https://github.com/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-27210](https://github.com/B1ack4sh/Blackash-CVE-2025-27210) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-27210.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-27210.svg)


## CVE-2025-25257
 An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89] in Fortinet FortiWeb version 7.6.0 through 7.6.3, 7.4.0 through 7.4.7, 7.2.0 through 7.2.10 and below 7.0.10 allows an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPs requests.

- [https://github.com/aitorfirm/CVE-2025-25257](https://github.com/aitorfirm/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/aitorfirm/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/aitorfirm/CVE-2025-25257.svg)


## CVE-2025-7783
This issue affects form-data:  2.5.4, 3.0.0 - 3.0.3, 4.0.0 - 4.0.3.

- [https://github.com/benweissmann/CVE-2025-7783-poc](https://github.com/benweissmann/CVE-2025-7783-poc) :  ![starts](https://img.shields.io/github/stars/benweissmann/CVE-2025-7783-poc.svg) ![forks](https://img.shields.io/github/forks/benweissmann/CVE-2025-7783-poc.svg)


## CVE-2025-7753
 A vulnerability was found in code-projects Online Appointment Booking System 1.0. It has been classified as critical. This affects an unknown part of the file /admin/adddoctor.php. The manipulation of the argument Username leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/byteReaper77/CVE-2025-7753](https://github.com/byteReaper77/CVE-2025-7753) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-7753.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-7753.svg)


## CVE-2025-4551
 A vulnerability, which was classified as problematic, was found in ContiNew Admin up to 3.6.0. Affected is an unknown function of the file /dev-api/common/file. The manipulation of the argument File leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/AzhariRamadhan/CVE-2025-45512](https://github.com/AzhariRamadhan/CVE-2025-45512) :  ![starts](https://img.shields.io/github/stars/AzhariRamadhan/CVE-2025-45512.svg) ![forks](https://img.shields.io/github/forks/AzhariRamadhan/CVE-2025-45512.svg)


## CVE-2022-44136
 Zenario CMS 9.3.57186 is vulnerable to Remote Code Excution (RCE).

- [https://github.com/Ch35h1r3c47/CVE-2022-44136-poc](https://github.com/Ch35h1r3c47/CVE-2022-44136-poc) :  ![starts](https://img.shields.io/github/stars/Ch35h1r3c47/CVE-2022-44136-poc.svg) ![forks](https://img.shields.io/github/forks/Ch35h1r3c47/CVE-2022-44136-poc.svg)


## CVE-2022-41352
 An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15 and 9.0. An attacker can upload arbitrary files through amavis via a cpio loophole (extraction to /opt/zimbra/jetty/webapps/zimbra/public) that can lead to incorrect access to any other user accounts. Zimbra recommends pax over cpio. Also, pax is in the prerequisites of Zimbra on Ubuntu; however, pax is no longer part of a default Red Hat installation after RHEL 6 (or CentOS 6). Once pax is installed, amavis automatically prefers it over cpio.

- [https://github.com/Cr4ckC4t/cve-2022-41352-zimbra-rce](https://github.com/Cr4ckC4t/cve-2022-41352-zimbra-rce) :  ![starts](https://img.shields.io/github/stars/Cr4ckC4t/cve-2022-41352-zimbra-rce.svg) ![forks](https://img.shields.io/github/forks/Cr4ckC4t/cve-2022-41352-zimbra-rce.svg)
- [https://github.com/segfault-it/cve-2022-41352](https://github.com/segfault-it/cve-2022-41352) :  ![starts](https://img.shields.io/github/stars/segfault-it/cve-2022-41352.svg) ![forks](https://img.shields.io/github/forks/segfault-it/cve-2022-41352.svg)
- [https://github.com/rxerium/CVE-2022-41352](https://github.com/rxerium/CVE-2022-41352) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2022-41352.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2022-41352.svg)
- [https://github.com/MuhammadWaseem29/cve-2022-41352](https://github.com/MuhammadWaseem29/cve-2022-41352) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/cve-2022-41352.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/cve-2022-41352.svg)
- [https://github.com/qailanet/cve-2022-41352-zimbra-rce](https://github.com/qailanet/cve-2022-41352-zimbra-rce) :  ![starts](https://img.shields.io/github/stars/qailanet/cve-2022-41352-zimbra-rce.svg) ![forks](https://img.shields.io/github/forks/qailanet/cve-2022-41352-zimbra-rce.svg)


## CVE-2022-4610
 A vulnerability, which was classified as problematic, has been found in Click Studios Passwordstate and Passwordstate Browser Extension Chrome. Affected by this issue is some unknown functionality. The manipulation leads to risky cryptographic algorithm. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-216272.

- [https://github.com/NurSec747/CVE-2022-46104---POC](https://github.com/NurSec747/CVE-2022-46104---POC) :  ![starts](https://img.shields.io/github/stars/NurSec747/CVE-2022-46104---POC.svg) ![forks](https://img.shields.io/github/forks/NurSec747/CVE-2022-46104---POC.svg)


## CVE-2022-4395
 The Membership For WooCommerce WordPress plugin before 2.1.7 does not validate uploaded files, which could allow unauthenticated users to upload arbitrary files, such as malicious PHP code, and achieve RCE.

- [https://github.com/MrG3P5/CVE-2022-4395](https://github.com/MrG3P5/CVE-2022-4395) :  ![starts](https://img.shields.io/github/stars/MrG3P5/CVE-2022-4395.svg) ![forks](https://img.shields.io/github/forks/MrG3P5/CVE-2022-4395.svg)


## CVE-2022-3869
 Code Injection in GitHub repository froxlor/froxlor prior to 0.10.38.2.

- [https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader](https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader) :  ![starts](https://img.shields.io/github/stars/TomKing062/CVE-2022-38694_unlock_bootloader.svg) ![forks](https://img.shields.io/github/forks/TomKing062/CVE-2022-38694_unlock_bootloader.svg)
- [https://github.com/TomKing062/CVE-2022-38691_38692](https://github.com/TomKing062/CVE-2022-38691_38692) :  ![starts](https://img.shields.io/github/stars/TomKing062/CVE-2022-38691_38692.svg) ![forks](https://img.shields.io/github/forks/TomKing062/CVE-2022-38691_38692.svg)


## CVE-2022-3328
 Race condition in snap-confine's must_mkdir_and_open_with_perms()

- [https://github.com/Mr-xn/CVE-2022-3328](https://github.com/Mr-xn/CVE-2022-3328) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2022-3328.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2022-3328.svg)


## CVE-2021-32099
 A SQL injection vulnerability in the pandora_console component of Artica Pandora FMS 742 allows an unauthenticated attacker to upgrade his unprivileged session via the /include/chart_generator.php session_id parameter, leading to a login bypass.

- [https://github.com/magicrc/CVE-2021-32099](https://github.com/magicrc/CVE-2021-32099) :  ![starts](https://img.shields.io/github/stars/magicrc/CVE-2021-32099.svg) ![forks](https://img.shields.io/github/forks/magicrc/CVE-2021-32099.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/Maalfer/Sudo-CVE-2021-3156](https://github.com/Maalfer/Sudo-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Maalfer/Sudo-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Maalfer/Sudo-CVE-2021-3156.svg)


## CVE-2012-2688
 Unspecified vulnerability in the _php_stream_scandir function in the stream implementation in PHP before 5.3.15 and 5.4.x before 5.4.5 has unknown impact and remote attack vectors, related to an "overflow."

- [https://github.com/shelld3v/CVE-2012-2688](https://github.com/shelld3v/CVE-2012-2688) :  ![starts](https://img.shields.io/github/stars/shelld3v/CVE-2012-2688.svg) ![forks](https://img.shields.io/github/forks/shelld3v/CVE-2012-2688.svg)


## CVE-2012-2661
 The Active Record component in Ruby on Rails 3.0.x before 3.0.13, 3.1.x before 3.1.5, and 3.2.x before 3.2.4 does not properly implement the passing of request data to a where method in an ActiveRecord class, which allows remote attackers to conduct certain SQL injection attacks via nested query parameters that leverage unintended recursion, a related issue to CVE-2012-2695.

- [https://github.com/r4x0r1337/-CVE-2012-2661-ActiveRecord-SQL-injection-](https://github.com/r4x0r1337/-CVE-2012-2661-ActiveRecord-SQL-injection-) :  ![starts](https://img.shields.io/github/stars/r4x0r1337/-CVE-2012-2661-ActiveRecord-SQL-injection-.svg) ![forks](https://img.shields.io/github/forks/r4x0r1337/-CVE-2012-2661-ActiveRecord-SQL-injection-.svg)

