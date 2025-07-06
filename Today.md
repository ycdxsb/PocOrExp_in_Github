# Update 2025-07-06
## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/uxieltc/CVE-2025-49132](https://github.com/uxieltc/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/uxieltc/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/uxieltc/CVE-2025-49132.svg)


## CVE-2025-41646
 An unauthorized remote attacker can bypass the authentication of the affected software package by misusing an incorrect type conversion. This leads to full compromise of the device

- [https://github.com/cyberre124/CVE-2025-41646---Critical-Authentication-Bypass-](https://github.com/cyberre124/CVE-2025-41646---Critical-Authentication-Bypass-) :  ![starts](https://img.shields.io/github/stars/cyberre124/CVE-2025-41646---Critical-Authentication-Bypass-.svg) ![forks](https://img.shields.io/github/forks/cyberre124/CVE-2025-41646---Critical-Authentication-Bypass-.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-32463](https://github.com/B1ack4sh/Blackash-CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-32463.svg)
- [https://github.com/zinzloun/CVE-2025-32463](https://github.com/zinzloun/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/zinzloun/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/zinzloun/CVE-2025-32463.svg)
- [https://github.com/SkylerMC/CVE-2025-32463](https://github.com/SkylerMC/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/SkylerMC/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/SkylerMC/CVE-2025-32463.svg)
- [https://github.com/ill-deed/CVE-2025-32463_illdeed](https://github.com/ill-deed/CVE-2025-32463_illdeed) :  ![starts](https://img.shields.io/github/stars/ill-deed/CVE-2025-32463_illdeed.svg) ![forks](https://img.shields.io/github/forks/ill-deed/CVE-2025-32463_illdeed.svg)
- [https://github.com/yeremeu/CVE-2025-32463_chwoot](https://github.com/yeremeu/CVE-2025-32463_chwoot) :  ![starts](https://img.shields.io/github/stars/yeremeu/CVE-2025-32463_chwoot.svg) ![forks](https://img.shields.io/github/forks/yeremeu/CVE-2025-32463_chwoot.svg)
- [https://github.com/cyberpoul/CVE-2025-32463-POC](https://github.com/cyberpoul/CVE-2025-32463-POC) :  ![starts](https://img.shields.io/github/stars/cyberpoul/CVE-2025-32463-POC.svg) ![forks](https://img.shields.io/github/forks/cyberpoul/CVE-2025-32463-POC.svg)


## CVE-2025-32462
 Sudo before 1.9.17p1, when used with a sudoers file that specifies a host that is neither the current host nor ALL, allows listed users to execute commands on unintended machines.

- [https://github.com/cyberpoul/CVE-2025-32462-POC](https://github.com/cyberpoul/CVE-2025-32462-POC) :  ![starts](https://img.shields.io/github/stars/cyberpoul/CVE-2025-32462-POC.svg) ![forks](https://img.shields.io/github/forks/cyberpoul/CVE-2025-32462-POC.svg)


## CVE-2025-27817
Since Apache Kafka 3.9.1/4.0.0, we have added a system property ("-Dorg.apache.kafka.sasl.oauthbearer.allowed.urls") to set the allowed urls in SASL JAAS configuration. In 3.9.1, it accepts all urls by default for backward compatibility. However in 4.0.0 and newer, the default value is empty list and users have to set the allowed urls explicitly.

- [https://github.com/iSee857/CVE-2025-27817](https://github.com/iSee857/CVE-2025-27817) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-27817.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-27817.svg)


## CVE-2025-20281
This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by submitting a crafted API request. A successful exploit could allow the attacker to obtain root privileges on an affected device.

- [https://github.com/ill-deed/Cisco-CVE-2025-20281-illdeed](https://github.com/ill-deed/Cisco-CVE-2025-20281-illdeed) :  ![starts](https://img.shields.io/github/stars/ill-deed/Cisco-CVE-2025-20281-illdeed.svg) ![forks](https://img.shields.io/github/forks/ill-deed/Cisco-CVE-2025-20281-illdeed.svg)


## CVE-2025-6907
 A vulnerability classified as critical was found in code-projects Car Rental System 1.0. This vulnerability affects unknown code of the file /book_car.php. The manipulation of the argument fname leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/byteReaper77/cve-2025-6907](https://github.com/byteReaper77/cve-2025-6907) :  ![starts](https://img.shields.io/github/stars/byteReaper77/cve-2025-6907.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/cve-2025-6907.svg)


## CVE-2025-6586
 The Download Plugin plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the dpwap_plugin_locInstall function in all versions up to, and including, 2.2.8. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/d0n601/CVE-2025-6586](https://github.com/d0n601/CVE-2025-6586) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-6586.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-6586.svg)


## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/windz3r0day/CVE-2025-6554](https://github.com/windz3r0day/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/windz3r0day/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/windz3r0day/CVE-2025-6554.svg)
- [https://github.com/PwnToday/CVE-2025-6554](https://github.com/PwnToday/CVE-2025-6554) :  ![starts](https://img.shields.io/github/stars/PwnToday/CVE-2025-6554.svg) ![forks](https://img.shields.io/github/forks/PwnToday/CVE-2025-6554.svg)


## CVE-2025-5961
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'wpvivid_upload_import_files' function in all versions up to, and including, 0.9.116. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible. NOTE: Uploaded files are only accessible on WordPress instances running on the NGINX web server as the existing .htaccess within the target file upload folder prevents access on Apache servers.

- [https://github.com/Nxploited/CVE-2025-5961](https://github.com/Nxploited/CVE-2025-5961) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-5961.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-5961.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/RickGeex/CVE-2025-5777-CitrixBleed](https://github.com/RickGeex/CVE-2025-5777-CitrixBleed) :  ![starts](https://img.shields.io/github/stars/RickGeex/CVE-2025-5777-CitrixBleed.svg) ![forks](https://img.shields.io/github/forks/RickGeex/CVE-2025-5777-CitrixBleed.svg)


## CVE-2025-4781
 A vulnerability classified as critical has been found in PHPGurukul Park Ticketing Management System 2.0. Affected is an unknown function of the file /forgot-password.php. The manipulation of the argument email/contactno leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/ill-deed/WingFTP-CVE-2025-47812-illdeed](https://github.com/ill-deed/WingFTP-CVE-2025-47812-illdeed) :  ![starts](https://img.shields.io/github/stars/ill-deed/WingFTP-CVE-2025-47812-illdeed.svg) ![forks](https://img.shields.io/github/forks/ill-deed/WingFTP-CVE-2025-47812-illdeed.svg)


## CVE-2025-4722
 A vulnerability classified as critical has been found in itsourcecode Placement Management System 1.0. Affected is an unknown function of the file /edit_profile.php. The manipulation of the argument Name leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/synacktiv/CVE-2025-47227_CVE-2025-47228](https://github.com/synacktiv/CVE-2025-47227_CVE-2025-47228) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2025-47227_CVE-2025-47228.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2025-47227_CVE-2025-47228.svg)


## CVE-2024-4040
 A server side template injection vulnerability in CrushFTP in all versions before 10.7.1 and 11.1.0 on all platforms allows unauthenticated remote attackers to read files from the filesystem outside of the VFS Sandbox, bypass authentication to gain administrative access, and perform remote code execution on the server.

- [https://github.com/ill-deed/CrushFTP-CVE-2024-4040-illdeed](https://github.com/ill-deed/CrushFTP-CVE-2024-4040-illdeed) :  ![starts](https://img.shields.io/github/stars/ill-deed/CrushFTP-CVE-2024-4040-illdeed.svg) ![forks](https://img.shields.io/github/forks/ill-deed/CrushFTP-CVE-2024-4040-illdeed.svg)


## CVE-2022-46485
 Data Illusion Survey Software Solutions ngSurvey version 2.4.28 and below is vulnerable to Denial of Service if a survey contains a "Text Field", "Comment Field" or "Contact Details".

- [https://github.com/NevaSec/CVE-2022-46485](https://github.com/NevaSec/CVE-2022-46485) :  ![starts](https://img.shields.io/github/stars/NevaSec/CVE-2022-46485.svg) ![forks](https://img.shields.io/github/forks/NevaSec/CVE-2022-46485.svg)


## CVE-2022-46484
 Information disclosure in password protected surveys in Data Illusion Survey Software Solutions NGSurvey v2.4.28 and below allows attackers to view the password to access and arbitrarily submit surveys.

- [https://github.com/NevaSec/CVE-2022-46484](https://github.com/NevaSec/CVE-2022-46484) :  ![starts](https://img.shields.io/github/stars/NevaSec/CVE-2022-46484.svg) ![forks](https://img.shields.io/github/forks/NevaSec/CVE-2022-46484.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2018-12636
 The iThemes Security (better-wp-security) plugin before 7.0.3 for WordPress allows SQL Injection (by attackers with Admin privileges) via the logs page.

- [https://github.com/nth347/CVE-2018-12636_exploit](https://github.com/nth347/CVE-2018-12636_exploit) :  ![starts](https://img.shields.io/github/stars/nth347/CVE-2018-12636_exploit.svg) ![forks](https://img.shields.io/github/forks/nth347/CVE-2018-12636_exploit.svg)


## CVE-2017-12717
 An Uncontrolled Search Path Element issue was discovered in Advantech WebAccess versions prior to V8.2_20170817. A maliciously crafted dll file placed earlier in the search path may allow an attacker to execute code within the context of the application.

- [https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717](https://github.com/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717) :  ![starts](https://img.shields.io/github/stars/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg) ![forks](https://img.shields.io/github/forks/zi0Black/POC-CVE-2017-12615-or-CVE-2017-12717.svg)


## CVE-2017-12636
 CouchDB administrative users can configure the database server via HTTP(S). Some of the configuration options include paths for operating system-level binaries that are subsequently launched by CouchDB. This allows an admin user in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to execute arbitrary shell commands as the CouchDB user, including downloading and executing scripts from the public internet.

- [https://github.com/XTeam-Wing/CVE-2017-12636](https://github.com/XTeam-Wing/CVE-2017-12636) :  ![starts](https://img.shields.io/github/stars/XTeam-Wing/CVE-2017-12636.svg) ![forks](https://img.shields.io/github/forks/XTeam-Wing/CVE-2017-12636.svg)
- [https://github.com/moayadalmalat/CVE-2017-12636](https://github.com/moayadalmalat/CVE-2017-12636) :  ![starts](https://img.shields.io/github/stars/moayadalmalat/CVE-2017-12636.svg) ![forks](https://img.shields.io/github/forks/moayadalmalat/CVE-2017-12636.svg)


## CVE-2017-12635
 Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit _users documents with duplicate keys for 'roles' used for access control within the database, including the special case '_admin' role, that denotes administrative users. In combination with CVE-2017-12636 (Remote Code Execution), this can be used to give non-admin users access to arbitrary shell commands on the server as the database system user. The JSON parser differences result in behaviour that if two 'roles' keys are available in the JSON, the second one will be used for authorising the document write, but the first 'roles' key is used for subsequent authorization for the newly created user. By design, users can not assign themselves roles. The vulnerability allows non-admin users to give themselves admin privileges.

- [https://github.com/assalielmehdi/CVE-2017-12635](https://github.com/assalielmehdi/CVE-2017-12635) :  ![starts](https://img.shields.io/github/stars/assalielmehdi/CVE-2017-12635.svg) ![forks](https://img.shields.io/github/forks/assalielmehdi/CVE-2017-12635.svg)
- [https://github.com/cyberharsh/Apache-couchdb-CVE-2017-12635](https://github.com/cyberharsh/Apache-couchdb-CVE-2017-12635) :  ![starts](https://img.shields.io/github/stars/cyberharsh/Apache-couchdb-CVE-2017-12635.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/Apache-couchdb-CVE-2017-12635.svg)


## CVE-2017-12426
 GitLab Community Edition (CE) and Enterprise Edition (EE) before 8.17.8, 9.0.x before 9.0.13, 9.1.x before 9.1.10, 9.2.x before 9.2.10, 9.3.x before 9.3.10, and 9.4.x before 9.4.4 might allow remote attackers to execute arbitrary code via a crafted SSH URL in a project import.

- [https://github.com/sm-paul-schuette/CVE-2017-12426](https://github.com/sm-paul-schuette/CVE-2017-12426) :  ![starts](https://img.shields.io/github/stars/sm-paul-schuette/CVE-2017-12426.svg) ![forks](https://img.shields.io/github/forks/sm-paul-schuette/CVE-2017-12426.svg)

