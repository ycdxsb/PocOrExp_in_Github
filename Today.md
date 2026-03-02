# Update 2026-03-02
## CVE-2026-28372
 telnetd in GNU inetutils through 2.7 allows privilege escalation that can be exploited by abusing systemd service credentials support added to the login(1) implementation of util-linux in release 2.40. This is related to client control over the CREDENTIALS_DIRECTORY environment variable, and requires an unprivileged local user to create a login.noauth file.

- [https://github.com/kalibb/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation-main](https://github.com/kalibb/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation-main) :  ![starts](https://img.shields.io/github/stars/kalibb/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation-main.svg) ![forks](https://img.shields.io/github/forks/kalibb/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation-main.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-60787
 MotionEye v0.43.1b4 and before is vulnerable to OS Command Injection in configuration parameters such as image_file_name. Unsanitized user input is written to Motion configuration files, allowing remote authenticated attackers with admin access to achieve code execution when Motion is restarted.

- [https://github.com/GarethMSheldon/CVE-2025-60787-Detection-motionEye-RCE-via-Config-Injection](https://github.com/GarethMSheldon/CVE-2025-60787-Detection-motionEye-RCE-via-Config-Injection) :  ![starts](https://img.shields.io/github/stars/GarethMSheldon/CVE-2025-60787-Detection-motionEye-RCE-via-Config-Injection.svg) ![forks](https://img.shields.io/github/forks/GarethMSheldon/CVE-2025-60787-Detection-motionEye-RCE-via-Config-Injection.svg)


## CVE-2025-50286
 A Remote Code Execution (RCE) vulnerability in Grav CMS v1.7.48 allows an authenticated admin to upload a malicious plugin via the /admin/tools/direct-install interface. Once uploaded, the plugin is automatically extracted and loaded, allowing arbitrary PHP code execution and reverse shell access.

- [https://github.com/x1o3/CVE-2025-50286](https://github.com/x1o3/CVE-2025-50286) :  ![starts](https://img.shields.io/github/stars/x1o3/CVE-2025-50286.svg) ![forks](https://img.shields.io/github/forks/x1o3/CVE-2025-50286.svg)


## CVE-2025-15030
 The User Profile Builder  WordPress plugin before 3.15.2 does not have a proper password reset process, allowing a few unauthenticated requests to reset the password of any user by knowing their username, such as administrator ones, and therefore gain access to their account

- [https://github.com/haxorsecv1-netizen/CVE-2025-15030](https://github.com/haxorsecv1-netizen/CVE-2025-15030) :  ![starts](https://img.shields.io/github/stars/haxorsecv1-netizen/CVE-2025-15030.svg) ![forks](https://img.shields.io/github/forks/haxorsecv1-netizen/CVE-2025-15030.svg)


## CVE-2024-25096
 Improper Control of Generation of Code ('Code Injection') vulnerability in Canto Inc. Canto allows Code Injection.This issue affects Canto: from n/a through 3.0.7.

- [https://github.com/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE-CVE-2024-25096](https://github.com/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE-CVE-2024-25096) :  ![starts](https://img.shields.io/github/stars/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE-CVE-2024-25096.svg) ![forks](https://img.shields.io/github/forks/puppetma4ster/Metasploit-Wordpress-Canto-Exploit-RCE-CVE-2024-25096.svg)


## CVE-2024-21626
 runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem ("attack 2"). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run ("attack 1"). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes ("attack 3a" and "attack 3b"). runc 1.1.12 includes patches for this issue.

- [https://github.com/strikoder/cve-2024-21626-runc-1.1.11-escape](https://github.com/strikoder/cve-2024-21626-runc-1.1.11-escape) :  ![starts](https://img.shields.io/github/stars/strikoder/cve-2024-21626-runc-1.1.11-escape.svg) ![forks](https://img.shields.io/github/forks/strikoder/cve-2024-21626-runc-1.1.11-escape.svg)


## CVE-2023-30185
 CRMEB v4.4 to v4.6 was discovered to contain an arbitrary file upload vulnerability via the component \attachment\SystemAttachmentServices.php.

- [https://github.com/c7w1n/CVE-2023-30185](https://github.com/c7w1n/CVE-2023-30185) :  ![starts](https://img.shields.io/github/stars/c7w1n/CVE-2023-30185.svg) ![forks](https://img.shields.io/github/forks/c7w1n/CVE-2023-30185.svg)


## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- [https://github.com/7rootsec/CVE-2022-21661-Technical-Analysis](https://github.com/7rootsec/CVE-2022-21661-Technical-Analysis) :  ![starts](https://img.shields.io/github/stars/7rootsec/CVE-2022-21661-Technical-Analysis.svg) ![forks](https://img.shields.io/github/forks/7rootsec/CVE-2022-21661-Technical-Analysis.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)


## CVE-2021-23337
 Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.

- [https://github.com/khayashi4337/lodash.template-fixed](https://github.com/khayashi4337/lodash.template-fixed) :  ![starts](https://img.shields.io/github/stars/khayashi4337/lodash.template-fixed.svg) ![forks](https://img.shields.io/github/forks/khayashi4337/lodash.template-fixed.svg)


## CVE-2021-3928
 vim is vulnerable to Use of Uninitialized Variable

- [https://github.com/Fearless523/CVE-2021-39287-Stored-XSS](https://github.com/Fearless523/CVE-2021-39287-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/Fearless523/CVE-2021-39287-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/Fearless523/CVE-2021-39287-Stored-XSS.svg)


## CVE-2021-3019
 ffay lanproxy 0.1 allows Directory Traversal to read /../conf/config.properties to obtain credentials for a connection to the intranet.

- [https://github.com/0xf4n9x/CVE-2021-3019](https://github.com/0xf4n9x/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2021-3019.svg)
- [https://github.com/B1anda0/CVE-2021-3019](https://github.com/B1anda0/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/B1anda0/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/B1anda0/CVE-2021-3019.svg)
- [https://github.com/Maksim-venus/CVE-2021-3019](https://github.com/Maksim-venus/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/Maksim-venus/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/Maksim-venus/CVE-2021-3019.svg)
- [https://github.com/murataydemir/CVE-2021-3019](https://github.com/murataydemir/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2021-3019.svg)
- [https://github.com/a1665454764/CVE-2021-3019](https://github.com/a1665454764/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/a1665454764/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/a1665454764/CVE-2021-3019.svg)
- [https://github.com/Aoyuh/cve-2021-3019](https://github.com/Aoyuh/cve-2021-3019) :  ![starts](https://img.shields.io/github/stars/Aoyuh/cve-2021-3019.svg) ![forks](https://img.shields.io/github/forks/Aoyuh/cve-2021-3019.svg)
- [https://github.com/givemefivw/CVE-2021-3019](https://github.com/givemefivw/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/givemefivw/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/givemefivw/CVE-2021-3019.svg)
- [https://github.com/qiezi-maozi/CVE-2021-3019-Lanproxy](https://github.com/qiezi-maozi/CVE-2021-3019-Lanproxy) :  ![starts](https://img.shields.io/github/stars/qiezi-maozi/CVE-2021-3019-Lanproxy.svg) ![forks](https://img.shields.io/github/forks/qiezi-maozi/CVE-2021-3019-Lanproxy.svg)


## CVE-2020-29607
 A file upload restriction bypass vulnerability in Pluck CMS before 4.7.13 allows an admin privileged user to gain access in the host through the "manage files" functionality, which may result in remote code execution.

- [https://github.com/estebanzarate/CVE-2020-29607-Pluck-CMS-4.7.13-Authenticated-File-Upload-RCE-PoC](https://github.com/estebanzarate/CVE-2020-29607-Pluck-CMS-4.7.13-Authenticated-File-Upload-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/estebanzarate/CVE-2020-29607-Pluck-CMS-4.7.13-Authenticated-File-Upload-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/estebanzarate/CVE-2020-29607-Pluck-CMS-4.7.13-Authenticated-File-Upload-RCE-PoC.svg)


## CVE-2019-20149
 ctorName in index.js in kind-of v6.0.2 allows external user input to overwrite certain internal attributes via a conflicting name, as demonstrated by 'constructor': {'name':'Symbol'}. Hence, a crafted payload can overwrite this builtin attribute to manipulate the type detection result.

- [https://github.com/mrknowledgshare/testing_cve-2019-20149](https://github.com/mrknowledgshare/testing_cve-2019-20149) :  ![starts](https://img.shields.io/github/stars/mrknowledgshare/testing_cve-2019-20149.svg) ![forks](https://img.shields.io/github/forks/mrknowledgshare/testing_cve-2019-20149.svg)


## CVE-2019-13288
 In Xpdf 4.01.01, the Parser::getObj() function in Parser.cc may cause infinite recursion via a crafted file. A remote attacker can leverage this for a DoS attack. This is similar to CVE-2018-16646.

- [https://github.com/ngtuonghung/CVE-2019-13288](https://github.com/ngtuonghung/CVE-2019-13288) :  ![starts](https://img.shields.io/github/stars/ngtuonghung/CVE-2019-13288.svg) ![forks](https://img.shields.io/github/forks/ngtuonghung/CVE-2019-13288.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/vadaysakiv/cve-2019-9053](https://github.com/vadaysakiv/cve-2019-9053) :  ![starts](https://img.shields.io/github/stars/vadaysakiv/cve-2019-9053.svg) ![forks](https://img.shields.io/github/forks/vadaysakiv/cve-2019-9053.svg)


## CVE-2018-11235
 In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs "git clone --recurse-submodules" because submodule "names" are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with "../" in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.

- [https://github.com/jhswartz/CVE-2018-11235](https://github.com/jhswartz/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/jhswartz/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/jhswartz/CVE-2018-11235.svg)


## CVE-2018-6537
 A buffer overflow vulnerability in the control protocol of Flexense SyncBreeze Enterprise v10.4.18 allows remote attackers to execute arbitrary code by sending a crafted packet to TCP port 9121.

- [https://github.com/damariion/CVE-2018-6537](https://github.com/damariion/CVE-2018-6537) :  ![starts](https://img.shields.io/github/stars/damariion/CVE-2018-6537.svg) ![forks](https://img.shields.io/github/forks/damariion/CVE-2018-6537.svg)


## CVE-2017-14980
 Buffer overflow in Sync Breeze Enterprise 10.0.28 allows remote attackers to have unspecified impact via a long username parameter to /login.

- [https://github.com/damariion/CVE-2017-14980](https://github.com/damariion/CVE-2017-14980) :  ![starts](https://img.shields.io/github/stars/damariion/CVE-2017-14980.svg) ![forks](https://img.shields.io/github/forks/damariion/CVE-2017-14980.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/MR-LeonardoGomes/CVE-2017-9841](https://github.com/MR-LeonardoGomes/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/MR-LeonardoGomes/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/MR-LeonardoGomes/CVE-2017-9841.svg)


## CVE-2017-9805
 The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.

- [https://github.com/7s26simon/CVE-2017-9805-S2-052](https://github.com/7s26simon/CVE-2017-9805-S2-052) :  ![starts](https://img.shields.io/github/stars/7s26simon/CVE-2017-9805-S2-052.svg) ![forks](https://img.shields.io/github/forks/7s26simon/CVE-2017-9805-S2-052.svg)


## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka "Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API."

- [https://github.com/BlueShield-CyberDefense/RCE-CVE-2017-0199-detection-analysis](https://github.com/BlueShield-CyberDefense/RCE-CVE-2017-0199-detection-analysis) :  ![starts](https://img.shields.io/github/stars/BlueShield-CyberDefense/RCE-CVE-2017-0199-detection-analysis.svg) ![forks](https://img.shields.io/github/forks/BlueShield-CyberDefense/RCE-CVE-2017-0199-detection-analysis.svg)


## CVE-2016-0856
 Multiple stack-based buffer overflows in Advantech WebAccess before 8.1 allow remote attackers to execute arbitrary code via unspecified vectors.

- [https://github.com/mamon9022/poc-fls-node-epicronicles](https://github.com/mamon9022/poc-fls-node-epicronicles) :  ![starts](https://img.shields.io/github/stars/mamon9022/poc-fls-node-epicronicles.svg) ![forks](https://img.shields.io/github/forks/mamon9022/poc-fls-node-epicronicles.svg)
- [https://github.com/hamzamalik3461/CVE-2026-20841](https://github.com/hamzamalik3461/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/hamzamalik3461/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/hamzamalik3461/CVE-2026-20841.svg)
- [https://github.com/404godd/CVE-2026-20841-PoC](https://github.com/404godd/CVE-2026-20841-PoC) :  ![starts](https://img.shields.io/github/stars/404godd/CVE-2026-20841-PoC.svg) ![forks](https://img.shields.io/github/forks/404godd/CVE-2026-20841-PoC.svg)


## CVE-2015-3306
 The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.

- [https://github.com/xyk0x/cpx_proftpd](https://github.com/xyk0x/cpx_proftpd) :  ![starts](https://img.shields.io/github/stars/xyk0x/cpx_proftpd.svg) ![forks](https://img.shields.io/github/forks/xyk0x/cpx_proftpd.svg)
- [https://github.com/Z3R0space/CVE-2015-3306](https://github.com/Z3R0space/CVE-2015-3306) :  ![starts](https://img.shields.io/github/stars/Z3R0space/CVE-2015-3306.svg) ![forks](https://img.shields.io/github/forks/Z3R0space/CVE-2015-3306.svg)


## CVE-2015-1925
 Stack-based buffer overflow in the server in IBM Tivoli Storage Manager FastBack 6.1 before 6.1.12 allows remote attackers to cause a denial of service (daemon crash) via unspecified vectors, a different vulnerability than CVE-2015-1924, CVE-2015-1929, CVE-2015-1930, CVE-2015-1948, CVE-2015-1953, CVE-2015-1954, CVE-2015-1962, CVE-2015-1963, CVE-2015-1964, and CVE-2015-1965.

- [https://github.com/damariion/CVE-2015-1925](https://github.com/damariion/CVE-2015-1925) :  ![starts](https://img.shields.io/github/stars/damariion/CVE-2015-1925.svg) ![forks](https://img.shields.io/github/forks/damariion/CVE-2015-1925.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/Z3R0space/CVE-2014-6287](https://github.com/Z3R0space/CVE-2014-6287) :  ![starts](https://img.shields.io/github/stars/Z3R0space/CVE-2014-6287.svg) ![forks](https://img.shields.io/github/forks/Z3R0space/CVE-2014-6287.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/zaryouhashraf/CVE-2014-0160](https://github.com/zaryouhashraf/CVE-2014-0160) :  ![starts](https://img.shields.io/github/stars/zaryouhashraf/CVE-2014-0160.svg) ![forks](https://img.shields.io/github/forks/zaryouhashraf/CVE-2014-0160.svg)

