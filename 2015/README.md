## CVE-2015-20107
 In Python (aka CPython) up to 3.10.8, the mailcap module does not add escape characters into commands discovered in the system mailcap file. This may allow attackers to inject shell commands into applications that call mailcap.findmatch with untrusted input (if they lack validation of user-provided filenames or arguments). The fix is also back-ported to 3.7, 3.8, 3.9



- [https://github.com/codeskipper/python-patrol](https://github.com/codeskipper/python-patrol) :  ![starts](https://img.shields.io/github/stars/codeskipper/python-patrol.svg) ![forks](https://img.shields.io/github/forks/codeskipper/python-patrol.svg)

## CVE-2015-10141
 An unauthenticated OS command injection vulnerability exists within Xdebug versions 2.5.5 and earlier, a PHP debugging extension developed by Derick Rethans. When remote debugging is enabled, Xdebug listens on port 9000 and accepts debugger protocol commands without authentication. An attacker can send a crafted eval command over this interface to execute arbitrary PHP code, which may invoke system-level functions such as system() or passthru(). This results in full compromise of the host under the privileges of the web server user.



- [https://github.com/D3Ext/CVE-2015-10141](https://github.com/D3Ext/CVE-2015-10141) :  ![starts](https://img.shields.io/github/stars/D3Ext/CVE-2015-10141.svg) ![forks](https://img.shields.io/github/forks/D3Ext/CVE-2015-10141.svg)

- [https://github.com/n0m4d22/PoC-CVE-2015-10141-Xdebug](https://github.com/n0m4d22/PoC-CVE-2015-10141-Xdebug) :  ![starts](https://img.shields.io/github/stars/n0m4d22/PoC-CVE-2015-10141-Xdebug.svg) ![forks](https://img.shields.io/github/forks/n0m4d22/PoC-CVE-2015-10141-Xdebug.svg)

## CVE-2015-10137
 The Website Contact Form With File Upload plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'upload_file()' function in versions up to, and including, 1.3.4. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected sites server which may make remote code execution possible.



- [https://github.com/Kai-One001/-CVE-2015-10137-WordPress-N-Media-Website-Contact-Form-with-File-Upload-1.3.4](https://github.com/Kai-One001/-CVE-2015-10137-WordPress-N-Media-Website-Contact-Form-with-File-Upload-1.3.4) :  ![starts](https://img.shields.io/github/stars/Kai-One001/-CVE-2015-10137-WordPress-N-Media-Website-Contact-Form-with-File-Upload-1.3.4.svg) ![forks](https://img.shields.io/github/forks/Kai-One001/-CVE-2015-10137-WordPress-N-Media-Website-Contact-Form-with-File-Upload-1.3.4.svg)

## CVE-2015-10034
 A vulnerability has been found in j-nowak workout-organizer and classified as critical. This vulnerability affects unknown code. The manipulation leads to sql injection. The patch is identified as 13cd6c3d1210640bfdb39872b2bb3597aa991279. It is recommended to apply a patch to fix this issue. VDB-217714 is the identifier assigned to this vulnerability.



- [https://github.com/andrenasx/CVE-2015-10034](https://github.com/andrenasx/CVE-2015-10034) :  ![starts](https://img.shields.io/github/stars/andrenasx/CVE-2015-10034.svg) ![forks](https://img.shields.io/github/forks/andrenasx/CVE-2015-10034.svg)

## CVE-2015-9251
 jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request is performed without the dataType option, causing text/javascript responses to be executed.



- [https://github.com/halkichi0308/CVE-2015-9251](https://github.com/halkichi0308/CVE-2015-9251) :  ![starts](https://img.shields.io/github/stars/halkichi0308/CVE-2015-9251.svg) ![forks](https://img.shields.io/github/forks/halkichi0308/CVE-2015-9251.svg)

- [https://github.com/hackgiver/CVE-2015-9251](https://github.com/hackgiver/CVE-2015-9251) :  ![starts](https://img.shields.io/github/stars/hackgiver/CVE-2015-9251.svg) ![forks](https://img.shields.io/github/forks/hackgiver/CVE-2015-9251.svg)

- [https://github.com/moften/CVE-2015-9251](https://github.com/moften/CVE-2015-9251) :  ![starts](https://img.shields.io/github/stars/moften/CVE-2015-9251.svg) ![forks](https://img.shields.io/github/forks/moften/CVE-2015-9251.svg)

- [https://github.com/rox-11/xss](https://github.com/rox-11/xss) :  ![starts](https://img.shields.io/github/stars/rox-11/xss.svg) ![forks](https://img.shields.io/github/forks/rox-11/xss.svg)

## CVE-2015-9238
 secure-compare 3.0.0 and below do not actually compare two strings properly. compare was actually comparing the first argument with itself, meaning the check passed for any two strings of the same length.



- [https://github.com/m0d0ri205/wargame-turkey_in_2](https://github.com/m0d0ri205/wargame-turkey_in_2) :  ![starts](https://img.shields.io/github/stars/m0d0ri205/wargame-turkey_in_2.svg) ![forks](https://img.shields.io/github/forks/m0d0ri205/wargame-turkey_in_2.svg)

## CVE-2015-9235
 In jsonwebtoken node module before 4.2.2 it is possible for an attacker to bypass verification when a token digitally signed with an asymmetric key (RS/ES family) of algorithms but instead the attacker send a token digitally signed with a symmetric algorithm (HS* family).



- [https://github.com/z-bool/Venom-JWT](https://github.com/z-bool/Venom-JWT) :  ![starts](https://img.shields.io/github/stars/z-bool/Venom-JWT.svg) ![forks](https://img.shields.io/github/forks/z-bool/Venom-JWT.svg)

- [https://github.com/WinDyAlphA/CVE-2015-9235_JWT_key_confusion](https://github.com/WinDyAlphA/CVE-2015-9235_JWT_key_confusion) :  ![starts](https://img.shields.io/github/stars/WinDyAlphA/CVE-2015-9235_JWT_key_confusion.svg) ![forks](https://img.shields.io/github/forks/WinDyAlphA/CVE-2015-9235_JWT_key_confusion.svg)

- [https://github.com/aalex954/jwt-key-confusion-poc](https://github.com/aalex954/jwt-key-confusion-poc) :  ![starts](https://img.shields.io/github/stars/aalex954/jwt-key-confusion-poc.svg) ![forks](https://img.shields.io/github/forks/aalex954/jwt-key-confusion-poc.svg)

## CVE-2015-8710
 The htmlParseComment function in HTMLparser.c in libxml2 allows attackers to obtain sensitive information, cause a denial of service (out-of-bounds heap memory access and application crash), or possibly have unspecified other impact via an unclosed HTML comment.



- [https://github.com/Karm/CVE-2015-8710](https://github.com/Karm/CVE-2015-8710) :  ![starts](https://img.shields.io/github/stars/Karm/CVE-2015-8710.svg) ![forks](https://img.shields.io/github/forks/Karm/CVE-2015-8710.svg)

## CVE-2015-8660
 The ovl_setattr function in fs/overlayfs/inode.c in the Linux kernel through 4.3.3 attempts to merge distinct setattr operations, which allows local users to bypass intended access restrictions and modify the attributes of arbitrary overlay files via a crafted application.



- [https://github.com/whu-enjoy/CVE-2015-8660](https://github.com/whu-enjoy/CVE-2015-8660) :  ![starts](https://img.shields.io/github/stars/whu-enjoy/CVE-2015-8660.svg) ![forks](https://img.shields.io/github/forks/whu-enjoy/CVE-2015-8660.svg)

- [https://github.com/carradolly/CVE-2015-8660](https://github.com/carradolly/CVE-2015-8660) :  ![starts](https://img.shields.io/github/stars/carradolly/CVE-2015-8660.svg) ![forks](https://img.shields.io/github/forks/carradolly/CVE-2015-8660.svg)

- [https://github.com/nhamle2/CVE-2015-8660](https://github.com/nhamle2/CVE-2015-8660) :  ![starts](https://img.shields.io/github/stars/nhamle2/CVE-2015-8660.svg) ![forks](https://img.shields.io/github/forks/nhamle2/CVE-2015-8660.svg)

## CVE-2015-8651
 Integer overflow in Adobe Flash Player before 18.0.0.324 and 19.x and 20.x before 20.0.0.267 on Windows and OS X and before 11.2.202.559 on Linux, Adobe AIR before 20.0.0.233, Adobe AIR SDK before 20.0.0.233, and Adobe AIR SDK & Compiler before 20.0.0.233 allows attackers to execute arbitrary code via unspecified vectors.



- [https://github.com/Gitlabpro/The-analysis-of-the-cve-2015-8651](https://github.com/Gitlabpro/The-analysis-of-the-cve-2015-8651) :  ![starts](https://img.shields.io/github/stars/Gitlabpro/The-analysis-of-the-cve-2015-8651.svg) ![forks](https://img.shields.io/github/forks/Gitlabpro/The-analysis-of-the-cve-2015-8651.svg)

## CVE-2015-8562
 Joomla! 1.5.x, 2.x, and 3.x before 3.4.6 allow remote attackers to conduct PHP object injection attacks and execute arbitrary PHP code via the HTTP User-Agent header, as exploited in the wild in December 2015.



- [https://github.com/paralelo14/JoomlaMassExploiter](https://github.com/paralelo14/JoomlaMassExploiter) :  ![starts](https://img.shields.io/github/stars/paralelo14/JoomlaMassExploiter.svg) ![forks](https://img.shields.io/github/forks/paralelo14/JoomlaMassExploiter.svg)

- [https://github.com/VoidSec/Joomla_CVE-2015-8562](https://github.com/VoidSec/Joomla_CVE-2015-8562) :  ![starts](https://img.shields.io/github/stars/VoidSec/Joomla_CVE-2015-8562.svg) ![forks](https://img.shields.io/github/forks/VoidSec/Joomla_CVE-2015-8562.svg)

- [https://github.com/ZaleHack/joomla_rce_CVE-2015-8562](https://github.com/ZaleHack/joomla_rce_CVE-2015-8562) :  ![starts](https://img.shields.io/github/stars/ZaleHack/joomla_rce_CVE-2015-8562.svg) ![forks](https://img.shields.io/github/forks/ZaleHack/joomla_rce_CVE-2015-8562.svg)

- [https://github.com/paralelo14/CVE-2015-8562](https://github.com/paralelo14/CVE-2015-8562) :  ![starts](https://img.shields.io/github/stars/paralelo14/CVE-2015-8562.svg) ![forks](https://img.shields.io/github/forks/paralelo14/CVE-2015-8562.svg)

- [https://github.com/RobinHoutevelts/Joomla-CVE-2015-8562-PHP-POC](https://github.com/RobinHoutevelts/Joomla-CVE-2015-8562-PHP-POC) :  ![starts](https://img.shields.io/github/stars/RobinHoutevelts/Joomla-CVE-2015-8562-PHP-POC.svg) ![forks](https://img.shields.io/github/forks/RobinHoutevelts/Joomla-CVE-2015-8562-PHP-POC.svg)

- [https://github.com/Caihuar/Joomla-cve-2015-8562](https://github.com/Caihuar/Joomla-cve-2015-8562) :  ![starts](https://img.shields.io/github/stars/Caihuar/Joomla-cve-2015-8562.svg) ![forks](https://img.shields.io/github/forks/Caihuar/Joomla-cve-2015-8562.svg)

- [https://github.com/atcasanova/cve-2015-8562-exploit](https://github.com/atcasanova/cve-2015-8562-exploit) :  ![starts](https://img.shields.io/github/stars/atcasanova/cve-2015-8562-exploit.svg) ![forks](https://img.shields.io/github/forks/atcasanova/cve-2015-8562-exploit.svg)

- [https://github.com/xnorkl/Joomla_Payload](https://github.com/xnorkl/Joomla_Payload) :  ![starts](https://img.shields.io/github/stars/xnorkl/Joomla_Payload.svg) ![forks](https://img.shields.io/github/forks/xnorkl/Joomla_Payload.svg)

- [https://github.com/guanjivip/CVE-2015-8562](https://github.com/guanjivip/CVE-2015-8562) :  ![starts](https://img.shields.io/github/stars/guanjivip/CVE-2015-8562.svg) ![forks](https://img.shields.io/github/forks/guanjivip/CVE-2015-8562.svg)

- [https://github.com/lorenzodegiorgi/setup-cve-2015-8562](https://github.com/lorenzodegiorgi/setup-cve-2015-8562) :  ![starts](https://img.shields.io/github/stars/lorenzodegiorgi/setup-cve-2015-8562.svg) ![forks](https://img.shields.io/github/forks/lorenzodegiorgi/setup-cve-2015-8562.svg)

- [https://github.com/thejackerz/scanner-exploit-joomla-CVE-2015-8562](https://github.com/thejackerz/scanner-exploit-joomla-CVE-2015-8562) :  ![starts](https://img.shields.io/github/stars/thejackerz/scanner-exploit-joomla-CVE-2015-8562.svg) ![forks](https://img.shields.io/github/forks/thejackerz/scanner-exploit-joomla-CVE-2015-8562.svg)

## CVE-2015-8543
 The networking implementation in the Linux kernel through 4.3.3, as used in Android and other products, does not validate protocol identifiers for certain protocol families, which allows local users to cause a denial of service (NULL function pointer dereference and system crash) or possibly gain privileges by leveraging CLONE_NEWUSER support to execute a crafted SOCK_RAW application.



- [https://github.com/bittorrent3389/CVE-2015-8543_for_SLE12SP1](https://github.com/bittorrent3389/CVE-2015-8543_for_SLE12SP1) :  ![starts](https://img.shields.io/github/stars/bittorrent3389/CVE-2015-8543_for_SLE12SP1.svg) ![forks](https://img.shields.io/github/forks/bittorrent3389/CVE-2015-8543_for_SLE12SP1.svg)

## CVE-2015-8351
 PHP remote file inclusion vulnerability in the Gwolle Guestbook plugin before 1.5.4 for WordPress, when allow_url_include is enabled, allows remote authenticated users to execute arbitrary PHP code via a URL in the abspath parameter to frontend/captcha/ajaxresponse.php.  NOTE: this can also be leveraged to include and execute arbitrary local files via directory traversal sequences regardless of whether allow_url_include is enabled.



- [https://github.com/G4sp4rCS/exploit-CVE-2015-8351](https://github.com/G4sp4rCS/exploit-CVE-2015-8351) :  ![starts](https://img.shields.io/github/stars/G4sp4rCS/exploit-CVE-2015-8351.svg) ![forks](https://img.shields.io/github/forks/G4sp4rCS/exploit-CVE-2015-8351.svg)

- [https://github.com/G01d3nW01f/CVE-2015-8351](https://github.com/G01d3nW01f/CVE-2015-8351) :  ![starts](https://img.shields.io/github/stars/G01d3nW01f/CVE-2015-8351.svg) ![forks](https://img.shields.io/github/forks/G01d3nW01f/CVE-2015-8351.svg)

- [https://github.com/Philip-Otter/CVE-2015-8351_Otter_Remix](https://github.com/Philip-Otter/CVE-2015-8351_Otter_Remix) :  ![starts](https://img.shields.io/github/stars/Philip-Otter/CVE-2015-8351_Otter_Remix.svg) ![forks](https://img.shields.io/github/forks/Philip-Otter/CVE-2015-8351_Otter_Remix.svg)

## CVE-2015-8299
 Buffer overflow in the Group messages monitor (Falcon) in KNX ETS 4.1.5 (Build 3246) allows remote attackers to execute arbitrary code via a crafted KNXnet/IP UDP packet.



- [https://github.com/kernoelpanic/CVE-2015-8299](https://github.com/kernoelpanic/CVE-2015-8299) :  ![starts](https://img.shields.io/github/stars/kernoelpanic/CVE-2015-8299.svg) ![forks](https://img.shields.io/github/forks/kernoelpanic/CVE-2015-8299.svg)

## CVE-2015-8277
 Multiple buffer overflows in (1) lmgrd and (2) Vendor Daemon in Flexera FlexNet Publisher before 11.13.1.2 Security Update 1 allow remote attackers to execute arbitrary code via a crafted packet with opcode (a) 0x107 or (b) 0x10a.



- [https://github.com/securifera/CVE-2015-8277-Exploit](https://github.com/securifera/CVE-2015-8277-Exploit) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2015-8277-Exploit.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2015-8277-Exploit.svg)

## CVE-2015-8239
 The SHA-2 digest support in the sudoers plugin in sudo after 1.8.7 allows local users with write permissions to parts of the called command to replace them before it is executed.



- [https://github.com/justinsteven/sudo_digest_toctou_poc_CVE-2015-8239](https://github.com/justinsteven/sudo_digest_toctou_poc_CVE-2015-8239) :  ![starts](https://img.shields.io/github/stars/justinsteven/sudo_digest_toctou_poc_CVE-2015-8239.svg) ![forks](https://img.shields.io/github/forks/justinsteven/sudo_digest_toctou_poc_CVE-2015-8239.svg)

## CVE-2015-8103
 The Jenkins CLI subsystem in Jenkins before 1.638 and LTS before 1.625.2 allows remote attackers to execute arbitrary code via a crafted serialized Java object, related to a problematic webapps/ROOT/WEB-INF/lib/commons-collections-*.jar file and the "Groovy variant in 'ysoserial'".



- [https://github.com/r00t4dm/Jenkins-CVE-2015-8103](https://github.com/r00t4dm/Jenkins-CVE-2015-8103) :  ![starts](https://img.shields.io/github/stars/r00t4dm/Jenkins-CVE-2015-8103.svg) ![forks](https://img.shields.io/github/forks/r00t4dm/Jenkins-CVE-2015-8103.svg)

- [https://github.com/cved-sources/cve-2015-8103](https://github.com/cved-sources/cve-2015-8103) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2015-8103.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2015-8103.svg)

## CVE-2015-8088
 Heap-based buffer overflow in the HIFI driver in Huawei Mate 7 phones with software MT7-UL00 before MT7-UL00C17B354, MT7-TL10 before MT7-TL10C00B354, MT7-TL00 before MT7-TL00C01B354, and MT7-CL00 before MT7-CL00C92B354 and P8 phones with software GRA-TL00 before GRA-TL00C01B220SP01, GRA-CL00 before GRA-CL00C92B220, GRA-CL10 before GRA-CL10C92B220, GRA-UL00 before GRA-UL00C00B220, and GRA-UL10 before GRA-UL10C00B220 allows attackers to cause a denial of service (reboot) or execute arbitrary code via a crafted application.



- [https://github.com/Pray3r/CVE-2015-8088](https://github.com/Pray3r/CVE-2015-8088) :  ![starts](https://img.shields.io/github/stars/Pray3r/CVE-2015-8088.svg) ![forks](https://img.shields.io/github/forks/Pray3r/CVE-2015-8088.svg)

## CVE-2015-7858
 SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands via unspecified vectors, a different vulnerability than CVE-2015-7297.



- [https://github.com/CCrashBandicot/ContentHistory](https://github.com/CCrashBandicot/ContentHistory) :  ![starts](https://img.shields.io/github/stars/CCrashBandicot/ContentHistory.svg) ![forks](https://img.shields.io/github/forks/CCrashBandicot/ContentHistory.svg)

- [https://github.com/areaventuno/exploit-joomla](https://github.com/areaventuno/exploit-joomla) :  ![starts](https://img.shields.io/github/stars/areaventuno/exploit-joomla.svg) ![forks](https://img.shields.io/github/forks/areaventuno/exploit-joomla.svg)

## CVE-2015-7857
 SQL injection vulnerability in the getListQuery function in administrator/components/com_contenthistory/models/history.php in Joomla! 3.2 before 3.4.5 allows remote attackers to execute arbitrary SQL commands via the list[select] parameter to index.php.



- [https://github.com/CCrashBandicot/ContentHistory](https://github.com/CCrashBandicot/ContentHistory) :  ![starts](https://img.shields.io/github/stars/CCrashBandicot/ContentHistory.svg) ![forks](https://img.shields.io/github/forks/CCrashBandicot/ContentHistory.svg)

- [https://github.com/areaventuno/exploit-joomla](https://github.com/areaventuno/exploit-joomla) :  ![starts](https://img.shields.io/github/stars/areaventuno/exploit-joomla.svg) ![forks](https://img.shields.io/github/forks/areaventuno/exploit-joomla.svg)

## CVE-2015-7808
 The vB_Api_Hook::decodeArguments method in vBulletin 5 Connect 5.1.2 through 5.1.9 allows remote attackers to conduct PHP object injection attacks and execute arbitrary PHP code via a crafted serialized object in the arguments parameter to ajax/api/hook/decodeArguments.



- [https://github.com/Prajithp/CVE-2015-7808](https://github.com/Prajithp/CVE-2015-7808) :  ![starts](https://img.shields.io/github/stars/Prajithp/CVE-2015-7808.svg) ![forks](https://img.shields.io/github/forks/Prajithp/CVE-2015-7808.svg)

## CVE-2015-7756
 The encryption implementation in Juniper ScreenOS 6.2.0r15 through 6.2.0r18, 6.3.0r12 before 6.3.0r12b, 6.3.0r13 before 6.3.0r13b, 6.3.0r14 before 6.3.0r14b, 6.3.0r15 before 6.3.0r15b, 6.3.0r16 before 6.3.0r16b, 6.3.0r17 before 6.3.0r17b, 6.3.0r18 before 6.3.0r18b, 6.3.0r19 before 6.3.0r19b, and 6.3.0r20 before 6.3.0r21 makes it easier for remote attackers to discover the plaintext content of VPN sessions by sniffing the network for ciphertext data and conducting an unspecified decryption attack.



- [https://github.com/hdm/juniper-cve-2015-7755](https://github.com/hdm/juniper-cve-2015-7755) :  ![starts](https://img.shields.io/github/stars/hdm/juniper-cve-2015-7755.svg) ![forks](https://img.shields.io/github/forks/hdm/juniper-cve-2015-7755.svg)

## CVE-2015-7755
 Juniper ScreenOS 6.2.0r15 through 6.2.0r18, 6.3.0r12 before 6.3.0r12b, 6.3.0r13 before 6.3.0r13b, 6.3.0r14 before 6.3.0r14b, 6.3.0r15 before 6.3.0r15b, 6.3.0r16 before 6.3.0r16b, 6.3.0r17 before 6.3.0r17b, 6.3.0r18 before 6.3.0r18b, 6.3.0r19 before 6.3.0r19b, and 6.3.0r20 before 6.3.0r21 allows remote attackers to obtain administrative access by entering an unspecified password during a (1) SSH or (2) TELNET session.



- [https://github.com/hdm/juniper-cve-2015-7755](https://github.com/hdm/juniper-cve-2015-7755) :  ![starts](https://img.shields.io/github/stars/hdm/juniper-cve-2015-7755.svg) ![forks](https://img.shields.io/github/forks/hdm/juniper-cve-2015-7755.svg)

- [https://github.com/cinno/CVE-2015-7755-POC](https://github.com/cinno/CVE-2015-7755-POC) :  ![starts](https://img.shields.io/github/stars/cinno/CVE-2015-7755-POC.svg) ![forks](https://img.shields.io/github/forks/cinno/CVE-2015-7755-POC.svg)

## CVE-2015-7576
 The http_basic_authenticate_with method in actionpack/lib/action_controller/metal/http_authentication.rb in the Basic Authentication implementation in Action Controller in Ruby on Rails before 3.2.22.1, 4.0.x and 4.1.x before 4.1.14.1, 4.2.x before 4.2.5.1, and 5.x before 5.0.0.beta1.1 does not use a constant-time algorithm for verifying credentials, which makes it easier for remote attackers to bypass authentication by measuring timing differences.



- [https://github.com/yield-c/CVE2015-7576](https://github.com/yield-c/CVE2015-7576) :  ![starts](https://img.shields.io/github/stars/yield-c/CVE2015-7576.svg) ![forks](https://img.shields.io/github/forks/yield-c/CVE2015-7576.svg)

## CVE-2015-7547
 Multiple stack-based buffer overflows in the (1) send_dg and (2) send_vc functions in the libresolv library in the GNU C Library (aka glibc or libc6) before 2.23 allow remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted DNS response that triggers a call to the getaddrinfo function with the AF_UNSPEC or AF_INET6 address family, related to performing "dual A/AAAA DNS queries" and the libnss_dns.so.2 NSS module.



- [https://github.com/fjserna/CVE-2015-7547](https://github.com/fjserna/CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/fjserna/CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/fjserna/CVE-2015-7547.svg)

- [https://github.com/eSentire/cve-2015-7547-public](https://github.com/eSentire/cve-2015-7547-public) :  ![starts](https://img.shields.io/github/stars/eSentire/cve-2015-7547-public.svg) ![forks](https://img.shields.io/github/forks/eSentire/cve-2015-7547-public.svg)

- [https://github.com/jgajek/cve-2015-7547](https://github.com/jgajek/cve-2015-7547) :  ![starts](https://img.shields.io/github/stars/jgajek/cve-2015-7547.svg) ![forks](https://img.shields.io/github/forks/jgajek/cve-2015-7547.svg)

- [https://github.com/cakuzo/CVE-2015-7547](https://github.com/cakuzo/CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/cakuzo/CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/cakuzo/CVE-2015-7547.svg)

- [https://github.com/t0r0t0r0/CVE-2015-7547](https://github.com/t0r0t0r0/CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/t0r0t0r0/CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/t0r0t0r0/CVE-2015-7547.svg)

- [https://github.com/Stick-U235/CVE-2015-7547-Research](https://github.com/Stick-U235/CVE-2015-7547-Research) :  ![starts](https://img.shields.io/github/stars/Stick-U235/CVE-2015-7547-Research.svg) ![forks](https://img.shields.io/github/forks/Stick-U235/CVE-2015-7547-Research.svg)

- [https://github.com/Amilaperera12/Glibc-Vulnerability-Exploit-CVE-2015-7547](https://github.com/Amilaperera12/Glibc-Vulnerability-Exploit-CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/Amilaperera12/Glibc-Vulnerability-Exploit-CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/Amilaperera12/Glibc-Vulnerability-Exploit-CVE-2015-7547.svg)

- [https://github.com/babykillerblack/CVE-2015-7547](https://github.com/babykillerblack/CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/babykillerblack/CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/babykillerblack/CVE-2015-7547.svg)

- [https://github.com/miracle03/CVE-2015-7547-master](https://github.com/miracle03/CVE-2015-7547-master) :  ![starts](https://img.shields.io/github/stars/miracle03/CVE-2015-7547-master.svg) ![forks](https://img.shields.io/github/forks/miracle03/CVE-2015-7547-master.svg)

- [https://github.com/bluebluelan/CVE-2015-7547-proj-master](https://github.com/bluebluelan/CVE-2015-7547-proj-master) :  ![starts](https://img.shields.io/github/stars/bluebluelan/CVE-2015-7547-proj-master.svg) ![forks](https://img.shields.io/github/forks/bluebluelan/CVE-2015-7547-proj-master.svg)

- [https://github.com/rexifiles/rex-sec-glibc](https://github.com/rexifiles/rex-sec-glibc) :  ![starts](https://img.shields.io/github/stars/rexifiles/rex-sec-glibc.svg) ![forks](https://img.shields.io/github/forks/rexifiles/rex-sec-glibc.svg)

## CVE-2015-7545
 The (1) git-remote-ext and (2) unspecified other remote helper programs in Git before 2.3.10, 2.4.x before 2.4.10, 2.5.x before 2.5.4, and 2.6.x before 2.6.1 do not properly restrict the allowed protocols, which might allow remote attackers to execute arbitrary code via a URL in a (a) .gitmodules file or (b) unknown other sources in a submodule.



- [https://github.com/avuserow/bug-free-chainsaw](https://github.com/avuserow/bug-free-chainsaw) :  ![starts](https://img.shields.io/github/stars/avuserow/bug-free-chainsaw.svg) ![forks](https://img.shields.io/github/forks/avuserow/bug-free-chainsaw.svg)

## CVE-2015-7501
 Red Hat JBoss A-MQ 6.x; BPM Suite (BPMS) 6.x; BRMS 6.x and 5.x; Data Grid (JDG) 6.x; Data Virtualization (JDV) 6.x and 5.x; Enterprise Application Platform 6.x, 5.x, and 4.3.x; Fuse 6.x; Fuse Service Works (FSW) 6.x; Operations Network (JBoss ON) 3.x; Portal 6.x; SOA Platform (SOA-P) 5.x; Web Server (JWS) 3.x; Red Hat OpenShift/xPAAS 3.x; and Red Hat Subscription Asset Manager 1.3 allow remote attackers to execute arbitrary commands via a crafted serialized Java object, related to the Apache Commons Collections (ACC) library.



- [https://github.com/ianxtianxt/CVE-2015-7501](https://github.com/ianxtianxt/CVE-2015-7501) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2015-7501.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2015-7501.svg)

## CVE-2015-7297
 SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands via unspecified vectors, a different vulnerability than CVE-2015-7858.



- [https://github.com/Cappricio-Securities/CVE-2015-7297](https://github.com/Cappricio-Securities/CVE-2015-7297) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2015-7297.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2015-7297.svg)

- [https://github.com/CCrashBandicot/ContentHistory](https://github.com/CCrashBandicot/ContentHistory) :  ![starts](https://img.shields.io/github/stars/CCrashBandicot/ContentHistory.svg) ![forks](https://img.shields.io/github/forks/CCrashBandicot/ContentHistory.svg)

- [https://github.com/areaventuno/exploit-joomla](https://github.com/areaventuno/exploit-joomla) :  ![starts](https://img.shields.io/github/stars/areaventuno/exploit-joomla.svg) ![forks](https://img.shields.io/github/forks/areaventuno/exploit-joomla.svg)

## CVE-2015-7214
 Mozilla Firefox before 43.0 and Firefox ESR 38.x before 38.5 allow remote attackers to bypass the Same Origin Policy via data: and view-source: URIs.



- [https://github.com/llamakko/CVE-2015-7214](https://github.com/llamakko/CVE-2015-7214) :  ![starts](https://img.shields.io/github/stars/llamakko/CVE-2015-7214.svg) ![forks](https://img.shields.io/github/forks/llamakko/CVE-2015-7214.svg)

## CVE-2015-6967
 Unrestricted file upload vulnerability in the My Image plugin in Nibbleblog before 4.0.5 allows remote administrators to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in content/private/plugins/my_image/image.php.



- [https://github.com/dix0nym/CVE-2015-6967](https://github.com/dix0nym/CVE-2015-6967) :  ![starts](https://img.shields.io/github/stars/dix0nym/CVE-2015-6967.svg) ![forks](https://img.shields.io/github/forks/dix0nym/CVE-2015-6967.svg)

- [https://github.com/hadrian3689/nibbleblog_4.0.3](https://github.com/hadrian3689/nibbleblog_4.0.3) :  ![starts](https://img.shields.io/github/stars/hadrian3689/nibbleblog_4.0.3.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/nibbleblog_4.0.3.svg)

- [https://github.com/innocentx0/CVE-2015-6967-EXPLOIT](https://github.com/innocentx0/CVE-2015-6967-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/innocentx0/CVE-2015-6967-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/innocentx0/CVE-2015-6967-EXPLOIT.svg)

- [https://github.com/cuerv0x/CVE-2015-6967](https://github.com/cuerv0x/CVE-2015-6967) :  ![starts](https://img.shields.io/github/stars/cuerv0x/CVE-2015-6967.svg) ![forks](https://img.shields.io/github/forks/cuerv0x/CVE-2015-6967.svg)

- [https://github.com/FredBrave/CVE-2015-6967](https://github.com/FredBrave/CVE-2015-6967) :  ![starts](https://img.shields.io/github/stars/FredBrave/CVE-2015-6967.svg) ![forks](https://img.shields.io/github/forks/FredBrave/CVE-2015-6967.svg)

- [https://github.com/3mpir3Albert/HTB_Nibbles](https://github.com/3mpir3Albert/HTB_Nibbles) :  ![starts](https://img.shields.io/github/stars/3mpir3Albert/HTB_Nibbles.svg) ![forks](https://img.shields.io/github/forks/3mpir3Albert/HTB_Nibbles.svg)

## CVE-2015-6835
 The session deserializer in PHP before 5.4.45, 5.5.x before 5.5.29, and 5.6.x before 5.6.13 mishandles multiple php_var_unserialize calls, which allow remote attackers to execute arbitrary code or cause a denial of service (use-after-free) via crafted session content.



- [https://github.com/ockeghem/CVE-2015-6835-checker](https://github.com/ockeghem/CVE-2015-6835-checker) :  ![starts](https://img.shields.io/github/stars/ockeghem/CVE-2015-6835-checker.svg) ![forks](https://img.shields.io/github/forks/ockeghem/CVE-2015-6835-checker.svg)

## CVE-2015-6748
 Cross-site scripting (XSS) vulnerability in jsoup before 1.8.3.



- [https://github.com/epicosy/VUL4J-59](https://github.com/epicosy/VUL4J-59) :  ![starts](https://img.shields.io/github/stars/epicosy/VUL4J-59.svg) ![forks](https://img.shields.io/github/forks/epicosy/VUL4J-59.svg)

## CVE-2015-6668
 The Job Manager plugin before 0.7.25 allows remote attackers to read arbitrary CV files via a brute force attack to the WordPress upload directory structure, related to an insecure direct object reference.



- [https://github.com/h3x0v3rl0rd/CVE-2015-6668](https://github.com/h3x0v3rl0rd/CVE-2015-6668) :  ![starts](https://img.shields.io/github/stars/h3x0v3rl0rd/CVE-2015-6668.svg) ![forks](https://img.shields.io/github/forks/h3x0v3rl0rd/CVE-2015-6668.svg)

- [https://github.com/G01d3nW01f/CVE-2015-6668](https://github.com/G01d3nW01f/CVE-2015-6668) :  ![starts](https://img.shields.io/github/stars/G01d3nW01f/CVE-2015-6668.svg) ![forks](https://img.shields.io/github/forks/G01d3nW01f/CVE-2015-6668.svg)

- [https://github.com/jimdiroffii/CVE-2015-6668](https://github.com/jimdiroffii/CVE-2015-6668) :  ![starts](https://img.shields.io/github/stars/jimdiroffii/CVE-2015-6668.svg) ![forks](https://img.shields.io/github/forks/jimdiroffii/CVE-2015-6668.svg)

- [https://github.com/nika0x38/CVE-2015-6668](https://github.com/nika0x38/CVE-2015-6668) :  ![starts](https://img.shields.io/github/stars/nika0x38/CVE-2015-6668.svg) ![forks](https://img.shields.io/github/forks/nika0x38/CVE-2015-6668.svg)

- [https://github.com/NoTrustedx/Job-Manager-Disclosure](https://github.com/NoTrustedx/Job-Manager-Disclosure) :  ![starts](https://img.shields.io/github/stars/NoTrustedx/Job-Manager-Disclosure.svg) ![forks](https://img.shields.io/github/forks/NoTrustedx/Job-Manager-Disclosure.svg)

## CVE-2015-6640
 The prctl_set_vma_anon_name function in kernel/sys.c in Android before 5.1.1 LMY49F and 6.0 before 2016-01-01 does not ensure that only one vma is accessed in a certain update action, which allows attackers to gain privileges or cause a denial of service (vma list corruption) via a crafted application, aka internal bug 20017123.



- [https://github.com/betalphafai/CVE-2015-6640](https://github.com/betalphafai/CVE-2015-6640) :  ![starts](https://img.shields.io/github/stars/betalphafai/CVE-2015-6640.svg) ![forks](https://img.shields.io/github/forks/betalphafai/CVE-2015-6640.svg)

## CVE-2015-6639
 The Widevine QSEE TrustZone application in Android 5.x before 5.1.1 LMY49F and 6.0 before 2016-01-01 allows attackers to gain privileges via a crafted application that leverages QSEECOM access, aka internal bug 24446875.



- [https://github.com/laginimaineb/ExtractKeyMaster](https://github.com/laginimaineb/ExtractKeyMaster) :  ![starts](https://img.shields.io/github/stars/laginimaineb/ExtractKeyMaster.svg) ![forks](https://img.shields.io/github/forks/laginimaineb/ExtractKeyMaster.svg)

- [https://github.com/laginimaineb/cve-2015-6639](https://github.com/laginimaineb/cve-2015-6639) :  ![starts](https://img.shields.io/github/stars/laginimaineb/cve-2015-6639.svg) ![forks](https://img.shields.io/github/forks/laginimaineb/cve-2015-6639.svg)

## CVE-2015-6637
 The MediaTek misc-sd driver in Android before 5.1.1 LMY49F and 6.0 before 2016-01-01 allows attackers to gain privileges via a crafted application, aka internal bug 25307013.



- [https://github.com/betalphafai/CVE-2015-6637](https://github.com/betalphafai/CVE-2015-6637) :  ![starts](https://img.shields.io/github/stars/betalphafai/CVE-2015-6637.svg) ![forks](https://img.shields.io/github/forks/betalphafai/CVE-2015-6637.svg)

## CVE-2015-6620
 libstagefright in Android before 5.1.1 LMY48Z and 6.0 before 2015-12-01 allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bugs 24123723 and 24445127.



- [https://github.com/flankerhqd/mediacodecoob](https://github.com/flankerhqd/mediacodecoob) :  ![starts](https://img.shields.io/github/stars/flankerhqd/mediacodecoob.svg) ![forks](https://img.shields.io/github/forks/flankerhqd/mediacodecoob.svg)

- [https://github.com/flankerhqd/CVE-2015-6620-POC](https://github.com/flankerhqd/CVE-2015-6620-POC) :  ![starts](https://img.shields.io/github/stars/flankerhqd/CVE-2015-6620-POC.svg) ![forks](https://img.shields.io/github/forks/flankerhqd/CVE-2015-6620-POC.svg)

## CVE-2015-6612
 libmedia in Android before 5.1.1 LMY48X and 6.0 before 2015-11-01 allows attackers to gain privileges via a crafted application, aka internal bug 23540426.



- [https://github.com/secmob/CVE-2015-6612](https://github.com/secmob/CVE-2015-6612) :  ![starts](https://img.shields.io/github/stars/secmob/CVE-2015-6612.svg) ![forks](https://img.shields.io/github/forks/secmob/CVE-2015-6612.svg)

- [https://github.com/flankerhqd/cve-2015-6612poc-forM](https://github.com/flankerhqd/cve-2015-6612poc-forM) :  ![starts](https://img.shields.io/github/stars/flankerhqd/cve-2015-6612poc-forM.svg) ![forks](https://img.shields.io/github/forks/flankerhqd/cve-2015-6612poc-forM.svg)

## CVE-2015-6606
 The Secure Element Evaluation Kit (aka SEEK or SmartCard API) plugin in Android before 5.1.1 LMY48T allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bug 22301786.



- [https://github.com/michaelroland/omapi-cve-2015-6606-exploit](https://github.com/michaelroland/omapi-cve-2015-6606-exploit) :  ![starts](https://img.shields.io/github/stars/michaelroland/omapi-cve-2015-6606-exploit.svg) ![forks](https://img.shields.io/github/forks/michaelroland/omapi-cve-2015-6606-exploit.svg)

## CVE-2015-6576
 Bamboo 2.2 before 5.8.5 and 5.9.x before 5.9.7 allows remote attackers with access to the Bamboo web interface to execute arbitrary Java code via an unspecified resource.



- [https://github.com/CallMeJonas/CVE-2015-6576](https://github.com/CallMeJonas/CVE-2015-6576) :  ![starts](https://img.shields.io/github/stars/CallMeJonas/CVE-2015-6576.svg) ![forks](https://img.shields.io/github/forks/CallMeJonas/CVE-2015-6576.svg)

## CVE-2015-6420
 Serialized-object interfaces in certain Cisco Collaboration and Social Media; Endpoint Clients and Client Software; Network Application, Service, and Acceleration; Network and Content Security Devices; Network Management and Provisioning; Routing and Switching - Enterprise and Service Provider; Unified Computing; Voice and Unified Communications Devices; Video, Streaming, TelePresence, and Transcoding Devices; Wireless; and Cisco Hosted Services products allow remote attackers to execute arbitrary commands via a crafted serialized Java object, related to the Apache Commons Collections (ACC) library.



- [https://github.com/Leeziao/CVE-2015-6420](https://github.com/Leeziao/CVE-2015-6420) :  ![starts](https://img.shields.io/github/stars/Leeziao/CVE-2015-6420.svg) ![forks](https://img.shields.io/github/forks/Leeziao/CVE-2015-6420.svg)

## CVE-2015-6357
 The rule-update feature in Cisco FireSIGHT Management Center (MC) 5.2 through 5.4.0.1 does not verify the X.509 certificate of the support.sourcefire.com SSL server, which allows man-in-the-middle attackers to spoof this server and provide an invalid package, and consequently execute arbitrary code, via a crafted certificate, aka Bug ID CSCuw06444.



- [https://github.com/mattimustang/firepwner](https://github.com/mattimustang/firepwner) :  ![starts](https://img.shields.io/github/stars/mattimustang/firepwner.svg) ![forks](https://img.shields.io/github/forks/mattimustang/firepwner.svg)

## CVE-2015-6132
 Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT Gold and 8.1, and Windows 10 Gold and 1511 mishandle library loading, which allows local users to gain privileges via a crafted application, aka "Windows Library Loading Remote Code Execution Vulnerability."



- [https://github.com/hexx0r/CVE-2015-6132](https://github.com/hexx0r/CVE-2015-6132) :  ![starts](https://img.shields.io/github/stars/hexx0r/CVE-2015-6132.svg) ![forks](https://img.shields.io/github/forks/hexx0r/CVE-2015-6132.svg)

## CVE-2015-6095
 Kerberos in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT Gold and 8.1, and Windows 10 Gold and 1511 mishandles password changes, which allows physically proximate attackers to bypass authentication, and conduct decryption attacks against certain BitLocker configurations, by connecting to an unintended Key Distribution Center (KDC), aka "Windows Kerberos Security Feature Bypass."



- [https://github.com/JackOfMostTrades/bluebox](https://github.com/JackOfMostTrades/bluebox) :  ![starts](https://img.shields.io/github/stars/JackOfMostTrades/bluebox.svg) ![forks](https://img.shields.io/github/forks/JackOfMostTrades/bluebox.svg)

## CVE-2015-6086
 Microsoft Internet Explorer 9 through 11 allows remote attackers to obtain sensitive information from process memory via a crafted web site, aka "Internet Explorer Information Disclosure Vulnerability."



- [https://github.com/payatu/CVE-2015-6086](https://github.com/payatu/CVE-2015-6086) :  ![starts](https://img.shields.io/github/stars/payatu/CVE-2015-6086.svg) ![forks](https://img.shields.io/github/forks/payatu/CVE-2015-6086.svg)

## CVE-2015-5995
 Mediabridge Medialink MWN-WAPR300N devices with firmware 5.07.50 and Tenda N3 Wireless N150 devices allow remote attackers to obtain administrative access via a certain admin substring in an HTTP Cookie header.



- [https://github.com/shaheemirza/TendaSpill](https://github.com/shaheemirza/TendaSpill) :  ![starts](https://img.shields.io/github/stars/shaheemirza/TendaSpill.svg) ![forks](https://img.shields.io/github/forks/shaheemirza/TendaSpill.svg)

## CVE-2015-5932
 The kernel in Apple OS X before 10.11.1 allows local users to gain privileges by leveraging an unspecified "type confusion" during Mach task processing.



- [https://github.com/jndok/tpwn-bis](https://github.com/jndok/tpwn-bis) :  ![starts](https://img.shields.io/github/stars/jndok/tpwn-bis.svg) ![forks](https://img.shields.io/github/forks/jndok/tpwn-bis.svg)

## CVE-2015-5864
 IOAudioFamily in Apple OS X before 10.11 allows local users to obtain sensitive kernel memory-layout information via unspecified vectors.



- [https://github.com/jndok/tpwn-bis](https://github.com/jndok/tpwn-bis) :  ![starts](https://img.shields.io/github/stars/jndok/tpwn-bis.svg) ![forks](https://img.shields.io/github/forks/jndok/tpwn-bis.svg)

## CVE-2015-5847
 The Disk Images component in Apple iOS before 9 allows local users to gain privileges or cause a denial of service (memory corruption) via unspecified vectors.



- [https://github.com/jndok/tpwn-bis](https://github.com/jndok/tpwn-bis) :  ![starts](https://img.shields.io/github/stars/jndok/tpwn-bis.svg) ![forks](https://img.shields.io/github/forks/jndok/tpwn-bis.svg)

## CVE-2015-5736
 The Fortishield.sys driver in Fortinet FortiClient before 5.2.4 allows local users to execute arbitrary code with kernel privileges by setting the callback function in a (1) 0x220024 or (2) 0x220028 ioctl call.



- [https://github.com/avielzecharia/CVE-2015-5736](https://github.com/avielzecharia/CVE-2015-5736) :  ![starts](https://img.shields.io/github/stars/avielzecharia/CVE-2015-5736.svg) ![forks](https://img.shields.io/github/forks/avielzecharia/CVE-2015-5736.svg)

- [https://github.com/ApexPredator-InfoSec/forti_shield](https://github.com/ApexPredator-InfoSec/forti_shield) :  ![starts](https://img.shields.io/github/stars/ApexPredator-InfoSec/forti_shield.svg) ![forks](https://img.shields.io/github/forks/ApexPredator-InfoSec/forti_shield.svg)

## CVE-2015-5711
 TIBCO Managed File Transfer Internet Server before 7.2.5, Managed File Transfer Command Center before 7.2.5, Slingshot before 1.9.4, and Vault before 2.0.1 allow remote authenticated users to obtain sensitive information via a crafted HTTP request.



- [https://github.com/TrixSec/CVE-2015-57115](https://github.com/TrixSec/CVE-2015-57115) :  ![starts](https://img.shields.io/github/stars/TrixSec/CVE-2015-57115.svg) ![forks](https://img.shields.io/github/forks/TrixSec/CVE-2015-57115.svg)

## CVE-2015-5602
 sudoedit in Sudo before 1.8.15 allows local users to gain privileges via a symlink attack on a file whose full path is defined using multiple wildcards in /etc/sudoers, as demonstrated by "/home/*/*/file.txt."



- [https://github.com/t0kx/privesc-CVE-2015-5602](https://github.com/t0kx/privesc-CVE-2015-5602) :  ![starts](https://img.shields.io/github/stars/t0kx/privesc-CVE-2015-5602.svg) ![forks](https://img.shields.io/github/forks/t0kx/privesc-CVE-2015-5602.svg)

- [https://github.com/cved-sources/cve-2015-5602](https://github.com/cved-sources/cve-2015-5602) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2015-5602.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2015-5602.svg)

## CVE-2015-5600
 The kbdint_next_device function in auth2-chall.c in sshd in OpenSSH through 6.9 does not properly restrict the processing of keyboard-interactive devices within a single connection, which makes it easier for remote attackers to conduct brute-force attacks or cause a denial of service (CPU consumption) via a long and duplicative list in the ssh -oKbdInteractiveDevices option, as demonstrated by a modified client that provides a different password for each pam element on this list.



- [https://github.com/Abdirisaq-ali-aynab/openssh-vulnerability-assessment](https://github.com/Abdirisaq-ali-aynab/openssh-vulnerability-assessment) :  ![starts](https://img.shields.io/github/stars/Abdirisaq-ali-aynab/openssh-vulnerability-assessment.svg) ![forks](https://img.shields.io/github/forks/Abdirisaq-ali-aynab/openssh-vulnerability-assessment.svg)

## CVE-2015-5531
 Directory traversal vulnerability in Elasticsearch before 1.6.1 allows remote attackers to read arbitrary files via unspecified vectors related to snapshot API calls.



- [https://github.com/MoCh3n/CVE-2015-5531-POC](https://github.com/MoCh3n/CVE-2015-5531-POC) :  ![starts](https://img.shields.io/github/stars/MoCh3n/CVE-2015-5531-POC.svg) ![forks](https://img.shields.io/github/forks/MoCh3n/CVE-2015-5531-POC.svg)

- [https://github.com/xpgdgit/CVE-2015-5531](https://github.com/xpgdgit/CVE-2015-5531) :  ![starts](https://img.shields.io/github/stars/xpgdgit/CVE-2015-5531.svg) ![forks](https://img.shields.io/github/forks/xpgdgit/CVE-2015-5531.svg)

## CVE-2015-5477
 named in ISC BIND 9.x before 9.9.7-P2 and 9.10.x before 9.10.2-P3 allows remote attackers to cause a denial of service (REQUIRE assertion failure and daemon exit) via TKEY queries.



- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)

- [https://github.com/robertdavidgraham/cve-2015-5477](https://github.com/robertdavidgraham/cve-2015-5477) :  ![starts](https://img.shields.io/github/stars/robertdavidgraham/cve-2015-5477.svg) ![forks](https://img.shields.io/github/forks/robertdavidgraham/cve-2015-5477.svg)

- [https://github.com/elceef/tkeypoc](https://github.com/elceef/tkeypoc) :  ![starts](https://img.shields.io/github/stars/elceef/tkeypoc.svg) ![forks](https://img.shields.io/github/forks/elceef/tkeypoc.svg)

- [https://github.com/ilanyu/cve-2015-5477](https://github.com/ilanyu/cve-2015-5477) :  ![starts](https://img.shields.io/github/stars/ilanyu/cve-2015-5477.svg) ![forks](https://img.shields.io/github/forks/ilanyu/cve-2015-5477.svg)

- [https://github.com/knqyf263/cve-2015-5477](https://github.com/knqyf263/cve-2015-5477) :  ![starts](https://img.shields.io/github/stars/knqyf263/cve-2015-5477.svg) ![forks](https://img.shields.io/github/forks/knqyf263/cve-2015-5477.svg)

- [https://github.com/hmlio/vaas-cve-2015-5477](https://github.com/hmlio/vaas-cve-2015-5477) :  ![starts](https://img.shields.io/github/stars/hmlio/vaas-cve-2015-5477.svg) ![forks](https://img.shields.io/github/forks/hmlio/vaas-cve-2015-5477.svg)

- [https://github.com/xycloops123/TKEY-remote-DoS-vulnerability-exploit](https://github.com/xycloops123/TKEY-remote-DoS-vulnerability-exploit) :  ![starts](https://img.shields.io/github/stars/xycloops123/TKEY-remote-DoS-vulnerability-exploit.svg) ![forks](https://img.shields.io/github/forks/xycloops123/TKEY-remote-DoS-vulnerability-exploit.svg)

- [https://github.com/likekabin/ShareDoc_cve-2015-5477](https://github.com/likekabin/ShareDoc_cve-2015-5477) :  ![starts](https://img.shields.io/github/stars/likekabin/ShareDoc_cve-2015-5477.svg) ![forks](https://img.shields.io/github/forks/likekabin/ShareDoc_cve-2015-5477.svg)

## CVE-2015-5383
 Roundcube Webmail 1.1.x before 1.1.2 allows remote attackers to obtain sensitive information by reading files in the (1) config, (2) temp, or (3) logs directory.



- [https://github.com/starnightcyber/Exploit-Database-For-Webmail](https://github.com/starnightcyber/Exploit-Database-For-Webmail) :  ![starts](https://img.shields.io/github/stars/starnightcyber/Exploit-Database-For-Webmail.svg) ![forks](https://img.shields.io/github/forks/starnightcyber/Exploit-Database-For-Webmail.svg)

## CVE-2015-5381
 Cross-site scripting (XSS) vulnerability in program/include/rcmail.php in Roundcube Webmail 1.1.x before 1.1.2 allows remote attackers to inject arbitrary web script or HTML via the _mbox parameter to the default URI.



- [https://github.com/starnightcyber/Exploit-Database-For-Webmail](https://github.com/starnightcyber/Exploit-Database-For-Webmail) :  ![starts](https://img.shields.io/github/stars/starnightcyber/Exploit-Database-For-Webmail.svg) ![forks](https://img.shields.io/github/forks/starnightcyber/Exploit-Database-For-Webmail.svg)

## CVE-2015-5377
 Elasticsearch before 1.6.1 allows remote attackers to execute arbitrary code via unspecified vectors involving the transport protocol.  NOTE: ZDI appears to claim that CVE-2015-3253 and CVE-2015-5377 are the same vulnerability



- [https://github.com/fi3ro/CVE-2015-5377](https://github.com/fi3ro/CVE-2015-5377) :  ![starts](https://img.shields.io/github/stars/fi3ro/CVE-2015-5377.svg) ![forks](https://img.shields.io/github/forks/fi3ro/CVE-2015-5377.svg)

## CVE-2015-5374
 A vulnerability has been identified in Firmware variant PROFINET IO for EN100 Ethernet module : All versions  V1.04.01; Firmware variant Modbus TCP for EN100 Ethernet module : All versions  V1.11.00; Firmware variant DNP3 TCP for EN100 Ethernet module : All versions  V1.03; Firmware variant IEC 104 for EN100 Ethernet module : All versions  V1.21; EN100 Ethernet module included in SIPROTEC Merging Unit 6MU80 : All versions  1.02.02. Specially crafted packets sent to port 50000/UDP could cause a denial-of-service of the affected device. A manual reboot may be required to recover the service of the device.



- [https://github.com/can/CVE-2015-5374-DoS-PoC](https://github.com/can/CVE-2015-5374-DoS-PoC) :  ![starts](https://img.shields.io/github/stars/can/CVE-2015-5374-DoS-PoC.svg) ![forks](https://img.shields.io/github/forks/can/CVE-2015-5374-DoS-PoC.svg)

## CVE-2015-5347
 Cross-site scripting (XSS) vulnerability in the getWindowOpenJavaScript function in org.apache.wicket.extensions.ajax.markup.html.modal.ModalWindow in Apache Wicket 1.5.x before 1.5.15, 6.x before 6.22.0, and 7.x before 7.2.0 might allow remote attackers to inject arbitrary web script or HTML via a ModalWindow title.



- [https://github.com/alexanderkjall/wicker-cve-2015-5347](https://github.com/alexanderkjall/wicker-cve-2015-5347) :  ![starts](https://img.shields.io/github/stars/alexanderkjall/wicker-cve-2015-5347.svg) ![forks](https://img.shields.io/github/forks/alexanderkjall/wicker-cve-2015-5347.svg)

## CVE-2015-5254
 Apache ActiveMQ 5.x before 5.13.0 does not restrict the classes that can be serialized in the broker, which allows remote attackers to execute arbitrary code via a crafted serialized Java Message Service (JMS) ObjectMessage object.



- [https://github.com/jas502n/CVE-2015-5254](https://github.com/jas502n/CVE-2015-5254) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2015-5254.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2015-5254.svg)

- [https://github.com/Ma1Dong/ActiveMQ_CVE-2015-5254](https://github.com/Ma1Dong/ActiveMQ_CVE-2015-5254) :  ![starts](https://img.shields.io/github/stars/Ma1Dong/ActiveMQ_CVE-2015-5254.svg) ![forks](https://img.shields.io/github/forks/Ma1Dong/ActiveMQ_CVE-2015-5254.svg)

- [https://github.com/guigui237/Exploitation-de-la-vuln-rabilit-CVE-2015-5254-](https://github.com/guigui237/Exploitation-de-la-vuln-rabilit-CVE-2015-5254-) :  ![starts](https://img.shields.io/github/stars/guigui237/Exploitation-de-la-vuln-rabilit-CVE-2015-5254-.svg) ![forks](https://img.shields.io/github/forks/guigui237/Exploitation-de-la-vuln-rabilit-CVE-2015-5254-.svg)

## CVE-2015-5195
 ntp_openssl.m4 in ntpd in NTP before 4.2.7p112 allows remote attackers to cause a denial of service (segmentation fault) via a crafted statistics or filegen configuration command that is not enabled during compilation.



- [https://github.com/theglife214/CVE-2015-5195](https://github.com/theglife214/CVE-2015-5195) :  ![starts](https://img.shields.io/github/stars/theglife214/CVE-2015-5195.svg) ![forks](https://img.shields.io/github/forks/theglife214/CVE-2015-5195.svg)

## CVE-2015-5122
 Use-after-free vulnerability in the DisplayObject class in the ActionScript 3 (AS3) implementation in Adobe Flash Player 13.x through 13.0.0.302 on Windows and OS X, 14.x through 18.0.0.203 on Windows and OS X, 11.x through 11.2.202.481 on Linux, and 12.x through 18.0.0.204 on Linux Chrome installations allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted Flash content that leverages improper handling of the opaqueBackground property, as exploited in the wild in July 2015.



- [https://github.com/Xattam1/Adobe-Flash-Exploits_17-18](https://github.com/Xattam1/Adobe-Flash-Exploits_17-18) :  ![starts](https://img.shields.io/github/stars/Xattam1/Adobe-Flash-Exploits_17-18.svg) ![forks](https://img.shields.io/github/forks/Xattam1/Adobe-Flash-Exploits_17-18.svg)

## CVE-2015-5119
 Use-after-free vulnerability in the ByteArray class in the ActionScript 3 (AS3) implementation in Adobe Flash Player 13.x through 13.0.0.296 and 14.x through 18.0.0.194 on Windows and OS X and 11.x through 11.2.202.468 on Linux allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted Flash content that overrides a valueOf function, as exploited in the wild in July 2015.



- [https://github.com/CiscoCXSecurity/CVE-2015-5119_walkthrough](https://github.com/CiscoCXSecurity/CVE-2015-5119_walkthrough) :  ![starts](https://img.shields.io/github/stars/CiscoCXSecurity/CVE-2015-5119_walkthrough.svg) ![forks](https://img.shields.io/github/forks/CiscoCXSecurity/CVE-2015-5119_walkthrough.svg)

- [https://github.com/jvazquez-r7/CVE-2015-5119](https://github.com/jvazquez-r7/CVE-2015-5119) :  ![starts](https://img.shields.io/github/stars/jvazquez-r7/CVE-2015-5119.svg) ![forks](https://img.shields.io/github/forks/jvazquez-r7/CVE-2015-5119.svg)

- [https://github.com/dangokyo/CVE-2015-5119](https://github.com/dangokyo/CVE-2015-5119) :  ![starts](https://img.shields.io/github/stars/dangokyo/CVE-2015-5119.svg) ![forks](https://img.shields.io/github/forks/dangokyo/CVE-2015-5119.svg)

- [https://github.com/Xattam1/Adobe-Flash-Exploits_17-18](https://github.com/Xattam1/Adobe-Flash-Exploits_17-18) :  ![starts](https://img.shields.io/github/stars/Xattam1/Adobe-Flash-Exploits_17-18.svg) ![forks](https://img.shields.io/github/forks/Xattam1/Adobe-Flash-Exploits_17-18.svg)

## CVE-2015-4870
 Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier, and 5.6.26 and earlier, allows remote authenticated users to affect availability via unknown vectors related to Server : Parser.



- [https://github.com/OsandaMalith/CVE-2015-4870](https://github.com/OsandaMalith/CVE-2015-4870) :  ![starts](https://img.shields.io/github/stars/OsandaMalith/CVE-2015-4870.svg) ![forks](https://img.shields.io/github/forks/OsandaMalith/CVE-2015-4870.svg)

## CVE-2015-4852
 The WLS Security component in Oracle WebLogic Server 10.3.6.0, 12.1.2.0, 12.1.3.0, and 12.2.1.0 allows remote attackers to execute arbitrary commands via a crafted serialized Java object in T3 protocol traffic to TCP port 7001, related to oracle_common/modules/com.bea.core.apache.commons.collections.jar. NOTE: the scope of this CVE is limited to the WebLogic Server product.



- [https://github.com/roo7break/serialator](https://github.com/roo7break/serialator) :  ![starts](https://img.shields.io/github/stars/roo7break/serialator.svg) ![forks](https://img.shields.io/github/forks/roo7break/serialator.svg)

- [https://github.com/zhzhdoai/Weblogic_Vuln](https://github.com/zhzhdoai/Weblogic_Vuln) :  ![starts](https://img.shields.io/github/stars/zhzhdoai/Weblogic_Vuln.svg) ![forks](https://img.shields.io/github/forks/zhzhdoai/Weblogic_Vuln.svg)

- [https://github.com/minhangxiaohui/Weblogic_direct_T3_Rces](https://github.com/minhangxiaohui/Weblogic_direct_T3_Rces) :  ![starts](https://img.shields.io/github/stars/minhangxiaohui/Weblogic_direct_T3_Rces.svg) ![forks](https://img.shields.io/github/forks/minhangxiaohui/Weblogic_direct_T3_Rces.svg)

- [https://github.com/AndersonSingh/serialization-vulnerability-scanner](https://github.com/AndersonSingh/serialization-vulnerability-scanner) :  ![starts](https://img.shields.io/github/stars/AndersonSingh/serialization-vulnerability-scanner.svg) ![forks](https://img.shields.io/github/forks/AndersonSingh/serialization-vulnerability-scanner.svg)

- [https://github.com/nex1less/CVE-2015-4852](https://github.com/nex1less/CVE-2015-4852) :  ![starts](https://img.shields.io/github/stars/nex1less/CVE-2015-4852.svg) ![forks](https://img.shields.io/github/forks/nex1less/CVE-2015-4852.svg)

## CVE-2015-4843
 Unspecified vulnerability in Oracle Java SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51, allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Libraries.



- [https://github.com/Soteria-Research/cve-2015-4843-type-confusion-phrack](https://github.com/Soteria-Research/cve-2015-4843-type-confusion-phrack) :  ![starts](https://img.shields.io/github/stars/Soteria-Research/cve-2015-4843-type-confusion-phrack.svg) ![forks](https://img.shields.io/github/forks/Soteria-Research/cve-2015-4843-type-confusion-phrack.svg)

## CVE-2015-4495
 The PDF reader in Mozilla Firefox before 39.0.3, Firefox ESR 38.x before 38.1.1, and Firefox OS before 2.2 allows remote attackers to bypass the Same Origin Policy, and read arbitrary files or gain privileges, via vectors involving crafted JavaScript code and a native setter, as exploited in the wild in August 2015.



- [https://github.com/vincd/CVE-2015-4495](https://github.com/vincd/CVE-2015-4495) :  ![starts](https://img.shields.io/github/stars/vincd/CVE-2015-4495.svg) ![forks](https://img.shields.io/github/forks/vincd/CVE-2015-4495.svg)

## CVE-2015-4133
 Unrestricted file upload vulnerability in admin/scripts/FileUploader/php.php in the ReFlex Gallery plugin before 3.1.4 for WordPress allows remote attackers to execute arbitrary PHP code by uploading a file with a PHP extension, then accessing it via a direct request to the file in uploads/ directory.



- [https://github.com/D3Ext/CVE-2015-4133](https://github.com/D3Ext/CVE-2015-4133) :  ![starts](https://img.shields.io/github/stars/D3Ext/CVE-2015-4133.svg) ![forks](https://img.shields.io/github/forks/D3Ext/CVE-2015-4133.svg)

- [https://github.com/sug4r-wr41th/CVE-2015-4133](https://github.com/sug4r-wr41th/CVE-2015-4133) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2015-4133.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2015-4133.svg)

## CVE-2015-4077
 The (1) mdare64_48.sys, (2) mdare32_48.sys, (3) mdare32_52.sys, and (4) mdare64_52.sys drivers in Fortinet FortiClient before 5.2.4 allow local users to read arbitrary kernel memory via a 0x22608C ioctl call.



- [https://github.com/ApexPredator-InfoSec/forti_shield](https://github.com/ApexPredator-InfoSec/forti_shield) :  ![starts](https://img.shields.io/github/stars/ApexPredator-InfoSec/forti_shield.svg) ![forks](https://img.shields.io/github/forks/ApexPredator-InfoSec/forti_shield.svg)

## CVE-2015-4024
 Algorithmic complexity vulnerability in the multipart_buffer_headers function in main/rfc1867.c in PHP before 5.4.41, 5.5.x before 5.5.25, and 5.6.x before 5.6.9 allows remote attackers to cause a denial of service (CPU consumption) via crafted form data that triggers an improper order-of-growth outcome.



- [https://github.com/typcn/php-load-test](https://github.com/typcn/php-load-test) :  ![starts](https://img.shields.io/github/stars/typcn/php-load-test.svg) ![forks](https://img.shields.io/github/forks/typcn/php-load-test.svg)

## CVE-2015-4000
 The TLS protocol 1.2 and earlier, when a DHE_EXPORT ciphersuite is enabled on a server but not on a client, does not properly convey a DHE_EXPORT choice, which allows man-in-the-middle attackers to conduct cipher-downgrade attacks by rewriting a ClientHello with DHE replaced by DHE_EXPORT and then rewriting a ServerHello with DHE_EXPORT replaced by DHE, aka the "Logjam" issue.



- [https://github.com/fatlan/HAProxy-Keepalived-Sec-HighLoads](https://github.com/fatlan/HAProxy-Keepalived-Sec-HighLoads) :  ![starts](https://img.shields.io/github/stars/fatlan/HAProxy-Keepalived-Sec-HighLoads.svg) ![forks](https://img.shields.io/github/forks/fatlan/HAProxy-Keepalived-Sec-HighLoads.svg)

- [https://github.com/anthophilee/A2SV--SSL-VUL-Scan](https://github.com/anthophilee/A2SV--SSL-VUL-Scan) :  ![starts](https://img.shields.io/github/stars/anthophilee/A2SV--SSL-VUL-Scan.svg) ![forks](https://img.shields.io/github/forks/anthophilee/A2SV--SSL-VUL-Scan.svg)

## CVE-2015-3864
 Integer underflow in the MPEG4Extractor::parseChunk function in MPEG4Extractor.cpp in libstagefright in mediaserver in Android before 5.1.1 LMY48M allows remote attackers to execute arbitrary code via crafted MPEG-4 data, aka internal bug 23034759.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-3824.



- [https://github.com/eudemonics/scaredycat](https://github.com/eudemonics/scaredycat) :  ![starts](https://img.shields.io/github/stars/eudemonics/scaredycat.svg) ![forks](https://img.shields.io/github/forks/eudemonics/scaredycat.svg)

- [https://github.com/pwnaccelerator/stagefright-cve-2015-3864](https://github.com/pwnaccelerator/stagefright-cve-2015-3864) :  ![starts](https://img.shields.io/github/stars/pwnaccelerator/stagefright-cve-2015-3864.svg) ![forks](https://img.shields.io/github/forks/pwnaccelerator/stagefright-cve-2015-3864.svg)

- [https://github.com/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864](https://github.com/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864) :  ![starts](https://img.shields.io/github/stars/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864.svg) ![forks](https://img.shields.io/github/forks/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864.svg)

- [https://github.com/HenryVHuang/CVE-2015-3864](https://github.com/HenryVHuang/CVE-2015-3864) :  ![starts](https://img.shields.io/github/stars/HenryVHuang/CVE-2015-3864.svg) ![forks](https://img.shields.io/github/forks/HenryVHuang/CVE-2015-3864.svg)

- [https://github.com/Cmadhushanka/CVE-2015-3864-Exploitation](https://github.com/Cmadhushanka/CVE-2015-3864-Exploitation) :  ![starts](https://img.shields.io/github/stars/Cmadhushanka/CVE-2015-3864-Exploitation.svg) ![forks](https://img.shields.io/github/forks/Cmadhushanka/CVE-2015-3864-Exploitation.svg)

## CVE-2015-3839
 The updateMessageStatus function in Android 5.1.1 and earlier allows local users to cause a denial of service (NULL pointer exception and process crash).



- [https://github.com/mabin004/cve-2015-3839_PoC](https://github.com/mabin004/cve-2015-3839_PoC) :  ![starts](https://img.shields.io/github/stars/mabin004/cve-2015-3839_PoC.svg) ![forks](https://img.shields.io/github/forks/mabin004/cve-2015-3839_PoC.svg)

## CVE-2015-3837
 The OpenSSLX509Certificate class in org/conscrypt/OpenSSLX509Certificate.java in Android before 5.1.1 LMY48I improperly includes certain context data during serialization and deserialization, which allows attackers to execute arbitrary code via an application that sends a crafted Intent, aka internal bug 21437603.



- [https://github.com/roeeh/conscryptchecker](https://github.com/roeeh/conscryptchecker) :  ![starts](https://img.shields.io/github/stars/roeeh/conscryptchecker.svg) ![forks](https://img.shields.io/github/forks/roeeh/conscryptchecker.svg)

- [https://github.com/itibs/IsildursBane](https://github.com/itibs/IsildursBane) :  ![starts](https://img.shields.io/github/stars/itibs/IsildursBane.svg) ![forks](https://img.shields.io/github/forks/itibs/IsildursBane.svg)

## CVE-2015-3825
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2015-3837. Reason: This candidate is a reservation duplicate of CVE-2015-3837. Notes: All CVE users should reference CVE-2015-3837 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage



- [https://github.com/roeeh/conscryptchecker](https://github.com/roeeh/conscryptchecker) :  ![starts](https://img.shields.io/github/stars/roeeh/conscryptchecker.svg) ![forks](https://img.shields.io/github/forks/roeeh/conscryptchecker.svg)

## CVE-2015-3673
 Admin Framework in Apple OS X before 10.10.4 does not properly restrict the location of writeconfig clients, which allows local users to obtain root privileges by moving and then modifying Directory Utility.



- [https://github.com/sideeffect42/RootPipeTester](https://github.com/sideeffect42/RootPipeTester) :  ![starts](https://img.shields.io/github/stars/sideeffect42/RootPipeTester.svg) ![forks](https://img.shields.io/github/forks/sideeffect42/RootPipeTester.svg)

## CVE-2015-3636
 The ping_unhash function in net/ipv4/ping.c in the Linux kernel before 4.0.3 does not initialize a certain list data structure during an unhash operation, which allows local users to gain privileges or cause a denial of service (use-after-free and system crash) by leveraging the ability to make a SOCK_DGRAM socket system call for the IPPROTO_ICMP or IPPROTO_ICMPV6 protocol, and then making a connect system call after a disconnect.



- [https://github.com/fi01/CVE-2015-3636](https://github.com/fi01/CVE-2015-3636) :  ![starts](https://img.shields.io/github/stars/fi01/CVE-2015-3636.svg) ![forks](https://img.shields.io/github/forks/fi01/CVE-2015-3636.svg)

- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)

- [https://github.com/android-rooting-tools/libpingpong_exploit](https://github.com/android-rooting-tools/libpingpong_exploit) :  ![starts](https://img.shields.io/github/stars/android-rooting-tools/libpingpong_exploit.svg) ![forks](https://img.shields.io/github/forks/android-rooting-tools/libpingpong_exploit.svg)

- [https://github.com/a7vinx/CVE-2015-3636](https://github.com/a7vinx/CVE-2015-3636) :  ![starts](https://img.shields.io/github/stars/a7vinx/CVE-2015-3636.svg) ![forks](https://img.shields.io/github/forks/a7vinx/CVE-2015-3636.svg)

- [https://github.com/betalphafai/cve-2015-3636_crash](https://github.com/betalphafai/cve-2015-3636_crash) :  ![starts](https://img.shields.io/github/stars/betalphafai/cve-2015-3636_crash.svg) ![forks](https://img.shields.io/github/forks/betalphafai/cve-2015-3636_crash.svg)

- [https://github.com/askk/libping_unhash_exploit_POC](https://github.com/askk/libping_unhash_exploit_POC) :  ![starts](https://img.shields.io/github/stars/askk/libping_unhash_exploit_POC.svg) ![forks](https://img.shields.io/github/forks/askk/libping_unhash_exploit_POC.svg)

- [https://github.com/debugfan/rattle_root](https://github.com/debugfan/rattle_root) :  ![starts](https://img.shields.io/github/stars/debugfan/rattle_root.svg) ![forks](https://img.shields.io/github/forks/debugfan/rattle_root.svg)

- [https://github.com/ludongxu/cve-2015-3636](https://github.com/ludongxu/cve-2015-3636) :  ![starts](https://img.shields.io/github/stars/ludongxu/cve-2015-3636.svg) ![forks](https://img.shields.io/github/forks/ludongxu/cve-2015-3636.svg)

## CVE-2015-3456
 The Floppy Disk Controller (FDC) in QEMU, as used in Xen 4.5.x and earlier and KVM, allows local guest users to cause a denial of service (out-of-bounds write and guest crash) or possibly execute arbitrary code via the (1) FD_CMD_READ_ID, (2) FD_CMD_DRIVE_SPECIFICATION_COMMAND, or other unspecified commands, aka VENOM.



- [https://github.com/vincentbernat/cve-2015-3456](https://github.com/vincentbernat/cve-2015-3456) :  ![starts](https://img.shields.io/github/stars/vincentbernat/cve-2015-3456.svg) ![forks](https://img.shields.io/github/forks/vincentbernat/cve-2015-3456.svg)

- [https://github.com/orf53975/poisonfrog](https://github.com/orf53975/poisonfrog) :  ![starts](https://img.shields.io/github/stars/orf53975/poisonfrog.svg) ![forks](https://img.shields.io/github/forks/orf53975/poisonfrog.svg)

## CVE-2015-3337
 Directory traversal vulnerability in Elasticsearch before 1.4.5 and 1.5.x before 1.5.2, when a site plugin is enabled, allows remote attackers to read arbitrary files via unspecified vectors.



- [https://github.com/jas502n/CVE-2015-3337](https://github.com/jas502n/CVE-2015-3337) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2015-3337.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2015-3337.svg)

## CVE-2015-3306
 The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.



- [https://github.com/t0kx/exploit-CVE-2015-3306](https://github.com/t0kx/exploit-CVE-2015-3306) :  ![starts](https://img.shields.io/github/stars/t0kx/exploit-CVE-2015-3306.svg) ![forks](https://img.shields.io/github/forks/t0kx/exploit-CVE-2015-3306.svg)

- [https://github.com/nootropics/propane](https://github.com/nootropics/propane) :  ![starts](https://img.shields.io/github/stars/nootropics/propane.svg) ![forks](https://img.shields.io/github/forks/nootropics/propane.svg)

- [https://github.com/shk0x/cpx_proftpd](https://github.com/shk0x/cpx_proftpd) :  ![starts](https://img.shields.io/github/stars/shk0x/cpx_proftpd.svg) ![forks](https://img.shields.io/github/forks/shk0x/cpx_proftpd.svg)

- [https://github.com/davidtavarez/CVE-2015-3306](https://github.com/davidtavarez/CVE-2015-3306) :  ![starts](https://img.shields.io/github/stars/davidtavarez/CVE-2015-3306.svg) ![forks](https://img.shields.io/github/forks/davidtavarez/CVE-2015-3306.svg)

- [https://github.com/cd6629/CVE-2015-3306-Python-PoC](https://github.com/cd6629/CVE-2015-3306-Python-PoC) :  ![starts](https://img.shields.io/github/stars/cd6629/CVE-2015-3306-Python-PoC.svg) ![forks](https://img.shields.io/github/forks/cd6629/CVE-2015-3306-Python-PoC.svg)

- [https://github.com/jptr218/proftpd_bypass](https://github.com/jptr218/proftpd_bypass) :  ![starts](https://img.shields.io/github/stars/jptr218/proftpd_bypass.svg) ![forks](https://img.shields.io/github/forks/jptr218/proftpd_bypass.svg)

- [https://github.com/cybersensei-EH/hackviser_labs_CVE-2015-3306](https://github.com/cybersensei-EH/hackviser_labs_CVE-2015-3306) :  ![starts](https://img.shields.io/github/stars/cybersensei-EH/hackviser_labs_CVE-2015-3306.svg) ![forks](https://img.shields.io/github/forks/cybersensei-EH/hackviser_labs_CVE-2015-3306.svg)

- [https://github.com/0xm4ud/ProFTPD_CVE-2015-3306](https://github.com/0xm4ud/ProFTPD_CVE-2015-3306) :  ![starts](https://img.shields.io/github/stars/0xm4ud/ProFTPD_CVE-2015-3306.svg) ![forks](https://img.shields.io/github/forks/0xm4ud/ProFTPD_CVE-2015-3306.svg)

- [https://github.com/cved-sources/cve-2015-3306](https://github.com/cved-sources/cve-2015-3306) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2015-3306.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2015-3306.svg)

- [https://github.com/hackarada/cve-2015-3306](https://github.com/hackarada/cve-2015-3306) :  ![starts](https://img.shields.io/github/stars/hackarada/cve-2015-3306.svg) ![forks](https://img.shields.io/github/forks/hackarada/cve-2015-3306.svg)

- [https://github.com/donmedfor/CVE-2015-3306](https://github.com/donmedfor/CVE-2015-3306) :  ![starts](https://img.shields.io/github/stars/donmedfor/CVE-2015-3306.svg) ![forks](https://img.shields.io/github/forks/donmedfor/CVE-2015-3306.svg)

- [https://github.com/Z3R0-0x30/CVE-2015-3306](https://github.com/Z3R0-0x30/CVE-2015-3306) :  ![starts](https://img.shields.io/github/stars/Z3R0-0x30/CVE-2015-3306.svg) ![forks](https://img.shields.io/github/forks/Z3R0-0x30/CVE-2015-3306.svg)

- [https://github.com/cdedmondson/Modified-CVE-2015-3306-Exploit](https://github.com/cdedmondson/Modified-CVE-2015-3306-Exploit) :  ![starts](https://img.shields.io/github/stars/cdedmondson/Modified-CVE-2015-3306-Exploit.svg) ![forks](https://img.shields.io/github/forks/cdedmondson/Modified-CVE-2015-3306-Exploit.svg)

- [https://github.com/JoseLRC97/ProFTPd-1.3.5-mod_copy-Remote-Command-Execution](https://github.com/JoseLRC97/ProFTPd-1.3.5-mod_copy-Remote-Command-Execution) :  ![starts](https://img.shields.io/github/stars/JoseLRC97/ProFTPd-1.3.5-mod_copy-Remote-Command-Execution.svg) ![forks](https://img.shields.io/github/forks/JoseLRC97/ProFTPd-1.3.5-mod_copy-Remote-Command-Execution.svg)

## CVE-2015-3239
 Off-by-one error in the dwarf_to_unw_regnum function in include/dwarf_i.h in libunwind 1.1 allows local users to have unspecified impact via invalid dwarf opcodes.



- [https://github.com/RenukaSelvar/libunwind_CVE-2015-3239](https://github.com/RenukaSelvar/libunwind_CVE-2015-3239) :  ![starts](https://img.shields.io/github/stars/RenukaSelvar/libunwind_CVE-2015-3239.svg) ![forks](https://img.shields.io/github/forks/RenukaSelvar/libunwind_CVE-2015-3239.svg)

- [https://github.com/RenukaSelvar/libunwind_CVE-2015-3239_After](https://github.com/RenukaSelvar/libunwind_CVE-2015-3239_After) :  ![starts](https://img.shields.io/github/stars/RenukaSelvar/libunwind_CVE-2015-3239_After.svg) ![forks](https://img.shields.io/github/forks/RenukaSelvar/libunwind_CVE-2015-3239_After.svg)

- [https://github.com/RenukaSelvar/libunwind_CVE-2015-3239_AfterPatch](https://github.com/RenukaSelvar/libunwind_CVE-2015-3239_AfterPatch) :  ![starts](https://img.shields.io/github/stars/RenukaSelvar/libunwind_CVE-2015-3239_AfterPatch.svg) ![forks](https://img.shields.io/github/forks/RenukaSelvar/libunwind_CVE-2015-3239_AfterPatch.svg)

## CVE-2015-3224
 request.rb in Web Console before 2.1.3, as used with Ruby on Rails 3.x and 4.x, does not properly restrict the use of X-Forwarded-For headers in determining a client's IP address, which allows remote attackers to bypass the whitelisted_ips protection mechanism via a crafted request.



- [https://github.com/0xEval/cve-2015-3224](https://github.com/0xEval/cve-2015-3224) :  ![starts](https://img.shields.io/github/stars/0xEval/cve-2015-3224.svg) ![forks](https://img.shields.io/github/forks/0xEval/cve-2015-3224.svg)

- [https://github.com/0x00-0x00/CVE-2015-3224](https://github.com/0x00-0x00/CVE-2015-3224) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/CVE-2015-3224.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/CVE-2015-3224.svg)

- [https://github.com/n000xy/CVE-2015-3224-](https://github.com/n000xy/CVE-2015-3224-) :  ![starts](https://img.shields.io/github/stars/n000xy/CVE-2015-3224-.svg) ![forks](https://img.shields.io/github/forks/n000xy/CVE-2015-3224-.svg)

- [https://github.com/Sic4rio/CVE-2015-3224](https://github.com/Sic4rio/CVE-2015-3224) :  ![starts](https://img.shields.io/github/stars/Sic4rio/CVE-2015-3224.svg) ![forks](https://img.shields.io/github/forks/Sic4rio/CVE-2015-3224.svg)

## CVE-2015-3197
 ssl/s2_srvr.c in OpenSSL 1.0.1 before 1.0.1r and 1.0.2 before 1.0.2f does not prevent use of disabled ciphers, which makes it easier for man-in-the-middle attackers to defeat cryptographic protection mechanisms by performing computations on SSLv2 traffic, related to the get_client_master_key and get_client_hello functions.



- [https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3197](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3197) :  ![starts](https://img.shields.io/github/stars/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3197.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3197.svg)

## CVE-2015-3195
 The ASN1_TFLG_COMBINE implementation in crypto/asn1/tasn_dec.c in OpenSSL before 0.9.8zh, 1.0.0 before 1.0.0t, 1.0.1 before 1.0.1q, and 1.0.2 before 1.0.2e mishandles errors caused by malformed X509_ATTRIBUTE data, which allows remote attackers to obtain sensitive information from process memory by triggering a decoding failure in a PKCS#7 or CMS application.



- [https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3195](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3195) :  ![starts](https://img.shields.io/github/stars/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3195.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3195.svg)

## CVE-2015-3194
 crypto/rsa/rsa_ameth.c in OpenSSL 1.0.1 before 1.0.1q and 1.0.2 before 1.0.2e allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via an RSA PSS ASN.1 signature that lacks a mask generation function parameter.



- [https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3194](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3194) :  ![starts](https://img.shields.io/github/stars/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3194.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/OpenSSL-1_0_1g_CVE-2015-3194.svg)

## CVE-2015-3152
 Oracle MySQL before 5.7.3, Oracle MySQL Connector/C (aka libmysqlclient) before 6.1.3, and MariaDB before 5.5.44 use the --ssl option to mean that SSL is optional, which allows man-in-the-middle attackers to spoof servers via a cleartext-downgrade attack, aka a "BACKRONYM" attack.



- [https://github.com/duo-labs/mysslstrip](https://github.com/duo-labs/mysslstrip) :  ![starts](https://img.shields.io/github/stars/duo-labs/mysslstrip.svg) ![forks](https://img.shields.io/github/forks/duo-labs/mysslstrip.svg)

## CVE-2015-3145
 The sanitize_cookie_path function in cURL and libcurl 7.31.0 through 7.41.0 does not properly calculate an index, which allows remote attackers to cause a denial of service (out-of-bounds write and crash) or possibly have other unspecified impact via a cookie path containing only a double-quote character.



- [https://github.com/serz999/CVE-2015-3145](https://github.com/serz999/CVE-2015-3145) :  ![starts](https://img.shields.io/github/stars/serz999/CVE-2015-3145.svg) ![forks](https://img.shields.io/github/forks/serz999/CVE-2015-3145.svg)

## CVE-2015-3105
 Adobe Flash Player before 13.0.0.292 and 14.x through 18.x before 18.0.0.160 on Windows and OS X and before 11.2.202.466 on Linux, Adobe AIR before 18.0.0.144 on Windows and before 18.0.0.143 on OS X and Android, Adobe AIR SDK before 18.0.0.144 on Windows and before 18.0.0.143 on OS X, and Adobe AIR SDK & Compiler before 18.0.0.144 on Windows and before 18.0.0.143 on OS X allow attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors.



- [https://github.com/Xattam1/Adobe-Flash-Exploits_17-18](https://github.com/Xattam1/Adobe-Flash-Exploits_17-18) :  ![starts](https://img.shields.io/github/stars/Xattam1/Adobe-Flash-Exploits_17-18.svg) ![forks](https://img.shields.io/github/forks/Xattam1/Adobe-Flash-Exploits_17-18.svg)

## CVE-2015-3090
 Adobe Flash Player before 13.0.0.289 and 14.x through 17.x before 17.0.0.188 on Windows and OS X and before 11.2.202.460 on Linux, Adobe AIR before 17.0.0.172, Adobe AIR SDK before 17.0.0.172, and Adobe AIR SDK & Compiler before 17.0.0.172 allow attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, a different vulnerability than CVE-2015-3078, CVE-2015-3089, and CVE-2015-3093.



- [https://github.com/Xattam1/Adobe-Flash-Exploits_17-18](https://github.com/Xattam1/Adobe-Flash-Exploits_17-18) :  ![starts](https://img.shields.io/github/stars/Xattam1/Adobe-Flash-Exploits_17-18.svg) ![forks](https://img.shields.io/github/forks/Xattam1/Adobe-Flash-Exploits_17-18.svg)

## CVE-2015-3073
 Adobe Reader and Acrobat 10.x before 10.1.14 and 11.x before 11.0.11 on Windows and OS X allow attackers to bypass intended restrictions on JavaScript API execution via unspecified vectors, a different vulnerability than CVE-2015-3060, CVE-2015-3061, CVE-2015-3062, CVE-2015-3063, CVE-2015-3064, CVE-2015-3065, CVE-2015-3066, CVE-2015-3067, CVE-2015-3068, CVE-2015-3069, CVE-2015-3071, CVE-2015-3072, and CVE-2015-3074.



- [https://github.com/reigningshells/CVE-2015-3073](https://github.com/reigningshells/CVE-2015-3073) :  ![starts](https://img.shields.io/github/stars/reigningshells/CVE-2015-3073.svg) ![forks](https://img.shields.io/github/forks/reigningshells/CVE-2015-3073.svg)

## CVE-2015-3043
 Adobe Flash Player before 13.0.0.281 and 14.x through 17.x before 17.0.0.169 on Windows and OS X and before 11.2.202.457 on Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors, as exploited in the wild in April 2015, a different vulnerability than CVE-2015-0347, CVE-2015-0350, CVE-2015-0352, CVE-2015-0353, CVE-2015-0354, CVE-2015-0355, CVE-2015-0360, CVE-2015-3038, CVE-2015-3041, and CVE-2015-3042.



- [https://github.com/whitehairman/Exploit](https://github.com/whitehairman/Exploit) :  ![starts](https://img.shields.io/github/stars/whitehairman/Exploit.svg) ![forks](https://img.shields.io/github/forks/whitehairman/Exploit.svg)

## CVE-2015-2925
 The prepend_path function in fs/dcache.c in the Linux kernel before 4.2.4 does not properly handle rename actions inside a bind mount, which allows local users to bypass an intended container protection mechanism by renaming a directory, related to a "double-chroot attack."



- [https://github.com/Kagami/docker_cve-2015-2925](https://github.com/Kagami/docker_cve-2015-2925) :  ![starts](https://img.shields.io/github/stars/Kagami/docker_cve-2015-2925.svg) ![forks](https://img.shields.io/github/forks/Kagami/docker_cve-2015-2925.svg)

## CVE-2015-2900
 The AddUserFinding add_userfinding2 function in Medicomp MEDCIN Engine before 2.22.20153.226 allows remote attackers to cause a denial of service (out-of-bounds write) or possibly have unspecified other impact via a crafted packet on port 8190.



- [https://github.com/securifera/CVE-2015-2900-Exploit](https://github.com/securifera/CVE-2015-2900-Exploit) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2015-2900-Exploit.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2015-2900-Exploit.svg)

## CVE-2015-2797
 Stack-based buffer overflow in AirTies Air 6372, 5760, 5750, 5650TT, 5453, 5444TT, 5443, 5442, 5343, 5342, 5341, and 5021 DSL modems with firmware 1.0.2.0 and earlier allows remote attackers to execute arbitrary code via a long string in the redirect parameter to cgi-bin/login.



- [https://github.com/Bariskizilkaya/CVE-2015-2797-PoC](https://github.com/Bariskizilkaya/CVE-2015-2797-PoC) :  ![starts](https://img.shields.io/github/stars/Bariskizilkaya/CVE-2015-2797-PoC.svg) ![forks](https://img.shields.io/github/forks/Bariskizilkaya/CVE-2015-2797-PoC.svg)

## CVE-2015-2794
 The installation wizard in DotNetNuke (DNN) before 7.4.1 allows remote attackers to reinstall the application and gain SuperUser access via a direct request to Install/InstallWizard.aspx.



- [https://github.com/styx00/DNN_CVE-2015-2794](https://github.com/styx00/DNN_CVE-2015-2794) :  ![starts](https://img.shields.io/github/stars/styx00/DNN_CVE-2015-2794.svg) ![forks](https://img.shields.io/github/forks/styx00/DNN_CVE-2015-2794.svg)

- [https://github.com/wilsc0w/CVE-2015-2794-finder](https://github.com/wilsc0w/CVE-2015-2794-finder) :  ![starts](https://img.shields.io/github/stars/wilsc0w/CVE-2015-2794-finder.svg) ![forks](https://img.shields.io/github/forks/wilsc0w/CVE-2015-2794-finder.svg)

## CVE-2015-2546
 The kernel-mode driver in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT Gold and 8.1, and Windows 10 allows local users to gain privileges via a crafted application, aka "Win32k Memory Corruption Elevation of Privilege Vulnerability," a different vulnerability than CVE-2015-2511, CVE-2015-2517, and CVE-2015-2518.



- [https://github.com/k0keoyo/CVE-2015-2546-Exploit](https://github.com/k0keoyo/CVE-2015-2546-Exploit) :  ![starts](https://img.shields.io/github/stars/k0keoyo/CVE-2015-2546-Exploit.svg) ![forks](https://img.shields.io/github/forks/k0keoyo/CVE-2015-2546-Exploit.svg)

## CVE-2015-2523
 Microsoft Excel 2007 SP3, Excel 2010 SP2, Excel 2013 SP1, Excel 2013 RT SP1, Excel for Mac 2011 and 2016, Office Compatibility Pack SP3, and Excel Viewer allow remote attackers to execute arbitrary code via a crafted Office document, aka "Microsoft Office Memory Corruption Vulnerability."



- [https://github.com/krdsploit/MSFu-Extentions-](https://github.com/krdsploit/MSFu-Extentions-) :  ![starts](https://img.shields.io/github/stars/krdsploit/MSFu-Extentions-.svg) ![forks](https://img.shields.io/github/forks/krdsploit/MSFu-Extentions-.svg)

## CVE-2015-2315
 Cross-site scripting (XSS) vulnerability in the WPML plugin before 3.1.9 for WordPress allows remote attackers to inject arbitrary web script or HTML via the target parameter in a reminder_popup action to the default URI.



- [https://github.com/weidongl74/cve-2015-2315-report](https://github.com/weidongl74/cve-2015-2315-report) :  ![starts](https://img.shields.io/github/stars/weidongl74/cve-2015-2315-report.svg) ![forks](https://img.shields.io/github/forks/weidongl74/cve-2015-2315-report.svg)

## CVE-2015-2291
 (1) IQVW32.sys before 1.3.1.0 and (2) IQVW64.sys before 1.3.1.0 in the Intel Ethernet diagnostics driver for Windows allows local users to cause a denial of service or possibly execute arbitrary code with kernel privileges via a crafted (a) 0x80862013, (b) 0x8086200B, (c) 0x8086200F, or (d) 0x80862007 IOCTL call.



- [https://github.com/Tare05/Intel-CVE-2015-2291](https://github.com/Tare05/Intel-CVE-2015-2291) :  ![starts](https://img.shields.io/github/stars/Tare05/Intel-CVE-2015-2291.svg) ![forks](https://img.shields.io/github/forks/Tare05/Intel-CVE-2015-2291.svg)

- [https://github.com/gmh5225/CVE-2015-2291](https://github.com/gmh5225/CVE-2015-2291) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2015-2291.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2015-2291.svg)

## CVE-2015-2231
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/rednaga/adups-get-super-serial](https://github.com/rednaga/adups-get-super-serial) :  ![starts](https://img.shields.io/github/stars/rednaga/adups-get-super-serial.svg) ![forks](https://img.shields.io/github/forks/rednaga/adups-get-super-serial.svg)

## CVE-2015-2208
 The saveObject function in moadmin.php in phpMoAdmin 1.1.2 allows remote attackers to execute arbitrary commands via shell metacharacters in the object parameter.



- [https://github.com/ptantiku/cve-2015-2208](https://github.com/ptantiku/cve-2015-2208) :  ![starts](https://img.shields.io/github/stars/ptantiku/cve-2015-2208.svg) ![forks](https://img.shields.io/github/forks/ptantiku/cve-2015-2208.svg)

## CVE-2015-2166
 Directory traversal vulnerability in the Instance Monitor in Ericsson Drutt Mobile Service Delivery Platform (MSDP) 4, 5, and 6 allows remote attackers to read arbitrary files via a ..%2f (dot dot encoded slash) in the default URI.



- [https://github.com/K3ysTr0K3R/CVE-2015-2166-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2015-2166-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2015-2166-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2015-2166-EXPLOIT.svg)

## CVE-2015-2153
 The rpki_rtr_pdu_print function in print-rpki-rtr.c in the TCP printer in tcpdump before 4.7.2 allows remote attackers to cause a denial of service (out-of-bounds read or write and crash) via a crafted header length in an RPKI-RTR Protocol Data Unit (PDU).



- [https://github.com/arntsonl/CVE-2015-2153](https://github.com/arntsonl/CVE-2015-2153) :  ![starts](https://img.shields.io/github/stars/arntsonl/CVE-2015-2153.svg) ![forks](https://img.shields.io/github/forks/arntsonl/CVE-2015-2153.svg)

## CVE-2015-1986
 The server in IBM Tivoli Storage Manager FastBack 6.1 before 6.1.12 allows remote attackers to execute arbitrary commands via unspecified vectors, a different vulnerability than CVE-2015-1938.



- [https://github.com/MayaOfVeil/CVE-2015-1986](https://github.com/MayaOfVeil/CVE-2015-1986) :  ![starts](https://img.shields.io/github/stars/MayaOfVeil/CVE-2015-1986.svg) ![forks](https://img.shields.io/github/forks/MayaOfVeil/CVE-2015-1986.svg)

## CVE-2015-1855
 verify_certificate_identity in the OpenSSL extension in Ruby before 2.0.0 patchlevel 645, 2.1.x before 2.1.6, and 2.2.x before 2.2.2 does not properly validate hostnames, which allows remote attackers to spoof servers via vectors related to (1) multiple wildcards, (1) wildcards in IDNA names, (3) case sensitivity, and (4) non-ASCII characters.



- [https://github.com/vpereira/CVE-2015-1855](https://github.com/vpereira/CVE-2015-1855) :  ![starts](https://img.shields.io/github/stars/vpereira/CVE-2015-1855.svg) ![forks](https://img.shields.io/github/forks/vpereira/CVE-2015-1855.svg)

## CVE-2015-1805
 The (1) pipe_read and (2) pipe_write implementations in fs/pipe.c in the Linux kernel before 3.16 do not properly consider the side effects of failed __copy_to_user_inatomic and __copy_from_user_inatomic calls, which allows local users to cause a denial of service (system crash) or possibly gain privileges via a crafted application, aka an "I/O vector array overrun."



- [https://github.com/dosomder/iovyroot](https://github.com/dosomder/iovyroot) :  ![starts](https://img.shields.io/github/stars/dosomder/iovyroot.svg) ![forks](https://img.shields.io/github/forks/dosomder/iovyroot.svg)

- [https://github.com/idhyt/androotzf](https://github.com/idhyt/androotzf) :  ![starts](https://img.shields.io/github/stars/idhyt/androotzf.svg) ![forks](https://img.shields.io/github/forks/idhyt/androotzf.svg)

- [https://github.com/panyu6325/CVE-2015-1805](https://github.com/panyu6325/CVE-2015-1805) :  ![starts](https://img.shields.io/github/stars/panyu6325/CVE-2015-1805.svg) ![forks](https://img.shields.io/github/forks/panyu6325/CVE-2015-1805.svg)

- [https://github.com/FloatingGuy/cve-2015-1805](https://github.com/FloatingGuy/cve-2015-1805) :  ![starts](https://img.shields.io/github/stars/FloatingGuy/cve-2015-1805.svg) ![forks](https://img.shields.io/github/forks/FloatingGuy/cve-2015-1805.svg)

- [https://github.com/ireshchaminda1/Android-Privilege-Escalation-Remote-Access-Vulnerability-CVE-2015-1805](https://github.com/ireshchaminda1/Android-Privilege-Escalation-Remote-Access-Vulnerability-CVE-2015-1805) :  ![starts](https://img.shields.io/github/stars/ireshchaminda1/Android-Privilege-Escalation-Remote-Access-Vulnerability-CVE-2015-1805.svg) ![forks](https://img.shields.io/github/forks/ireshchaminda1/Android-Privilege-Escalation-Remote-Access-Vulnerability-CVE-2015-1805.svg)

- [https://github.com/mobilelinux/iovy_root_research](https://github.com/mobilelinux/iovy_root_research) :  ![starts](https://img.shields.io/github/stars/mobilelinux/iovy_root_research.svg) ![forks](https://img.shields.io/github/forks/mobilelinux/iovy_root_research.svg)

## CVE-2015-1792
 The do_free_upto function in crypto/cms/cms_smime.c in OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before 1.0.2b allows remote attackers to cause a denial of service (infinite loop) via vectors that trigger a NULL value of a BIO data structure, as demonstrated by an unrecognized X.660 OID for a hash function.



- [https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1792](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1792) :  ![starts](https://img.shields.io/github/stars/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1792.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1792.svg)

## CVE-2015-1791
 Race condition in the ssl3_get_new_session_ticket function in ssl/s3_clnt.c in OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before 1.0.2b, when used for a multi-threaded client, allows remote attackers to cause a denial of service (double free and application crash) or possibly have unspecified other impact by providing a NewSessionTicket during an attempt to reuse a ticket that had been obtained earlier.



- [https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1791](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1791) :  ![starts](https://img.shields.io/github/stars/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1791.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1791.svg)

## CVE-2015-1790
 The PKCS7_dataDecodefunction in crypto/pkcs7/pk7_doit.c in OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before 1.0.2b allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via a PKCS#7 blob that uses ASN.1 encoding and lacks inner EncryptedContent data.



- [https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1790](https://github.com/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1790) :  ![starts](https://img.shields.io/github/stars/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1790.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/OpenSSL-1_0_1g_CVE-2015-1790.svg)

## CVE-2015-1788
 The BN_GF2m_mod_inv function in crypto/bn/bn_gf2m.c in OpenSSL before 0.9.8s, 1.0.0 before 1.0.0e, 1.0.1 before 1.0.1n, and 1.0.2 before 1.0.2b does not properly handle ECParameters structures in which the curve is over a malformed binary polynomial field, which allows remote attackers to cause a denial of service (infinite loop) via a session that uses an Elliptic Curve algorithm, as demonstrated by an attack against a server that supports client authentication.



- [https://github.com/pazhanivel07/OpenSSL_1_0_1g_CVE-2015-1788](https://github.com/pazhanivel07/OpenSSL_1_0_1g_CVE-2015-1788) :  ![starts](https://img.shields.io/github/stars/pazhanivel07/OpenSSL_1_0_1g_CVE-2015-1788.svg) ![forks](https://img.shields.io/github/forks/pazhanivel07/OpenSSL_1_0_1g_CVE-2015-1788.svg)

## CVE-2015-1769
 Mount Manager in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT Gold and 8.1, and Windows 10 mishandles symlinks, which allows physically proximate attackers to execute arbitrary code by connecting a crafted USB device, aka "Mount Manager Elevation of Privilege Vulnerability."



- [https://github.com/int0/CVE-2015-1769](https://github.com/int0/CVE-2015-1769) :  ![starts](https://img.shields.io/github/stars/int0/CVE-2015-1769.svg) ![forks](https://img.shields.io/github/forks/int0/CVE-2015-1769.svg)

## CVE-2015-1701
 Win32k.sys in the kernel-mode drivers in Microsoft Windows Server 2003 SP2, Vista SP2, and Server 2008 SP2 allows local users to gain privileges via a crafted application, as exploited in the wild in April 2015, aka "Win32k Elevation of Privilege Vulnerability."



- [https://github.com/hfiref0x/CVE-2015-1701](https://github.com/hfiref0x/CVE-2015-1701) :  ![starts](https://img.shields.io/github/stars/hfiref0x/CVE-2015-1701.svg) ![forks](https://img.shields.io/github/forks/hfiref0x/CVE-2015-1701.svg)

- [https://github.com/Anonymous-Family/CVE-2015-1701](https://github.com/Anonymous-Family/CVE-2015-1701) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/CVE-2015-1701.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/CVE-2015-1701.svg)

- [https://github.com/Anonymous-Family/CVE-2015-1701-download](https://github.com/Anonymous-Family/CVE-2015-1701-download) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/CVE-2015-1701-download.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/CVE-2015-1701-download.svg)

- [https://github.com/chefphenix25/vuln-rabilit-windows7](https://github.com/chefphenix25/vuln-rabilit-windows7) :  ![starts](https://img.shields.io/github/stars/chefphenix25/vuln-rabilit-windows7.svg) ![forks](https://img.shields.io/github/forks/chefphenix25/vuln-rabilit-windows7.svg)

## CVE-2015-1641
 Microsoft Word 2007 SP3, Office 2010 SP2, Word 2010 SP2, Word 2013 SP1, Word 2013 RT SP1, Word for Mac 2011, Office Compatibility Pack SP3, Word Automation Services on SharePoint Server 2010 SP2 and 2013 SP1, and Office Web Apps Server 2010 SP2 and 2013 SP1 allow remote attackers to execute arbitrary code via a crafted RTF document, aka "Microsoft Office Memory Corruption Vulnerability."



- [https://github.com/Cyberclues/rtf_exploit_extractor](https://github.com/Cyberclues/rtf_exploit_extractor) :  ![starts](https://img.shields.io/github/stars/Cyberclues/rtf_exploit_extractor.svg) ![forks](https://img.shields.io/github/forks/Cyberclues/rtf_exploit_extractor.svg)

## CVE-2015-1635
 HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka "HTTP.sys Remote Code Execution Vulnerability."



- [https://github.com/xPaw/HTTPsys](https://github.com/xPaw/HTTPsys) :  ![starts](https://img.shields.io/github/stars/xPaw/HTTPsys.svg) ![forks](https://img.shields.io/github/forks/xPaw/HTTPsys.svg)

- [https://github.com/technion/erlvulnscan](https://github.com/technion/erlvulnscan) :  ![starts](https://img.shields.io/github/stars/technion/erlvulnscan.svg) ![forks](https://img.shields.io/github/forks/technion/erlvulnscan.svg)

- [https://github.com/aedoo/CVE-2015-1635-POC](https://github.com/aedoo/CVE-2015-1635-POC) :  ![starts](https://img.shields.io/github/stars/aedoo/CVE-2015-1635-POC.svg) ![forks](https://img.shields.io/github/forks/aedoo/CVE-2015-1635-POC.svg)

- [https://github.com/Zx7ffa4512-Python/Project-CVE-2015-1635](https://github.com/Zx7ffa4512-Python/Project-CVE-2015-1635) :  ![starts](https://img.shields.io/github/stars/Zx7ffa4512-Python/Project-CVE-2015-1635.svg) ![forks](https://img.shields.io/github/forks/Zx7ffa4512-Python/Project-CVE-2015-1635.svg)

- [https://github.com/h3x0v3rl0rd/CVE-2015-1635-POC](https://github.com/h3x0v3rl0rd/CVE-2015-1635-POC) :  ![starts](https://img.shields.io/github/stars/h3x0v3rl0rd/CVE-2015-1635-POC.svg) ![forks](https://img.shields.io/github/forks/h3x0v3rl0rd/CVE-2015-1635-POC.svg)

- [https://github.com/neu5ron/cve_2015-1635](https://github.com/neu5ron/cve_2015-1635) :  ![starts](https://img.shields.io/github/stars/neu5ron/cve_2015-1635.svg) ![forks](https://img.shields.io/github/forks/neu5ron/cve_2015-1635.svg)

- [https://github.com/bongbongco/MS15-034](https://github.com/bongbongco/MS15-034) :  ![starts](https://img.shields.io/github/stars/bongbongco/MS15-034.svg) ![forks](https://img.shields.io/github/forks/bongbongco/MS15-034.svg)

- [https://github.com/Cappricio-Securities/CVE-2015-1635](https://github.com/Cappricio-Securities/CVE-2015-1635) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2015-1635.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2015-1635.svg)

- [https://github.com/w01ke/CVE-2015-1635-POC](https://github.com/w01ke/CVE-2015-1635-POC) :  ![starts](https://img.shields.io/github/stars/w01ke/CVE-2015-1635-POC.svg) ![forks](https://img.shields.io/github/forks/w01ke/CVE-2015-1635-POC.svg)

- [https://github.com/u0pattern/Remove-IIS-RIIS](https://github.com/u0pattern/Remove-IIS-RIIS) :  ![starts](https://img.shields.io/github/stars/u0pattern/Remove-IIS-RIIS.svg) ![forks](https://img.shields.io/github/forks/u0pattern/Remove-IIS-RIIS.svg)

- [https://github.com/h3x0v3rl0rd/CVE-2015-1635](https://github.com/h3x0v3rl0rd/CVE-2015-1635) :  ![starts](https://img.shields.io/github/stars/h3x0v3rl0rd/CVE-2015-1635.svg) ![forks](https://img.shields.io/github/forks/h3x0v3rl0rd/CVE-2015-1635.svg)

- [https://github.com/moeinmiadi/CVE-2015-1635_PoC](https://github.com/moeinmiadi/CVE-2015-1635_PoC) :  ![starts](https://img.shields.io/github/stars/moeinmiadi/CVE-2015-1635_PoC.svg) ![forks](https://img.shields.io/github/forks/moeinmiadi/CVE-2015-1635_PoC.svg)

- [https://github.com/SkinAir/ms15-034-Scan](https://github.com/SkinAir/ms15-034-Scan) :  ![starts](https://img.shields.io/github/stars/SkinAir/ms15-034-Scan.svg) ![forks](https://img.shields.io/github/forks/SkinAir/ms15-034-Scan.svg)

- [https://github.com/wiredaem0n/chk-ms15-034](https://github.com/wiredaem0n/chk-ms15-034) :  ![starts](https://img.shields.io/github/stars/wiredaem0n/chk-ms15-034.svg) ![forks](https://img.shields.io/github/forks/wiredaem0n/chk-ms15-034.svg)

## CVE-2015-1592
 Movable Type Pro, Open Source, and Advanced before 5.2.12 and Pro and Advanced 6.0.x before 6.0.7 does not properly use the Perl Storable::thaw function, which allows remote attackers to include and execute arbitrary local Perl files and possibly execute arbitrary code via unspecified vectors.



- [https://github.com/lightsey/cve-2015-1592](https://github.com/lightsey/cve-2015-1592) :  ![starts](https://img.shields.io/github/stars/lightsey/cve-2015-1592.svg) ![forks](https://img.shields.io/github/forks/lightsey/cve-2015-1592.svg)

## CVE-2015-1579
 Directory traversal vulnerability in the Elegant Themes Divi theme for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the img parameter in a revslider_show_image action to wp-admin/admin-ajax.php.  NOTE: this vulnerability may be a duplicate of CVE-2014-9734.



- [https://github.com/paralelo14/WordPressMassExploiter](https://github.com/paralelo14/WordPressMassExploiter) :  ![starts](https://img.shields.io/github/stars/paralelo14/WordPressMassExploiter.svg) ![forks](https://img.shields.io/github/forks/paralelo14/WordPressMassExploiter.svg)

- [https://github.com/paralelo14/CVE-2015-1579](https://github.com/paralelo14/CVE-2015-1579) :  ![starts](https://img.shields.io/github/stars/paralelo14/CVE-2015-1579.svg) ![forks](https://img.shields.io/github/forks/paralelo14/CVE-2015-1579.svg)

## CVE-2015-1578
 Multiple open redirect vulnerabilities in u5CMS before 3.9.4 allow remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the (1) pidvesa cookie to u5admin/pidvesa.php or (2) uri parameter to u5admin/meta2.php.



- [https://github.com/Zeppperoni/CVE-2015-1578](https://github.com/Zeppperoni/CVE-2015-1578) :  ![starts](https://img.shields.io/github/stars/Zeppperoni/CVE-2015-1578.svg) ![forks](https://img.shields.io/github/forks/Zeppperoni/CVE-2015-1578.svg)

- [https://github.com/yaldobaoth/CVE-2015-1578-PoC](https://github.com/yaldobaoth/CVE-2015-1578-PoC) :  ![starts](https://img.shields.io/github/stars/yaldobaoth/CVE-2015-1578-PoC.svg) ![forks](https://img.shields.io/github/forks/yaldobaoth/CVE-2015-1578-PoC.svg)

- [https://github.com/yaldobaoth/CVE-2015-1578-PoC-Metasploit](https://github.com/yaldobaoth/CVE-2015-1578-PoC-Metasploit) :  ![starts](https://img.shields.io/github/stars/yaldobaoth/CVE-2015-1578-PoC-Metasploit.svg) ![forks](https://img.shields.io/github/forks/yaldobaoth/CVE-2015-1578-PoC-Metasploit.svg)

## CVE-2015-1561
 The escape_command function in include/Administration/corePerformance/getStats.php in Centreon (formerly Merethis Centreon) 2.5.4 and earlier (fixed in Centreon 19.10.0) uses an incorrect regular expression, which allows remote authenticated users to execute arbitrary commands via shell metacharacters in the ns_id parameter.



- [https://github.com/Iansus/Centreon-CVE-2015-1560_1561](https://github.com/Iansus/Centreon-CVE-2015-1560_1561) :  ![starts](https://img.shields.io/github/stars/Iansus/Centreon-CVE-2015-1560_1561.svg) ![forks](https://img.shields.io/github/forks/Iansus/Centreon-CVE-2015-1560_1561.svg)

## CVE-2015-1560
 SQL injection vulnerability in the isUserAdmin function in include/common/common-Func.php in Centreon (formerly Merethis Centreon) 2.5.4 and earlier (fixed in Centreon web 2.7.0) allows remote attackers to execute arbitrary SQL commands via the sid parameter to include/common/XmlTree/GetXmlTree.php.



- [https://github.com/Iansus/Centreon-CVE-2015-1560_1561](https://github.com/Iansus/Centreon-CVE-2015-1560_1561) :  ![starts](https://img.shields.io/github/stars/Iansus/Centreon-CVE-2015-1560_1561.svg) ![forks](https://img.shields.io/github/forks/Iansus/Centreon-CVE-2015-1560_1561.svg)

## CVE-2015-1538
 Integer overflow in the SampleTable::setSampleToChunkParams function in SampleTable.cpp in libstagefright in Android before 5.1.1 LMY48I allows remote attackers to execute arbitrary code via crafted atoms in MP4 data that trigger an unchecked multiplication, aka internal bug 20139950, a related issue to CVE-2015-4496.



- [https://github.com/jduck/cve-2015-1538-1](https://github.com/jduck/cve-2015-1538-1) :  ![starts](https://img.shields.io/github/stars/jduck/cve-2015-1538-1.svg) ![forks](https://img.shields.io/github/forks/jduck/cve-2015-1538-1.svg)

- [https://github.com/oguzhantopgul/cve-2015-1538-1](https://github.com/oguzhantopgul/cve-2015-1538-1) :  ![starts](https://img.shields.io/github/stars/oguzhantopgul/cve-2015-1538-1.svg) ![forks](https://img.shields.io/github/forks/oguzhantopgul/cve-2015-1538-1.svg)

- [https://github.com/Tharana/vulnerability-exploitation](https://github.com/Tharana/vulnerability-exploitation) :  ![starts](https://img.shields.io/github/stars/Tharana/vulnerability-exploitation.svg) ![forks](https://img.shields.io/github/forks/Tharana/vulnerability-exploitation.svg)

- [https://github.com/renjithsasidharan/cve-2015-1538-1](https://github.com/renjithsasidharan/cve-2015-1538-1) :  ![starts](https://img.shields.io/github/stars/renjithsasidharan/cve-2015-1538-1.svg) ![forks](https://img.shields.io/github/forks/renjithsasidharan/cve-2015-1538-1.svg)

- [https://github.com/Tharana/Android-vulnerability-exploitation](https://github.com/Tharana/Android-vulnerability-exploitation) :  ![starts](https://img.shields.io/github/stars/Tharana/Android-vulnerability-exploitation.svg) ![forks](https://img.shields.io/github/forks/Tharana/Android-vulnerability-exploitation.svg)

- [https://github.com/niranjanshr13/Stagefright-cve-2015-1538-1](https://github.com/niranjanshr13/Stagefright-cve-2015-1538-1) :  ![starts](https://img.shields.io/github/stars/niranjanshr13/Stagefright-cve-2015-1538-1.svg) ![forks](https://img.shields.io/github/forks/niranjanshr13/Stagefright-cve-2015-1538-1.svg)

## CVE-2015-1528
 Integer overflow in the native_handle_create function in libcutils/native_handle.c in Android before 5.1.1 LMY48M allows attackers to obtain a different application's privileges or cause a denial of service (Binder heap memory corruption) via a crafted application, aka internal bug 19334482.



- [https://github.com/secmob/PoCForCVE-2015-1528](https://github.com/secmob/PoCForCVE-2015-1528) :  ![starts](https://img.shields.io/github/stars/secmob/PoCForCVE-2015-1528.svg) ![forks](https://img.shields.io/github/forks/secmob/PoCForCVE-2015-1528.svg)

- [https://github.com/kanpol/PoCForCVE-2015-1528](https://github.com/kanpol/PoCForCVE-2015-1528) :  ![starts](https://img.shields.io/github/stars/kanpol/PoCForCVE-2015-1528.svg) ![forks](https://img.shields.io/github/forks/kanpol/PoCForCVE-2015-1528.svg)

## CVE-2015-1474
 Multiple integer overflows in the GraphicBuffer::unflatten function in platform/frameworks/native/libs/ui/GraphicBuffer.cpp in Android through 5.0 allow attackers to gain privileges or cause a denial of service (memory corruption) via vectors that trigger a large number of (1) file descriptors or (2) integer values.



- [https://github.com/p1gl3t/CVE-2015-1474_poc](https://github.com/p1gl3t/CVE-2015-1474_poc) :  ![starts](https://img.shields.io/github/stars/p1gl3t/CVE-2015-1474_poc.svg) ![forks](https://img.shields.io/github/forks/p1gl3t/CVE-2015-1474_poc.svg)

## CVE-2015-1427
 The Groovy scripting engine in Elasticsearch before 1.3.8 and 1.4.x before 1.4.3 allows remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands via a crafted script.



- [https://github.com/t0kx/exploit-CVE-2015-1427](https://github.com/t0kx/exploit-CVE-2015-1427) :  ![starts](https://img.shields.io/github/stars/t0kx/exploit-CVE-2015-1427.svg) ![forks](https://img.shields.io/github/forks/t0kx/exploit-CVE-2015-1427.svg)

- [https://github.com/cved-sources/cve-2015-1427](https://github.com/cved-sources/cve-2015-1427) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2015-1427.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2015-1427.svg)

- [https://github.com/h3inzzz/cve2015_1427](https://github.com/h3inzzz/cve2015_1427) :  ![starts](https://img.shields.io/github/stars/h3inzzz/cve2015_1427.svg) ![forks](https://img.shields.io/github/forks/h3inzzz/cve2015_1427.svg)

- [https://github.com/xpgdgit/CVE-2015-1427](https://github.com/xpgdgit/CVE-2015-1427) :  ![starts](https://img.shields.io/github/stars/xpgdgit/CVE-2015-1427.svg) ![forks](https://img.shields.io/github/forks/xpgdgit/CVE-2015-1427.svg)

- [https://github.com/Sebikea/CVE-2015-1427-for-trixie](https://github.com/Sebikea/CVE-2015-1427-for-trixie) :  ![starts](https://img.shields.io/github/stars/Sebikea/CVE-2015-1427-for-trixie.svg) ![forks](https://img.shields.io/github/forks/Sebikea/CVE-2015-1427-for-trixie.svg)

- [https://github.com/cyberharsh/Groovy-scripting-engine-CVE-2015-1427](https://github.com/cyberharsh/Groovy-scripting-engine-CVE-2015-1427) :  ![starts](https://img.shields.io/github/stars/cyberharsh/Groovy-scripting-engine-CVE-2015-1427.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/Groovy-scripting-engine-CVE-2015-1427.svg)

## CVE-2015-1397
 SQL injection vulnerability in the getCsvFile function in the Mage_Adminhtml_Block_Widget_Grid class in Magento Community Edition (CE) 1.9.1.0 and Enterprise Edition (EE) 1.14.1.0 allows remote administrators to execute arbitrary SQL commands via the popularity[field_expr] parameter when the popularity[from] or popularity[to] parameter is set.



- [https://github.com/47Cid/Magento-Shoplift-SQLI](https://github.com/47Cid/Magento-Shoplift-SQLI) :  ![starts](https://img.shields.io/github/stars/47Cid/Magento-Shoplift-SQLI.svg) ![forks](https://img.shields.io/github/forks/47Cid/Magento-Shoplift-SQLI.svg)

- [https://github.com/tmatejicek/CVE-2015-1397](https://github.com/tmatejicek/CVE-2015-1397) :  ![starts](https://img.shields.io/github/stars/tmatejicek/CVE-2015-1397.svg) ![forks](https://img.shields.io/github/forks/tmatejicek/CVE-2015-1397.svg)

- [https://github.com/WHOISshuvam/CVE-2015-1397](https://github.com/WHOISshuvam/CVE-2015-1397) :  ![starts](https://img.shields.io/github/stars/WHOISshuvam/CVE-2015-1397.svg) ![forks](https://img.shields.io/github/forks/WHOISshuvam/CVE-2015-1397.svg)

- [https://github.com/Wytchwulf/CVE-2015-1397-Magento-Shoplift](https://github.com/Wytchwulf/CVE-2015-1397-Magento-Shoplift) :  ![starts](https://img.shields.io/github/stars/Wytchwulf/CVE-2015-1397-Magento-Shoplift.svg) ![forks](https://img.shields.io/github/forks/Wytchwulf/CVE-2015-1397-Magento-Shoplift.svg)

- [https://github.com/0xDTC/Magento-eCommerce-RCE-CVE-2015-1397](https://github.com/0xDTC/Magento-eCommerce-RCE-CVE-2015-1397) :  ![starts](https://img.shields.io/github/stars/0xDTC/Magento-eCommerce-RCE-CVE-2015-1397.svg) ![forks](https://img.shields.io/github/forks/0xDTC/Magento-eCommerce-RCE-CVE-2015-1397.svg)

## CVE-2015-1328
 The overlayfs implementation in the linux (aka Linux kernel) package before 3.19.0-21.21 in Ubuntu through 15.04 does not properly check permissions for file creation in the upper filesystem directory, which allows local users to obtain root access by leveraging a configuration in which overlayfs is permitted in an arbitrary mount namespace.



- [https://github.com/elit3pwner/CVE-2015-1328-GoldenEye](https://github.com/elit3pwner/CVE-2015-1328-GoldenEye) :  ![starts](https://img.shields.io/github/stars/elit3pwner/CVE-2015-1328-GoldenEye.svg) ![forks](https://img.shields.io/github/forks/elit3pwner/CVE-2015-1328-GoldenEye.svg)

- [https://github.com/notlikethis/CVE-2015-1328](https://github.com/notlikethis/CVE-2015-1328) :  ![starts](https://img.shields.io/github/stars/notlikethis/CVE-2015-1328.svg) ![forks](https://img.shields.io/github/forks/notlikethis/CVE-2015-1328.svg)

- [https://github.com/YastrebX/CVE-2015-1328](https://github.com/YastrebX/CVE-2015-1328) :  ![starts](https://img.shields.io/github/stars/YastrebX/CVE-2015-1328.svg) ![forks](https://img.shields.io/github/forks/YastrebX/CVE-2015-1328.svg)

- [https://github.com/0xf1d0/CVE-2015-1328](https://github.com/0xf1d0/CVE-2015-1328) :  ![starts](https://img.shields.io/github/stars/0xf1d0/CVE-2015-1328.svg) ![forks](https://img.shields.io/github/forks/0xf1d0/CVE-2015-1328.svg)

- [https://github.com/BlackFrog-hub/cve-2015-1328](https://github.com/BlackFrog-hub/cve-2015-1328) :  ![starts](https://img.shields.io/github/stars/BlackFrog-hub/cve-2015-1328.svg) ![forks](https://img.shields.io/github/forks/BlackFrog-hub/cve-2015-1328.svg)

- [https://github.com/1mgR00T/CVE-2015-1328](https://github.com/1mgR00T/CVE-2015-1328) :  ![starts](https://img.shields.io/github/stars/1mgR00T/CVE-2015-1328.svg) ![forks](https://img.shields.io/github/forks/1mgR00T/CVE-2015-1328.svg)

- [https://github.com/SR7-HACKING/LINUX-VULNERABILITY-CVE-2015-1328](https://github.com/SR7-HACKING/LINUX-VULNERABILITY-CVE-2015-1328) :  ![starts](https://img.shields.io/github/stars/SR7-HACKING/LINUX-VULNERABILITY-CVE-2015-1328.svg) ![forks](https://img.shields.io/github/forks/SR7-HACKING/LINUX-VULNERABILITY-CVE-2015-1328.svg)

- [https://github.com/thieveshkar/RootQuest-CTF-Box-Multi-Stage-Exploitation-VM](https://github.com/thieveshkar/RootQuest-CTF-Box-Multi-Stage-Exploitation-VM) :  ![starts](https://img.shields.io/github/stars/thieveshkar/RootQuest-CTF-Box-Multi-Stage-Exploitation-VM.svg) ![forks](https://img.shields.io/github/forks/thieveshkar/RootQuest-CTF-Box-Multi-Stage-Exploitation-VM.svg)

## CVE-2015-1318
 The crash reporting feature in Apport 2.13 through 2.17.x before 2.17.1 allows local users to gain privileges via a crafted usr/share/apport/apport file in a namespace (container).



- [https://github.com/ScottyBauer/CVE-2015-1318](https://github.com/ScottyBauer/CVE-2015-1318) :  ![starts](https://img.shields.io/github/stars/ScottyBauer/CVE-2015-1318.svg) ![forks](https://img.shields.io/github/forks/ScottyBauer/CVE-2015-1318.svg)

## CVE-2015-1157
 CoreText in Apple iOS 8.x through 8.3 allows remote attackers to cause a denial of service (reboot and messaging disruption) via crafted Unicode text that is not properly handled during display truncation in the Notifications feature, as demonstrated by Arabic characters in (1) an SMS message or (2) a WhatsApp message.



- [https://github.com/perillamint/CVE-2015-1157](https://github.com/perillamint/CVE-2015-1157) :  ![starts](https://img.shields.io/github/stars/perillamint/CVE-2015-1157.svg) ![forks](https://img.shields.io/github/forks/perillamint/CVE-2015-1157.svg)

## CVE-2015-1140
 Buffer overflow in IOHIDFamily in Apple OS X before 10.10.3 allows local users to gain privileges via unspecified vectors.



- [https://github.com/kpwn/vpwn](https://github.com/kpwn/vpwn) :  ![starts](https://img.shields.io/github/stars/kpwn/vpwn.svg) ![forks](https://img.shields.io/github/forks/kpwn/vpwn.svg)

## CVE-2015-1130
 The XPC implementation in Admin Framework in Apple OS X before 10.10.3 allows local users to bypass authentication and obtain admin privileges via unspecified vectors.



- [https://github.com/sideeffect42/RootPipeTester](https://github.com/sideeffect42/RootPipeTester) :  ![starts](https://img.shields.io/github/stars/sideeffect42/RootPipeTester.svg) ![forks](https://img.shields.io/github/forks/sideeffect42/RootPipeTester.svg)

- [https://github.com/Shmoopi/RootPipe-Demo](https://github.com/Shmoopi/RootPipe-Demo) :  ![starts](https://img.shields.io/github/stars/Shmoopi/RootPipe-Demo.svg) ![forks](https://img.shields.io/github/forks/Shmoopi/RootPipe-Demo.svg)

## CVE-2015-0568
 Use-after-free vulnerability in the msm_set_crop function in drivers/media/video/msm/msm_camera.c in the MSM-Camera driver for the Linux kernel 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, allows attackers to gain privileges or cause a denial of service (memory corruption) via an application that makes a crafted ioctl call.



- [https://github.com/betalphafai/CVE-2015-0568](https://github.com/betalphafai/CVE-2015-0568) :  ![starts](https://img.shields.io/github/stars/betalphafai/CVE-2015-0568.svg) ![forks](https://img.shields.io/github/forks/betalphafai/CVE-2015-0568.svg)

## CVE-2015-0345
 Cross-site scripting (XSS) vulnerability in Adobe ColdFusion 10 before Update 16 and 11 before Update 5 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.



- [https://github.com/BishopFox/coldfusion-10-11-xss](https://github.com/BishopFox/coldfusion-10-11-xss) :  ![starts](https://img.shields.io/github/stars/BishopFox/coldfusion-10-11-xss.svg) ![forks](https://img.shields.io/github/forks/BishopFox/coldfusion-10-11-xss.svg)

## CVE-2015-0313
 Use-after-free vulnerability in Adobe Flash Player before 13.0.0.269 and 14.x through 16.x before 16.0.0.305 on Windows and OS X and before 11.2.202.442 on Linux allows remote attackers to execute arbitrary code via unspecified vectors, as exploited in the wild in February 2015, a different vulnerability than CVE-2015-0315, CVE-2015-0320, and CVE-2015-0322.



- [https://github.com/SecurityObscurity/cve-2015-0313](https://github.com/SecurityObscurity/cve-2015-0313) :  ![starts](https://img.shields.io/github/stars/SecurityObscurity/cve-2015-0313.svg) ![forks](https://img.shields.io/github/forks/SecurityObscurity/cve-2015-0313.svg)

## CVE-2015-0311
 Unspecified vulnerability in Adobe Flash Player through 13.0.0.262 and 14.x, 15.x, and 16.x through 16.0.0.287 on Windows and OS X and through 11.2.202.438 on Linux allows remote attackers to execute arbitrary code via unknown vectors, as exploited in the wild in January 2015.



- [https://github.com/jr64/CVE-2015-0311](https://github.com/jr64/CVE-2015-0311) :  ![starts](https://img.shields.io/github/stars/jr64/CVE-2015-0311.svg) ![forks](https://img.shields.io/github/forks/jr64/CVE-2015-0311.svg)

## CVE-2015-0235
 Heap-based buffer overflow in the __nss_hostname_digits_dots function in glibc 2.2, and other 2.x versions before 2.18, allows context-dependent attackers to execute arbitrary code via vectors related to the (1) gethostbyname or (2) gethostbyname2 function, aka "GHOST."



- [https://github.com/aaronfay/CVE-2015-0235-test](https://github.com/aaronfay/CVE-2015-0235-test) :  ![starts](https://img.shields.io/github/stars/aaronfay/CVE-2015-0235-test.svg) ![forks](https://img.shields.io/github/forks/aaronfay/CVE-2015-0235-test.svg)

- [https://github.com/makelinux/CVE-2015-0235-workaround](https://github.com/makelinux/CVE-2015-0235-workaround) :  ![starts](https://img.shields.io/github/stars/makelinux/CVE-2015-0235-workaround.svg) ![forks](https://img.shields.io/github/forks/makelinux/CVE-2015-0235-workaround.svg)

- [https://github.com/fser/ghost-checker](https://github.com/fser/ghost-checker) :  ![starts](https://img.shields.io/github/stars/fser/ghost-checker.svg) ![forks](https://img.shields.io/github/forks/fser/ghost-checker.svg)

- [https://github.com/arm13/ghost_exploit](https://github.com/arm13/ghost_exploit) :  ![starts](https://img.shields.io/github/stars/arm13/ghost_exploit.svg) ![forks](https://img.shields.io/github/forks/arm13/ghost_exploit.svg)

- [https://github.com/gh-ost00/XMLRPC-Ghost](https://github.com/gh-ost00/XMLRPC-Ghost) :  ![starts](https://img.shields.io/github/stars/gh-ost00/XMLRPC-Ghost.svg) ![forks](https://img.shields.io/github/forks/gh-ost00/XMLRPC-Ghost.svg)

- [https://github.com/mikesplain/CVE-2015-0235-cookbook](https://github.com/mikesplain/CVE-2015-0235-cookbook) :  ![starts](https://img.shields.io/github/stars/mikesplain/CVE-2015-0235-cookbook.svg) ![forks](https://img.shields.io/github/forks/mikesplain/CVE-2015-0235-cookbook.svg)

- [https://github.com/nickanderson/cfengine-CVE_2015_0235](https://github.com/nickanderson/cfengine-CVE_2015_0235) :  ![starts](https://img.shields.io/github/stars/nickanderson/cfengine-CVE_2015_0235.svg) ![forks](https://img.shields.io/github/forks/nickanderson/cfengine-CVE_2015_0235.svg)

- [https://github.com/furyutei/CVE-2015-0235_GHOST](https://github.com/furyutei/CVE-2015-0235_GHOST) :  ![starts](https://img.shields.io/github/stars/furyutei/CVE-2015-0235_GHOST.svg) ![forks](https://img.shields.io/github/forks/furyutei/CVE-2015-0235_GHOST.svg)

- [https://github.com/adherzog/ansible-CVE-2015-0235-GHOST](https://github.com/adherzog/ansible-CVE-2015-0235-GHOST) :  ![starts](https://img.shields.io/github/stars/adherzog/ansible-CVE-2015-0235-GHOST.svg) ![forks](https://img.shields.io/github/forks/adherzog/ansible-CVE-2015-0235-GHOST.svg)

- [https://github.com/sUbc0ol/CVE-2015-0235](https://github.com/sUbc0ol/CVE-2015-0235) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/CVE-2015-0235.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/CVE-2015-0235.svg)

- [https://github.com/alanmeyer/CVE-glibc](https://github.com/alanmeyer/CVE-glibc) :  ![starts](https://img.shields.io/github/stars/alanmeyer/CVE-glibc.svg) ![forks](https://img.shields.io/github/forks/alanmeyer/CVE-glibc.svg)

- [https://github.com/tobyzxj/CVE-2015-0235](https://github.com/tobyzxj/CVE-2015-0235) :  ![starts](https://img.shields.io/github/stars/tobyzxj/CVE-2015-0235.svg) ![forks](https://img.shields.io/github/forks/tobyzxj/CVE-2015-0235.svg)

- [https://github.com/chayim/GHOSTCHECK-cve-2015-0235](https://github.com/chayim/GHOSTCHECK-cve-2015-0235) :  ![starts](https://img.shields.io/github/stars/chayim/GHOSTCHECK-cve-2015-0235.svg) ![forks](https://img.shields.io/github/forks/chayim/GHOSTCHECK-cve-2015-0235.svg)

- [https://github.com/koudaiii-archives/cookbook-update-glibc](https://github.com/koudaiii-archives/cookbook-update-glibc) :  ![starts](https://img.shields.io/github/stars/koudaiii-archives/cookbook-update-glibc.svg) ![forks](https://img.shields.io/github/forks/koudaiii-archives/cookbook-update-glibc.svg)

- [https://github.com/1and1-serversupport/ghosttester](https://github.com/1and1-serversupport/ghosttester) :  ![starts](https://img.shields.io/github/stars/1and1-serversupport/ghosttester.svg) ![forks](https://img.shields.io/github/forks/1and1-serversupport/ghosttester.svg)

- [https://github.com/favoretti/lenny-libc6](https://github.com/favoretti/lenny-libc6) :  ![starts](https://img.shields.io/github/stars/favoretti/lenny-libc6.svg) ![forks](https://img.shields.io/github/forks/favoretti/lenny-libc6.svg)

- [https://github.com/F88/ghostbusters15](https://github.com/F88/ghostbusters15) :  ![starts](https://img.shields.io/github/stars/F88/ghostbusters15.svg) ![forks](https://img.shields.io/github/forks/F88/ghostbusters15.svg)

## CVE-2015-0231
 Use-after-free vulnerability in the process_nested_data function in ext/standard/var_unserializer.re in PHP before 5.4.37, 5.5.x before 5.5.21, and 5.6.x before 5.6.5 allows remote attackers to execute arbitrary code via a crafted unserialize call that leverages improper handling of duplicate numerical keys within the serialized properties of an object.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-8142.



- [https://github.com/3xp10it/php_cve-2014-8142_cve-2015-0231](https://github.com/3xp10it/php_cve-2014-8142_cve-2015-0231) :  ![starts](https://img.shields.io/github/stars/3xp10it/php_cve-2014-8142_cve-2015-0231.svg) ![forks](https://img.shields.io/github/forks/3xp10it/php_cve-2014-8142_cve-2015-0231.svg)

## CVE-2015-0205
 The ssl3_get_cert_verify function in s3_srvr.c in OpenSSL 1.0.0 before 1.0.0p and 1.0.1 before 1.0.1k accepts client authentication with a Diffie-Hellman (DH) certificate without requiring a CertificateVerify message, which allows remote attackers to obtain access without knowledge of a private key via crafted TLS Handshake Protocol traffic to a server that recognizes a Certification Authority with DH support.



- [https://github.com/saurabh2088/OpenSSL_1_0_1g_CVE-2015-0205](https://github.com/saurabh2088/OpenSSL_1_0_1g_CVE-2015-0205) :  ![starts](https://img.shields.io/github/stars/saurabh2088/OpenSSL_1_0_1g_CVE-2015-0205.svg) ![forks](https://img.shields.io/github/forks/saurabh2088/OpenSSL_1_0_1g_CVE-2015-0205.svg)

## CVE-2015-0204
 The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote SSL servers to conduct RSA-to-EXPORT_RSA downgrade attacks and facilitate brute-force decryption by offering a weak ephemeral RSA key in a noncompliant role, related to the "FREAK" issue.  NOTE: the scope of this CVE is only client code based on OpenSSL, not EXPORT_RSA issues associated with servers or other TLS implementations.



- [https://github.com/AbhishekGhosh/FREAK-Attack-CVE-2015-0204-Testing-Script](https://github.com/AbhishekGhosh/FREAK-Attack-CVE-2015-0204-Testing-Script) :  ![starts](https://img.shields.io/github/stars/AbhishekGhosh/FREAK-Attack-CVE-2015-0204-Testing-Script.svg) ![forks](https://img.shields.io/github/forks/AbhishekGhosh/FREAK-Attack-CVE-2015-0204-Testing-Script.svg)

- [https://github.com/anthophilee/A2SV--SSL-VUL-Scan](https://github.com/anthophilee/A2SV--SSL-VUL-Scan) :  ![starts](https://img.shields.io/github/stars/anthophilee/A2SV--SSL-VUL-Scan.svg) ![forks](https://img.shields.io/github/forks/anthophilee/A2SV--SSL-VUL-Scan.svg)

- [https://github.com/scottjpack/Freak-Scanner](https://github.com/scottjpack/Freak-Scanner) :  ![starts](https://img.shields.io/github/stars/scottjpack/Freak-Scanner.svg) ![forks](https://img.shields.io/github/forks/scottjpack/Freak-Scanner.svg)

- [https://github.com/felmoltor/FreakVulnChecker](https://github.com/felmoltor/FreakVulnChecker) :  ![starts](https://img.shields.io/github/stars/felmoltor/FreakVulnChecker.svg) ![forks](https://img.shields.io/github/forks/felmoltor/FreakVulnChecker.svg)

- [https://github.com/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204](https://github.com/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204) :  ![starts](https://img.shields.io/github/stars/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204.svg) ![forks](https://img.shields.io/github/forks/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204.svg)

## CVE-2015-0072
 Cross-site scripting (XSS) vulnerability in Microsoft Internet Explorer 9 through 11 allows remote attackers to bypass the Same Origin Policy and inject arbitrary web script or HTML via vectors involving an IFRAME element that triggers a redirect, a second IFRAME element that does not trigger a redirect, and an eval of a WindowProxy object, aka "Universal XSS (UXSS)."



- [https://github.com/dbellavista/uxss-poc](https://github.com/dbellavista/uxss-poc) :  ![starts](https://img.shields.io/github/stars/dbellavista/uxss-poc.svg) ![forks](https://img.shields.io/github/forks/dbellavista/uxss-poc.svg)

## CVE-2015-0057
 win32k.sys in the kernel-mode drivers in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allows local users to gain privileges via a crafted application, aka "Win32k Elevation of Privilege Vulnerability."



- [https://github.com/highandhigh/CVE-2015-0057](https://github.com/highandhigh/CVE-2015-0057) :  ![starts](https://img.shields.io/github/stars/highandhigh/CVE-2015-0057.svg) ![forks](https://img.shields.io/github/forks/highandhigh/CVE-2015-0057.svg)

## CVE-2015-0009
 The Group Policy Security Configuration policy implementation in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allows man-in-the-middle attackers to disable a signing requirement and trigger a revert-to-default action by spoofing domain-controller responses, aka "Group Policy Security Feature Bypass Vulnerability."



- [https://github.com/PhoenixC46/ExploitPOC_MS15-014_CVE-2015-0009](https://github.com/PhoenixC46/ExploitPOC_MS15-014_CVE-2015-0009) :  ![starts](https://img.shields.io/github/stars/PhoenixC46/ExploitPOC_MS15-014_CVE-2015-0009.svg) ![forks](https://img.shields.io/github/forks/PhoenixC46/ExploitPOC_MS15-014_CVE-2015-0009.svg)

## CVE-2015-0006
 The Network Location Awareness (NLA) service in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 does not perform mutual authentication to determine a domain connection, which allows remote attackers to trigger an unintended permissive configuration by spoofing DNS and LDAP responses on a local network, aka "NLA Security Feature Bypass Vulnerability."



- [https://github.com/bugch3ck/imposter](https://github.com/bugch3ck/imposter) :  ![starts](https://img.shields.io/github/stars/bugch3ck/imposter.svg) ![forks](https://img.shields.io/github/forks/bugch3ck/imposter.svg)
