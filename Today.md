# Update 2022-03-21
## CVE-2022-24126
 A buffer overflow in the NRSessionSearchResult parser in Bandai Namco FromSoftware Dark Souls III through 2022-03-19 allows remote attackers to execute arbitrary code via matchmaking servers, a different vulnerability than CVE-2021-34170.

- [https://github.com/tremwil/ds3-nrssr-rce](https://github.com/tremwil/ds3-nrssr-rce) :  ![starts](https://img.shields.io/github/stars/tremwil/ds3-nrssr-rce.svg) ![forks](https://img.shields.io/github/forks/tremwil/ds3-nrssr-rce.svg)


## CVE-2022-24125
 The matchmaking servers of Bandai Namco FromSoftware Dark Souls III through 2022-03-19 allow remote attackers to send arbitrary push requests to clients via a RequestSendMessageToPlayers request. For example, ability to send a push message to hundreds of thousands of machines is only restricted on the client side, and can thus be bypassed with a modified client.

- [https://github.com/tremwil/ds3-nrssr-rce](https://github.com/tremwil/ds3-nrssr-rce) :  ![starts](https://img.shields.io/github/stars/tremwil/ds3-nrssr-rce.svg) ![forks](https://img.shields.io/github/forks/tremwil/ds3-nrssr-rce.svg)


## CVE-2022-24087
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Sam00rx/CVE-2022-24087](https://github.com/Sam00rx/CVE-2022-24087) :  ![starts](https://img.shields.io/github/stars/Sam00rx/CVE-2022-24087.svg) ![forks](https://img.shields.io/github/forks/Sam00rx/CVE-2022-24087.svg)


## CVE-2022-24086
 Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier) are affected by an improper input validation vulnerability during the checkout process. Exploitation of this issue does not require user interaction and could result in arbitrary code execution.

- [https://github.com/Sam00rx/CVE-2022-24087](https://github.com/Sam00rx/CVE-2022-24087) :  ![starts](https://img.shields.io/github/stars/Sam00rx/CVE-2022-24087.svg) ![forks](https://img.shields.io/github/forks/Sam00rx/CVE-2022-24087.svg)


## CVE-2022-23731
 V8 javascript engine (heap vulnerability) can cause privilege escalation ,which can impact on some webOS TV models.

- [https://github.com/DavidBuchanan314/WAMpage](https://github.com/DavidBuchanan314/WAMpage) :  ![starts](https://img.shields.io/github/stars/DavidBuchanan314/WAMpage.svg) ![forks](https://img.shields.io/github/forks/DavidBuchanan314/WAMpage.svg)


## CVE-2022-23727
 There is a privilege escalation vulnerability in some webOS TVs. Due to wrong setting environments, local attacker is able to perform specific operation to exploit this vulnerability. Exploitation may cause the attacker to obtain a higher privilege

- [https://github.com/RootMyTV/RootMyTV.github.io](https://github.com/RootMyTV/RootMyTV.github.io) :  ![starts](https://img.shields.io/github/stars/RootMyTV/RootMyTV.github.io.svg) ![forks](https://img.shields.io/github/forks/RootMyTV/RootMyTV.github.io.svg)


## CVE-2022-22600
 The issue was addressed with improved permissions logic. This issue is fixed in tvOS 15.4, iOS 15.4 and iPadOS 15.4, macOS Monterey 12.3, watchOS 8.5. A malicious application may be able to bypass certain Privacy preferences.

- [https://github.com/KlinKlinKlin/MSF-screenrecord-on-MacOS](https://github.com/KlinKlinKlin/MSF-screenrecord-on-MacOS) :  ![starts](https://img.shields.io/github/stars/KlinKlinKlin/MSF-screenrecord-on-MacOS.svg) ![forks](https://img.shields.io/github/forks/KlinKlinKlin/MSF-screenrecord-on-MacOS.svg)


## CVE-2022-0337
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera](https://github.com/Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera) :  ![starts](https://img.shields.io/github/stars/Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera.svg) ![forks](https://img.shields.io/github/forks/Puliczek/CVE-2022-0337-PoC-Google-Chrome-Microsoft-Edge-Opera.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/Hifumi1337/apache-traversal](https://github.com/Hifumi1337/apache-traversal) :  ![starts](https://img.shields.io/github/stars/Hifumi1337/apache-traversal.svg) ![forks](https://img.shields.io/github/forks/Hifumi1337/apache-traversal.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Hifumi1337/apache-traversal](https://github.com/Hifumi1337/apache-traversal) :  ![starts](https://img.shields.io/github/stars/Hifumi1337/apache-traversal.svg) ![forks](https://img.shields.io/github/forks/Hifumi1337/apache-traversal.svg)


## CVE-2021-2119
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.0 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N).

- [https://github.com/chatbottesisgmailh/Sauercloude](https://github.com/chatbottesisgmailh/Sauercloude) :  ![starts](https://img.shields.io/github/stars/chatbottesisgmailh/Sauercloude.svg) ![forks](https://img.shields.io/github/forks/chatbottesisgmailh/Sauercloude.svg)


## CVE-2020-9759
 A Vulnerability of LG Electronic web OS TV Emulator could allow an attacker to escalate privileges and overwrite certain files. This vulnerability is due to wrong environment setting. An attacker could exploit this vulnerability through crafted configuration files and executable files.

- [https://github.com/RootMyTV/RootMyTV.github.io](https://github.com/RootMyTV/RootMyTV.github.io) :  ![starts](https://img.shields.io/github/stars/RootMyTV/RootMyTV.github.io.svg) ![forks](https://img.shields.io/github/forks/RootMyTV/RootMyTV.github.io.svg)


## CVE-2020-0890
 A denial of service vulnerability exists when Microsoft Hyper-V on a host server fails to properly validate specific malicious data from a user on a guest operating system.To exploit the vulnerability, an attacker who already has a privileged account on a guest operating system, running as a virtual machine, could run a specially crafted application.The security update addresses the vulnerability by resolving the conditions where Hyper-V would fail to handle these requests., aka 'Windows Hyper-V Denial of Service Vulnerability'. This CVE ID is unique from CVE-2020-0904.

- [https://github.com/skasanagottu57gmailv/gerhart01](https://github.com/skasanagottu57gmailv/gerhart01) :  ![starts](https://img.shields.io/github/stars/skasanagottu57gmailv/gerhart01.svg) ![forks](https://img.shields.io/github/forks/skasanagottu57gmailv/gerhart01.svg)


## CVE-2019-18634
 In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.

- [https://github.com/mtthwstffrd/saleemrashid-sudo-cve-2019-18634](https://github.com/mtthwstffrd/saleemrashid-sudo-cve-2019-18634) :  ![starts](https://img.shields.io/github/stars/mtthwstffrd/saleemrashid-sudo-cve-2019-18634.svg) ![forks](https://img.shields.io/github/forks/mtthwstffrd/saleemrashid-sudo-cve-2019-18634.svg)


## CVE-2019-17240
 bl-kernel/security.class.php in Bludit 3.9.2 allows attackers to bypass a brute-force protection mechanism by using many different forged X-Forwarded-For or Client-IP HTTP headers.

- [https://github.com/0xbrunosergio/bloodit](https://github.com/0xbrunosergio/bloodit) :  ![starts](https://img.shields.io/github/stars/0xbrunosergio/bloodit.svg) ![forks](https://img.shields.io/github/forks/0xbrunosergio/bloodit.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/akr3ch/CVE-2017-9841](https://github.com/akr3ch/CVE-2017-9841) :  ![starts](https://img.shields.io/github/stars/akr3ch/CVE-2017-9841.svg) ![forks](https://img.shields.io/github/forks/akr3ch/CVE-2017-9841.svg)


## CVE-2017-8601
 Microsoft Edge in Microsoft Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allow an attacker to execute arbitrary code in the context of the current user when the JavaScript engine fails to render when handling objects in memory in Microsoft Edge, aka &quot;Scripting Engine Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-8596, CVE-2017-8610, CVE-2017-8618, CVE-2017-8619, CVE-2017-8603, CVE-2017-8604, CVE-2017-8605, CVE-2017-8606, CVE-2017-8607, CVE-2017-8608, CVE-2017-8598 and CVE-2017-8609.

- [https://github.com/Exploitables/EXP-401-Preparation](https://github.com/Exploitables/EXP-401-Preparation) :  ![starts](https://img.shields.io/github/stars/Exploitables/EXP-401-Preparation.svg) ![forks](https://img.shields.io/github/forks/Exploitables/EXP-401-Preparation.svg)


## CVE-2015-5736
 The Fortishield.sys driver in Fortinet FortiClient before 5.2.4 allows local users to execute arbitrary code with kernel privileges by setting the callback function in a (1) 0x220024 or (2) 0x220028 ioctl call.

- [https://github.com/Exploitables/EXP-401-Preparation](https://github.com/Exploitables/EXP-401-Preparation) :  ![starts](https://img.shields.io/github/stars/Exploitables/EXP-401-Preparation.svg) ![forks](https://img.shields.io/github/forks/Exploitables/EXP-401-Preparation.svg)


## CVE-2015-3104
 Integer overflow in Adobe Flash Player before 13.0.0.292 and 14.x through 18.x before 18.0.0.160 on Windows and OS X and before 11.2.202.466 on Linux, Adobe AIR before 18.0.0.144 on Windows and before 18.0.0.143 on OS X and Android, Adobe AIR SDK before 18.0.0.144 on Windows and before 18.0.0.143 on OS X, and Adobe AIR SDK &amp; Compiler before 18.0.0.144 on Windows and before 18.0.0.143 on OS X allows attackers to execute arbitrary code via unspecified vectors.

- [https://github.com/Exploitables/EXP-401-Preparation](https://github.com/Exploitables/EXP-401-Preparation) :  ![starts](https://img.shields.io/github/stars/Exploitables/EXP-401-Preparation.svg) ![forks](https://img.shields.io/github/forks/Exploitables/EXP-401-Preparation.svg)


## CVE-2013-0156
 active_support/core_ext/hash/conversions.rb in Ruby on Rails before 2.3.15, 3.0.x before 3.0.19, 3.1.x before 3.1.10, and 3.2.x before 3.2.11 does not properly restrict casts of string values, which allows remote attackers to conduct object-injection attacks and execute arbitrary code, or cause a denial of service (memory and CPU consumption) involving nested XML entity references, by leveraging Action Pack support for (1) YAML type conversion or (2) Symbol type conversion.

- [https://github.com/Atreb92/CVE-2013-0156](https://github.com/Atreb92/CVE-2013-0156) :  ![starts](https://img.shields.io/github/stars/Atreb92/CVE-2013-0156.svg) ![forks](https://img.shields.io/github/forks/Atreb92/CVE-2013-0156.svg)

