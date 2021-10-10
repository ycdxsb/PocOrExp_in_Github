# Update 2021-10-10
## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/inbug-team/CVE-2021-41773_CVE-2021-42013](https://github.com/inbug-team/CVE-2021-41773_CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/inbug-team/CVE-2021-41773_CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/inbug-team/CVE-2021-41773_CVE-2021-42013.svg)
- [https://github.com/Zeop-CyberSec/apache_normalize_path](https://github.com/Zeop-CyberSec/apache_normalize_path) :  ![starts](https://img.shields.io/github/stars/Zeop-CyberSec/apache_normalize_path.svg) ![forks](https://img.shields.io/github/forks/Zeop-CyberSec/apache_normalize_path.svg)
- [https://github.com/im-hanzou/apachrot](https://github.com/im-hanzou/apachrot) :  ![starts](https://img.shields.io/github/stars/im-hanzou/apachrot.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/apachrot.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by &quot;require all denied&quot; these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.

- [https://github.com/HightechSec/scarce-apache2](https://github.com/HightechSec/scarce-apache2) :  ![starts](https://img.shields.io/github/stars/HightechSec/scarce-apache2.svg) ![forks](https://img.shields.io/github/forks/HightechSec/scarce-apache2.svg)
- [https://github.com/inbug-team/CVE-2021-41773_CVE-2021-42013](https://github.com/inbug-team/CVE-2021-41773_CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/inbug-team/CVE-2021-41773_CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/inbug-team/CVE-2021-41773_CVE-2021-42013.svg)
- [https://github.com/ComdeyOverFlow/CVE-2021-41773](https://github.com/ComdeyOverFlow/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ComdeyOverFlow/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ComdeyOverFlow/CVE-2021-41773.svg)
- [https://github.com/zeronine9/CVE-2021-41773](https://github.com/zeronine9/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zeronine9/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zeronine9/CVE-2021-41773.svg)
- [https://github.com/superzerosec/CVE-2021-41773](https://github.com/superzerosec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/superzerosec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/superzerosec/CVE-2021-41773.svg)
- [https://github.com/im-hanzou/apachrot](https://github.com/im-hanzou/apachrot) :  ![starts](https://img.shields.io/github/stars/im-hanzou/apachrot.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/apachrot.svg)
- [https://github.com/n3k00n3/CVE-2021-41773](https://github.com/n3k00n3/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/n3k00n3/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/n3k00n3/CVE-2021-41773.svg)
- [https://github.com/KAB8345/CVE-2021-41773](https://github.com/KAB8345/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/KAB8345/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/KAB8345/CVE-2021-41773.svg)
- [https://github.com/b1tsec/CVE-2021-41773](https://github.com/b1tsec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/b1tsec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/b1tsec/CVE-2021-41773.svg)


## CVE-2021-27513
 The module admin_ITSM in EyesOfNetwork 5.3-10 allows remote authenticated users to upload arbitrary .xml.php files because it relies on &quot;le filtre userside.&quot;

- [https://github.com/ArianeBlow/CVE-2021-27513](https://github.com/ArianeBlow/CVE-2021-27513) :  ![starts](https://img.shields.io/github/stars/ArianeBlow/CVE-2021-27513.svg) ![forks](https://img.shields.io/github/forks/ArianeBlow/CVE-2021-27513.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/oxctdev/CVE-2020-0796](https://github.com/oxctdev/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/oxctdev/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/oxctdev/CVE-2020-0796.svg)


## CVE-2019-5737
 In Node.js including 6.x before 6.17.0, 8.x before 8.15.1, 10.x before 10.15.2, and 11.x before 11.10.1, an attacker can cause a Denial of Service (DoS) by establishing an HTTP or HTTPS connection in keep-alive mode and by sending headers very slowly. This keeps the connection and associated resources alive for a long period of time. Potential attacks are mitigated by the use of a load balancer or other proxy layer. This vulnerability is an extension of CVE-2018-12121, addressed in November and impacts all active Node.js release lines including 6.x before 6.17.0, 8.x before 8.15.1, 10.x before 10.15.2, and 11.x before 11.10.1.

- [https://github.com/beelzebruh/cve-2019-5737](https://github.com/beelzebruh/cve-2019-5737) :  ![starts](https://img.shields.io/github/stars/beelzebruh/cve-2019-5737.svg) ![forks](https://img.shields.io/github/forks/beelzebruh/cve-2019-5737.svg)


## CVE-2018-5728
 Cobham Sea Tel 121 build 222701 devices allow remote attackers to obtain potentially sensitive information via a /cgi-bin/getSysStatus request, as demonstrated by the Latitude/Longitude of the ship, or satellite details.

- [https://github.com/ezelf/seatel_terminals](https://github.com/ezelf/seatel_terminals) :  ![starts](https://img.shields.io/github/stars/ezelf/seatel_terminals.svg) ![forks](https://img.shields.io/github/forks/ezelf/seatel_terminals.svg)


## CVE-2016-9079
 A use-after-free vulnerability in SVG Animation has been discovered. An exploit built on this vulnerability has been discovered in the wild targeting Firefox and Tor Browser users on Windows. This vulnerability affects Firefox &lt; 50.0.2, Firefox ESR &lt; 45.5.1, and Thunderbird &lt; 45.5.1.

- [https://github.com/Tau-hub/Firefox-CVE-2016-9079](https://github.com/Tau-hub/Firefox-CVE-2016-9079) :  ![starts](https://img.shields.io/github/stars/Tau-hub/Firefox-CVE-2016-9079.svg) ![forks](https://img.shields.io/github/forks/Tau-hub/Firefox-CVE-2016-9079.svg)


## CVE-2016-3962
 Stack-based buffer overflow in the NTP time-server interface on Meinberg IMS-LANTIME M3000, IMS-LANTIME M1000, IMS-LANTIME M500, LANTIME M900, LANTIME M600, LANTIME M400, LANTIME M300, LANTIME M200, LANTIME M100, SyncFire 1100, and LCES devices with firmware before 6.20.004 allows remote attackers to obtain sensitive information, modify data, or cause a denial of service via a crafted parameter in a POST request.

- [https://github.com/securifera/CVE-2016-3962-Exploit](https://github.com/securifera/CVE-2016-3962-Exploit) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2016-3962-Exploit.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2016-3962-Exploit.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/PinkP4nther/Heartbleed_PoC](https://github.com/PinkP4nther/Heartbleed_PoC) :  ![starts](https://img.shields.io/github/stars/PinkP4nther/Heartbleed_PoC.svg) ![forks](https://img.shields.io/github/forks/PinkP4nther/Heartbleed_PoC.svg)

