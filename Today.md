# Update 2022-05-16
## CVE-2022-30489
 WAVLINK WN535 G3 was discovered to contain a cross-site scripting (XSS) vulnerability via the hostname parameter at /cgi-bin/login.cgi.

- [https://github.com/badboycxcc/XSS-CVE-2022-30489](https://github.com/badboycxcc/XSS-CVE-2022-30489) :  ![starts](https://img.shields.io/github/stars/badboycxcc/XSS-CVE-2022-30489.svg) ![forks](https://img.shields.io/github/forks/badboycxcc/XSS-CVE-2022-30489.svg)


## CVE-2022-29383
 NETGEAR ProSafe SSL VPN firmware FVS336Gv2 and FVS336Gv3 was discovered to contain a SQL injection vulnerability via USERDBDomains.Domainname at cgi-bin/platform.cgi.

- [https://github.com/cxaqhq/netgear-to-CVE-2022-29383](https://github.com/cxaqhq/netgear-to-CVE-2022-29383) :  ![starts](https://img.shields.io/github/stars/cxaqhq/netgear-to-CVE-2022-29383.svg) ![forks](https://img.shields.io/github/forks/cxaqhq/netgear-to-CVE-2022-29383.svg)
- [https://github.com/badboycxcc/Netgear-ssl-vpn-20211222-CVE-2022-29383](https://github.com/badboycxcc/Netgear-ssl-vpn-20211222-CVE-2022-29383) :  ![starts](https://img.shields.io/github/stars/badboycxcc/Netgear-ssl-vpn-20211222-CVE-2022-29383.svg) ![forks](https://img.shields.io/github/forks/badboycxcc/Netgear-ssl-vpn-20211222-CVE-2022-29383.svg)


## CVE-2022-28346
 An issue was discovered in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4. QuerySet.annotate(), aggregate(), and extra() methods are subject to SQL injection in column aliases via a crafted dictionary (with dictionary expansion) as the passed **kwargs.

- [https://github.com/ahsentekdemir/CVE-2022-28346](https://github.com/ahsentekdemir/CVE-2022-28346) :  ![starts](https://img.shields.io/github/stars/ahsentekdemir/CVE-2022-28346.svg) ![forks](https://img.shields.io/github/forks/ahsentekdemir/CVE-2022-28346.svg)


## CVE-2022-26923
 Active Directory Domain Services Elevation of Privilege Vulnerability.

- [https://github.com/LudovicPatho/CVE-2022-26923_AD-Certificate-Services](https://github.com/LudovicPatho/CVE-2022-26923_AD-Certificate-Services) :  ![starts](https://img.shields.io/github/stars/LudovicPatho/CVE-2022-26923_AD-Certificate-Services.svg) ![forks](https://img.shields.io/github/forks/LudovicPatho/CVE-2022-26923_AD-Certificate-Services.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/sherlocksecurity/CVE-2022-1388-Exploit-POC](https://github.com/sherlocksecurity/CVE-2022-1388-Exploit-POC) :  ![starts](https://img.shields.io/github/stars/sherlocksecurity/CVE-2022-1388-Exploit-POC.svg) ![forks](https://img.shields.io/github/forks/sherlocksecurity/CVE-2022-1388-Exploit-POC.svg)
- [https://github.com/PsychoSec2/CVE-2022-1388-POC](https://github.com/PsychoSec2/CVE-2022-1388-POC) :  ![starts](https://img.shields.io/github/stars/PsychoSec2/CVE-2022-1388-POC.svg) ![forks](https://img.shields.io/github/forks/PsychoSec2/CVE-2022-1388-POC.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit](https://github.com/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit) :  ![starts](https://img.shields.io/github/stars/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit.svg) ![forks](https://img.shields.io/github/forks/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit.svg)


## CVE-2021-38314
 The Gutenberg Template Library &amp; Redux Framework plugin &lt;= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site&#8217;s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.

- [https://github.com/twseptian/cve-2021-38314](https://github.com/twseptian/cve-2021-38314) :  ![starts](https://img.shields.io/github/stars/twseptian/cve-2021-38314.svg) ![forks](https://img.shields.io/github/forks/twseptian/cve-2021-38314.svg)


## CVE-2008-0166
 OpenSSL 0.9.8c-1 up to versions before 0.9.8g-9 on Debian-based operating systems uses a random number generator that generates predictable numbers, which makes it easier for remote attackers to conduct brute force guessing attacks against cryptographic keys.

- [https://github.com/badkeys/debianopenssl](https://github.com/badkeys/debianopenssl) :  ![starts](https://img.shields.io/github/stars/badkeys/debianopenssl.svg) ![forks](https://img.shields.io/github/forks/badkeys/debianopenssl.svg)

