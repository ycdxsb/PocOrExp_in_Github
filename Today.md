# Update 2022-11-27
## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/dr6817/CVE-2022-22963](https://github.com/dr6817/CVE-2022-22963) :  ![starts](https://img.shields.io/github/stars/dr6817/CVE-2022-22963.svg) ![forks](https://img.shields.io/github/forks/dr6817/CVE-2022-22963.svg)


## CVE-2022-3236
 A code injection vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v19.0 MR1 and older.

- [https://github.com/Adynervi/CVE-2022-3236-MASS-RCE](https://github.com/Adynervi/CVE-2022-3236-MASS-RCE) :  ![starts](https://img.shields.io/github/stars/Adynervi/CVE-2022-3236-MASS-RCE.svg) ![forks](https://img.shields.io/github/forks/Adynervi/CVE-2022-3236-MASS-RCE.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/robertdebock/ansible-role-cve_2021_44228](https://github.com/robertdebock/ansible-role-cve_2021_44228) :  ![starts](https://img.shields.io/github/stars/robertdebock/ansible-role-cve_2021_44228.svg) ![forks](https://img.shields.io/github/forks/robertdebock/ansible-role-cve_2021_44228.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/CVE-2021-41773-i-](https://github.com/mightysai1997/CVE-2021-41773-i-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-i-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-i-.svg)
- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)
- [https://github.com/hab1b0x/CVE-2021-41773](https://github.com/hab1b0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/hab1b0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/hab1b0x/CVE-2021-41773.svg)


## CVE-2019-2017
 In rw_t2t_handle_tlv_detect_rsp of rw_t2t_ndef.cc, there is a possible out-of-bound write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9Android ID: A-121035711

- [https://github.com/grmono/CVE2019-2017_POC](https://github.com/grmono/CVE2019-2017_POC) :  ![starts](https://img.shields.io/github/stars/grmono/CVE2019-2017_POC.svg) ![forks](https://img.shields.io/github/forks/grmono/CVE2019-2017_POC.svg)

