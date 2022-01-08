# Update 2022-01-08
## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/Yuji-Kakeya/log4j-CVE-2021-45046-poc](https://github.com/Yuji-Kakeya/log4j-CVE-2021-45046-poc) :  ![starts](https://img.shields.io/github/stars/Yuji-Kakeya/log4j-CVE-2021-45046-poc.svg) ![forks](https://img.shields.io/github/forks/Yuji-Kakeya/log4j-CVE-2021-45046-poc.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/mr-r3b00t/CVE-2021-44228](https://github.com/mr-r3b00t/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2021-44228.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/rnsss/CVE-2021-43798-poc](https://github.com/rnsss/CVE-2021-43798-poc) :  ![starts](https://img.shields.io/github/stars/rnsss/CVE-2021-43798-poc.svg) ![forks](https://img.shields.io/github/forks/rnsss/CVE-2021-43798-poc.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/rnsss/CVE-2021-42013](https://github.com/rnsss/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/rnsss/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/rnsss/CVE-2021-42013.svg)


## CVE-2021-41349
 Microsoft Exchange Server Spoofing Vulnerability This CVE ID is unique from CVE-2021-42305.

- [https://github.com/exploit-io/CVE-2021-41349](https://github.com/exploit-io/CVE-2021-41349) :  ![starts](https://img.shields.io/github/stars/exploit-io/CVE-2021-41349.svg) ![forks](https://img.shields.io/github/forks/exploit-io/CVE-2021-41349.svg)


## CVE-2021-39863
 Acrobat Reader DC versions 2021.005.20060 (and earlier), 2020.004.30006 (and earlier) and 2017.011.30199 (and earlier) are affected by a Buffer Overflow vulnerability when parsing a specially crafted PDF file. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/lsw29475/CVE-2021-39863](https://github.com/lsw29475/CVE-2021-39863) :  ![starts](https://img.shields.io/github/stars/lsw29475/CVE-2021-39863.svg) ![forks](https://img.shields.io/github/forks/lsw29475/CVE-2021-39863.svg)


## CVE-2019-15126
 An issue was discovered on Broadcom Wi-Fi client devices. Specifically timed and handcrafted traffic can cause internal errors (related to state transitions) in a WLAN device that lead to improper layer 2 Wi-Fi encryption with a consequent possibility of information disclosure over the air for a discrete set of traffic, a different vulnerability than CVE-2019-9500, CVE-2019-9501, CVE-2019-9502, and CVE-2019-9503.

- [https://github.com/5l1v3r1/kr00k-vulnerability](https://github.com/5l1v3r1/kr00k-vulnerability) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/kr00k-vulnerability.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/kr00k-vulnerability.svg)


## CVE-2018-14847
 MikroTik RouterOS through 6.42 allows unauthenticated remote attackers to read arbitrary files and remote authenticated attackers to write arbitrary files due to a directory traversal vulnerability in the WinBox interface.

- [https://github.com/jas502n/CVE-2018-14847](https://github.com/jas502n/CVE-2018-14847) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2018-14847.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2018-14847.svg)

