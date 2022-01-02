# Update 2022-01-02
## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/zhzyker/logmap](https://github.com/zhzyker/logmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/logmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/logmap.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/evilashz/CVE-2021-1675-LPE-EXP](https://github.com/evilashz/CVE-2021-1675-LPE-EXP) :  ![starts](https://img.shields.io/github/stars/evilashz/CVE-2021-1675-LPE-EXP.svg) ![forks](https://img.shields.io/github/forks/evilashz/CVE-2021-1675-LPE-EXP.svg)
- [https://github.com/cybersecurityworks553/CVE-2021-1675_PrintNightMare](https://github.com/cybersecurityworks553/CVE-2021-1675_PrintNightMare) :  ![starts](https://img.shields.io/github/stars/cybersecurityworks553/CVE-2021-1675_PrintNightMare.svg) ![forks](https://img.shields.io/github/forks/cybersecurityworks553/CVE-2021-1675_PrintNightMare.svg)
- [https://github.com/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery](https://github.com/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery) :  ![starts](https://img.shields.io/github/stars/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery.svg) ![forks](https://img.shields.io/github/forks/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery.svg)


## CVE-2018-1285
 Apache log4net versions before 2.0.10 do not disable XML external entities when parsing log4net configuration files. This allows for XXE-based attacks in applications that accept attacker-controlled log4net configuration files.

- [https://github.com/alex-ermolaev/Log4NetSolarWindsSNMP-](https://github.com/alex-ermolaev/Log4NetSolarWindsSNMP-) :  ![starts](https://img.shields.io/github/stars/alex-ermolaev/Log4NetSolarWindsSNMP-.svg) ![forks](https://img.shields.io/github/forks/alex-ermolaev/Log4NetSolarWindsSNMP-.svg)

