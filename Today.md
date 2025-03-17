# Update 2025-03-17
## CVE-2025-22604
 Cacti is an open source performance and fault management framework. Due to a flaw in multi-line SNMP result parser, authenticated users can inject malformed OIDs in the response. When processed by ss_net_snmp_disk_io() or ss_net_snmp_disk_bytes(), a part of each OID will be used as a key in an array that is used as part of a system command, causing a command execution vulnerability. This vulnerability is fixed in 1.2.29.

- [https://github.com/ishwardeepp/CVE-2025-22604-Cacti-RCE](https://github.com/ishwardeepp/CVE-2025-22604-Cacti-RCE) :  ![starts](https://img.shields.io/github/stars/ishwardeepp/CVE-2025-22604-Cacti-RCE.svg) ![forks](https://img.shields.io/github/forks/ishwardeepp/CVE-2025-22604-Cacti-RCE.svg)


## CVE-2024-8926
 In PHP versions 8.1.* before 8.1.30, 8.2.* before 8.2.24, 8.3.* before 8.3.12, when using a certain non-standard configurations of Windows codepages, the fixes for  CVE-2024-4577 https://github.com/advisories/GHSA-vxpp-6299-mxw3  may still be bypassed and the same command injection related to Windows "Best Fit" codepage behavior can be achieved. This may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/Night-have-dreams/php-cgi-Injector](https://github.com/Night-have-dreams/php-cgi-Injector) :  ![starts](https://img.shields.io/github/stars/Night-have-dreams/php-cgi-Injector.svg) ![forks](https://img.shields.io/github/forks/Night-have-dreams/php-cgi-Injector.svg)


## CVE-2024-7014
 versions 10.14.4 and older.

- [https://github.com/absholi7ly/PoC-for-CVE-2024-7014-Exploit](https://github.com/absholi7ly/PoC-for-CVE-2024-7014-Exploit) :  ![starts](https://img.shields.io/github/stars/absholi7ly/PoC-for-CVE-2024-7014-Exploit.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/PoC-for-CVE-2024-7014-Exploit.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/Night-have-dreams/php-cgi-Injector](https://github.com/Night-have-dreams/php-cgi-Injector) :  ![starts](https://img.shields.io/github/stars/Night-have-dreams/php-cgi-Injector.svg) ![forks](https://img.shields.io/github/forks/Night-have-dreams/php-cgi-Injector.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/hupe1980/scan4log4shell](https://github.com/hupe1980/scan4log4shell) :  ![starts](https://img.shields.io/github/stars/hupe1980/scan4log4shell.svg) ![forks](https://img.shields.io/github/forks/hupe1980/scan4log4shell.svg)

