# Update 2022-01-11
## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/Hydragyrum/evil-rmi-server](https://github.com/Hydragyrum/evil-rmi-server) :  ![starts](https://img.shields.io/github/stars/Hydragyrum/evil-rmi-server.svg) ![forks](https://img.shields.io/github/forks/Hydragyrum/evil-rmi-server.svg)


## CVE-2021-42392
 The org.h2.util.JdbcUtils.getConnection method of the H2 database takes as parameters the class name of the driver and URL of the database. An attacker may pass a JNDI driver name and a URL leading to a LDAP or RMI servers, causing remote code execution. This can be exploited through various attack vectors, most notably through the H2 Console which leads to unauthenticated remote code execution.

- [https://github.com/cybersecurityworks553/CVE-2021-42392-Detect](https://github.com/cybersecurityworks553/CVE-2021-42392-Detect) :  ![starts](https://img.shields.io/github/stars/cybersecurityworks553/CVE-2021-42392-Detect.svg) ![forks](https://img.shields.io/github/forks/cybersecurityworks553/CVE-2021-42392-Detect.svg)


## CVE-2021-41277
 Metabase is an open source data analytics platform. In affected versions a security issue has been discovered with the custom GeoJSON map (`admin-&gt;settings-&gt;maps-&gt;custom maps-&gt;add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded. This issue is fixed in a new maintenance release (0.40.5 and 1.40.5), and any subsequent release after that. If you&#8217;re unable to upgrade immediately, you can mitigate this by including rules in your reverse proxy or load balancer or WAF to provide a validation filter before the application.

- [https://github.com/sasukeourad/CVE-2021-41277_SSRF](https://github.com/sasukeourad/CVE-2021-41277_SSRF) :  ![starts](https://img.shields.io/github/stars/sasukeourad/CVE-2021-41277_SSRF.svg) ![forks](https://img.shields.io/github/forks/sasukeourad/CVE-2021-41277_SSRF.svg)

