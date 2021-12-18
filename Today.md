# Update 2021-12-18
## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in a denial of service (DOS) attack. Log4j 2.15.0 makes a best-effort attempt to restrict JNDI LDAP lookups to localhost by default. Log4j 2.16.0 fixes this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/mergebase/log4j-samples](https://github.com/mergebase/log4j-samples) :  ![starts](https://img.shields.io/github/stars/mergebase/log4j-samples.svg) ![forks](https://img.shields.io/github/forks/mergebase/log4j-samples.svg)
- [https://github.com/benarculus/detecting-cve-2021-44228](https://github.com/benarculus/detecting-cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/benarculus/detecting-cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/benarculus/detecting-cve-2021-44228.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/NCSC-NL/log4shell](https://github.com/NCSC-NL/log4shell) :  ![starts](https://img.shields.io/github/stars/NCSC-NL/log4shell.svg) ![forks](https://img.shields.io/github/forks/NCSC-NL/log4shell.svg)
- [https://github.com/yahoo/check-log4j](https://github.com/yahoo/check-log4j) :  ![starts](https://img.shields.io/github/stars/yahoo/check-log4j.svg) ![forks](https://img.shields.io/github/forks/yahoo/check-log4j.svg)
- [https://github.com/DXC-StrikeForce/Burp-Log4j-HammerTime](https://github.com/DXC-StrikeForce/Burp-Log4j-HammerTime) :  ![starts](https://img.shields.io/github/stars/DXC-StrikeForce/Burp-Log4j-HammerTime.svg) ![forks](https://img.shields.io/github/forks/DXC-StrikeForce/Burp-Log4j-HammerTime.svg)
- [https://github.com/Kr0ff/CVE-2021-44228](https://github.com/Kr0ff/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Kr0ff/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Kr0ff/CVE-2021-44228.svg)
- [https://github.com/name/log4j-scanner](https://github.com/name/log4j-scanner) :  ![starts](https://img.shields.io/github/stars/name/log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/name/log4j-scanner.svg)
- [https://github.com/isuruwa/Log4j](https://github.com/isuruwa/Log4j) :  ![starts](https://img.shields.io/github/stars/isuruwa/Log4j.svg) ![forks](https://img.shields.io/github/forks/isuruwa/Log4j.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/ScorpionsMAX/CVE-2021-43798-Grafana-POC](https://github.com/ScorpionsMAX/CVE-2021-43798-Grafana-POC) :  ![starts](https://img.shields.io/github/stars/ScorpionsMAX/CVE-2021-43798-Grafana-POC.svg) ![forks](https://img.shields.io/github/forks/ScorpionsMAX/CVE-2021-43798-Grafana-POC.svg)


## CVE-2021-39316
 The Zoomsounds plugin &lt;= 6.45 for WordPress allows arbitrary files, including sensitive configuration files such as wp-config.php, to be downloaded via the `dzsap_download` action using directory traversal in the `link` parameter.

- [https://github.com/anggoroexe/Mass-CVE-2021-39316](https://github.com/anggoroexe/Mass-CVE-2021-39316) :  ![starts](https://img.shields.io/github/stars/anggoroexe/Mass-CVE-2021-39316.svg) ![forks](https://img.shields.io/github/forks/anggoroexe/Mass-CVE-2021-39316.svg)


## CVE-2021-38314
 The Gutenberg Template Library &amp; Redux Framework plugin &lt;= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site&#8217;s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.

- [https://github.com/shubhayu-64/CVE-2021-38314](https://github.com/shubhayu-64/CVE-2021-38314) :  ![starts](https://img.shields.io/github/stars/shubhayu-64/CVE-2021-38314.svg) ![forks](https://img.shields.io/github/forks/shubhayu-64/CVE-2021-38314.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/prod1gy1/CVE-2021-26084_Confluence](https://github.com/prod1gy1/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/prod1gy1/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/prod1gy1/CVE-2021-26084_Confluence.svg)


## CVE-2020-26525
 Damstra Smart Asset 2020.7 has SQL injection via the API/api/Asset originator parameter. This allows forcing the database and server to initiate remote connections to third party DNS servers.

- [https://github.com/lukaszstu/SmartAsset-SQLinj-CVE-2020-26525](https://github.com/lukaszstu/SmartAsset-SQLinj-CVE-2020-26525) :  ![starts](https://img.shields.io/github/stars/lukaszstu/SmartAsset-SQLinj-CVE-2020-26525.svg) ![forks](https://img.shields.io/github/forks/lukaszstu/SmartAsset-SQLinj-CVE-2020-26525.svg)

