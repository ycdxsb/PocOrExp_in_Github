# Update 2021-12-16
## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in a denial of service (DOS) attack. Log4j 2.15.0 restricts JNDI LDAP lookups to localhost by default. Note that previous mitigations involving configuration such as to set the system property `log4j2.noFormatMsgLookup` to `true` do NOT mitigate this specific vulnerability. Log4j 2.16.0 fixes this issue by removing support for message lookup patterns and disabling JNDI functionality by default. This issue can be mitigated in prior releases (&lt;2.16.0) by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class).

- [https://github.com/cckuailong/Log4j_CVE-2021-45046](https://github.com/cckuailong/Log4j_CVE-2021-45046) :  ![starts](https://img.shields.io/github/stars/cckuailong/Log4j_CVE-2021-45046.svg) ![forks](https://img.shields.io/github/forks/cckuailong/Log4j_CVE-2021-45046.svg)


## CVE-2021-44228
 Apache Log4j2 &lt;=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. In previous releases (&gt;2.10) this behavior can be mitigated by setting system property &quot;log4j2.formatMsgNoLookups&quot; to &#8220;true&#8221; or it can be mitigated in prior releases (&lt;2.10) by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class).

- [https://github.com/NorthwaveSecurity/log4jcheck](https://github.com/NorthwaveSecurity/log4jcheck) :  ![starts](https://img.shields.io/github/stars/NorthwaveSecurity/log4jcheck.svg) ![forks](https://img.shields.io/github/forks/NorthwaveSecurity/log4jcheck.svg)
- [https://github.com/zhzyker/logmap](https://github.com/zhzyker/logmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/logmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/logmap.svg)
- [https://github.com/0xInfection/LogMePwn](https://github.com/0xInfection/LogMePwn) :  ![starts](https://img.shields.io/github/stars/0xInfection/LogMePwn.svg) ![forks](https://img.shields.io/github/forks/0xInfection/LogMePwn.svg)
- [https://github.com/MalwareTech/Log4jTools](https://github.com/MalwareTech/Log4jTools) :  ![starts](https://img.shields.io/github/stars/MalwareTech/Log4jTools.svg) ![forks](https://img.shields.io/github/forks/MalwareTech/Log4jTools.svg)
- [https://github.com/BinaryDefense/log4j-honeypot-flask](https://github.com/BinaryDefense/log4j-honeypot-flask) :  ![starts](https://img.shields.io/github/stars/BinaryDefense/log4j-honeypot-flask.svg) ![forks](https://img.shields.io/github/forks/BinaryDefense/log4j-honeypot-flask.svg)
- [https://github.com/fox-it/log4j-finder](https://github.com/fox-it/log4j-finder) :  ![starts](https://img.shields.io/github/stars/fox-it/log4j-finder.svg) ![forks](https://img.shields.io/github/forks/fox-it/log4j-finder.svg)
- [https://github.com/darkarnium/Log4j-CVE-Detect](https://github.com/darkarnium/Log4j-CVE-Detect) :  ![starts](https://img.shields.io/github/stars/darkarnium/Log4j-CVE-Detect.svg) ![forks](https://img.shields.io/github/forks/darkarnium/Log4j-CVE-Detect.svg)
- [https://github.com/tippexs/nginx-njs-waf-cve2021-44228](https://github.com/tippexs/nginx-njs-waf-cve2021-44228) :  ![starts](https://img.shields.io/github/stars/tippexs/nginx-njs-waf-cve2021-44228.svg) ![forks](https://img.shields.io/github/forks/tippexs/nginx-njs-waf-cve2021-44228.svg)
- [https://github.com/rwincey/CVE-2021-44228-Log4j-Payloads](https://github.com/rwincey/CVE-2021-44228-Log4j-Payloads) :  ![starts](https://img.shields.io/github/stars/rwincey/CVE-2021-44228-Log4j-Payloads.svg) ![forks](https://img.shields.io/github/forks/rwincey/CVE-2021-44228-Log4j-Payloads.svg)
- [https://github.com/mufeedvh/log4jail](https://github.com/mufeedvh/log4jail) :  ![starts](https://img.shields.io/github/stars/mufeedvh/log4jail.svg) ![forks](https://img.shields.io/github/forks/mufeedvh/log4jail.svg)
- [https://github.com/hupe1980/scan4log4shell](https://github.com/hupe1980/scan4log4shell) :  ![starts](https://img.shields.io/github/stars/hupe1980/scan4log4shell.svg) ![forks](https://img.shields.io/github/forks/hupe1980/scan4log4shell.svg)
- [https://github.com/fireeye/CVE-2021-44228](https://github.com/fireeye/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/fireeye/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/fireeye/CVE-2021-44228.svg)
- [https://github.com/CERTCC/CVE-2021-44228_scanner](https://github.com/CERTCC/CVE-2021-44228_scanner) :  ![starts](https://img.shields.io/github/stars/CERTCC/CVE-2021-44228_scanner.svg) ![forks](https://img.shields.io/github/forks/CERTCC/CVE-2021-44228_scanner.svg)
- [https://github.com/manuel-alvarez-alvarez/log4j-cve-2021-44228](https://github.com/manuel-alvarez-alvarez/log4j-cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/manuel-alvarez-alvarez/log4j-cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/manuel-alvarez-alvarez/log4j-cve-2021-44228.svg)
- [https://github.com/back2root/log4shell-rex](https://github.com/back2root/log4shell-rex) :  ![starts](https://img.shields.io/github/stars/back2root/log4shell-rex.svg) ![forks](https://img.shields.io/github/forks/back2root/log4shell-rex.svg)
- [https://github.com/Koupah/MC-Log4j-Patcher](https://github.com/Koupah/MC-Log4j-Patcher) :  ![starts](https://img.shields.io/github/stars/Koupah/MC-Log4j-Patcher.svg) ![forks](https://img.shields.io/github/forks/Koupah/MC-Log4j-Patcher.svg)
- [https://github.com/Occamsec/log4j-checker](https://github.com/Occamsec/log4j-checker) :  ![starts](https://img.shields.io/github/stars/Occamsec/log4j-checker.svg) ![forks](https://img.shields.io/github/forks/Occamsec/log4j-checker.svg)
- [https://github.com/perryflynn/find-log4j](https://github.com/perryflynn/find-log4j) :  ![starts](https://img.shields.io/github/stars/perryflynn/find-log4j.svg) ![forks](https://img.shields.io/github/forks/perryflynn/find-log4j.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/Ryze-T/CVE-2021-43798](https://github.com/Ryze-T/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/Ryze-T/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/Ryze-T/CVE-2021-43798.svg)


## CVE-2021-42287
 Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42278, CVE-2021-42282, CVE-2021-42291.

- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)


## CVE-2021-42278
 Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42282, CVE-2021-42287, CVE-2021-42291.

- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/i6c/MASS_CVE-2021-41773](https://github.com/i6c/MASS_CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/i6c/MASS_CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/i6c/MASS_CVE-2021-41773.svg)


## CVE-2021-40154
 NXP LPC55S69 devices before A3 have a buffer over-read via a crafted wlength value in a GET Descriptor Configuration request during use of USB In-System Programming (ISP) mode. This discloses protected flash memory.

- [https://github.com/Xen1thLabs-AE/CVE-2021-40154](https://github.com/Xen1thLabs-AE/CVE-2021-40154) :  ![starts](https://img.shields.io/github/stars/Xen1thLabs-AE/CVE-2021-40154.svg) ![forks](https://img.shields.io/github/forks/Xen1thLabs-AE/CVE-2021-40154.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/0xf4n9x/CVE-2021-26084](https://github.com/0xf4n9x/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2021-26084.svg)


## CVE-2021-21315
 The System Information Library for Node.JS (npm package &quot;systeminformation&quot;) is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected.

- [https://github.com/eR072391/cve-2021-21315](https://github.com/eR072391/cve-2021-21315) :  ![starts](https://img.shields.io/github/stars/eR072391/cve-2021-21315.svg) ![forks](https://img.shields.io/github/forks/eR072391/cve-2021-21315.svg)


## CVE-2021-3019
 ffay lanproxy 0.1 allows Directory Traversal to read /../conf/config.properties to obtain credentials for a connection to the intranet.

- [https://github.com/0xf4n9x/CVE-2021-3019](https://github.com/0xf4n9x/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2021-3019.svg)


## CVE-2019-15658
 connect-pg-simple before 6.0.1 allows SQL injection if tableName or schemaName is untrusted data.

- [https://github.com/ossf-cve-benchmark/CVE-2019-15658](https://github.com/ossf-cve-benchmark/CVE-2019-15658) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2019-15658.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2019-15658.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/robiul-awal/CVE-2018-15473](https://github.com/robiul-awal/CVE-2018-15473) :  ![starts](https://img.shields.io/github/stars/robiul-awal/CVE-2018-15473.svg) ![forks](https://img.shields.io/github/forks/robiul-awal/CVE-2018-15473.svg)


## CVE-2017-5645
 In Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive serialized log events from another application, a specially crafted binary payload can be sent that, when deserialized, can execute arbitrary code.

- [https://github.com/sefayfr/log4j-impl](https://github.com/sefayfr/log4j-impl) :  ![starts](https://img.shields.io/github/stars/sefayfr/log4j-impl.svg) ![forks](https://img.shields.io/github/forks/sefayfr/log4j-impl.svg)

