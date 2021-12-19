# Update 2021-12-19
## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in a denial of service (DOS) attack. Log4j 2.15.0 makes a best-effort attempt to restrict JNDI LDAP lookups to localhost by default. Log4j 2.16.0 fixes this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/1lann/log4shelldetect](https://github.com/1lann/log4shelldetect) :  ![starts](https://img.shields.io/github/stars/1lann/log4shelldetect.svg) ![forks](https://img.shields.io/github/forks/1lann/log4shelldetect.svg)
- [https://github.com/darkarnium/Log4j-CVE-Detect](https://github.com/darkarnium/Log4j-CVE-Detect) :  ![starts](https://img.shields.io/github/stars/darkarnium/Log4j-CVE-Detect.svg) ![forks](https://img.shields.io/github/forks/darkarnium/Log4j-CVE-Detect.svg)
- [https://github.com/hupe1980/scan4log4shell](https://github.com/hupe1980/scan4log4shell) :  ![starts](https://img.shields.io/github/stars/hupe1980/scan4log4shell.svg) ![forks](https://img.shields.io/github/forks/hupe1980/scan4log4shell.svg)
- [https://github.com/DANSI/PowerShell-Log4J-Scanner](https://github.com/DANSI/PowerShell-Log4J-Scanner) :  ![starts](https://img.shields.io/github/stars/DANSI/PowerShell-Log4J-Scanner.svg) ![forks](https://img.shields.io/github/forks/DANSI/PowerShell-Log4J-Scanner.svg)
- [https://github.com/lukepasek/log4jjndilookupremove](https://github.com/lukepasek/log4jjndilookupremove) :  ![starts](https://img.shields.io/github/stars/lukepasek/log4jjndilookupremove.svg) ![forks](https://img.shields.io/github/forks/lukepasek/log4jjndilookupremove.svg)
- [https://github.com/Aschen/log4j-patched](https://github.com/Aschen/log4j-patched) :  ![starts](https://img.shields.io/github/stars/Aschen/log4j-patched.svg) ![forks](https://img.shields.io/github/forks/Aschen/log4j-patched.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/redhuntlabs/Log4JHunt](https://github.com/redhuntlabs/Log4JHunt) :  ![starts](https://img.shields.io/github/stars/redhuntlabs/Log4JHunt.svg) ![forks](https://img.shields.io/github/forks/redhuntlabs/Log4JHunt.svg)
- [https://github.com/For-ACGN/Log4Shell](https://github.com/For-ACGN/Log4Shell) :  ![starts](https://img.shields.io/github/stars/For-ACGN/Log4Shell.svg) ![forks](https://img.shields.io/github/forks/For-ACGN/Log4Shell.svg)
- [https://github.com/obscuritylabs/log4shell-poc-lab](https://github.com/obscuritylabs/log4shell-poc-lab) :  ![starts](https://img.shields.io/github/stars/obscuritylabs/log4shell-poc-lab.svg) ![forks](https://img.shields.io/github/forks/obscuritylabs/log4shell-poc-lab.svg)


## CVE-2021-43883
 Windows Installer Elevation of Privilege Vulnerability

- [https://github.com/jbaines-r7/shakeitoff](https://github.com/jbaines-r7/shakeitoff) :  ![starts](https://img.shields.io/github/stars/jbaines-r7/shakeitoff.svg) ![forks](https://img.shields.io/github/forks/jbaines-r7/shakeitoff.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/k3rwin/CVE-2021-43798-Grafana-](https://github.com/k3rwin/CVE-2021-43798-Grafana-) :  ![starts](https://img.shields.io/github/stars/k3rwin/CVE-2021-43798-Grafana-.svg) ![forks](https://img.shields.io/github/forks/k3rwin/CVE-2021-43798-Grafana-.svg)


## CVE-2021-42550
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)


## CVE-2021-23017
 A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server to cause 1-byte memory overwrite, resulting in worker process crash or potential other impact.

- [https://github.com/niandy/nginx-patch](https://github.com/niandy/nginx-patch) :  ![starts](https://img.shields.io/github/stars/niandy/nginx-patch.svg) ![forks](https://img.shields.io/github/forks/niandy/nginx-patch.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

