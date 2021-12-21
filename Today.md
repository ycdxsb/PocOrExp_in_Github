# Update 2021-12-21
## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0 and 2.12.3.

- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)
- [https://github.com/fox-it/log4j-finder](https://github.com/fox-it/log4j-finder) :  ![starts](https://img.shields.io/github/stars/fox-it/log4j-finder.svg) ![forks](https://img.shields.io/github/forks/fox-it/log4j-finder.svg)
- [https://github.com/dtact/divd-2021-00038--log4j-scanner](https://github.com/dtact/divd-2021-00038--log4j-scanner) :  ![starts](https://img.shields.io/github/stars/dtact/divd-2021-00038--log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/dtact/divd-2021-00038--log4j-scanner.svg)
- [https://github.com/hupe1980/scan4log4shell](https://github.com/hupe1980/scan4log4shell) :  ![starts](https://img.shields.io/github/stars/hupe1980/scan4log4shell.svg) ![forks](https://img.shields.io/github/forks/hupe1980/scan4log4shell.svg)
- [https://github.com/cckuailong/Log4j_dos_CVE-2021-45105](https://github.com/cckuailong/Log4j_dos_CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/cckuailong/Log4j_dos_CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/cckuailong/Log4j_dos_CVE-2021-45105.svg)
- [https://github.com/tejas-nagchandi/CVE-2021-45105](https://github.com/tejas-nagchandi/CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/tejas-nagchandi/CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/tejas-nagchandi/CVE-2021-45105.svg)
- [https://github.com/pravin-pp/log4j2-CVE-2021-45105](https://github.com/pravin-pp/log4j2-CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/pravin-pp/log4j2-CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/pravin-pp/log4j2-CVE-2021-45105.svg)
- [https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105](https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in a denial of service (DOS) attack. Log4j 2.15.0 makes a best-effort attempt to restrict JNDI LDAP lookups to localhost by default. Log4j 2.16.0 fixes this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/dtact/divd-2021-00038--log4j-scanner](https://github.com/dtact/divd-2021-00038--log4j-scanner) :  ![starts](https://img.shields.io/github/stars/dtact/divd-2021-00038--log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/dtact/divd-2021-00038--log4j-scanner.svg)
- [https://github.com/HynekPetrak/log4shell_finder](https://github.com/HynekPetrak/log4shell_finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell_finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell_finder.svg)
- [https://github.com/TheInterception/Log4J-Simulation-Tool](https://github.com/TheInterception/Log4J-Simulation-Tool) :  ![starts](https://img.shields.io/github/stars/TheInterception/Log4J-Simulation-Tool.svg) ![forks](https://img.shields.io/github/forks/TheInterception/Log4J-Simulation-Tool.svg)
- [https://github.com/at-bay/log4j-checker](https://github.com/at-bay/log4j-checker) :  ![starts](https://img.shields.io/github/stars/at-bay/log4j-checker.svg) ![forks](https://img.shields.io/github/forks/at-bay/log4j-checker.svg)
- [https://github.com/juergenhoetzel/log4j2go](https://github.com/juergenhoetzel/log4j2go) :  ![starts](https://img.shields.io/github/stars/juergenhoetzel/log4j2go.svg) ![forks](https://img.shields.io/github/forks/juergenhoetzel/log4j2go.svg)
- [https://github.com/ludy-dev/cve-2021-45046](https://github.com/ludy-dev/cve-2021-45046) :  ![starts](https://img.shields.io/github/stars/ludy-dev/cve-2021-45046.svg) ![forks](https://img.shields.io/github/forks/ludy-dev/cve-2021-45046.svg)
- [https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105](https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105.svg)
- [https://github.com/trickyearlobe/inspec-log4j](https://github.com/trickyearlobe/inspec-log4j) :  ![starts](https://img.shields.io/github/stars/trickyearlobe/inspec-log4j.svg) ![forks](https://img.shields.io/github/forks/trickyearlobe/inspec-log4j.svg)
- [https://github.com/sudo6/l4shunter](https://github.com/sudo6/l4shunter) :  ![starts](https://img.shields.io/github/stars/sudo6/l4shunter.svg) ![forks](https://img.shields.io/github/forks/sudo6/l4shunter.svg)
- [https://github.com/nagten/JndiLookupRemoval](https://github.com/nagten/JndiLookupRemoval) :  ![starts](https://img.shields.io/github/stars/nagten/JndiLookupRemoval.svg) ![forks](https://img.shields.io/github/forks/nagten/JndiLookupRemoval.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/dtact/divd-2021-00038--log4j-scanner](https://github.com/dtact/divd-2021-00038--log4j-scanner) :  ![starts](https://img.shields.io/github/stars/dtact/divd-2021-00038--log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/dtact/divd-2021-00038--log4j-scanner.svg)
- [https://github.com/dwisiswant0/look4jar](https://github.com/dwisiswant0/look4jar) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/look4jar.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/look4jar.svg)
- [https://github.com/KeysAU/Get-log4j-Windows.ps1](https://github.com/KeysAU/Get-log4j-Windows.ps1) :  ![starts](https://img.shields.io/github/stars/KeysAU/Get-log4j-Windows.ps1.svg) ![forks](https://img.shields.io/github/forks/KeysAU/Get-log4j-Windows.ps1.svg)
- [https://github.com/immunityinc/Log4j-JNDIServer](https://github.com/immunityinc/Log4j-JNDIServer) :  ![starts](https://img.shields.io/github/stars/immunityinc/Log4j-JNDIServer.svg) ![forks](https://img.shields.io/github/forks/immunityinc/Log4j-JNDIServer.svg)
- [https://github.com/mss/log4shell-hotfix-side-effect](https://github.com/mss/log4shell-hotfix-side-effect) :  ![starts](https://img.shields.io/github/stars/mss/log4shell-hotfix-side-effect.svg) ![forks](https://img.shields.io/github/forks/mss/log4shell-hotfix-side-effect.svg)


## CVE-2021-40444
 Microsoft MSHTML Remote Code Execution Vulnerability

- [https://github.com/34zY/Microsoft-Office-Word-MSHTML-Remote-Code-Execution-Exploit](https://github.com/34zY/Microsoft-Office-Word-MSHTML-Remote-Code-Execution-Exploit) :  ![starts](https://img.shields.io/github/stars/34zY/Microsoft-Office-Word-MSHTML-Remote-Code-Execution-Exploit.svg) ![forks](https://img.shields.io/github/forks/34zY/Microsoft-Office-Word-MSHTML-Remote-Code-Execution-Exploit.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/dock0d1/CVE-2021-26084_Confluence](https://github.com/dock0d1/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/dock0d1/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/dock0d1/CVE-2021-26084_Confluence.svg)


## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

- [https://github.com/shmilylty/cve-2021-22005-exp](https://github.com/shmilylty/cve-2021-22005-exp) :  ![starts](https://img.shields.io/github/stars/shmilylty/cve-2021-22005-exp.svg) ![forks](https://img.shields.io/github/forks/shmilylty/cve-2021-22005-exp.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/TheInterception/Log4J-Simulation-Tool](https://github.com/TheInterception/Log4J-Simulation-Tool) :  ![starts](https://img.shields.io/github/stars/TheInterception/Log4J-Simulation-Tool.svg) ![forks](https://img.shields.io/github/forks/TheInterception/Log4J-Simulation-Tool.svg)


## CVE-2019-15514
 The Privacy &gt; Phone Number feature in the Telegram app 5.10 for Android and iOS provides an incorrect indication that the access level is Nobody, because attackers can find these numbers via the Group Info feature, e.g., by adding a significant fraction of a region's assigned phone numbers.

- [https://github.com/graysuit/CVE-2019-15514](https://github.com/graysuit/CVE-2019-15514) :  ![starts](https://img.shields.io/github/stars/graysuit/CVE-2019-15514.svg) ![forks](https://img.shields.io/github/forks/graysuit/CVE-2019-15514.svg)

