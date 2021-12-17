# Update 2021-12-17
## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in a denial of service (DOS) attack. Log4j 2.15.0 makes a best-effort attempt to restrict JNDI LDAP lookups to localhost by default. Log4j 2.16.0 fixes this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words](https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words) :  ![starts](https://img.shields.io/github/stars/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words.svg) ![forks](https://img.shields.io/github/forks/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words.svg)
- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)
- [https://github.com/mergebase/log4j-detector](https://github.com/mergebase/log4j-detector) :  ![starts](https://img.shields.io/github/stars/mergebase/log4j-detector.svg) ![forks](https://img.shields.io/github/forks/mergebase/log4j-detector.svg)
- [https://github.com/fox-it/log4j-finder](https://github.com/fox-it/log4j-finder) :  ![starts](https://img.shields.io/github/stars/fox-it/log4j-finder.svg) ![forks](https://img.shields.io/github/forks/fox-it/log4j-finder.svg)
- [https://github.com/alexbakker/log4shell-tools](https://github.com/alexbakker/log4shell-tools) :  ![starts](https://img.shields.io/github/stars/alexbakker/log4shell-tools.svg) ![forks](https://img.shields.io/github/forks/alexbakker/log4shell-tools.svg)
- [https://github.com/xsultan/log4jshield](https://github.com/xsultan/log4jshield) :  ![starts](https://img.shields.io/github/stars/xsultan/log4jshield.svg) ![forks](https://img.shields.io/github/forks/xsultan/log4jshield.svg)
- [https://github.com/BobTheShoplifter/CVE-2021-45046-Info](https://github.com/BobTheShoplifter/CVE-2021-45046-Info) :  ![starts](https://img.shields.io/github/stars/BobTheShoplifter/CVE-2021-45046-Info.svg) ![forks](https://img.shields.io/github/forks/BobTheShoplifter/CVE-2021-45046-Info.svg)
- [https://github.com/DXC-StrikeForce/Burp-Log4j-HammerTime](https://github.com/DXC-StrikeForce/Burp-Log4j-HammerTime) :  ![starts](https://img.shields.io/github/stars/DXC-StrikeForce/Burp-Log4j-HammerTime.svg) ![forks](https://img.shields.io/github/forks/DXC-StrikeForce/Burp-Log4j-HammerTime.svg)
- [https://github.com/andalik/log4j-filescan](https://github.com/andalik/log4j-filescan) :  ![starts](https://img.shields.io/github/stars/andalik/log4j-filescan.svg) ![forks](https://img.shields.io/github/forks/andalik/log4j-filescan.svg)
- [https://github.com/gitlab-de/log4j-resources](https://github.com/gitlab-de/log4j-resources) :  ![starts](https://img.shields.io/github/stars/gitlab-de/log4j-resources.svg) ![forks](https://img.shields.io/github/forks/gitlab-de/log4j-resources.svg)
- [https://github.com/tejas-nagchandi/CVE-2021-45046](https://github.com/tejas-nagchandi/CVE-2021-45046) :  ![starts](https://img.shields.io/github/stars/tejas-nagchandi/CVE-2021-45046.svg) ![forks](https://img.shields.io/github/forks/tejas-nagchandi/CVE-2021-45046.svg)
- [https://github.com/pravin-pp/log4j2-CVE-2021-45046](https://github.com/pravin-pp/log4j2-CVE-2021-45046) :  ![starts](https://img.shields.io/github/stars/pravin-pp/log4j2-CVE-2021-45046.svg) ![forks](https://img.shields.io/github/forks/pravin-pp/log4j2-CVE-2021-45046.svg)


## CVE-2021-45043
 HD-Network Real-time Monitoring System 2.0 allows ../ directory traversal to read /etc/shadow via the /language/lang s_Language parameter.

- [https://github.com/g30rgyth3d4rk/cve-2021-45043](https://github.com/g30rgyth3d4rk/cve-2021-45043) :  ![starts](https://img.shields.io/github/stars/g30rgyth3d4rk/cve-2021-45043.svg) ![forks](https://img.shields.io/github/forks/g30rgyth3d4rk/cve-2021-45043.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/mergebase/log4j-detector](https://github.com/mergebase/log4j-detector) :  ![starts](https://img.shields.io/github/stars/mergebase/log4j-detector.svg) ![forks](https://img.shields.io/github/forks/mergebase/log4j-detector.svg)
- [https://github.com/curated-intel/Log4Shell-IOCs](https://github.com/curated-intel/Log4Shell-IOCs) :  ![starts](https://img.shields.io/github/stars/curated-intel/Log4Shell-IOCs.svg) ![forks](https://img.shields.io/github/forks/curated-intel/Log4Shell-IOCs.svg)
- [https://github.com/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent](https://github.com/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent) :  ![starts](https://img.shields.io/github/stars/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent.svg) ![forks](https://img.shields.io/github/forks/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent.svg)
- [https://github.com/stripe/log4j-remediation-tools](https://github.com/stripe/log4j-remediation-tools) :  ![starts](https://img.shields.io/github/stars/stripe/log4j-remediation-tools.svg) ![forks](https://img.shields.io/github/forks/stripe/log4j-remediation-tools.svg)
- [https://github.com/thomaspatzke/Log4Pot](https://github.com/thomaspatzke/Log4Pot) :  ![starts](https://img.shields.io/github/stars/thomaspatzke/Log4Pot.svg) ![forks](https://img.shields.io/github/forks/thomaspatzke/Log4Pot.svg)
- [https://github.com/corelight/cve-2021-44228](https://github.com/corelight/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/corelight/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/corelight/cve-2021-44228.svg)
- [https://github.com/faisalfs10x/Log4j2-CVE-2021-44228-revshell](https://github.com/faisalfs10x/Log4j2-CVE-2021-44228-revshell) :  ![starts](https://img.shields.io/github/stars/faisalfs10x/Log4j2-CVE-2021-44228-revshell.svg) ![forks](https://img.shields.io/github/forks/faisalfs10x/Log4j2-CVE-2021-44228-revshell.svg)
- [https://github.com/xsultan/log4jshield](https://github.com/xsultan/log4jshield) :  ![starts](https://img.shields.io/github/stars/xsultan/log4jshield.svg) ![forks](https://img.shields.io/github/forks/xsultan/log4jshield.svg)
- [https://github.com/ab0x90/CVE-2021-44228_PoC](https://github.com/ab0x90/CVE-2021-44228_PoC) :  ![starts](https://img.shields.io/github/stars/ab0x90/CVE-2021-44228_PoC.svg) ![forks](https://img.shields.io/github/forks/ab0x90/CVE-2021-44228_PoC.svg)
- [https://github.com/robertdebock/ansible-role-cve_2021_44228](https://github.com/robertdebock/ansible-role-cve_2021_44228) :  ![starts](https://img.shields.io/github/stars/robertdebock/ansible-role-cve_2021_44228.svg) ![forks](https://img.shields.io/github/forks/robertdebock/ansible-role-cve_2021_44228.svg)
- [https://github.com/mitiga/log4shell-cloud-scanner](https://github.com/mitiga/log4shell-cloud-scanner) :  ![starts](https://img.shields.io/github/stars/mitiga/log4shell-cloud-scanner.svg) ![forks](https://img.shields.io/github/forks/mitiga/log4shell-cloud-scanner.svg)
- [https://github.com/kubearmor/log4j-CVE-2021-44228](https://github.com/kubearmor/log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/kubearmor/log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/kubearmor/log4j-CVE-2021-44228.svg)
- [https://github.com/myyxl/cve-2021-44228-minecraft-poc](https://github.com/myyxl/cve-2021-44228-minecraft-poc) :  ![starts](https://img.shields.io/github/stars/myyxl/cve-2021-44228-minecraft-poc.svg) ![forks](https://img.shields.io/github/forks/myyxl/cve-2021-44228-minecraft-poc.svg)
- [https://github.com/thecyberneh/Log4j-RCE-Exploiter](https://github.com/thecyberneh/Log4j-RCE-Exploiter) :  ![starts](https://img.shields.io/github/stars/thecyberneh/Log4j-RCE-Exploiter.svg) ![forks](https://img.shields.io/github/forks/thecyberneh/Log4j-RCE-Exploiter.svg)


## CVE-2021-41962
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/lohyt/-CVE-2021-41962](https://github.com/lohyt/-CVE-2021-41962) :  ![starts](https://img.shields.io/github/stars/lohyt/-CVE-2021-41962.svg) ![forks](https://img.shields.io/github/forks/lohyt/-CVE-2021-41962.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/onsecuredev/CVE-2021-41773](https://github.com/onsecuredev/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-41773.svg)


## CVE-2021-40870
 An issue was discovered in Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal.

- [https://github.com/onsecuredev/CVE-2021-40870](https://github.com/onsecuredev/CVE-2021-40870) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-40870.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-40870.svg)


## CVE-2021-40444
 Microsoft MSHTML Remote Code Execution Vulnerability

- [https://github.com/kal1gh0st/CVE-2021-40444_CAB_archives](https://github.com/kal1gh0st/CVE-2021-40444_CAB_archives) :  ![starts](https://img.shields.io/github/stars/kal1gh0st/CVE-2021-40444_CAB_archives.svg) ![forks](https://img.shields.io/github/forks/kal1gh0st/CVE-2021-40444_CAB_archives.svg)


## CVE-2021-39685
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/szymonh/inspector-gadget](https://github.com/szymonh/inspector-gadget) :  ![starts](https://img.shields.io/github/stars/szymonh/inspector-gadget.svg) ![forks](https://img.shields.io/github/forks/szymonh/inspector-gadget.svg)


## CVE-2021-38314
 The Gutenberg Template Library &amp; Redux Framework plugin &lt;= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site&#8217;s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.

- [https://github.com/onsecuredev/CVE-2021-38314](https://github.com/onsecuredev/CVE-2021-38314) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-38314.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-38314.svg)


## CVE-2021-30573
 Use after free in GPU in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/onsecuredev/CVE-2021-30573](https://github.com/onsecuredev/CVE-2021-30573) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-30573.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-30573.svg)


## CVE-2021-27651
 In versions 8.2.1 through 8.5.2 of Pega Infinity, the password reset functionality for local accounts can be used to bypass local authentication checks.

- [https://github.com/onsecuredev/CVE-2021-27651](https://github.com/onsecuredev/CVE-2021-27651) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-27651.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-27651.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/onsecuredev/CVE-2021-26084](https://github.com/onsecuredev/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-26084.svg)
- [https://github.com/b1gw00d/CVE-2021-26084](https://github.com/b1gw00d/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/b1gw00d/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/b1gw00d/CVE-2021-26084.svg)


## CVE-2021-23758
 All versions of package ajaxpro.2 are vulnerable to Deserialization of Untrusted Data due to the possibility of deserialization of arbitrary .NET classes, which can be abused to gain remote code execution.

- [https://github.com/numanturle/CVE-2021-23758-POC](https://github.com/numanturle/CVE-2021-23758-POC) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2021-23758-POC.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2021-23758-POC.svg)


## CVE-2021-22893
 Pulse Connect Secure 9.0R3/9.1R1 and higher is vulnerable to an authentication bypass vulnerability exposed by the Windows File Share Browser and Pulse Secure Collaboration features of Pulse Connect Secure that can allow an unauthenticated user to perform remote arbitrary code execution on the Pulse Connect Secure gateway. This vulnerability has been exploited in the wild.

- [https://github.com/onsecuredev/CVE-2021-22893](https://github.com/onsecuredev/CVE-2021-22893) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-22893.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-22893.svg)


## CVE-2021-21972
 The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

- [https://github.com/onsecuredev/CVE-2021-21972](https://github.com/onsecuredev/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-21972.svg)


## CVE-2021-20837
 Movable Type 7 r.5002 and earlier (Movable Type 7 Series), Movable Type 6.8.2 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.5002 and earlier (Movable Type Advanced 7 Series), Movable Type Advanced 6.8.2 and earlier (Movable Type Advanced 6 Series), Movable Type Premium 1.46 and earlier, and Movable Type Premium Advanced 1.46 and earlier allow remote attackers to execute arbitrary OS commands via unspecified vectors. Note that all versions of Movable Type 4.0 or later including unsupported (End-of-Life, EOL) versions are also affected by this vulnerability.

- [https://github.com/onsecuredev/CVE-2021-20837](https://github.com/onsecuredev/CVE-2021-20837) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-20837.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-20837.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/cckuailong/log4shell_1.x](https://github.com/cckuailong/log4shell_1.x) :  ![starts](https://img.shields.io/github/stars/cckuailong/log4shell_1.x.svg) ![forks](https://img.shields.io/github/forks/cckuailong/log4shell_1.x.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/kal1gh0st/CVE-2021-3156](https://github.com/kal1gh0st/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/kal1gh0st/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/kal1gh0st/CVE-2021-3156.svg)


## CVE-2021-2394
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/fasanhlieu/CVE-2021-2394](https://github.com/fasanhlieu/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/fasanhlieu/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/fasanhlieu/CVE-2021-2394.svg)


## CVE-2020-17382
 The MSI AmbientLink MsIo64 driver 1.0.0.8 has a Buffer Overflow (0x80102040, 0x80102044, 0x80102050,and 0x80102054).

- [https://github.com/awsassets/CVE-2020-17382](https://github.com/awsassets/CVE-2020-17382) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2020-17382.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2020-17382.svg)


## CVE-2020-7209
 LinuxKI v6.0-1 and earlier is vulnerable to an remote code execution which is resolved in release 6.0-2.

- [https://github.com/awsassets/CVE-2020-7209](https://github.com/awsassets/CVE-2020-7209) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2020-7209.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2020-7209.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/sgdream/CVE-2020-1938](https://github.com/sgdream/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/sgdream/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/sgdream/CVE-2020-1938.svg)


## CVE-2020-0905
 An remote code execution vulnerability exists in Microsoft Dynamics Business Central, aka 'Dynamics Business Central Remote Code Execution Vulnerability'.

- [https://github.com/awsassets/CVE-2020-0905](https://github.com/awsassets/CVE-2020-0905) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2020-0905.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2020-0905.svg)


## CVE-2020-0883
 A remote code execution vulnerability exists in the way that the Windows Graphics Device Interface (GDI) handles objects in the memory, aka 'GDI+ Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0881.

- [https://github.com/awsassets/CVE-2020-0883](https://github.com/awsassets/CVE-2020-0883) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2020-0883.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2020-0883.svg)


## CVE-2020-0798
 An elevation of privilege vulnerability exists in the Windows Installer when the Windows Installer fails to properly sanitize input leading to an insecure library loading behavior.A locally authenticated attacker could run arbitrary code with elevated system privileges, aka 'Windows Installer Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0779, CVE-2020-0814, CVE-2020-0842, CVE-2020-0843.

- [https://github.com/awsassets/CVE-2020-0798](https://github.com/awsassets/CVE-2020-0798) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2020-0798.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2020-0798.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/onsecuredev/CVE-2020-0796](https://github.com/onsecuredev/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2020-0796.svg)
- [https://github.com/5l1v3r1/CVE-2020-0796-PoC-3](https://github.com/5l1v3r1/CVE-2020-0796-PoC-3) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-0796-PoC-3.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-0796-PoC-3.svg)
- [https://github.com/awsassets/CVE-2020-0798](https://github.com/awsassets/CVE-2020-0798) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2020-0798.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2020-0798.svg)


## CVE-2020-0692
 An elevation of privilege vulnerability exists in Microsoft Exchange Server, aka 'Microsoft Exchange Server Elevation of Privilege Vulnerability'.

- [https://github.com/awsassets/CVE-2020-0692](https://github.com/awsassets/CVE-2020-0692) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2020-0692.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2020-0692.svg)


## CVE-2020-0688
 A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.

- [https://github.com/awsassets/CVE-2020-0692](https://github.com/awsassets/CVE-2020-0692) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2020-0692.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2020-0692.svg)


## CVE-2019-15858
 admin/includes/class.import.snippet.php in the &quot;Woody ad snippets&quot; plugin before 2.2.5 for WordPress allows unauthenticated options import, as demonstrated by storing an XSS payload for remote code execution.

- [https://github.com/onsecuredev/CVE-2019-15858](https://github.com/onsecuredev/CVE-2019-15858) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2019-15858.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2019-15858.svg)


## CVE-2019-11932
 A double free vulnerability in the DDGifSlurp function in decoding.c in the android-gif-drawable library before version 1.2.18, as used in WhatsApp for Android before version 2.19.244 and many other Android applications, allows remote attackers to execute arbitrary code or cause a denial of service when the library is used to parse a specially crafted GIF image.

- [https://github.com/kal1gh0st/WhatsAppHACK-RCE](https://github.com/kal1gh0st/WhatsAppHACK-RCE) :  ![starts](https://img.shields.io/github/stars/kal1gh0st/WhatsAppHACK-RCE.svg) ![forks](https://img.shields.io/github/forks/kal1gh0st/WhatsAppHACK-RCE.svg)


## CVE-2018-15961
 Adobe ColdFusion versions July 12 release (2018.0.0.310739), Update 6 and earlier, and Update 14 and earlier have an unrestricted file upload vulnerability. Successful exploitation could lead to arbitrary code execution.

- [https://github.com/onsecuredev/CVE-2018-15961](https://github.com/onsecuredev/CVE-2018-15961) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2018-15961.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2018-15961.svg)


## CVE-2016-10956
 The mail-masta plugin 1.0 for WordPress has local file inclusion in count_of_send.php and csvexport.php.

- [https://github.com/p0dalirius/CVE-2016-10956_mail_masta](https://github.com/p0dalirius/CVE-2016-10956_mail_masta) :  ![starts](https://img.shields.io/github/stars/p0dalirius/CVE-2016-10956_mail_masta.svg) ![forks](https://img.shields.io/github/forks/p0dalirius/CVE-2016-10956_mail_masta.svg)

