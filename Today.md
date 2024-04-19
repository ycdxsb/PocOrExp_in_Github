# Update 2024-04-19
## CVE-2024-27316
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/aeyesec/CVE-2024-27316_poc](https://github.com/aeyesec/CVE-2024-27316_poc) :  ![starts](https://img.shields.io/github/stars/aeyesec/CVE-2024-27316_poc.svg) ![forks](https://img.shields.io/github/forks/aeyesec/CVE-2024-27316_poc.svg)


## CVE-2024-25600
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/0bl1v10nf0rg0773n/0BL1V10N-CVE-2024-25600-Bricks-Builder-plugin-for-WordPress](https://github.com/0bl1v10nf0rg0773n/0BL1V10N-CVE-2024-25600-Bricks-Builder-plugin-for-WordPress) :  ![starts](https://img.shields.io/github/stars/0bl1v10nf0rg0773n/0BL1V10N-CVE-2024-25600-Bricks-Builder-plugin-for-WordPress.svg) ![forks](https://img.shields.io/github/forks/0bl1v10nf0rg0773n/0BL1V10N-CVE-2024-25600-Bricks-Builder-plugin-for-WordPress.svg)


## CVE-2024-21338
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/UMU618/CVE-2024-21338](https://github.com/UMU618/CVE-2024-21338) :  ![starts](https://img.shields.io/github/stars/UMU618/CVE-2024-21338.svg) ![forks](https://img.shields.io/github/forks/UMU618/CVE-2024-21338.svg)


## CVE-2024-21107
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Alaatk/CVE-2024-21107](https://github.com/Alaatk/CVE-2024-21107) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2024-21107.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2024-21107.svg)


## CVE-2024-1874
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ox1111/-CVE-2024-1874-](https://github.com/ox1111/-CVE-2024-1874-) :  ![starts](https://img.shields.io/github/stars/ox1111/-CVE-2024-1874-.svg) ![forks](https://img.shields.io/github/forks/ox1111/-CVE-2024-1874-.svg)


## CVE-2024-0305
 A vulnerability was found in Guangzhou Yingke Electronic Technology Ncast up to 2017 and classified as problematic. Affected by this issue is some unknown functionality of the file /manage/IPSetup.php of the component Guest Login. The manipulation leads to information disclosure. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-249872.

- [https://github.com/jidle123/cve-2024-0305exp](https://github.com/jidle123/cve-2024-0305exp) :  ![starts](https://img.shields.io/github/stars/jidle123/cve-2024-0305exp.svg) ![forks](https://img.shields.io/github/forks/jidle123/cve-2024-0305exp.svg)


## CVE-2023-46604
 The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client or the broker (respectively) to instantiate any class on the classpath. Users are recommended to upgrade both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 which fixes this issue.

- [https://github.com/vulncheck-oss/cve-2023-46604](https://github.com/vulncheck-oss/cve-2023-46604) :  ![starts](https://img.shields.io/github/stars/vulncheck-oss/cve-2023-46604.svg) ![forks](https://img.shields.io/github/forks/vulncheck-oss/cve-2023-46604.svg)


## CVE-2023-25194
 A possible security vulnerability has been identified in Apache Kafka Connect API. This requires access to a Kafka Connect worker, and the ability to create/modify connectors on it with an arbitrary Kafka client SASL JAAS config and a SASL-based security protocol, which has been possible on Kafka Connect clusters since Apache Kafka Connect 2.3.0. When configuring the connector via the Kafka Connect REST API, an authenticated operator can set the `sasl.jaas.config` property for any of the connector's Kafka clients to &quot;com.sun.security.auth.module.JndiLoginModule&quot;, which can be done via the `producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` properties. This will allow the server to connect to the attacker's LDAP server and deserialize the LDAP response, which the attacker can use to execute java deserialization gadget chains on the Kafka connect server. Attacker can cause unrestricted deserialization of untrusted data (or) RCE vulnerability when there are gadgets in the classpath. Since Apache Kafka 3.0.0, users are allowed to specify these properties in connector configurations for Kafka Connect clusters running with out-of-the-box configurations. Before Apache Kafka 3.0.0, users may not specify these properties unless the Kafka Connect cluster has been reconfigured with a connector client override policy that permits them. Since Apache Kafka 3.4.0, we have added a system property (&quot;-Dorg.apache.kafka.disallowed.login.modules&quot;) to disable the problematic login modules usage in SASL JAAS configuration. Also by default &quot;com.sun.security.auth.module.JndiLoginModule&quot; is disabled in Apache Kafka Connect 3.4.0. We advise the Kafka Connect users to validate connector configurations and only allow trusted JNDI configurations. Also examine connector dependencies for vulnerable versions and either upgrade their connectors, upgrading that specific dependency, or removing the connectors as options for remediation. Finally, in addition to leveraging the &quot;org.apache.kafka.disallowed.login.modules&quot; system property, Kafka Connect users can also implement their own connector client config override policy, which can be used to control which Kafka client properties can be overridden directly in a connector config and which cannot.

- [https://github.com/vulncheck-oss/cve-2023-25194](https://github.com/vulncheck-oss/cve-2023-25194) :  ![starts](https://img.shields.io/github/stars/vulncheck-oss/cve-2023-25194.svg) ![forks](https://img.shields.io/github/forks/vulncheck-oss/cve-2023-25194.svg)


## CVE-2019-10392
 Jenkins Git Client Plugin 2.8.4 and earlier and 3.0.0-rc did not properly restrict values passed as URL argument to an invocation of 'git ls-remote', resulting in OS command injection.

- [https://github.com/jas502n/CVE-2019-10392](https://github.com/jas502n/CVE-2019-10392) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-10392.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-10392.svg)
- [https://github.com/ftk-sostupid/CVE-2019-10392_EXP](https://github.com/ftk-sostupid/CVE-2019-10392_EXP) :  ![starts](https://img.shields.io/github/stars/ftk-sostupid/CVE-2019-10392_EXP.svg) ![forks](https://img.shields.io/github/forks/ftk-sostupid/CVE-2019-10392_EXP.svg)


## CVE-2018-11759
 The Apache Web Server (httpd) specific code that normalised the requested path before matching it to the URI-worker map in Apache Tomcat JK (mod_jk) Connector 1.2.0 to 1.2.44 did not handle some edge cases correctly. If only a sub-set of the URLs supported by Tomcat were exposed via httpd, then it was possible for a specially constructed request to expose application functionality through the reverse proxy that was not intended for clients accessing the application via the reverse proxy. It was also possible in some configurations for a specially constructed request to bypass the access controls configured in httpd. While there is some overlap between this issue and CVE-2018-1323, they are not identical.

- [https://github.com/julioliraup/Identificador-CVE-2018-11759](https://github.com/julioliraup/Identificador-CVE-2018-11759) :  ![starts](https://img.shields.io/github/stars/julioliraup/Identificador-CVE-2018-11759.svg) ![forks](https://img.shields.io/github/forks/julioliraup/Identificador-CVE-2018-11759.svg)


## CVE-2016-2098
 Action Pack in Ruby on Rails before 3.2.22.2, 4.x before 4.1.14.2, and 4.2.x before 4.2.5.2 allows remote attackers to execute arbitrary Ruby code by leveraging an application's unrestricted use of the render method.

- [https://github.com/JoseLRC97/Ruby-on-Rails-ActionPack-Inline-ERB-Remote-Code-Execution](https://github.com/JoseLRC97/Ruby-on-Rails-ActionPack-Inline-ERB-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/JoseLRC97/Ruby-on-Rails-ActionPack-Inline-ERB-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/JoseLRC97/Ruby-on-Rails-ActionPack-Inline-ERB-Remote-Code-Execution.svg)


## CVE-2015-3306
 The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.

- [https://github.com/JoseLRC97/ProFTPd-1.3.5-mod_copy-Remote-Command-Execution](https://github.com/JoseLRC97/ProFTPd-1.3.5-mod_copy-Remote-Command-Execution) :  ![starts](https://img.shields.io/github/stars/JoseLRC97/ProFTPd-1.3.5-mod_copy-Remote-Command-Execution.svg) ![forks](https://img.shields.io/github/forks/JoseLRC97/ProFTPd-1.3.5-mod_copy-Remote-Command-Execution.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/JoseLRC97/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution](https://github.com/JoseLRC97/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution) :  ![starts](https://img.shields.io/github/stars/JoseLRC97/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution.svg) ![forks](https://img.shields.io/github/forks/JoseLRC97/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution.svg)

