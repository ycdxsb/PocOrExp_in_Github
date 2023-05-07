# Update 2023-05-07
## CVE-2023-30185
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/c7w1n/CVE-2023-30185](https://github.com/c7w1n/CVE-2023-30185) :  ![starts](https://img.shields.io/github/stars/c7w1n/CVE-2023-30185.svg) ![forks](https://img.shields.io/github/forks/c7w1n/CVE-2023-30185.svg)


## CVE-2023-29489
 An issue was discovered in cPanel before 11.109.9999.116. XSS can occur on the cpsrvd error page via an invalid webcall ID, aka SEC-669. The fixed versions are 11.109.9999.116, 11.108.0.13, 11.106.0.18, and 11.102.0.31.

- [https://github.com/1337r0j4n/CVE-2023-29489](https://github.com/1337r0j4n/CVE-2023-29489) :  ![starts](https://img.shields.io/github/stars/1337r0j4n/CVE-2023-29489.svg) ![forks](https://img.shields.io/github/forks/1337r0j4n/CVE-2023-29489.svg)


## CVE-2023-28929
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/glencooper872/excel-zero-day-exploit](https://github.com/glencooper872/excel-zero-day-exploit) :  ![starts](https://img.shields.io/github/stars/glencooper872/excel-zero-day-exploit.svg) ![forks](https://img.shields.io/github/forks/glencooper872/excel-zero-day-exploit.svg)
- [https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass](https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass) :  ![starts](https://img.shields.io/github/stars/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg)


## CVE-2023-28771
 Improper error message handling in Zyxel ZyWALL/USG series firmware versions 4.60 through 4.73, VPN series firmware versions 4.60 through 5.35, USG FLEX series firmware versions 4.60 through 5.35, and ATP series firmware versions 4.60 through 5.35, which could allow an unauthenticated attacker to execute some OS commands remotely by sending crafted packets to an affected device.

- [https://github.com/glencooper872/excel-zero-day-exploit](https://github.com/glencooper872/excel-zero-day-exploit) :  ![starts](https://img.shields.io/github/stars/glencooper872/excel-zero-day-exploit.svg) ![forks](https://img.shields.io/github/forks/glencooper872/excel-zero-day-exploit.svg)
- [https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass](https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass) :  ![starts](https://img.shields.io/github/stars/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg)


## CVE-2023-28231
 DHCP Server Service Remote Code Execution Vulnerability

- [https://github.com/glencooper872/excel-zero-day-exploit](https://github.com/glencooper872/excel-zero-day-exploit) :  ![starts](https://img.shields.io/github/stars/glencooper872/excel-zero-day-exploit.svg) ![forks](https://img.shields.io/github/forks/glencooper872/excel-zero-day-exploit.svg)
- [https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass](https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass) :  ![starts](https://img.shields.io/github/stars/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg)
- [https://github.com/glavstroy/CVE-2023-28231](https://github.com/glavstroy/CVE-2023-28231) :  ![starts](https://img.shields.io/github/stars/glavstroy/CVE-2023-28231.svg) ![forks](https://img.shields.io/github/forks/glavstroy/CVE-2023-28231.svg)


## CVE-2023-27326
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Malwareman007/CVE-2023-27326](https://github.com/Malwareman007/CVE-2023-27326) :  ![starts](https://img.shields.io/github/stars/Malwareman007/CVE-2023-27326.svg) ![forks](https://img.shields.io/github/forks/Malwareman007/CVE-2023-27326.svg)


## CVE-2023-25194
 A possible security vulnerability has been identified in Apache Kafka Connect. This requires access to a Kafka Connect worker, and the ability to create/modify connectors on it with an arbitrary Kafka client SASL JAAS config and a SASL-based security protocol, which has been possible on Kafka Connect clusters since Apache Kafka 2.3.0. When configuring the connector via the Kafka Connect REST API, an authenticated operator can set the `sasl.jaas.config` property for any of the connector's Kafka clients to &quot;com.sun.security.auth.module.JndiLoginModule&quot;, which can be done via the `producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` properties. This will allow the server to connect to the attacker's LDAP server and deserialize the LDAP response, which the attacker can use to execute java deserialization gadget chains on the Kafka connect server. Attacker can cause unrestricted deserialization of untrusted data (or) RCE vulnerability when there are gadgets in the classpath. Since Apache Kafka 3.0.0, users are allowed to specify these properties in connector configurations for Kafka Connect clusters running with out-of-the-box configurations. Before Apache Kafka 3.0.0, users may not specify these properties unless the Kafka Connect cluster has been reconfigured with a connector client override policy that permits them. Since Apache Kafka 3.4.0, we have added a system property (&quot;-Dorg.apache.kafka.disallowed.login.modules&quot;) to disable the problematic login modules usage in SASL JAAS configuration. Also by default &quot;com.sun.security.auth.module.JndiLoginModule&quot; is disabled in Apache Kafka 3.4.0. We advise the Kafka Connect users to validate connector configurations and only allow trusted JNDI configurations. Also examine connector dependencies for vulnerable versions and either upgrade their connectors, upgrading that specific dependency, or removing the connectors as options for remediation. Finally, in addition to leveraging the &quot;org.apache.kafka.disallowed.login.modules&quot; system property, Kafka Connect users can also implement their own connector client config override policy, which can be used to control which Kafka client properties can be overridden directly in a connector config and which cannot.

- [https://github.com/Avento/Apache_Druid_JNDI_Vuln](https://github.com/Avento/Apache_Druid_JNDI_Vuln) :  ![starts](https://img.shields.io/github/stars/Avento/Apache_Druid_JNDI_Vuln.svg) ![forks](https://img.shields.io/github/forks/Avento/Apache_Druid_JNDI_Vuln.svg)


## CVE-2023-21932
 Vulnerability in the Oracle Hospitality OPERA 5 Property Services product of Oracle Hospitality Applications (component: OXI). The supported version that is affected is 5.6. Difficult to exploit vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle Hospitality OPERA 5 Property Services. While the vulnerability is in Oracle Hospitality OPERA 5 Property Services, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Hospitality OPERA 5 Property Services accessible data as well as unauthorized update, insert or delete access to some of Oracle Hospitality OPERA 5 Property Services accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Hospitality OPERA 5 Property Services. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:L/A:L).

- [https://github.com/glencooper872/excel-zero-day-exploit](https://github.com/glencooper872/excel-zero-day-exploit) :  ![starts](https://img.shields.io/github/stars/glencooper872/excel-zero-day-exploit.svg) ![forks](https://img.shields.io/github/forks/glencooper872/excel-zero-day-exploit.svg)
- [https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass](https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass) :  ![starts](https://img.shields.io/github/stars/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg)


## CVE-2023-21839
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/glencooper872/excel-zero-day-exploit](https://github.com/glencooper872/excel-zero-day-exploit) :  ![starts](https://img.shields.io/github/stars/glencooper872/excel-zero-day-exploit.svg) ![forks](https://img.shields.io/github/forks/glencooper872/excel-zero-day-exploit.svg)
- [https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass](https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass) :  ![starts](https://img.shields.io/github/stars/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg)


## CVE-2023-21707
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass](https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass) :  ![starts](https://img.shields.io/github/stars/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg)
- [https://github.com/glencooper872/excel-zero-day-exploit](https://github.com/glencooper872/excel-zero-day-exploit) :  ![starts](https://img.shields.io/github/stars/glencooper872/excel-zero-day-exploit.svg) ![forks](https://img.shields.io/github/forks/glencooper872/excel-zero-day-exploit.svg)


## CVE-2023-20126
 A vulnerability in the web-based management interface of Cisco SPA112 2-Port Phone Adapters could allow an unauthenticated, remote attacker to execute arbitrary code on an affected device. This vulnerability is due to a missing authentication process within the firmware upgrade function. An attacker could exploit this vulnerability by upgrading an affected device to a crafted version of firmware. A successful exploit could allow the attacker to execute arbitrary code on the affected device with full privileges. Cisco has not released firmware updates to address this vulnerability.

- [https://github.com/glencooper872/excel-zero-day-exploit](https://github.com/glencooper872/excel-zero-day-exploit) :  ![starts](https://img.shields.io/github/stars/glencooper872/excel-zero-day-exploit.svg) ![forks](https://img.shields.io/github/forks/glencooper872/excel-zero-day-exploit.svg)
- [https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass](https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass) :  ![starts](https://img.shields.io/github/stars/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg)


## CVE-2023-2131
 Versions of INEA ME RTU firmware prior to 3.36 are vulnerable to OS command injection, which could allow an attacker to remotely execute arbitrary code.

- [https://github.com/glencooper872/excel-zero-day-exploit](https://github.com/glencooper872/excel-zero-day-exploit) :  ![starts](https://img.shields.io/github/stars/glencooper872/excel-zero-day-exploit.svg) ![forks](https://img.shields.io/github/forks/glencooper872/excel-zero-day-exploit.svg)
- [https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass](https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass) :  ![starts](https://img.shields.io/github/stars/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg)


## CVE-2023-1389
 TP-Link Archer AX21 (AX1800) firmware versions before 1.1.4 Build 20230219 contained a command injection vulnerability in the country form of the /cgi-bin/luci;stok=/locale endpoint on the web management interface. Specifically, the country parameter of the write operation was not sanitized before being used in a call to popen(), allowing an unauthenticated attacker to inject commands, which would be run as root, with a simple POST request.

- [https://github.com/glencooper872/excel-zero-day-exploit](https://github.com/glencooper872/excel-zero-day-exploit) :  ![starts](https://img.shields.io/github/stars/glencooper872/excel-zero-day-exploit.svg) ![forks](https://img.shields.io/github/forks/glencooper872/excel-zero-day-exploit.svg)
- [https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass](https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass) :  ![starts](https://img.shields.io/github/stars/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/RSA-Demo/cve-2022-42889-text4shell](https://github.com/RSA-Demo/cve-2022-42889-text4shell) :  ![starts](https://img.shields.io/github/stars/RSA-Demo/cve-2022-42889-text4shell.svg) ![forks](https://img.shields.io/github/forks/RSA-Demo/cve-2022-42889-text4shell.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/glencooper872/excel-zero-day-exploit](https://github.com/glencooper872/excel-zero-day-exploit) :  ![starts](https://img.shields.io/github/stars/glencooper872/excel-zero-day-exploit.svg) ![forks](https://img.shields.io/github/forks/glencooper872/excel-zero-day-exploit.svg)
- [https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass](https://github.com/glencooper872/tightvnc-zeroday-exploit-auth-bypass) :  ![starts](https://img.shields.io/github/stars/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/glencooper872/tightvnc-zeroday-exploit-auth-bypass.svg)


## CVE-2021-32160
 A Cross-Site Scripting (XSS) vulnerability exists in Webmin 1.973 through the Add Users feature.

- [https://github.com/Mesh3l911/CVE-2021-32160](https://github.com/Mesh3l911/CVE-2021-32160) :  ![starts](https://img.shields.io/github/stars/Mesh3l911/CVE-2021-32160.svg) ![forks](https://img.shields.io/github/forks/Mesh3l911/CVE-2021-32160.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/G0urmetD/Zerologon-CVE-2020-1472](https://github.com/G0urmetD/Zerologon-CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/G0urmetD/Zerologon-CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/G0urmetD/Zerologon-CVE-2020-1472.svg)


## CVE-2019-1253
 An elevation of privilege vulnerability exists when the Windows AppX Deployment Server improperly handles junctions.To exploit this vulnerability, an attacker would first have to gain execution on the victim system, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1215, CVE-2019-1278, CVE-2019-1303.

- [https://github.com/padovah4ck/CVE-2019-1253](https://github.com/padovah4ck/CVE-2019-1253) :  ![starts](https://img.shields.io/github/stars/padovah4ck/CVE-2019-1253.svg) ![forks](https://img.shields.io/github/forks/padovah4ck/CVE-2019-1253.svg)
- [https://github.com/likescam/CVE-2019-1253](https://github.com/likescam/CVE-2019-1253) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2019-1253.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2019-1253.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/GaboLC98/userenum-CVE-2018-15473](https://github.com/GaboLC98/userenum-CVE-2018-15473) :  ![starts](https://img.shields.io/github/stars/GaboLC98/userenum-CVE-2018-15473.svg) ![forks](https://img.shields.io/github/forks/GaboLC98/userenum-CVE-2018-15473.svg)


## CVE-2018-13379
 An Improper Limitation of a Pathname to a Restricted Directory (&quot;Path Traversal&quot;) in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 and 5.4.6 to 5.4.12 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, 1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows an unauthenticated attacker to download system files via special crafted HTTP resource requests.

- [https://github.com/Blazz3/cve2018-13379-nmap-script](https://github.com/Blazz3/cve2018-13379-nmap-script) :  ![starts](https://img.shields.io/github/stars/Blazz3/cve2018-13379-nmap-script.svg) ![forks](https://img.shields.io/github/forks/Blazz3/cve2018-13379-nmap-script.svg)
- [https://github.com/Zeop-CyberSec/fortios_vpnssl_traversal_leak](https://github.com/Zeop-CyberSec/fortios_vpnssl_traversal_leak) :  ![starts](https://img.shields.io/github/stars/Zeop-CyberSec/fortios_vpnssl_traversal_leak.svg) ![forks](https://img.shields.io/github/forks/Zeop-CyberSec/fortios_vpnssl_traversal_leak.svg)

