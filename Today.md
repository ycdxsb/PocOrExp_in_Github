# Update 2023-10-09
## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/joaoviictorti/CVE-2023-38646](https://github.com/joaoviictorti/CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/joaoviictorti/CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/joaoviictorti/CVE-2023-38646.svg)


## CVE-2023-37988
 Unauth. Reflected Cross-Site Scripting (XSS) vulnerability in Creative Solutions Contact Form Generator plugin &lt;= 2.5.5 versions.

- [https://github.com/codeb0ss/CVE-2023-37988-PoC](https://github.com/codeb0ss/CVE-2023-37988-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-37988-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-37988-PoC.svg)


## CVE-2023-25194
 A possible security vulnerability has been identified in Apache Kafka Connect API. This requires access to a Kafka Connect worker, and the ability to create/modify connectors on it with an arbitrary Kafka client SASL JAAS config and a SASL-based security protocol, which has been possible on Kafka Connect clusters since Apache Kafka Connect 2.3.0. When configuring the connector via the Kafka Connect REST API, an authenticated operator can set the `sasl.jaas.config` property for any of the connector's Kafka clients to &quot;com.sun.security.auth.module.JndiLoginModule&quot;, which can be done via the `producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` properties. This will allow the server to connect to the attacker's LDAP server and deserialize the LDAP response, which the attacker can use to execute java deserialization gadget chains on the Kafka connect server. Attacker can cause unrestricted deserialization of untrusted data (or) RCE vulnerability when there are gadgets in the classpath. Since Apache Kafka 3.0.0, users are allowed to specify these properties in connector configurations for Kafka Connect clusters running with out-of-the-box configurations. Before Apache Kafka 3.0.0, users may not specify these properties unless the Kafka Connect cluster has been reconfigured with a connector client override policy that permits them. Since Apache Kafka 3.4.0, we have added a system property (&quot;-Dorg.apache.kafka.disallowed.login.modules&quot;) to disable the problematic login modules usage in SASL JAAS configuration. Also by default &quot;com.sun.security.auth.module.JndiLoginModule&quot; is disabled in Apache Kafka Connect 3.4.0. We advise the Kafka Connect users to validate connector configurations and only allow trusted JNDI configurations. Also examine connector dependencies for vulnerable versions and either upgrade their connectors, upgrading that specific dependency, or removing the connectors as options for remediation. Finally, in addition to leveraging the &quot;org.apache.kafka.disallowed.login.modules&quot; system property, Kafka Connect users can also implement their own connector client config override policy, which can be used to control which Kafka client properties can be overridden directly in a connector config and which cannot.

- [https://github.com/ohnonoyesyes/CVE-2023-25194](https://github.com/ohnonoyesyes/CVE-2023-25194) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2023-25194.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2023-25194.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/xiaoQ1z/CVE-2023-4911](https://github.com/xiaoQ1z/CVE-2023-4911) :  ![starts](https://img.shields.io/github/stars/xiaoQ1z/CVE-2023-4911.svg) ![forks](https://img.shields.io/github/forks/xiaoQ1z/CVE-2023-4911.svg)


## CVE-2023-4128
 A use-after-free flaw was found in net/sched/cls_fw.c in classifiers (cls_fw, cls_u32, and cls_route) in the Linux Kernel. This flaw allows a local attacker to perform a local privilege escalation due to incorrect handling of the existing filter, leading to a kernel information leak issue.

- [https://github.com/Trinadh465/linux-4.1.15_CVE-2023-4128](https://github.com/Trinadh465/linux-4.1.15_CVE-2023-4128) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.1.15_CVE-2023-4128.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.1.15_CVE-2023-4128.svg)


## CVE-2022-32548
 An issue was discovered on certain DrayTek Vigor routers before July 2022 such as the Vigor3910 before 4.3.1.1. /cgi-bin/wlogin.cgi has a buffer overflow via the username or password to the aa or ab field.

- [https://github.com/gl3s7/CVE-2022-32548-PoC](https://github.com/gl3s7/CVE-2022-32548-PoC) :  ![starts](https://img.shields.io/github/stars/gl3s7/CVE-2022-32548-PoC.svg) ![forks](https://img.shields.io/github/forks/gl3s7/CVE-2022-32548-PoC.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/sule01u/SBSCAN](https://github.com/sule01u/SBSCAN) :  ![starts](https://img.shields.io/github/stars/sule01u/SBSCAN.svg) ![forks](https://img.shields.io/github/forks/sule01u/SBSCAN.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/sule01u/SBSCAN](https://github.com/sule01u/SBSCAN) :  ![starts](https://img.shields.io/github/stars/sule01u/SBSCAN.svg) ![forks](https://img.shields.io/github/forks/sule01u/SBSCAN.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/sule01u/SBSCAN](https://github.com/sule01u/SBSCAN) :  ![starts](https://img.shields.io/github/stars/sule01u/SBSCAN.svg) ![forks](https://img.shields.io/github/forks/sule01u/SBSCAN.svg)


## CVE-2022-3602
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/colmmacc/CVE-2022-3602](https://github.com/colmmacc/CVE-2022-3602) :  ![starts](https://img.shields.io/github/stars/colmmacc/CVE-2022-3602.svg) ![forks](https://img.shields.io/github/forks/colmmacc/CVE-2022-3602.svg)
- [https://github.com/alicangnll/SpookySSL-Scanner](https://github.com/alicangnll/SpookySSL-Scanner) :  ![starts](https://img.shields.io/github/stars/alicangnll/SpookySSL-Scanner.svg) ![forks](https://img.shields.io/github/forks/alicangnll/SpookySSL-Scanner.svg)


## CVE-2021-45468
 Imperva Web Application Firewall (WAF) before 2021-12-23 allows remote unauthenticated attackers to use &quot;Content-Encoding: gzip&quot; to evade WAF security controls and send malicious HTTP POST requests to web servers behind the WAF.

- [https://github.com/0xhaggis/Imperva_gzip_bypass](https://github.com/0xhaggis/Imperva_gzip_bypass) :  ![starts](https://img.shields.io/github/stars/0xhaggis/Imperva_gzip_bypass.svg) ![forks](https://img.shields.io/github/forks/0xhaggis/Imperva_gzip_bypass.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-41073
 loop_rw_iter in fs/io_uring.c in the Linux kernel 5.10 through 5.14.6 allows local users to gain privileges by using IORING_OP_PROVIDE_BUFFERS to trigger a free of a kernel buffer, as demonstrated by using /proc/&lt;pid&gt;/maps for exploitation.

- [https://github.com/OneFriendlyCoder/cve2021-41073](https://github.com/OneFriendlyCoder/cve2021-41073) :  ![starts](https://img.shields.io/github/stars/OneFriendlyCoder/cve2021-41073.svg) ![forks](https://img.shields.io/github/forks/OneFriendlyCoder/cve2021-41073.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/zzwlpx/weblogicPoc](https://github.com/zzwlpx/weblogicPoc) :  ![starts](https://img.shields.io/github/stars/zzwlpx/weblogicPoc.svg) ![forks](https://img.shields.io/github/forks/zzwlpx/weblogicPoc.svg)


## CVE-2017-10271
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/Min-yeon/CVE-2017-10271](https://github.com/Min-yeon/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/Min-yeon/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/Min-yeon/CVE-2017-10271.svg)

