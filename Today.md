# Update 2023-02-11
## CVE-2023-25396
 Privilege escalation in the MSI repair functionality in Caphyon Advanced Installer 20.0 and below allows attackers to access and manipulate system files.

- [https://github.com/Live-Hack-CVE/CVE-2023-25396](https://github.com/Live-Hack-CVE/CVE-2023-25396) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25396.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25396.svg)


## CVE-2023-25194
 A possible security vulnerability has been identified in Apache Kafka Connect. This requires access to a Kafka Connect worker, and the ability to create/modify connectors on it with an arbitrary Kafka client SASL JAAS config and a SASL-based security protocol, which has been possible on Kafka Connect clusters since Apache Kafka 2.3.0. When configuring the connector via the Kafka Connect REST API, an authenticated operator can set the `sasl.jaas.config` property for any of the connector's Kafka clients to &quot;com.sun.security.auth.module.JndiLoginModule&quot;, which can be done via the `producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` properties. This will allow the server to connect to the attacker's LDAP server and deserialize the LDAP response, which the attacker can use to execute java deserialization gadget chains on the Kafka connect server. Attacker can cause unrestricted deserialization of untrusted data (or) RCE vulnerability when there are gadgets in the classpath. Since Apache Kafka 3.0.0, users are allowed to specify these properties in connector configurations for Kafka Connect clusters running with out-of-the-box configurations. Before Apache Kafka 3.0.0, users may not specify these properties unless the Kafka Connect cluster has been reconfigured with a connector client override policy that permits them. Since Apache Kafka 3.4.0, we have added a system property (&quot;-Dorg.apache.kafka.disallowed.login.modules&quot;) to disable the problematic login modules usage in SASL JAAS configuration. Also by default &quot;com.sun.security.auth.module.JndiLoginModule&quot; is disabled in Apache Kafka 3.4.0. We advise the Kafka Connect users to validate connector configurations and only allow trusted JNDI configurations. Also examine connector dependencies for vulnerable versions and either upgrade their connectors, upgrading that specific dependency, or removing the connectors as options for remediation. Finally, in addition to leveraging the &quot;org.apache.kafka.disallowed.login.modules&quot; system property, Kafka Connect users can also implement their own connector client config override policy, which can be used to control which Kafka client properties can be overridden directly in a connector config and which cannot.

- [https://github.com/ohnonoyesyes/CVE-2023-25194](https://github.com/ohnonoyesyes/CVE-2023-25194) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2023-25194.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2023-25194.svg)


## CVE-2023-25152
 Wings is Pterodactyl's server control plane. Affected versions are subject to a vulnerability which can be used to create new files and directory structures on the host system that previously did not exist, potentially allowing attackers to change their resource allocations, promote their containers to privileged mode, or potentially add ssh authorized keys to allow the attacker access to a remote shell on the target machine. In order to use this exploit, an attacker must have an existing &quot;server&quot; allocated and controlled by the Wings Daemon. This vulnerability has been resolved in version `v1.11.3` of the Wings Daemon, and has been back-ported to the 1.7 release series in `v1.7.3`. Anyone running `v1.11.x` should upgrade to `v1.11.3` and anyone running `v1.7.x` should upgrade to `v1.7.3`. There are no known workarounds for this vulnerability. ### Workarounds None at this time.

- [https://github.com/Live-Hack-CVE/CVE-2023-25152](https://github.com/Live-Hack-CVE/CVE-2023-25152) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25152.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25152.svg)


## CVE-2023-24815
 Vert.x-Web is a set of building blocks for building web applications in the java programming language. When running vertx web applications that serve files using `StaticHandler` on Windows Operating Systems and Windows File Systems, if the mount point is a wildcard (`*`) then an attacker can exfiltrate any class path resource. When computing the relative path to locate the resource, in case of wildcards, the code: `return &quot;/&quot; + rest;` from `Utils.java` returns the user input (without validation) as the segment to lookup. Even though checks are performed to avoid escaping the sandbox, given that the input was not sanitized `\` are not properly handled and an attacker can build a path that is valid within the classpath. This issue only affects users deploying in windows environments and upgrading is the advised remediation path. There are no known workarounds for this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-24815](https://github.com/Live-Hack-CVE/CVE-2023-24815) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24815.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24815.svg)


## CVE-2023-24689
 An issue in Mojoportal v2.7.0.0 and below allows an authenticated attacker to list all css files inside the root path of the webserver via manipulation of the &quot;s&quot; parameter in /DesignTools/ManageSkin.aspx

- [https://github.com/Live-Hack-CVE/CVE-2023-24689](https://github.com/Live-Hack-CVE/CVE-2023-24689) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24689.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24689.svg)


## CVE-2023-24688
 An issue in Mojoportal v2.7.0.0 allows an unauthenticated attacker to register a new user even if the Allow User Registrations feature is disabled.

- [https://github.com/Live-Hack-CVE/CVE-2023-24688](https://github.com/Live-Hack-CVE/CVE-2023-24688) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24688.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24688.svg)


## CVE-2023-24687
 Mojoportal v2.7.0.0 was discovered to contain a stored cross-site scripting (XSS) vulnerability in the Company Info Settings component. This vulnerability allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the txtCompanyName parameter.

- [https://github.com/Live-Hack-CVE/CVE-2023-24687](https://github.com/Live-Hack-CVE/CVE-2023-24687) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24687.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24687.svg)


## CVE-2023-24323
 Mojoportal v2.7 was discovered to contain an authenticated XML external entity (XXE) injection vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-24323](https://github.com/Live-Hack-CVE/CVE-2023-24323) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24323.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24323.svg)


## CVE-2023-24322
 A reflected cross-site scripting (XSS) vulnerability in the FileDialog.aspx component of mojoPortal v2.7.0.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the ed and tbi parameters.

- [https://github.com/Live-Hack-CVE/CVE-2023-24322](https://github.com/Live-Hack-CVE/CVE-2023-24322) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24322.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24322.svg)


## CVE-2023-24021
 Incorrect handling of '\0' bytes in file uploads in ModSecurity before 2.9.7 may allow for Web Application Firewall bypasses and buffer over-reads on the Web Application Firewall when executing rules that read the FILES_TMP_CONTENT collection.

- [https://github.com/Live-Hack-CVE/CVE-2023-24021](https://github.com/Live-Hack-CVE/CVE-2023-24021) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24021.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24021.svg)


## CVE-2023-23912
 A vulnerability, found in EdgeRouters Version 2.0.9-hotfix.5 and earlier and UniFi Security Gateways (USG) Version 4.4.56 and earlier with their DHCPv6 prefix delegation set to dhcpv6-stateless or dhcpv6-stateful, allows a malicious actor directly connected to the WAN interface of an affected device to create a remote code execution vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-23912](https://github.com/Live-Hack-CVE/CVE-2023-23912) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23912.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23912.svg)


## CVE-2023-23636
 In Jellyfin 10.8.x through 10.8.3, the name of a playlist is vulnerable to stored XSS. This allows an attacker to steal access tokens from the localStorage of the victim.

- [https://github.com/Live-Hack-CVE/CVE-2023-23636](https://github.com/Live-Hack-CVE/CVE-2023-23636) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23636.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23636.svg)


## CVE-2023-23475
 IBM Infosphere Information Server 11.7 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 245423.

- [https://github.com/Live-Hack-CVE/CVE-2023-23475](https://github.com/Live-Hack-CVE/CVE-2023-23475) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23475.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23475.svg)


## CVE-2023-23469
 IBM ICP4A - Automation Decision Services 18.0.0, 18.0.1, 18.0.2, 19.0.1, 19.0.2, 19.0.3, 20.0.1, 20.0.2, 20.0.3, 21.0.1, 21.0.2, 21.0.3, 22.0.1, and 22.0.2 allows web pages to be stored locally which can be read by another user on the system. IBM X-Force ID: 244504.

- [https://github.com/Live-Hack-CVE/CVE-2023-23469](https://github.com/Live-Hack-CVE/CVE-2023-23469) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23469.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23469.svg)


## CVE-2023-22799
 A ReDoS based DoS vulnerability in the GlobalID &lt;1.0.1 which could allow an attacker supplying a carefully crafted input can cause the regular expression engine to take an unexpected amount of time. All users running an affected release should either upgrade or use one of the workarounds immediately.

- [https://github.com/Live-Hack-CVE/CVE-2023-22799](https://github.com/Live-Hack-CVE/CVE-2023-22799) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22799.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22799.svg)


## CVE-2023-22798
 Prior to commit 51867e0d15a6d7f80d5b714fd0e9976b9c160bb0, https://github.com/brave/adblock-lists removed redirect interceptors on some websites like Facebook in which the redirect interceptor may have been there for security purposes. This could potentially cause open redirects on these websites. Brave's redirect interceptor removal feature is known as &quot;debouncing&quot; and is intended to remove unnecessary redirects that track users across the web.

- [https://github.com/Live-Hack-CVE/CVE-2023-22798](https://github.com/Live-Hack-CVE/CVE-2023-22798) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22798.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22798.svg)


## CVE-2023-22797
 An open redirect vulnerability is fixed in Rails 7.0.4.1 with the new protection against open redirects from calling redirect_to with untrusted user input. In prior versions the developer was fully responsible for only providing trusted input. However the check introduced could allow an attacker to bypass with a carefully crafted URL resulting in an open redirect vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-22797](https://github.com/Live-Hack-CVE/CVE-2023-22797) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22797.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22797.svg)


## CVE-2023-22796
 A regular expression based DoS vulnerability in Active Support &lt;6.1.7.1 and &lt;7.0.4.1. A specially crafted string passed to the underscore method can cause the regular expression engine to enter a state of catastrophic backtracking. This can cause the process to use large amounts of CPU and memory, leading to a possible DoS vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-22796](https://github.com/Live-Hack-CVE/CVE-2023-22796) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22796.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22796.svg)


## CVE-2023-22795
 A regular expression based DoS vulnerability in Action Dispatch &lt;6.1.7.1 and &lt;7.0.4.1 related to the If-None-Match header. A specially crafted HTTP If-None-Match header can cause the regular expression engine to enter a state of catastrophic backtracking, when on a version of Ruby below 3.2.0. This can cause the process to use large amounts of CPU and memory, leading to a possible DoS vulnerability All users running an affected release should either upgrade or use one of the workarounds immediately.

- [https://github.com/Live-Hack-CVE/CVE-2023-22795](https://github.com/Live-Hack-CVE/CVE-2023-22795) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22795.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22795.svg)


## CVE-2023-22794
 A vulnerability in ActiveRecord &lt;6.0.6.1, v6.1.7.1 and v7.0.4.1 related to the sanitization of comments. If malicious user input is passed to either the `annotate` query method, the `optimizer_hints` query method, or through the QueryLogs interface which automatically adds annotations, it may be sent to the database withinsufficient sanitization and be able to inject SQL outside of the comment.

- [https://github.com/Live-Hack-CVE/CVE-2023-22794](https://github.com/Live-Hack-CVE/CVE-2023-22794) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22794.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22794.svg)


## CVE-2023-22792
 A regular expression based DoS vulnerability in Action Dispatch &lt;6.0.6.1,&lt; 6.1.7.1, and &lt;7.0.4.1. Specially crafted cookies, in combination with a specially crafted X_FORWARDED_HOST header can cause the regular expression engine to enter a state of catastrophic backtracking. This can cause the process to use large amounts of CPU and memory, leading to a possible DoS vulnerability All users running an affected release should either upgrade or use one of the workarounds immediately.

- [https://github.com/Live-Hack-CVE/CVE-2023-22792](https://github.com/Live-Hack-CVE/CVE-2023-22792) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22792.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22792.svg)


## CVE-2023-0760
 Heap-based Buffer Overflow in GitHub repository gpac/gpac prior to V2.1.0-DEV.

- [https://github.com/Live-Hack-CVE/CVE-2023-0760](https://github.com/Live-Hack-CVE/CVE-2023-0760) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0760.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0760.svg)


## CVE-2023-0759
 Privilege Chaining in GitHub repository cockpit-hq/cockpit prior to 2.3.8.

- [https://github.com/Live-Hack-CVE/CVE-2023-0759](https://github.com/Live-Hack-CVE/CVE-2023-0759) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0759.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0759.svg)


## CVE-2023-0758
 A vulnerability was found in glorylion JFinalOA 1.0.2 and classified as critical. This issue affects some unknown processing of the file src/main/java/com/pointlion/mvc/common/model/SysOrg.java. The manipulation of the argument id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-220469 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0758](https://github.com/Live-Hack-CVE/CVE-2023-0758) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0758.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0758.svg)


## CVE-2023-0690
 HashiCorp Boundary from 0.10.0 through 0.11.2 contain an issue where when using a PKI-based worker with a Key Management Service (KMS) defined in the configuration file, new credentials created after an automatic rotation may not have been encrypted via the intended KMS. This would result in the credentials being stored in plaintext on the Boundary PKI worker&#8217;s disk. This issue is fixed in version 0.12.0.

- [https://github.com/Live-Hack-CVE/CVE-2023-0690](https://github.com/Live-Hack-CVE/CVE-2023-0690) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0690.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0690.svg)


## CVE-2023-0624
 OrangeScrum version 2.0.11 allows an external attacker to obtain arbitrary user accounts from the application. This is possible because the application returns malicious user input in the response with the content-type set to text/html.

- [https://github.com/Live-Hack-CVE/CVE-2023-0624](https://github.com/Live-Hack-CVE/CVE-2023-0624) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0624.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0624.svg)


## CVE-2022-48290
 The phone-PC collaboration module has a logic bypass vulnerability. Successful exploitation of this vulnerability may affect data confidentiality and integrity.

- [https://github.com/Live-Hack-CVE/CVE-2022-48290](https://github.com/Live-Hack-CVE/CVE-2022-48290) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48290.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48290.svg)


## CVE-2022-48289
 The bundle management module lacks authentication and control mechanisms in some APIs. Successful exploitation of this vulnerability may affect data confidentiality.

- [https://github.com/Live-Hack-CVE/CVE-2022-48289](https://github.com/Live-Hack-CVE/CVE-2022-48289) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48289.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48289.svg)


## CVE-2022-48288
 The bundle management module lacks authentication and control mechanisms in some APIs. Successful exploitation of this vulnerability may affect data confidentiality.

- [https://github.com/Live-Hack-CVE/CVE-2022-48288](https://github.com/Live-Hack-CVE/CVE-2022-48288) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48288.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48288.svg)


## CVE-2022-48287
 The HwContacts module has a logic bypass vulnerability. Successful exploitation of this vulnerability may affect data integrity.

- [https://github.com/Live-Hack-CVE/CVE-2022-48287](https://github.com/Live-Hack-CVE/CVE-2022-48287) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48287.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48287.svg)


## CVE-2022-48286
 The multi-screen collaboration module has a privilege escalation vulnerability. Successful exploitation of this vulnerability may affect data confidentiality.

- [https://github.com/Live-Hack-CVE/CVE-2022-48286](https://github.com/Live-Hack-CVE/CVE-2022-48286) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48286.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48286.svg)


## CVE-2022-46552
 D-Link DIR-846 Firmware FW100A53DBR was discovered to contain a remote command execution (RCE) vulnerability via the lan(0)_dhcps_staticlist parameter. This vulnerability is exploited via a crafted POST request.

- [https://github.com/Live-Hack-CVE/CVE-2022-46552](https://github.com/Live-Hack-CVE/CVE-2022-46552) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46552.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46552.svg)


## CVE-2022-46457
 NASM v2.16 was discovered to contain a segmentation violation in the component ieee_write_file at /output/outieee.c.

- [https://github.com/Live-Hack-CVE/CVE-2022-46457](https://github.com/Live-Hack-CVE/CVE-2022-46457) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46457.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46457.svg)


## CVE-2022-45755
 Cross-site scripting (XSS) vulnerability in EyouCMS v1.6.0 allows attackers to execute arbitrary code via the home page description on the basic information page.

- [https://github.com/Live-Hack-CVE/CVE-2022-45755](https://github.com/Live-Hack-CVE/CVE-2022-45755) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45755.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45755.svg)


## CVE-2022-45527
 File upload vulnerability in Future-Depth Institutional Management Website (IMS) 1.0, allows unauthorized attackers to directly upload malicious files to the courseimg directory.

- [https://github.com/Live-Hack-CVE/CVE-2022-45527](https://github.com/Live-Hack-CVE/CVE-2022-45527) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45527.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45527.svg)


## CVE-2022-45526
 SQL Injection vulnerability in Future-Depth Institutional Management Website (IMS) 1.0, allows attackers to execute arbitrary commands via the ad parameter to /admin_area/login_transfer.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-45526](https://github.com/Live-Hack-CVE/CVE-2022-45526) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45526.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45526.svg)


## CVE-2022-45492
 Buffer overflow vulnerability in function json_parse_number in sheredom json.h before commit 0825301a07cbf51653882bf2b153cc81fdadf41 (November 14, 2022) allows attackers to code arbitrary code and gain escalated privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-45492](https://github.com/Live-Hack-CVE/CVE-2022-45492) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45492.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45492.svg)


## CVE-2022-45491
 Buffer overflow vulnerability in function json_parse_value in sheredom json.h before commit 0825301a07cbf51653882bf2b153cc81fdadf41 (November 14, 2022) allows attackers to code arbitrary code and gain escalated privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-45491](https://github.com/Live-Hack-CVE/CVE-2022-45491) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45491.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45491.svg)


## CVE-2022-44572
 A denial of service vulnerability in the multipart parsing component of Rack fixed in 2.0.9.2, 2.1.4.2, 2.2.4.1 and 3.0.0.1 could allow an attacker tocraft input that can cause RFC2183 multipart boundary parsing in Rack to take an unexpected amount of time, possibly resulting in a denial of service attack vector. Any applications that parse multipart posts using Rack (virtually all Rails applications) are impacted.

- [https://github.com/Live-Hack-CVE/CVE-2022-44572](https://github.com/Live-Hack-CVE/CVE-2022-44572) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44572.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44572.svg)


## CVE-2022-44571
 There is a denial of service vulnerability in the Content-Disposition parsingcomponent of Rack fixed in 2.0.9.2, 2.1.4.2, 2.2.4.1, 3.0.0.1. This could allow an attacker to craft an input that can cause Content-Disposition header parsing in Rackto take an unexpected amount of time, possibly resulting in a denial ofservice attack vector. This header is used typically used in multipartparsing. Any applications that parse multipart posts using Rack (virtuallyall Rails applications) are impacted.

- [https://github.com/Live-Hack-CVE/CVE-2022-44571](https://github.com/Live-Hack-CVE/CVE-2022-44571) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44571.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44571.svg)


## CVE-2022-44570
 A denial of service vulnerability in the Range header parsing component of Rack &gt;= 1.5.0. A Carefully crafted input can cause the Range header parsing component in Rack to take an unexpected amount of time, possibly resulting in a denial of service attack vector. Any applications that deal with Range requests (such as streaming applications, or applications that serve files) may be impacted.

- [https://github.com/Live-Hack-CVE/CVE-2022-44570](https://github.com/Live-Hack-CVE/CVE-2022-44570) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44570.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44570.svg)


## CVE-2022-44566
 A denial of service vulnerability present in ActiveRecord's PostgreSQL adapter &lt;7.0.4.1 and &lt;6.1.7.1. When a value outside the range for a 64bit signed integer is provided to the PostgreSQL connection adapter, it will treat the target column type as numeric. Comparing integer values against numeric values can result in a slow sequential scan resulting in potential Denial of Service.

- [https://github.com/Live-Hack-CVE/CVE-2022-44566](https://github.com/Live-Hack-CVE/CVE-2022-44566) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44566.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44566.svg)


## CVE-2022-43552
 A use after free vulnerability exists in curl &lt;7.87.0. Curl can be asked to *tunnel* virtually all protocols it supports through an HTTP proxy. HTTP proxies can (and often do) deny such tunnel operations. When getting denied to tunnel the specific protocols SMB or TELNET, curl would use a heap-allocated struct after it had been freed, in its transfer shutdown code path.

- [https://github.com/Live-Hack-CVE/CVE-2022-43552](https://github.com/Live-Hack-CVE/CVE-2022-43552) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43552.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43552.svg)


## CVE-2022-43550
 A command injection vulnerability exists in Jitsi before commit 8aa7be58522f4264078d54752aae5483bfd854b2 when launching browsers on Windows which could allow an attacker to insert an arbitrary URL which opens up the opportunity to remote execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-43550](https://github.com/Live-Hack-CVE/CVE-2022-43550) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43550.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43550.svg)


## CVE-2022-43440
 Uncontrolled Search Path Element in Checkmk Agent in Tribe29 Checkmk before 2.1.0p1, before 2.0.0p25 and before 1.6.0p29 on a Checkmk server allows the site user to escalate privileges via a manipulated unixcat executable

- [https://github.com/Live-Hack-CVE/CVE-2022-43440](https://github.com/Live-Hack-CVE/CVE-2022-43440) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43440.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43440.svg)


## CVE-2022-42438
 IBM Cloud Pak for Multicloud Management Monitoring 2.0 and 2.3 allows users without admin roles access to admin functions by specifying direct URL paths. IBM X-Force ID: 238210.

- [https://github.com/Live-Hack-CVE/CVE-2022-42438](https://github.com/Live-Hack-CVE/CVE-2022-42438) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42438.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42438.svg)


## CVE-2022-35720
 IBM Sterling External Authentication Server 6.1.0 and IBM Sterling Secure Proxy 6.0.3 uses weaker than expected cryptographic algorithms during installation that could allow a local attacker to decrypt sensitive information. IBM X-Force ID: 231373.

- [https://github.com/Live-Hack-CVE/CVE-2022-35720](https://github.com/Live-Hack-CVE/CVE-2022-35720) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35720.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35720.svg)


## CVE-2022-34362
 IBM Sterling Secure Proxy 6.0.3 is vulnerable to HTTP header injection, caused by improper validation of input by the HOST headers. This could allow an attacker to conduct various attacks against the vulnerable system, including cross-site scripting, cache poisoning or session hijacking. IBM X-Force ID: 230523.

- [https://github.com/Live-Hack-CVE/CVE-2022-34362](https://github.com/Live-Hack-CVE/CVE-2022-34362) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34362.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34362.svg)


## CVE-2022-30564
 Some Dahua embedded products have a vulnerability of unauthorized modification of the device timestamp. By sending a specially crafted packet to the vulnerable interface, an attacker can modify the device system time.

- [https://github.com/Live-Hack-CVE/CVE-2022-30564](https://github.com/Live-Hack-CVE/CVE-2022-30564) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30564.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30564.svg)


## CVE-2022-29622
 An arbitrary file upload vulnerability in formidable v3.1.4 allows attackers to execute arbitrary code via a crafted filename. NOTE: some third parties dispute this issue because the product has common use cases in which uploading arbitrary files is the desired behavior. Also, there are configuration options in all versions that can change the default behavior of how files are handled.

- [https://github.com/Live-Hack-CVE/CVE-2022-29622](https://github.com/Live-Hack-CVE/CVE-2022-29622) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29622.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29622.svg)


## CVE-2022-28689
 A leftover debug code vulnerability exists in the console support functionality of InHand Networks InRouter302 V3.5.45. A specially-crafted network request can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-28689](https://github.com/Live-Hack-CVE/CVE-2022-28689) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28689.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28689.svg)


## CVE-2022-27904
 Automox Agent for macOS before version 39 was vulnerable to a time-of-check/time-of-use (TOCTOU) race-condition attack during the agent install process.

- [https://github.com/Live-Hack-CVE/CVE-2022-27904](https://github.com/Live-Hack-CVE/CVE-2022-27904) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-27904.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-27904.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/Live-Hack-CVE/CVE-2022-22965](https://github.com/Live-Hack-CVE/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22965.svg)


## CVE-2022-2895
 Measuresoft ScadaPro Server (All Versions) uses unmaintained ActiveX controls. These controls may allow two stack-based buffer overflow instances while processing a specific project file.

- [https://github.com/Live-Hack-CVE/CVE-2022-2895](https://github.com/Live-Hack-CVE/CVE-2022-2895) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2895.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2895.svg)


## CVE-2021-38291
 FFmpeg version (git commit de8e6e67e7523e48bb27ac224a0b446df05e1640) suffers from a an assertion failure at src/libavutil/mathematics.c.

- [https://github.com/Live-Hack-CVE/CVE-2021-38291](https://github.com/Live-Hack-CVE/CVE-2021-38291) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-38291.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-38291.svg)


## CVE-2021-37306
 An Insecure Permissions issue in jeecg-boot 2.4.5 and earlier allows remote attackers to gain escalated privilege and view sensitive information via api uri: api uri:/sys/user/checkOnlyUser?username=admin.

- [https://github.com/Live-Hack-CVE/CVE-2021-37306](https://github.com/Live-Hack-CVE/CVE-2021-37306) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37306.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37306.svg)


## CVE-2021-37305
 An Insecure Permissions issue in jeecg-boot 2.4.5 and earlier allows remote attackers to gain escalated privilege and view sensitive information via api uri: /sys/user/querySysUser?username=admin.

- [https://github.com/Live-Hack-CVE/CVE-2021-37305](https://github.com/Live-Hack-CVE/CVE-2021-37305) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37305.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37305.svg)


## CVE-2021-37304
 An Insecure Permissions issue in jeecg-boot 2.4.5 allows unauthenticated remote attackers to gain escalated privilege and view sensitive information via the httptrace interface.

- [https://github.com/Live-Hack-CVE/CVE-2021-37304](https://github.com/Live-Hack-CVE/CVE-2021-37304) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37304.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37304.svg)


## CVE-2021-36712
 Cross Site Scripting (XSS) vulnerability in yzmcms 6.1 allows attackers to steal user cookies via image clipping function.

- [https://github.com/Live-Hack-CVE/CVE-2021-36712](https://github.com/Live-Hack-CVE/CVE-2021-36712) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-36712.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-36712.svg)


## CVE-2021-36545
 Cross Site Scripting (XSS) vulnerability in tpcms 3.2 allows remote attackers to run arbitrary code via the cfg_copyright or cfg_tel field in Site Configuration page.

- [https://github.com/Live-Hack-CVE/CVE-2021-36545](https://github.com/Live-Hack-CVE/CVE-2021-36545) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-36545.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-36545.svg)


## CVE-2021-36538
 Cross Site Scripting (XSS) vulnerability in Gurock TestRail before 7.1.2 allows remote authenticated attackers to run arbitrary code via the reference field in milestones or description fields in reports.

- [https://github.com/Live-Hack-CVE/CVE-2021-36538](https://github.com/Live-Hack-CVE/CVE-2021-36538) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-36538.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-36538.svg)


## CVE-2021-3757
 immer is vulnerable to Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')

- [https://github.com/Live-Hack-CVE/CVE-2021-3757](https://github.com/Live-Hack-CVE/CVE-2021-3757) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3757.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3757.svg)


## CVE-2021-3631
 A flaw was found in libvirt while it generates SELinux MCS category pairs for VMs' dynamic labels. This flaw allows one exploited guest to access files labeled for another guest, resulting in the breaking out of sVirt confinement. The highest threat from this vulnerability is to confidentiality and integrity.

- [https://github.com/Live-Hack-CVE/CVE-2021-3631](https://github.com/Live-Hack-CVE/CVE-2021-3631) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3631.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3631.svg)


## CVE-2021-2163
 Vulnerability in the Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries). Supported versions that are affected are Java SE: 7u291, 8u281, 11.0.10, 16; Java SE Embedded: 8u281; Oracle GraalVM Enterprise Edition: 19.3.5, 20.3.1.2 and 21.0.0.2. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 5.3 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2021-2163](https://github.com/Live-Hack-CVE/CVE-2021-2163) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-2163.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-2163.svg)


## CVE-2020-23585
 A remote attacker can conduct a cross-site request forgery (CSRF) attack on OPTILINK OP-XT71000N Hardware Version: V2.2 , Firmware Version: OP_V3.3.1-191028. The vulnerability is due to insufficient CSRF protections for the &quot;mgm_config_file.asp&quot; because of which attacker can create a crafted &quot;csrf form&quot; which sends &quot; malicious xml data&quot; to &quot;/boaform/admin/formMgmConfigUpload&quot;. the exploit allows attacker to &quot;gain full privileges&quot; and to &quot;fully compromise of router &amp; network&quot;.

- [https://github.com/huzaifahussain98/CVE-2020-23585](https://github.com/huzaifahussain98/CVE-2020-23585) :  ![starts](https://img.shields.io/github/stars/huzaifahussain98/CVE-2020-23585.svg) ![forks](https://img.shields.io/github/forks/huzaifahussain98/CVE-2020-23585.svg)


## CVE-2020-12675
 The mappress-google-maps-for-wordpress plugin before 2.54.6 for WordPress does not correctly implement capability checks for AJAX functions related to creation/retrieval/deletion of PHP template files, leading to Remote Code Execution. NOTE: this issue exists because of an incomplete fix for CVE-2020-12077.

- [https://github.com/Live-Hack-CVE/CVE-2020-12675](https://github.com/Live-Hack-CVE/CVE-2020-12675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12675.svg)


## CVE-2020-12077
 The mappress-google-maps-for-wordpress plugin before 2.53.9 for WordPress does not correctly implement AJAX functions with nonces (or capability checks), leading to remote code execution.

- [https://github.com/Live-Hack-CVE/CVE-2020-12077](https://github.com/Live-Hack-CVE/CVE-2020-12077) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12077.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12077.svg)
- [https://github.com/Live-Hack-CVE/CVE-2020-12675](https://github.com/Live-Hack-CVE/CVE-2020-12675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12675.svg)


## CVE-2020-1054
 An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1143.

- [https://github.com/0xeb-bp/cve-2020-1054](https://github.com/0xeb-bp/cve-2020-1054) :  ![starts](https://img.shields.io/github/stars/0xeb-bp/cve-2020-1054.svg) ![forks](https://img.shields.io/github/forks/0xeb-bp/cve-2020-1054.svg)


## CVE-2018-19518
 University of Washington IMAP Toolkit 2007f on UNIX, as used in imap_open() in PHP and other products, launches an rsh command (by means of the imap_rimap function in c-client/imap4r1.c and the tcp_aopen function in osdep/unix/tcp_unix.c) without preventing argument injection, which might allow remote attackers to execute arbitrary OS commands if the IMAP server name is untrusted input (e.g., entered by a user of a web application) and if rsh has been replaced by a program with different argument semantics. For example, if rsh is a link to ssh (as seen on Debian and Ubuntu systems), then the attack can use an IMAP server name containing a &quot;-oProxyCommand&quot; argument.

- [https://github.com/houquanen/POC_CVE-2018-19518](https://github.com/houquanen/POC_CVE-2018-19518) :  ![starts](https://img.shields.io/github/stars/houquanen/POC_CVE-2018-19518.svg) ![forks](https://img.shields.io/github/forks/houquanen/POC_CVE-2018-19518.svg)


## CVE-2018-7935
 There is a vulnerability in 21.328.01.00.00 version of the E5573Cs-322. Remote attackers could exploit this vulnerability to make the network where the E5573Cs-322 is running temporarily unavailable.

- [https://github.com/Live-Hack-CVE/CVE-2018-7935](https://github.com/Live-Hack-CVE/CVE-2018-7935) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-7935.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-7935.svg)


## CVE-2016-9675
 openjpeg: A heap-based buffer overflow flaw was found in the patch for CVE-2013-6045. A crafted j2k image could cause the application to crash, or potentially execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2016-9675](https://github.com/Live-Hack-CVE/CVE-2016-9675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-9675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-9675.svg)


## CVE-2013-6045
 Multiple heap-based buffer overflows in OpenJPEG 1.3 and earlier might allow remote attackers to execute arbitrary code via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2016-9675](https://github.com/Live-Hack-CVE/CVE-2016-9675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-9675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-9675.svg)

