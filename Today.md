# Update 2026-02-18
## CVE-2026-26012
 vaultwarden is an unofficial Bitwarden compatible server written in Rust, formerly known as bitwarden_rs. Prior to 1.35.3, a regular organization member can retrieve all ciphers within an organization, regardless of collection permissions. The endpoint /ciphers/organization-details is accessible to any organization member and internally uses Cipher::find_by_org to retrieve all ciphers. These ciphers are returned with CipherSyncType::Organization without enforcing collection-level access control. This vulnerability is fixed in 1.35.3.

- [https://github.com/Dulieno/CVE-2026-26012](https://github.com/Dulieno/CVE-2026-26012) :  ![starts](https://img.shields.io/github/stars/Dulieno/CVE-2026-26012.svg) ![forks](https://img.shields.io/github/forks/Dulieno/CVE-2026-26012.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/rootdirective-sec/CVE-2026-23744-Lab](https://github.com/rootdirective-sec/CVE-2026-23744-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-23744-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-23744-Lab.svg)


## CVE-2026-20700
 A memory corruption issue was addressed with improved state management. This issue is fixed in watchOS 26.3, tvOS 26.3, macOS Tahoe 26.3, visionOS 26.3, iOS 26.3 and iPadOS 26.3. An attacker with memory write capability may be able to execute arbitrary code. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 and CVE-2025-43529 were also issued in response to this report.

- [https://github.com/bytehazard/CVE-2026-20700](https://github.com/bytehazard/CVE-2026-20700) :  ![starts](https://img.shields.io/github/stars/bytehazard/CVE-2026-20700.svg) ![forks](https://img.shields.io/github/forks/bytehazard/CVE-2026-20700.svg)


## CVE-2026-2441
 Use after free in CSS in Google Chrome prior to 145.0.7632.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/b1gchoi/CVE-2026-2441_POC](https://github.com/b1gchoi/CVE-2026-2441_POC) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2026-2441_POC.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2026-2441_POC.svg)


## CVE-2026-1844
 The PixelYourSite PRO plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'pysTrafficSource' parameter and the 'pys_landing_page' parameter in all versions up to, and including, 12.4.0.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/tingvoshage22/CVE-2026-1844-exploit](https://github.com/tingvoshage22/CVE-2026-1844-exploit) :  ![starts](https://img.shields.io/github/stars/tingvoshage22/CVE-2026-1844-exploit.svg) ![forks](https://img.shields.io/github/forks/tingvoshage22/CVE-2026-1844-exploit.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/popyue/CVE-2025-49132](https://github.com/popyue/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/popyue/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/popyue/CVE-2025-49132.svg)


## CVE-2025-6960
 A vulnerability classified as critical was found in Campcodes Employee Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /empproject.php. The manipulation of the argument ID leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Wise-Security/CVE-2025-69600](https://github.com/Wise-Security/CVE-2025-69600) :  ![starts](https://img.shields.io/github/stars/Wise-Security/CVE-2025-69600.svg) ![forks](https://img.shields.io/github/forks/Wise-Security/CVE-2025-69600.svg)


## CVE-2025-6959
 A vulnerability classified as critical has been found in Campcodes Employee Management System 1.0. Affected is an unknown function of the file /eloginwel.php. The manipulation of the argument ID leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Wise-Security/CVE-2025-69599](https://github.com/Wise-Security/CVE-2025-69599) :  ![starts](https://img.shields.io/github/stars/Wise-Security/CVE-2025-69599.svg) ![forks](https://img.shields.io/github/forks/Wise-Security/CVE-2025-69599.svg)


## CVE-2025-4517
Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

- [https://github.com/kerburenthusiasm/CVE-2025-4517-PoC](https://github.com/kerburenthusiasm/CVE-2025-4517-PoC) :  ![starts](https://img.shields.io/github/stars/kerburenthusiasm/CVE-2025-4517-PoC.svg) ![forks](https://img.shields.io/github/forks/kerburenthusiasm/CVE-2025-4517-PoC.svg)
- [https://github.com/Rohitberiwala/PyPath-Escape-CVE-2025-4517-Exploit-Research](https://github.com/Rohitberiwala/PyPath-Escape-CVE-2025-4517-Exploit-Research) :  ![starts](https://img.shields.io/github/stars/Rohitberiwala/PyPath-Escape-CVE-2025-4517-Exploit-Research.svg) ![forks](https://img.shields.io/github/forks/Rohitberiwala/PyPath-Escape-CVE-2025-4517-Exploit-Research.svg)
- [https://github.com/kyakei/CVE-2025-4138-poc](https://github.com/kyakei/CVE-2025-4138-poc) :  ![starts](https://img.shields.io/github/stars/kyakei/CVE-2025-4138-poc.svg) ![forks](https://img.shields.io/github/forks/kyakei/CVE-2025-4138-poc.svg)


## CVE-2025-4138
Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

- [https://github.com/localh0ste/CVE-2025-4138](https://github.com/localh0ste/CVE-2025-4138) :  ![starts](https://img.shields.io/github/stars/localh0ste/CVE-2025-4138.svg) ![forks](https://img.shields.io/github/forks/localh0ste/CVE-2025-4138.svg)
- [https://github.com/kyakei/CVE-2025-4138-poc](https://github.com/kyakei/CVE-2025-4138-poc) :  ![starts](https://img.shields.io/github/stars/kyakei/CVE-2025-4138-poc.svg) ![forks](https://img.shields.io/github/forks/kyakei/CVE-2025-4138-poc.svg)


## CVE-2024-33648
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in wzy Media Recencio Book Reviews allows Stored XSS.This issue affects Recencio Book Reviews: from n/a through 1.66.0.

- [https://github.com/tompos2/rcno-reviews](https://github.com/tompos2/rcno-reviews) :  ![starts](https://img.shields.io/github/stars/tompos2/rcno-reviews.svg) ![forks](https://img.shields.io/github/forks/tompos2/rcno-reviews.svg)


## CVE-2024-5527
 Zohocorp ManageEngine ADAudit Plus versions below 8110 are vulnerable to authenticated SQL Injection in file auditing configuration.

- [https://github.com/shoaibalam112/CVE-2024-55270](https://github.com/shoaibalam112/CVE-2024-55270) :  ![starts](https://img.shields.io/github/stars/shoaibalam112/CVE-2024-55270.svg) ![forks](https://img.shields.io/github/forks/shoaibalam112/CVE-2024-55270.svg)
- [https://github.com/shoaibalam112/CVE-2024-55271](https://github.com/shoaibalam112/CVE-2024-55271) :  ![starts](https://img.shields.io/github/stars/shoaibalam112/CVE-2024-55271.svg) ![forks](https://img.shields.io/github/forks/shoaibalam112/CVE-2024-55271.svg)


## CVE-2021-41269
 cron-utils is a Java library to define, parse, validate, migrate crons as well as get human readable descriptions for them. In affected versions A template Injection was identified in cron-utils enabling attackers to inject arbitrary Java EL expressions, leading to unauthenticated Remote Code Execution (RCE) vulnerability. Versions up to 9.1.2 are susceptible to this vulnerability. Please note, that only projects using the @Cron annotation to validate untrusted Cron expressions are affected. The issue was patched and a new version was released. Please upgrade to version 9.1.6. There are no known workarounds known.

- [https://github.com/andikahilmy/CVE-2021-41269-cron-utils-vulnerable](https://github.com/andikahilmy/CVE-2021-41269-cron-utils-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2021-41269-cron-utils-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2021-41269-cron-utils-vulnerable.svg)


## CVE-2021-36090
 When reading a specially crafted ZIP archive, Compress can be made to allocate large amounts of memory that finally leads to an out of memory error even for very small inputs. This could be used to mount a denial of service attack against services that use Compress' zip package.

- [https://github.com/andikahilmy/CVE-2021-36090-commons-compress-vulnerable](https://github.com/andikahilmy/CVE-2021-36090-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2021-36090-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2021-36090-commons-compress-vulnerable.svg)


## CVE-2021-35515
 When reading a specially crafted 7Z archive, the construction of the list of codecs that decompress an entry can result in an infinite loop. This could be used to mount a denial of service attack against services that use Compress' sevenz package.

- [https://github.com/andikahilmy/CVE-2021-35515-commons-compress-vulnerable](https://github.com/andikahilmy/CVE-2021-35515-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2021-35515-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2021-35515-commons-compress-vulnerable.svg)


## CVE-2021-21363
 swagger-codegen is an open-source project which contains a template-driven engine to generate documentation, API clients and server stubs in different languages by parsing your OpenAPI / Swagger definition. In swagger-codegen before version 2.4.19, on Unix like systems, the system's temporary directory is shared between all users on that system. A collocated user can observe the process of creating a temporary sub directory in the shared temporary directory and race to complete the creation of the temporary subdirectory. This vulnerability is local privilege escalation because the contents of the `outputFolder` can be appended to by an attacker. As such, code written to this directory, when executed can be attacker controlled. For more details refer to the referenced GitHub Security Advisory. This vulnerability is fixed in version 2.4.19. Note this is a distinct vulnerability from CVE-2021-21364.

- [https://github.com/andikahilmy/CVE-2021-21363-swagger-codegen-vulnerable](https://github.com/andikahilmy/CVE-2021-21363-swagger-codegen-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2021-21363-swagger-codegen-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2021-21363-swagger-codegen-vulnerable.svg)


## CVE-2020-36189
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to com.newrelic.agent.deps.ch.qos.logback.core.db.DriverManagerConnectionSource.

- [https://github.com/andikahilmy/CVE-2020-36189-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36189-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36189-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36189-jackson-databind-vulnerable.svg)


## CVE-2020-36186
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp.datasources.PerUserPoolDataSource.

- [https://github.com/andikahilmy/CVE-2020-36186-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36186-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36186-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36186-jackson-databind-vulnerable.svg)


## CVE-2020-36184
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource.

- [https://github.com/andikahilmy/CVE-2020-36184-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36184-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36184-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36184-jackson-databind-vulnerable.svg)


## CVE-2020-36182
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp2.cpdsadapter.DriverAdapterCPDS.

- [https://github.com/andikahilmy/CVE-2020-36182-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36182-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36182-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36182-jackson-databind-vulnerable.svg)


## CVE-2020-36181
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp.cpdsadapter.DriverAdapterCPDS.

- [https://github.com/andikahilmy/CVE-2020-36181-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-36181-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-36181-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-36181-jackson-databind-vulnerable.svg)


## CVE-2020-35728
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to com.oracle.wls.shaded.org.apache.xalan.lib.sql.JNDIConnectionPool (aka embedded Xalan in org.glassfish.web/javax.servlet.jsp.jstl).

- [https://github.com/andikahilmy/CVE-2020-35728-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-35728-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-35728-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-35728-jackson-databind-vulnerable.svg)


## CVE-2020-35490
 FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.datasources.PerUserPoolDataSource.

- [https://github.com/andikahilmy/CVE-2020-35490-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-35490-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-35490-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-35490-jackson-databind-vulnerable.svg)


## CVE-2020-28491
 This affects the package com.fasterxml.jackson.dataformat:jackson-dataformat-cbor from 0 and before 2.11.4, from 2.12.0-rc1 and before 2.12.1. Unchecked allocation of byte buffer can cause a java.lang.OutOfMemoryError exception.

- [https://github.com/andikahilmy/CVE-2020-28491-jackson-dataformats-binary-vulnerable](https://github.com/andikahilmy/CVE-2020-28491-jackson-dataformats-binary-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-28491-jackson-dataformats-binary-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-28491-jackson-dataformats-binary-vulnerable.svg)


## CVE-2020-26217
 XStream before version 1.4.14 is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker to run arbitrary shell commands only by manipulating the processed input stream. Only users who rely on blocklists are affected. Anyone using XStream's Security Framework allowlist is not affected. The linked advisory provides code workarounds for users who cannot upgrade. The issue is fixed in version 1.4.14.

- [https://github.com/andikahilmy/CVE-2020-26217-xstream-vulnerable](https://github.com/andikahilmy/CVE-2020-26217-xstream-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-26217-xstream-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-26217-xstream-vulnerable.svg)


## CVE-2020-25649
 A flaw was found in FasterXML Jackson Databind, where it did not have entity expansion secured properly. This flaw allows vulnerability to XML external entity (XXE) attacks. The highest threat from this vulnerability is data integrity.

- [https://github.com/andikahilmy/CVE-2020-25649-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-25649-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-25649-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-25649-jackson-databind-vulnerable.svg)


## CVE-2020-24750
 FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the interaction between serialization gadgets and typing, related to com.pastdev.httpcomponents.configuration.JndiConfiguration.

- [https://github.com/andikahilmy/CVE-2020-24750-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-24750-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-24750-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-24750-jackson-databind-vulnerable.svg)


## CVE-2020-14195
 FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to org.jsecurity.realm.jndi.JndiRealmFactory (aka org.jsecurity).

- [https://github.com/andikahilmy/CVE-2020-14195-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-14195-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-14195-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-14195-jackson-databind-vulnerable.svg)


## CVE-2020-14062
 FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to com.sun.org.apache.xalan.internal.lib.sql.JNDIConnectionPool (aka xalan2).

- [https://github.com/andikahilmy/CVE-2020-14062-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-14062-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-14062-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-14062-jackson-databind-vulnerable.svg)


## CVE-2020-14061
 FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to oracle.jms.AQjmsQueueConnectionFactory, oracle.jms.AQjmsXATopicConnectionFactory, oracle.jms.AQjmsTopicConnectionFactory, oracle.jms.AQjmsXAQueueConnectionFactory, and oracle.jms.AQjmsXAConnectionFactory (aka weblogic/oracle-aqjms).

- [https://github.com/andikahilmy/CVE-2020-14061-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-14061-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-14061-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-14061-jackson-databind-vulnerable.svg)


## CVE-2020-11619
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.springframework.aop.config.MethodLocatingFactoryBean (aka spring-aop).

- [https://github.com/andikahilmy/CVE-2020-11619-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-11619-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-11619-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-11619-jackson-databind-vulnerable.svg)


## CVE-2020-11113
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.openjpa.ee.WASRegistryManagedRuntime (aka openjpa).

- [https://github.com/andikahilmy/CVE-2020-11113-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-11113-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-11113-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-11113-jackson-databind-vulnerable.svg)


## CVE-2020-11111
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.activemq.* (aka activemq-jms, activemq-core, activemq-pool, and activemq-pool-jms).

- [https://github.com/andikahilmy/CVE-2020-11111-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-11111-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-11111-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-11111-jackson-databind-vulnerable.svg)


## CVE-2020-10968
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.aoju.bus.proxy.provider.remoting.RmiProvider (aka bus-proxy).

- [https://github.com/andikahilmy/CVE-2020-10968-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-10968-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-10968-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-10968-jackson-databind-vulnerable.svg)


## CVE-2020-9548
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to br.com.anteros.dbcp.AnterosDBCPConfig (aka anteros-core).

- [https://github.com/andikahilmy/CVE-2020-9548-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-9548-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-9548-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-9548-jackson-databind-vulnerable.svg)


## CVE-2020-9546
 FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig (aka shaded hikari-config).

- [https://github.com/andikahilmy/CVE-2020-9546-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2020-9546-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-9546-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-9546-jackson-databind-vulnerable.svg)


## CVE-2020-7692
 PKCE support is not implemented in accordance with the RFC for OAuth 2.0 for Native Apps. Without the use of PKCE, the authorization code returned by an authorization server is not enough to guarantee that the client that issued the initial authorization request is the one that will be authorized. An attacker is able to obtain the authorization code using a malicious app on the client-side and use it to gain authorization to the protected resource. This affects the package com.google.oauth-client:google-oauth-client before 1.31.0.

- [https://github.com/andikahilmy/CVE-2020-7692-google-oauth-java-client-vulnerable](https://github.com/andikahilmy/CVE-2020-7692-google-oauth-java-client-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-7692-google-oauth-java-client-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-7692-google-oauth-java-client-vulnerable.svg)


## CVE-2020-1695
 A flaw was found in all resteasy 3.x.x versions prior to 3.12.0.Final and all resteasy 4.x.x versions prior to 4.6.0.Final, where an improper input validation results in returning an illegal header that integrates into the server's response. This flaw may result in an injection, which leads to unexpected behavior when the HTTP response is constructed.

- [https://github.com/andikahilmy/CVE-2020-1695-Resteasy-vulnerable](https://github.com/andikahilmy/CVE-2020-1695-Resteasy-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2020-1695-Resteasy-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2020-1695-Resteasy-vulnerable.svg)


## CVE-2019-1003010
 A cross-site request forgery vulnerability exists in Jenkins Git Plugin 3.9.1 and earlier in src/main/java/hudson/plugins/git/GitTagAction.java that allows attackers to create a Git tag in a workspace and attach corresponding metadata to a build record.

- [https://github.com/andikahilmy/CVE-2019-1003010-Prasanna-vulnerable](https://github.com/andikahilmy/CVE-2019-1003010-Prasanna-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-1003010-Prasanna-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-1003010-Prasanna-vulnerable.svg)


## CVE-2019-18393
 PluginServlet.java in Ignite Realtime Openfire through 4.4.2 does not ensure that retrieved files are located under the Openfire home directory, aka a directory traversal vulnerability.

- [https://github.com/andikahilmy/CVE-2019-18393-Openfire-vulnerable](https://github.com/andikahilmy/CVE-2019-18393-Openfire-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-18393-Openfire-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-18393-Openfire-vulnerable.svg)


## CVE-2019-17558
 Apache Solr 5.0.0 to Apache Solr 8.3.1 are vulnerable to a Remote Code Execution through the VelocityResponseWriter. A Velocity template can be provided through Velocity templates in a configset `velocity/` directory or as a parameter. A user defined configset could contain renderable, potentially malicious, templates. Parameter provided templates are disabled by default, but can be enabled by setting `params.resource.loader.enabled` by defining a response writer with that setting set to `true`. Defining a response writer requires configuration API access. Solr 8.4 removed the params resource loader entirely, and only enables the configset-provided template rendering when the configset is `trusted` (has been uploaded by an authenticated user).

- [https://github.com/rogerzeferino/Apache-Solr-RCE-CVE-2019-17558](https://github.com/rogerzeferino/Apache-Solr-RCE-CVE-2019-17558) :  ![starts](https://img.shields.io/github/stars/rogerzeferino/Apache-Solr-RCE-CVE-2019-17558.svg) ![forks](https://img.shields.io/github/forks/rogerzeferino/Apache-Solr-RCE-CVE-2019-17558.svg)


## CVE-2019-17531
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0 through 2.9.10. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the apache-log4j-extra (version 1.2.x) jar in the classpath, and an attacker can provide a JNDI service to access, it is possible to make the service execute a malicious payload.

- [https://github.com/andikahilmy/CVE-2019-17531-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-17531-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-17531-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-17531-jackson-databind-vulnerable.svg)


## CVE-2019-16943
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0 through 2.9.10. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the p6spy (3.8.6) jar in the classpath, and an attacker can find an RMI service endpoint to access, it is possible to make the service execute a malicious payload. This issue exists because of com.p6spy.engine.spy.P6DataSource mishandling.

- [https://github.com/andikahilmy/CVE-2019-16943-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-16943-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-16943-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-16943-jackson-databind-vulnerable.svg)


## CVE-2019-16942
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0 through 2.9.10. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the commons-dbcp (1.4) jar in the classpath, and an attacker can find an RMI service endpoint to access, it is possible to make the service execute a malicious payload. This issue exists because of org.apache.commons.dbcp.datasources.SharedPoolDataSource and org.apache.commons.dbcp.datasources.PerUserPoolDataSource mishandling.

- [https://github.com/andikahilmy/CVE-2019-16942-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-16942-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-16942-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-16942-jackson-databind-vulnerable.svg)


## CVE-2019-14893
 A flaw was discovered in FasterXML jackson-databind in all versions before 2.9.10 and 2.10.0, where it would permit polymorphic deserialization of malicious objects using the xalan JNDI gadget when used in conjunction with polymorphic type handling methods such as `enableDefaultTyping()` or when @JsonTypeInfo is using `Id.CLASS` or `Id.MINIMAL_CLASS` or in any other way which ObjectMapper.readValue might instantiate objects from unsafe sources. An attacker could use this flaw to execute arbitrary code.

- [https://github.com/andikahilmy/CVE-2019-14893-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-14893-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-14893-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-14893-jackson-databind-vulnerable.svg)


## CVE-2019-14540
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind before 2.9.10. It is related to com.zaxxer.hikari.HikariConfig.

- [https://github.com/andikahilmy/CVE-2019-14540-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-14540-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-14540-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-14540-jackson-databind-vulnerable.svg)


## CVE-2019-14439
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9.2. This occurs when Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the logback jar in the classpath.

- [https://github.com/andikahilmy/CVE-2019-14439-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-14439-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-14439-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-14439-jackson-databind-vulnerable.svg)


## CVE-2019-14379
 SubTypeValidator.java in FasterXML jackson-databind before 2.9.9.2 mishandles default typing when ehcache is used (because of net.sf.ehcache.transaction.manager.DefaultTransactionManagerLookup), leading to remote code execution.

- [https://github.com/andikahilmy/CVE-2019-14379-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-14379-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-14379-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-14379-jackson-databind-vulnerable.svg)


## CVE-2019-12814
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x through 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has JDOM 1.x or 2.x jar in the classpath, an attacker can send a specifically crafted JSON message that allows them to read arbitrary local files on the server.

- [https://github.com/andikahilmy/CVE-2019-12814-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-12814-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-12814-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-12814-jackson-databind-vulnerable.svg)


## CVE-2019-12400
 In version 2.0.3 Apache Santuario XML Security for Java, a caching mechanism was introduced to speed up creating new XML documents using a static pool of DocumentBuilders. However, if some untrusted code can register a malicious implementation with the thread context class loader first, then this implementation might be cached and re-used by Apache Santuario - XML Security for Java, leading to potential security flaws when validating signed documents, etc. The vulnerability affects Apache Santuario - XML Security for Java 2.0.x releases from 2.0.3 and all 2.1.x releases before 2.1.4.

- [https://github.com/andikahilmy/CVE-2019-12400-santuario-java-vulnerable](https://github.com/andikahilmy/CVE-2019-12400-santuario-java-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-12400-santuario-java-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-12400-santuario-java-vulnerable.svg)


## CVE-2019-12384
 FasterXML jackson-databind 2.x before 2.9.9.1 might allow attackers to have a variety of impacts by leveraging failure to block the logback-core class from polymorphic deserialization. Depending on the classpath content, remote code execution may be possible.

- [https://github.com/andikahilmy/CVE-2019-12384-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-12384-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-12384-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-12384-jackson-databind-vulnerable.svg)


## CVE-2019-12086
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint, the service has the mysql-connector-java jar (8.0.14 or earlier) in the classpath, and an attacker can host a crafted MySQL server reachable by the victim, an attacker can send a crafted JSON message that allows them to read arbitrary local files on the server. This occurs because of missing com.mysql.cj.jdbc.admin.MiniAdmin validation.

- [https://github.com/andikahilmy/CVE-2019-12086-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2019-12086-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2019-12086-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2019-12086-jackson-databind-vulnerable.svg)


## CVE-2018-1002201
 zt-zip before 1.13 is vulnerable to directory traversal, allowing attackers to write to arbitrary files via a ../ (dot dot slash) in a Zip archive entry that is mishandled during extraction. This vulnerability is also known as 'Zip-Slip'.

- [https://github.com/andikahilmy/CVE-2018-1002201-zt-zip-vulnerable](https://github.com/andikahilmy/CVE-2018-1002201-zt-zip-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1002201-zt-zip-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1002201-zt-zip-vulnerable.svg)


## CVE-2018-1000844
 Square Open Source Retrofit version Prior to commit 4a693c5aeeef2be6c7ecf80e7b5ec79f6ab59437 contains a XML External Entity (XXE) vulnerability in JAXB that can result in An attacker could use this to remotely read files from the file system or to perform SSRF.. This vulnerability appears to have been fixed in After commit 4a693c5aeeef2be6c7ecf80e7b5ec79f6ab59437.

- [https://github.com/andikahilmy/CVE-2018-1000844-retrofit-vulnerable](https://github.com/andikahilmy/CVE-2018-1000844-retrofit-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1000844-retrofit-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1000844-retrofit-vulnerable.svg)


## CVE-2018-1000531
 inversoft prime-jwt version prior to commit abb0d479389a2509f939452a6767dc424bb5e6ba contains a CWE-20 vulnerability in JWTDecoder.decode that can result in an incorrect signature validation of a JWT token. This attack can be exploitable when an attacker crafts a JWT token with a valid header using 'none' as algorithm and a body to requests it be validated. This vulnerability was fixed after commit abb0d479389a2509f939452a6767dc424bb5e6ba.

- [https://github.com/andikahilmy/CVE-2018-1000531-prime-jwt-vulnerable](https://github.com/andikahilmy/CVE-2018-1000531-prime-jwt-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1000531-prime-jwt-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1000531-prime-jwt-vulnerable.svg)


## CVE-2018-1000125
 inversoft prime-jwt version prior to version 1.3.0 or prior to commit 0d94dcef0133d699f21d217e922564adbb83a227 contains an input validation vulnerability in JWTDecoder.decode that can result in a JWT that is decoded and thus implicitly validated even if it lacks a valid signature. This attack appear to be exploitable via an attacker crafting a token with a valid header and body and then requests it to be validated. This vulnerability appears to have been fixed in 1.3.0 and later or after commit 0d94dcef0133d699f21d217e922564adbb83a227.

- [https://github.com/andikahilmy/CVE-2018-1000125-prime-jwt-vulnerable](https://github.com/andikahilmy/CVE-2018-1000125-prime-jwt-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1000125-prime-jwt-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1000125-prime-jwt-vulnerable.svg)


## CVE-2018-20318
 An issue was discovered in weixin-java-tools v3.2.0. There is an XXE vulnerability in the getXmlDoc method of the BaseWxPayResult.java file.

- [https://github.com/andikahilmy/CVE-2018-20318-weixin-java-tools-vulnerable](https://github.com/andikahilmy/CVE-2018-20318-weixin-java-tools-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-20318-weixin-java-tools-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-20318-weixin-java-tools-vulnerable.svg)


## CVE-2018-20227
 RDF4J 2.4.2 allows Directory Traversal via ../ in an entry in a ZIP archive.

- [https://github.com/andikahilmy/CVE-2018-20227-rdf4j-vulnerable](https://github.com/andikahilmy/CVE-2018-20227-rdf4j-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-20227-rdf4j-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-20227-rdf4j-vulnerable.svg)


## CVE-2018-19362
 FasterXML jackson-databind 2.x before 2.9.8 might allow attackers to have unspecified impact by leveraging failure to block the jboss-common-core class from polymorphic deserialization.

- [https://github.com/andikahilmy/CVE-2018-19362-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-19362-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-19362-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-19362-jackson-databind-vulnerable.svg)


## CVE-2018-19360
 FasterXML jackson-databind 2.x before 2.9.8 might allow attackers to have unspecified impact by leveraging failure to block the axis2-transport-jms class from polymorphic deserialization.

- [https://github.com/andikahilmy/CVE-2018-19360-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-19360-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-19360-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-19360-jackson-databind-vulnerable.svg)


## CVE-2018-14721
 FasterXML jackson-databind 2.x before 2.9.7 might allow remote attackers to conduct server-side request forgery (SSRF) attacks by leveraging failure to block the axis2-jaxws class from polymorphic deserialization.

- [https://github.com/andikahilmy/CVE-2018-14721-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-14721-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-14721-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-14721-jackson-databind-vulnerable.svg)


## CVE-2018-14720
 FasterXML jackson-databind 2.x before 2.9.7 might allow attackers to conduct external XML entity (XXE) attacks by leveraging failure to block unspecified JDK classes from polymorphic deserialization.

- [https://github.com/andikahilmy/CVE-2018-14720-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-14720-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-14720-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-14720-jackson-databind-vulnerable.svg)


## CVE-2018-14719
 FasterXML jackson-databind 2.x before 2.9.7 might allow remote attackers to execute arbitrary code by leveraging failure to block the blaze-ds-opt and blaze-ds-core classes from polymorphic deserialization.

- [https://github.com/andikahilmy/CVE-2018-14719-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-14719-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-14719-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-14719-jackson-databind-vulnerable.svg)


## CVE-2018-14718
 FasterXML jackson-databind 2.x before 2.9.7 might allow remote attackers to execute arbitrary code by leveraging failure to block the slf4j-ext class from polymorphic deserialization.

- [https://github.com/andikahilmy/CVE-2018-14718-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-14718-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-14718-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-14718-jackson-databind-vulnerable.svg)


## CVE-2018-12542
 In version from 3.0.0 to 3.5.3 of Eclipse Vert.x, the StaticHandler uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize '\' (forward slashes) sequences that can resolve to a location that is outside of that directory when running on Windows Operating Systems.

- [https://github.com/andikahilmy/CVE-2018-12542-vertx-web-vulnerable](https://github.com/andikahilmy/CVE-2018-12542-vertx-web-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-12542-vertx-web-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-12542-vertx-web-vulnerable.svg)


## CVE-2018-12540
 In version from 3.0.0 to 3.5.2 of Eclipse Vert.x, the CSRFHandler do not assert that the XSRF Cookie matches the returned XSRF header/form parameter. This allows replay attacks with previously issued tokens which are not expired yet.

- [https://github.com/andikahilmy/CVE-2018-12540-vertx-web-vulnerable](https://github.com/andikahilmy/CVE-2018-12540-vertx-web-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-12540-vertx-web-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-12540-vertx-web-vulnerable.svg)


## CVE-2018-12023
 An issue was discovered in FasterXML jackson-databind prior to 2.7.9.4, 2.8.11.2, and 2.9.6. When Default Typing is enabled (either globally or for a specific property), the service has the Oracle JDBC jar in the classpath, and an attacker can provide an LDAP service to access, it is possible to make the service execute a malicious payload.

- [https://github.com/andikahilmy/CVE-2018-12023-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-12023-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-12023-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-12023-jackson-databind-vulnerable.svg)


## CVE-2018-12022
 An issue was discovered in FasterXML jackson-databind prior to 2.7.9.4, 2.8.11.2, and 2.9.6. When Default Typing is enabled (either globally or for a specific property), the service has the Jodd-db jar (for database access for the Jodd framework) in the classpath, and an attacker can provide an LDAP service to access, it is possible to make the service execute a malicious payload.

- [https://github.com/andikahilmy/CVE-2018-12022-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-12022-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-12022-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-12022-jackson-databind-vulnerable.svg)


## CVE-2018-11771
 When reading a specially crafted ZIP archive, the read method of Apache Commons Compress 1.7 to 1.17's ZipArchiveInputStream can fail to return the correct EOF indication after the end of the stream has been reached. When combined with a java.io.InputStreamReader this can lead to an infinite stream, which can be used to mount a denial of service attack against services that use Compress' zip package.

- [https://github.com/andikahilmy/CVE-2018-11771-commons-compress-vulnerable](https://github.com/andikahilmy/CVE-2018-11771-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-11771-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-11771-commons-compress-vulnerable.svg)


## CVE-2018-11307
 An issue was discovered in FasterXML jackson-databind 2.0.0 through 2.9.5. Use of Jackson default typing along with a gadget class from iBatis allows exfiltration of content. Fixed in 2.7.9.4, 2.8.11.2, and 2.9.6.

- [https://github.com/andikahilmy/CVE-2018-11307-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-11307-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-11307-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-11307-jackson-databind-vulnerable.svg)


## CVE-2018-10936
 A weakness was found in postgresql-jdbc before version 42.2.5. It was possible to provide an SSL Factory and not check the host name if a host name verifier was not provided to the driver. This could lead to a condition where a man-in-the-middle attacker could masquerade as a trusted server by providing a certificate for the wrong host, as long as it was signed by a trusted CA.

- [https://github.com/andikahilmy/CVE-2018-10936-pgjdbc-vulnerable](https://github.com/andikahilmy/CVE-2018-10936-pgjdbc-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-10936-pgjdbc-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-10936-pgjdbc-vulnerable.svg)


## CVE-2018-9159
 In Spark before 2.7.2, a remote attacker can read unintended static files via various representations of absolute or relative pathnames, as demonstrated by file: URLs and directory traversal sequences. NOTE: this product is unrelated to Ignite Realtime Spark.

- [https://github.com/andikahilmy/CVE-2018-9159-perwendel-spark-vulnerable](https://github.com/andikahilmy/CVE-2018-9159-perwendel-spark-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-9159-perwendel-spark-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-9159-perwendel-spark-vulnerable.svg)


## CVE-2018-8030
 A Denial of Service vulnerability was found in Apache Qpid Broker-J versions 7.0.0-7.0.4 when AMQP protocols 0-8, 0-9 or 0-91 are used to publish messages with size greater than allowed maximum message size limit (100MB by default). The broker crashes due to the defect. AMQP protocols 0-10 and 1.0 are not affected.

- [https://github.com/andikahilmy/CVE-2018-8030-qpid-broker-j-vulnerable](https://github.com/andikahilmy/CVE-2018-8030-qpid-broker-j-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-8030-qpid-broker-j-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-8030-qpid-broker-j-vulnerable.svg)


## CVE-2018-5968
 FasterXML jackson-databind through 2.8.11 and 2.9.x through 2.9.3 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 and CVE-2017-17485 deserialization flaws. This is exploitable via two different gadgets that bypass a blacklist.

- [https://github.com/andikahilmy/CVE-2018-5968-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2018-5968-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-5968-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-5968-jackson-databind-vulnerable.svg)


## CVE-2018-1324
 A specially crafted ZIP archive can be used to cause an infinite loop inside of Apache Commons Compress' extra field parser used by the ZipFile and ZipArchiveInputStream classes in versions 1.11 to 1.15. This can be used to mount a denial of service attack against services that use Compress' zip package.

- [https://github.com/andikahilmy/CVE-2018-1324-commons-compress-vulnerable](https://github.com/andikahilmy/CVE-2018-1324-commons-compress-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1324-commons-compress-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1324-commons-compress-vulnerable.svg)


## CVE-2018-1306
 The PortletV3AnnotatedDemo Multipart Portlet war file code provided in Apache Pluto version 3.0.0 could allow a remote attacker to obtain sensitive information, caused by the failure to restrict path information provided during a file upload. An attacker could exploit this vulnerability to obtain configuration data and other sensitive information.

- [https://github.com/andikahilmy/CVE-2018-1306-portals-pluto-vulnerable](https://github.com/andikahilmy/CVE-2018-1306-portals-pluto-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1306-portals-pluto-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1306-portals-pluto-vulnerable.svg)


## CVE-2018-1274
 Spring Data Commons, versions 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property path parser vulnerability caused by unlimited resource allocation. An unauthenticated remote malicious user (or attacker) can issue requests against Spring Data REST endpoints or endpoints using property path parsing which can cause a denial of service (CPU and memory consumption).

- [https://github.com/andikahilmy/CVE-2018-1274-spring-data-commons-vulnerable](https://github.com/andikahilmy/CVE-2018-1274-spring-data-commons-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1274-spring-data-commons-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1274-spring-data-commons-vulnerable.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/andikahilmy/CVE-2018-1273-spring-data-commons-vulnerable](https://github.com/andikahilmy/CVE-2018-1273-spring-data-commons-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1273-spring-data-commons-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1273-spring-data-commons-vulnerable.svg)


## CVE-2018-1114
 It was found that URLResource.getLastModified() in Undertow closes the file descriptors only when they are finalized which can cause file descriptors to exhaust. This leads to a file handler leak.

- [https://github.com/andikahilmy/CVE-2018-1114-undertow-vulnerable](https://github.com/andikahilmy/CVE-2018-1114-undertow-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2018-1114-undertow-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2018-1114-undertow-vulnerable.svg)


## CVE-2017-1000487
 Plexus-utils before 3.0.16 is vulnerable to command injection because it does not correctly process the contents of double quoted strings.

- [https://github.com/andikahilmy/CVE-2017-1000487-plexus-utils-vulnerable](https://github.com/andikahilmy/CVE-2017-1000487-plexus-utils-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-1000487-plexus-utils-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-1000487-plexus-utils-vulnerable.svg)


## CVE-2017-1000209
 The Java WebSocket client nv-websocket-client does not verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL/TLS servers via an arbitrary valid certificate.

- [https://github.com/andikahilmy/CVE-2017-1000209-nv-websocket-client-vulnerable](https://github.com/andikahilmy/CVE-2017-1000209-nv-websocket-client-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-1000209-nv-websocket-client-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-1000209-nv-websocket-client-vulnerable.svg)


## CVE-2017-1000208
 A vulnerability in Swagger-Parser's (version = 1.0.30) yaml parsing functionality results in arbitrary code being executed when a maliciously crafted yaml Open-API specification is parsed. This in particular, affects the 'generate' and 'validate' command in swagger-codegen (= 2.2.2) and can lead to arbitrary code being executed when these commands are used on a well-crafted yaml specification.

- [https://github.com/andikahilmy/CVE-2017-1000208-swagger-parser-vulnerable](https://github.com/andikahilmy/CVE-2017-1000208-swagger-parser-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-1000208-swagger-parser-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-1000208-swagger-parser-vulnerable.svg)


## CVE-2017-1000207
 A vulnerability in Swagger-Parser's version = 1.0.30 and Swagger codegen version = 2.2.2 yaml parsing functionality results in arbitrary code being executed when a maliciously crafted yaml Open-API specification is parsed. This in particular, affects the 'generate' and 'validate' command in swagger-codegen (= 2.2.2) and can lead to arbitrary code being executed when these commands are used on a well-crafted yaml specification.

- [https://github.com/andikahilmy/CVE-2017-1000207-swagger-parser-vulnerable](https://github.com/andikahilmy/CVE-2017-1000207-swagger-parser-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-1000207-swagger-parser-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-1000207-swagger-parser-vulnerable.svg)


## CVE-2017-18640
 The Alias feature in SnakeYAML before 1.26 allows entity expansion during a load operation, a related issue to CVE-2003-1564.

- [https://github.com/andikahilmy/CVE-2017-18640-snakeyaml-vulnerable](https://github.com/andikahilmy/CVE-2017-18640-snakeyaml-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-18640-snakeyaml-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-18640-snakeyaml-vulnerable.svg)


## CVE-2017-17485
 FasterXML jackson-databind through 2.8.10 and 2.9.x through 2.9.3 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the Spring libraries are available in the classpath.

- [https://github.com/andikahilmy/CVE-2017-17485-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2017-17485-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-17485-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-17485-jackson-databind-vulnerable.svg)


## CVE-2017-15717
 A flaw in the way URLs are escaped and encoded in the org.apache.sling.xss.impl.XSSAPIImpl#getValidHref and org.apache.sling.xss.impl.XSSFilterImpl#isValidHref allows special crafted URLs to pass as valid, although they carry XSS payloads. The affected versions are Apache Sling XSS Protection API 1.0.4 to 1.0.18, Apache Sling XSS Protection API Compat 1.1.0 and Apache Sling XSS Protection API 2.0.0.

- [https://github.com/andikahilmy/CVE-2017-15717-sling-org-apache-sling-xss-vulnerable](https://github.com/andikahilmy/CVE-2017-15717-sling-org-apache-sling-xss-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-15717-sling-org-apache-sling-xss-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-15717-sling-org-apache-sling-xss-vulnerable.svg)


## CVE-2017-15700
 A flaw in the org.apache.sling.auth.core.AuthUtil#isRedirectValid method in Apache Sling Authentication Service 1.4.0 allows an attacker, through the Sling login form, to trick a victim to send over their credentials.

- [https://github.com/andikahilmy/CVE-2017-15700-sling-org-apache-sling-auth-core-vulnerable](https://github.com/andikahilmy/CVE-2017-15700-sling-org-apache-sling-auth-core-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-15700-sling-org-apache-sling-auth-core-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-15700-sling-org-apache-sling-auth-core-vulnerable.svg)


## CVE-2017-15095
 A deserialization flaw was discovered in the jackson-databind in versions before 2.8.10 and 2.9.1, which could allow an unauthenticated user to perform code execution by sending the maliciously crafted input to the readValue method of the ObjectMapper. This issue extends the previous flaw CVE-2017-7525 by blacklisting more classes that could be used maliciously.

- [https://github.com/andikahilmy/CVE-2017-15095-jackson-databind-vulnerable](https://github.com/andikahilmy/CVE-2017-15095-jackson-databind-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-15095-jackson-databind-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-15095-jackson-databind-vulnerable.svg)


## CVE-2017-14063
 Async Http Client (aka async-http-client) before 2.0.35 can be tricked into connecting to a host different from the one extracted by java.net.URI if a '?' character occurs in a fragment identifier. Similar bugs were previously identified in cURL (CVE-2016-8624) and Oracle Java 8 java.net.URL.

- [https://github.com/andikahilmy/CVE-2017-14063-async-http-client-vulnerable](https://github.com/andikahilmy/CVE-2017-14063-async-http-client-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-14063-async-http-client-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-14063-async-http-client-vulnerable.svg)


## CVE-2017-12197
 It was found that libpam4j up to and including 1.8 did not properly validate user accounts when authenticating. A user with a valid password for a disabled account would be able to bypass security restrictions and possibly access sensitive information.

- [https://github.com/andikahilmy/CVE-2017-12197-libpam4j-vulnerable](https://github.com/andikahilmy/CVE-2017-12197-libpam4j-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-12197-libpam4j-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-12197-libpam4j-vulnerable.svg)


## CVE-2017-12165
 It was discovered that Undertow before 1.4.17, 1.3.31 and 2.0.0 processes http request headers with unusual whitespaces which can cause possible http request smuggling.

- [https://github.com/andikahilmy/CVE-2017-12165-undertow-vulnerable](https://github.com/andikahilmy/CVE-2017-12165-undertow-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-12165-undertow-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-12165-undertow-vulnerable.svg)


## CVE-2017-9801
 When a call-site passes a subject for an email that contains line-breaks in Apache Commons Email 1.0 through 1.4, the caller can add arbitrary SMTP headers.

- [https://github.com/andikahilmy/CVE-2017-9801-commons-email-vulnerable](https://github.com/andikahilmy/CVE-2017-9801-commons-email-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-9801-commons-email-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-9801-commons-email-vulnerable.svg)


## CVE-2017-7957
 XStream through 1.4.9, when a certain denyTypes workaround is not used, mishandles attempts to create an instance of the primitive type 'void' during unmarshalling, leading to a remote application crash, as demonstrated by an xstream.fromXML("void/") call.

- [https://github.com/andikahilmy/CVE-2017-7957-xstream-vulnerable](https://github.com/andikahilmy/CVE-2017-7957-xstream-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-7957-xstream-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-7957-xstream-vulnerable.svg)


## CVE-2017-7662
 Apache CXF Fediz ships with an OpenId Connect (OIDC) service which has a Client Registration Service, which is a simple web application that allows clients to be created, deleted, etc. A CSRF (Cross Style Request Forgery) style vulnerability has been found in this web application in Apache CXF Fediz prior to 1.4.0 and 1.3.2, meaning that a malicious web application could create new clients, or reset secrets, etc, after the admin user has logged on to the client registration service and the session is still active.

- [https://github.com/andikahilmy/CVE-2017-7662-cxf-fediz-vulnerable](https://github.com/andikahilmy/CVE-2017-7662-cxf-fediz-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-7662-cxf-fediz-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-7662-cxf-fediz-vulnerable.svg)


## CVE-2017-7661
 Apache CXF Fediz ships with a number of container-specific plugins to enable WS-Federation for applications. A CSRF (Cross Style Request Forgery) style vulnerability has been found in the Spring 2, Spring 3, Jetty 8 and Jetty 9 plugins in Apache CXF Fediz prior to 1.4.0, 1.3.2 and 1.2.4.

- [https://github.com/andikahilmy/CVE-2017-7661-cxf-fediz-vulnerable](https://github.com/andikahilmy/CVE-2017-7661-cxf-fediz-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-7661-cxf-fediz-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-7661-cxf-fediz-vulnerable.svg)


## CVE-2017-7561
 Red Hat JBoss EAP version 3.0.7 through before 4.0.0.Beta1 is vulnerable to a server-side cache poisoning or CORS requests in the JAX-RS component resulting in a moderate impact.

- [https://github.com/andikahilmy/CVE-2017-7561-Resteasy-vulnerable](https://github.com/andikahilmy/CVE-2017-7561-Resteasy-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-7561-Resteasy-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-7561-Resteasy-vulnerable.svg)


## CVE-2017-7559
 In Undertow 2.x before 2.0.0.Alpha2, 1.4.x before 1.4.17.Final, and 1.3.x before 1.3.31.Final, it was found that the fix for CVE-2017-2666 was incomplete and invalid characters are still allowed in the query string and path parameters. This could be exploited, in conjunction with a proxy that also permitted the invalid characters but with a different interpretation, to inject data into the HTTP response. By manipulating the HTTP response the attacker could poison a web-cache, perform an XSS attack, or obtain sensitive information from requests other than their own.

- [https://github.com/andikahilmy/CVE-2017-7559-undertow-vulnerable](https://github.com/andikahilmy/CVE-2017-7559-undertow-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-7559-undertow-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-7559-undertow-vulnerable.svg)


## CVE-2017-5929
 QOS.ch Logback before 1.2.0 has a serialization vulnerability affecting the SocketServer and ServerSocketReceiver components.

- [https://github.com/andikahilmy/CVE-2017-5929-logback-vulnerable](https://github.com/andikahilmy/CVE-2017-5929-logback-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-5929-logback-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-5929-logback-vulnerable.svg)


## CVE-2017-2649
 It was found that the Active Directory Plugin for Jenkins up to and including version 2.2 did not verify certificates of the Active Directory server, thereby enabling Man-in-the-Middle attacks.

- [https://github.com/andikahilmy/CVE-2017-2649-active-directory-plugin-vulnerable](https://github.com/andikahilmy/CVE-2017-2649-active-directory-plugin-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2017-2649-active-directory-plugin-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2017-2649-active-directory-plugin-vulnerable.svg)


## CVE-2016-1000031
 Apache Commons FileUpload before 1.3.3 DiskFileItem File Manipulation Remote Code Execution

- [https://github.com/andikahilmy/CVE-2016-1000031-commons-fileupload-vulnerable](https://github.com/andikahilmy/CVE-2016-1000031-commons-fileupload-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-1000031-commons-fileupload-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-1000031-commons-fileupload-vulnerable.svg)


## CVE-2016-9606
 JBoss RESTEasy before version 3.1.2 could be forced into parsing a request with YamlProvider, resulting in unmarshalling of potentially untrusted data which could allow an attacker to execute arbitrary code with RESTEasy application permissions.

- [https://github.com/andikahilmy/CVE-2016-9606-Resteasy-vulnerable](https://github.com/andikahilmy/CVE-2016-9606-Resteasy-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-9606-Resteasy-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-9606-Resteasy-vulnerable.svg)


## CVE-2016-9589
 Undertow in Red Hat wildfly before version 11.0.0.Beta1 is vulnerable to a resource exhaustion resulting in a denial of service. Undertow keeps a cache of seen HTTP headers in persistent connections. It was found that this cache can easily exploited to fill memory with garbage, up to "max-headers" (default 200) * "max-header-size" (default 1MB) per active TCP connection.

- [https://github.com/andikahilmy/CVE-2016-9589-undertow-vulnerable](https://github.com/andikahilmy/CVE-2016-9589-undertow-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-9589-undertow-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-9589-undertow-vulnerable.svg)


## CVE-2016-9177
 Directory traversal vulnerability in Spark 2.5 allows remote attackers to read arbitrary files via a .. (dot dot) in the URI.

- [https://github.com/andikahilmy/CVE-2016-9177-perwendel-spark-vulnerable](https://github.com/andikahilmy/CVE-2016-9177-perwendel-spark-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-9177-perwendel-spark-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-9177-perwendel-spark-vulnerable.svg)


## CVE-2016-8744
 Apache Brooklyn uses the SnakeYAML library for parsing YAML inputs. SnakeYAML allows the use of YAML tags to indicate that SnakeYAML should unmarshal data to a Java type. In the default configuration in Brooklyn before 0.10.0, SnakeYAML will allow unmarshalling to any Java type available on the classpath. This could provide an authenticated user with a means to cause the JVM running Brooklyn to load and run Java code without detection by Brooklyn. Such code would have the privileges of the Java process running Brooklyn, including the ability to open files and network connections, and execute system commands. There is known to be a proof-of-concept exploit using this vulnerability.

- [https://github.com/andikahilmy/CVE-2016-8744-brooklyn-server-vulnerable](https://github.com/andikahilmy/CVE-2016-8744-brooklyn-server-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-8744-brooklyn-server-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-8744-brooklyn-server-vulnerable.svg)


## CVE-2016-8741
 The Apache Qpid Broker for Java can be configured to use different so called AuthenticationProviders to handle user authentication. Among the choices are the SCRAM-SHA-1 and SCRAM-SHA-256 AuthenticationProvider types. It was discovered that these AuthenticationProviders in Apache Qpid Broker for Java 6.0.x before 6.0.6 and 6.1.x before 6.1.1 prematurely terminate the SCRAM SASL negotiation if the provided user name does not exist thus allowing remote attacker to determine the existence of user accounts. The Vulnerability does not apply to AuthenticationProviders other than SCRAM-SHA-1 and SCRAM-SHA-256.

- [https://github.com/andikahilmy/CVE-2016-8741-qpid-broker-j-vulnerable](https://github.com/andikahilmy/CVE-2016-8741-qpid-broker-j-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-8741-qpid-broker-j-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-8741-qpid-broker-j-vulnerable.svg)


## CVE-2016-7051
 XmlMapper in the Jackson XML dataformat component (aka jackson-dataformat-xml) before 2.7.8 and 2.8.x before 2.8.4 allows remote attackers to conduct server-side request forgery (SSRF) attacks via vectors related to a DTD.

- [https://github.com/andikahilmy/CVE-2016-7051-jackson-dataformat-xml-vulnerable](https://github.com/andikahilmy/CVE-2016-7051-jackson-dataformat-xml-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-7051-jackson-dataformat-xml-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-7051-jackson-dataformat-xml-vulnerable.svg)


## CVE-2016-6809
 Apache Tika before 1.14 allows Java code execution for serialized objects embedded in MATLAB files. The issue exists because Tika invokes JMatIO to do native deserialization.

- [https://github.com/andikahilmy/CVE-2016-6809-tika-vulnerable](https://github.com/andikahilmy/CVE-2016-6809-tika-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-6809-tika-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-6809-tika-vulnerable.svg)


## CVE-2016-6802
 Apache Shiro before 1.3.2 allows attackers to bypass intended servlet filters and gain access by leveraging use of a non-root servlet context path.

- [https://github.com/andikahilmy/CVE-2016-6802-shiro-vulnerable](https://github.com/andikahilmy/CVE-2016-6802-shiro-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-6802-shiro-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-6802-shiro-vulnerable.svg)


## CVE-2016-6801
 Cross-site request forgery (CSRF) vulnerability in the CSRF content-type check in Jackrabbit-Webdav in Apache Jackrabbit 2.4.x before 2.4.6, 2.6.x before 2.6.6, 2.8.x before 2.8.3, 2.10.x before 2.10.4, 2.12.x before 2.12.4, and 2.13.x before 2.13.3 allows remote attackers to hijack the authentication of unspecified victims for requests that create a resource via an HTTP POST request with a (1) missing or (2) crafted Content-Type header.

- [https://github.com/andikahilmy/CVE-2016-6801-jackrabbit-vulnerable](https://github.com/andikahilmy/CVE-2016-6801-jackrabbit-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-6801-jackrabbit-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-6801-jackrabbit-vulnerable.svg)


## CVE-2016-4974
 Apache Qpid AMQP 0-x JMS client before 6.0.4 and JMS (AMQP 1.0) before 0.10.0 does not restrict the use of classes available on the classpath, which might allow remote authenticated users with permission to send messages to deserialize arbitrary objects and execute arbitrary code by leveraging a crafted serialized object in a JMS ObjectMessage that is handled by the getObject function.

- [https://github.com/andikahilmy/CVE-2016-4974-qpid-broker-j-vulnerable](https://github.com/andikahilmy/CVE-2016-4974-qpid-broker-j-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-4974-qpid-broker-j-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-4974-qpid-broker-j-vulnerable.svg)


## CVE-2016-4464
 The application plugins in Apache CXF Fediz 1.2.x before 1.2.3 and 1.3.x before 1.3.1 do not match SAML AudienceRestriction values against configured audience URIs, which might allow remote attackers to have bypass intended restrictions and have unspecified other impact via a crafted SAML token with a trusted signature.

- [https://github.com/andikahilmy/CVE-2016-4464-cxf-fediz-vulnerable](https://github.com/andikahilmy/CVE-2016-4464-cxf-fediz-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-4464-cxf-fediz-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-4464-cxf-fediz-vulnerable.svg)


## CVE-2016-3092
 The MultipartStream class in Apache Commons Fileupload before 1.3.2, as used in Apache Tomcat 7.x before 7.0.70, 8.x before 8.0.36, 8.5.x before 8.5.3, and 9.x before 9.0.0.M7 and other products, allows remote attackers to cause a denial of service (CPU consumption) via a long boundary string.

- [https://github.com/andikahilmy/CVE-2016-3092-commons-fileupload-vulnerable](https://github.com/andikahilmy/CVE-2016-3092-commons-fileupload-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2016-3092-commons-fileupload-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2016-3092-commons-fileupload-vulnerable.svg)


## CVE-2015-6748
 Cross-site scripting (XSS) vulnerability in jsoup before 1.8.3.

- [https://github.com/andikahilmy/CVE-2015-6748-jsoup-vulnerable](https://github.com/andikahilmy/CVE-2015-6748-jsoup-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2015-6748-jsoup-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2015-6748-jsoup-vulnerable.svg)


## CVE-2015-6254
 The (1) Service Provider (SP) and (2) Identity Provider (IdP) in PicketLink before 2.7.0 does not ensure that the Destination attribute in a Response element in a SAML assertion matches the location from which the message was received, which allows remote attackers to have unspecified impact via unknown vectors.  NOTE: this identifier was SPLIT from CVE-2015-0277 per ADT2 due to different vulnerability types.

- [https://github.com/andikahilmy/CVE-2015-6254-picketlink-bindings-vulnerable](https://github.com/andikahilmy/CVE-2015-6254-picketlink-bindings-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2015-6254-picketlink-bindings-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2015-6254-picketlink-bindings-vulnerable.svg)


## CVE-2015-5253
 The SAML Web SSO module in Apache CXF before 2.7.18, 3.0.x before 3.0.7, and 3.1.x before 3.1.3 allows remote authenticated users to bypass authentication via a crafted SAML response with a valid signed assertion, related to a "wrapping attack."

- [https://github.com/andikahilmy/CVE-2015-5253-cxf-vulnerable](https://github.com/andikahilmy/CVE-2015-5253-cxf-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2015-5253-cxf-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2015-5253-cxf-vulnerable.svg)


## CVE-2015-3271
 Apache Tika server (aka tika-server) in Apache Tika 1.9 might allow remote attackers to read arbitrary files via the HTTP fileUrl header.

- [https://github.com/andikahilmy/CVE-2015-3271-tika-vulnerable](https://github.com/andikahilmy/CVE-2015-3271-tika-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2015-3271-tika-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2015-3271-tika-vulnerable.svg)


## CVE-2015-2913
 server/network/protocol/http/OHttpSessionManager.java in the Studio component in OrientDB Server Community Edition before 2.0.15 and 2.1.x before 2.1.1 improperly relies on the java.util.Random class for generation of random Session ID values, which makes it easier for remote attackers to predict a value by determining the internal state of the PRNG in this class.

- [https://github.com/andikahilmy/CVE-2015-2913-orientdb-vulnerable](https://github.com/andikahilmy/CVE-2015-2913-orientdb-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2015-2913-orientdb-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2015-2913-orientdb-vulnerable.svg)


## CVE-2015-2912
 The JSONP endpoint in the Studio component in OrientDB Server Community Edition before 2.0.15 and 2.1.x before 2.1.1 does not properly restrict callback values, which allows remote attackers to conduct cross-site request forgery (CSRF) attacks, and obtain sensitive information, via a crafted HTTP request.

- [https://github.com/andikahilmy/CVE-2015-2912-orientdb-vulnerable](https://github.com/andikahilmy/CVE-2015-2912-orientdb-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2015-2912-orientdb-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2015-2912-orientdb-vulnerable.svg)


## CVE-2015-2156
 Netty before 3.9.8.Final, 3.10.x before 3.10.3.Final, 4.0.x before 4.0.28.Final, and 4.1.x before 4.1.0.Beta5 and Play Framework 2.x before 2.3.9 might allow remote attackers to bypass the httpOnly flag on cookies and obtain sensitive information by leveraging improper validation of cookie name and value characters.

- [https://github.com/andikahilmy/CVE-2015-2156-netty-vulnerable](https://github.com/andikahilmy/CVE-2015-2156-netty-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2015-2156-netty-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2015-2156-netty-vulnerable.svg)


## CVE-2014-7816
 Directory traversal vulnerability in JBoss Undertow 1.0.x before 1.0.17, 1.1.x before 1.1.0.CR5, and 1.2.x before 1.2.0.Beta3, when running on Windows, allows remote attackers to read arbitrary files via a .. (dot dot) in a resource URI.

- [https://github.com/andikahilmy/CVE-2014-7816-undertow-vulnerable](https://github.com/andikahilmy/CVE-2014-7816-undertow-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2014-7816-undertow-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2014-7816-undertow-vulnerable.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/andres101c/Shellshock-CVE-2014-6271](https://github.com/andres101c/Shellshock-CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/andres101c/Shellshock-CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/andres101c/Shellshock-CVE-2014-6271.svg)


## CVE-2014-3651
 JBoss KeyCloak before 1.0.3.Final allows remote attackers to cause a denial of service (resource consumption) via a large value in the size parameter to auth/qrcode, related to QR code generation.

- [https://github.com/andikahilmy/CVE-2014-3651-keycloak-vulnerable](https://github.com/andikahilmy/CVE-2014-3651-keycloak-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2014-3651-keycloak-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2014-3651-keycloak-vulnerable.svg)


## CVE-2014-3488
 The SslHandler in Netty before 3.9.2 allows remote attackers to cause a denial of service (infinite loop and CPU consumption) via a crafted SSLv2Hello message.

- [https://github.com/andikahilmy/CVE-2014-3488-netty-vulnerable](https://github.com/andikahilmy/CVE-2014-3488-netty-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2014-3488-netty-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2014-3488-netty-vulnerable.svg)


## CVE-2014-0050
 MultipartStream.java in Apache Commons FileUpload before 1.3.1, as used in Apache Tomcat, JBoss Web, and other products, allows remote attackers to cause a denial of service (infinite loop and CPU consumption) via a crafted Content-Type header that bypasses a loop's intended exit conditions.

- [https://github.com/andikahilmy/CVE-2014-0050-commons-fileupload-vulnerable](https://github.com/andikahilmy/CVE-2014-0050-commons-fileupload-vulnerable) :  ![starts](https://img.shields.io/github/stars/andikahilmy/CVE-2014-0050-commons-fileupload-vulnerable.svg) ![forks](https://img.shields.io/github/forks/andikahilmy/CVE-2014-0050-commons-fileupload-vulnerable.svg)

