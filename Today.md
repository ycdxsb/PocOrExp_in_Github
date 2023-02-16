# Update 2023-02-16
## CVE-2023-25758
 Onekey Touch devices through 4.0.0 and Onekey Mini devices through 2.10.0 allow man-in-the-middle attackers to obtain the seed phase. The man-in-the-middle access can only be obtained after disassembling a device (i.e., here, &quot;man-in-the-middle&quot; does not refer to the attacker's position on an IP network). NOTE: the vendor states that &quot;our hardware team has updated the security patch without anyone being affected.&quot;

- [https://github.com/Live-Hack-CVE/CVE-2023-25758](https://github.com/Live-Hack-CVE/CVE-2023-25758) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25758.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25758.svg)


## CVE-2023-25725
 HAProxy before 2.7.3 may allow a bypass of access control because HTTP/1 headers are inadvertently lost in some situations, aka &quot;request smuggling.&quot; The HTTP header parsers in HAProxy may accept empty header field names, which could be used to truncate the list of HTTP headers and thus make some headers disappear after being parsed and processed for HTTP/1.0 and HTTP/1.1. For HTTP/2 and HTTP/3, the impact is limited because the headers disappear before being parsed and processed, as if they had not been sent by the client. The fixed versions are 2.7.3, 2.6.9, 2.5.12, 2.4.22, 2.2.29, and 2.0.31.

- [https://github.com/Live-Hack-CVE/CVE-2023-25725](https://github.com/Live-Hack-CVE/CVE-2023-25725) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25725.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25725.svg)


## CVE-2023-25724
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2023-25724](https://github.com/Live-Hack-CVE/CVE-2023-25724) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25724.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25724.svg)


## CVE-2023-25723
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2023-25723](https://github.com/Live-Hack-CVE/CVE-2023-25723) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25723.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25723.svg)


## CVE-2023-25614
 SAP NetWeaver AS ABAP (BSP Framework) application - versions 700, 701, 702, 731, 740, 750, 751, 752, 753, 754, 755, 756, 757, allow an unauthenticated attacker to inject the code that can be executed by the application over the network. On successful exploitation it can gain access to the sensitive information which leads to a limited impact on the confidentiality and the integrity of the application.

- [https://github.com/Live-Hack-CVE/CVE-2023-25614](https://github.com/Live-Hack-CVE/CVE-2023-25614) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25614.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25614.svg)


## CVE-2023-25576
 @fastify/multipart is a Fastify plugin to parse the multipart content-type. Prior to versions 7.4.1 and 6.0.1, @fastify/multipart may experience denial of service due to a number of situations in which an unlimited number of parts are accepted. This includes the multipart body parser accepting an unlimited number of file parts, the multipart body parser accepting an unlimited number of field parts, and the multipart body parser accepting an unlimited number of empty parts as field parts. This is fixed in v7.4.1 (for Fastify v4.x) and v6.0.1 (for Fastify v3.x). There are no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2023-25576](https://github.com/Live-Hack-CVE/CVE-2023-25576) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25576.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25576.svg)


## CVE-2023-25149
 TimescaleDB, an open-source time-series SQL database, has a privilege escalation vulnerability in versions 2.8.0 through 2.9.2. During installation, TimescaleDB creates a telemetry job that is runs as the installation user. The queries run as part of the telemetry data collection were not run with a locked down `search_path`, allowing malicious users to create functions that would be executed by the telemetry job, leading to privilege escalation. In order to be able to take advantage of this vulnerability, a user would need to be able to create objects in a database and then get a superuser to install TimescaleDB into their database. When TimescaleDB is installed as trusted extension, non-superusers can install the extension without help from a superuser. Version 2.9.3 fixes this issue. As a mitigation, the `search_path` of the user running the telemetry job can be locked down to not include schemas writable by other users. The vulnerability is not exploitable on instances in Timescale Cloud and Managed Service for TimescaleDB due to additional security provisions in place on those platforms.

- [https://github.com/Live-Hack-CVE/CVE-2023-25149](https://github.com/Live-Hack-CVE/CVE-2023-25149) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25149.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25149.svg)


## CVE-2023-25141
 Apache Sling JCR Base &lt; 3.1.12 has a critical injection vulnerability when running on old JDK versions (JDK 1.8.191 or earlier) through utility functions in RepositoryAccessor. The functions getRepository and getRepositoryFromURL allow an application to access data stored in a remote location via JDNI and RMI. Users of Apache Sling JCR Base are recommended to upgrade to Apache Sling JCR Base 3.1.12 or later, or to run on a more recent JDK.

- [https://github.com/Live-Hack-CVE/CVE-2023-25141](https://github.com/Live-Hack-CVE/CVE-2023-25141) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25141.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25141.svg)


## CVE-2023-25136
 OpenSSH server (sshd) 9.1 introduced a double-free vulnerability during options.kex_algorithms handling. This is fixed in OpenSSH 9.2. The double free can be leveraged, by an unauthenticated remote attacker in the default configuration, to jump to any location in the sshd address space. One third-party report states &quot;remote code execution is theoretically possible.&quot;

- [https://github.com/ticofookfook/CVE-2023-25136](https://github.com/ticofookfook/CVE-2023-25136) :  ![starts](https://img.shields.io/github/stars/ticofookfook/CVE-2023-25136.svg) ![forks](https://img.shields.io/github/forks/ticofookfook/CVE-2023-25136.svg)


## CVE-2023-25066
 Cross-Site Request Forgery (CSRF) vulnerability in FolioVision FV Flowplayer Video Player plugin &lt;= 7.5.30.7212 versions.

- [https://github.com/Live-Hack-CVE/CVE-2023-25066](https://github.com/Live-Hack-CVE/CVE-2023-25066) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25066.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25066.svg)


## CVE-2023-25065
 Cross-Site Request Forgery (CSRF) vulnerability in ShapedPlugin WP Tabs &#8211; Responsive Tabs Plugin for WordPress plugin &lt;= 2.1.14 versions.

- [https://github.com/Live-Hack-CVE/CVE-2023-25065](https://github.com/Live-Hack-CVE/CVE-2023-25065) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25065.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25065.svg)


## CVE-2023-24557
 A vulnerability has been identified in Solid Edge SE2022 (All versions &lt; V2210Update12), Solid Edge SE2023 (All versions &lt; V2023Update2). The affected applications contain an out of bounds read past the end of an allocated structure while parsing specially crafted PAR files. This could allow an attacker to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2023-24557](https://github.com/Live-Hack-CVE/CVE-2023-24557) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24557.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24557.svg)


## CVE-2023-24556
 A vulnerability has been identified in Solid Edge SE2022 (All versions &lt; V2210Update12), Solid Edge SE2023 (All versions &lt; V2023Update2). The affected applications contain an out of bounds read past the end of an allocated structure while parsing specially crafted PAR files. This could allow an attacker to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2023-24556](https://github.com/Live-Hack-CVE/CVE-2023-24556) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24556.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24556.svg)


## CVE-2023-24555
 A vulnerability has been identified in Solid Edge SE2022 (All versions &lt; V2210Update12), Solid Edge SE2023 (All versions &lt; V2023Update2). The affected applications contain an out of bounds read past the end of an allocated structure while parsing specially crafted PAR files. This could allow an attacker to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2023-24555](https://github.com/Live-Hack-CVE/CVE-2023-24555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24555.svg)


## CVE-2023-24554
 A vulnerability has been identified in Solid Edge SE2022 (All versions &lt; V2210Update12), Solid Edge SE2023 (All versions &lt; V2023Update2). The affected applications contain an out of bounds read past the end of an allocated structure while parsing specially crafted PAR files. This could allow an attacker to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2023-24554](https://github.com/Live-Hack-CVE/CVE-2023-24554) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24554.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24554.svg)


## CVE-2023-24553
 A vulnerability has been identified in Solid Edge SE2022 (All versions &lt; V2210Update12), Solid Edge SE2023 (All versions &lt; V2023Update2). The affected applications contain an out of bounds read past the end of an allocated structure while parsing specially crafted PAR files. This could allow an attacker to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2023-24553](https://github.com/Live-Hack-CVE/CVE-2023-24553) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24553.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24553.svg)


## CVE-2023-24552
 A vulnerability has been identified in Solid Edge SE2022 (All versions &lt; V2210Update12), Solid Edge SE2023 (All versions &lt; V2023Update2). The affected application contains an out of bounds read past the end of an allocated buffer while parsing a specially crafted PAR file. This could allow an attacker to to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2023-24552](https://github.com/Live-Hack-CVE/CVE-2023-24552) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24552.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24552.svg)


## CVE-2023-24551
 A vulnerability has been identified in Solid Edge SE2022 (All versions &lt; V2210Update12), Solid Edge SE2023 (All versions &lt; V2023Update2). The affected application is vulnerable to heap-based buffer underflow while parsing specially crafted PAR files. An attacker could leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2023-24551](https://github.com/Live-Hack-CVE/CVE-2023-24551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24551.svg)


## CVE-2023-24550
 A vulnerability has been identified in Solid Edge SE2022 (All versions &lt; V2210Update12), Solid Edge SE2023 (All versions &lt; V2023Update2). The affected application is vulnerable to heap-based buffer while parsing specially crafted PAR files. An attacker could leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2023-24550](https://github.com/Live-Hack-CVE/CVE-2023-24550) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24550.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24550.svg)


## CVE-2023-24549
 A vulnerability has been identified in Solid Edge SE2022 (All versions &lt; V2210Update12), Solid Edge SE2023 (All versions &lt; V2023Update2). The affected application is vulnerable to stack-based buffer while parsing specially crafted PAR files. An attacker could leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2023-24549](https://github.com/Live-Hack-CVE/CVE-2023-24549) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24549.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24549.svg)


## CVE-2023-24530
 SAP BusinessObjects Business Intelligence Platform (CMC) - versions 420, 430, allows an authenticated admin user to upload malicious code that can be executed by the application over the network. On successful exploitation, attacker can perform operations that may completely compromise the application causing high impact on confidentiality, integrity and availability of the application.

- [https://github.com/Live-Hack-CVE/CVE-2023-24530](https://github.com/Live-Hack-CVE/CVE-2023-24530) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24530.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24530.svg)


## CVE-2023-24529
 Due to lack of proper input validation, BSP application (CRM_BSP_FRAME) - versions 700, 701, 702, 731, 740, 750, 751, 752, 75C, 75D, 75E, 75F, 75G, 75H, allow malicious inputs from untrusted sources, which can be leveraged by an attacker to execute a Reflected Cross-Site Scripting (XSS) attack. As a result, an attacker may be able to hijack a user session, read and modify some sensitive information.

- [https://github.com/Live-Hack-CVE/CVE-2023-24529](https://github.com/Live-Hack-CVE/CVE-2023-24529) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24529.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24529.svg)


## CVE-2023-24528
 SAP Fiori apps for Travel Management in SAP ERP (My Travel Requests) - version 600, allows an authenticated attacker to exploit a certain misconfigured application endpoint to view sensitive data. This endpoint is normally exposed over the network and successful exploitation can lead to exposure of data like travel documents.

- [https://github.com/Live-Hack-CVE/CVE-2023-24528](https://github.com/Live-Hack-CVE/CVE-2023-24528) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24528.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24528.svg)


## CVE-2023-24525
 SAP CRM WebClient UI - versions WEBCUIF 748, 800, 801, S4FND 102, 103, does not sufficiently encode user-controlled inputs, resulting in Cross-Site Scripting (XSS) vulnerability. On successful exploitation an authenticated attacker can cause limited impact on confidentiality of the application.

- [https://github.com/Live-Hack-CVE/CVE-2023-24525](https://github.com/Live-Hack-CVE/CVE-2023-24525) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24525.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24525.svg)


## CVE-2023-24524
 SAP S/4 HANA Map Treasury Correspondence Format Data does not perform necessary authorization check for an authenticated user, resulting in escalation of privileges. This could allow an attacker to delete the data with a high impact to availability.

- [https://github.com/Live-Hack-CVE/CVE-2023-24524](https://github.com/Live-Hack-CVE/CVE-2023-24524) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24524.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24524.svg)


## CVE-2023-24523
 An attacker authenticated as a non-admin user with local access to a server port assigned to the SAP Host Agent (Start Service) - versions 7.21, 7.22, can submit a crafted ConfigureOutsideDiscovery request with an operating system command which will be executed with administrator privileges. The OS command can read or modify any user or system data and can make the system unavailable.

- [https://github.com/Live-Hack-CVE/CVE-2023-24523](https://github.com/Live-Hack-CVE/CVE-2023-24523) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24523.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24523.svg)


## CVE-2023-24522
 Due to insufficient input sanitization, SAP NetWeaver AS ABAP (Business Server Pages) - versions 700, 701, 702, 731, 740, allows an unauthenticated user to alter the current session of the user by injecting the malicious code over the network and gain access to the unintended data. This may lead to a limited impact on the confidentiality and the integrity of the application.

- [https://github.com/Live-Hack-CVE/CVE-2023-24522](https://github.com/Live-Hack-CVE/CVE-2023-24522) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24522.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24522.svg)


## CVE-2023-24521
 Due to insufficient input sanitization, SAP NetWeaver AS ABAP (BSP Framework) - versions 700, 701, 702, 731, 740, 750, 751, 752, 753, 754, 755, 756, 757, allows an unauthenticated user to alter the current session of the user by injecting the malicious code over the network and gain access to the unintended data. This may lead to a limited impact on the confidentiality and the integrity of the application.

- [https://github.com/Live-Hack-CVE/CVE-2023-24521](https://github.com/Live-Hack-CVE/CVE-2023-24521) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24521.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24521.svg)


## CVE-2023-24482
 A vulnerability has been identified in COMOS V10.2 (All versions), COMOS V10.3.3.1 (All versions &lt; V10.3.3.1.45), COMOS V10.3.3.2 (All versions &lt; V10.3.3.2.33), COMOS V10.3.3.3 (All versions &lt; V10.3.3.3.9), COMOS V10.3.3.4 (All versions &lt; V10.3.3.4.6), COMOS V10.4.0.0 (All versions &lt; V10.4.0.0.31), COMOS V10.4.1.0 (All versions &lt; V10.4.1.0.32), COMOS V10.4.2.0 (All versions &lt; V10.4.2.0.25). Cache validation service in COMOS is vulnerable to Structured Exception Handler (SEH) based buffer overflow. This could allow an attacker to execute arbitrary code on the target system or cause denial of service condition.

- [https://github.com/Live-Hack-CVE/CVE-2023-24482](https://github.com/Live-Hack-CVE/CVE-2023-24482) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24482.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24482.svg)


## CVE-2023-24382
 Cross-Site Request Forgery (CSRF) vulnerability in Photon WP Material Design Icons for Page Builders plugin &lt;= 1.4.2 versions.

- [https://github.com/Live-Hack-CVE/CVE-2023-24382](https://github.com/Live-Hack-CVE/CVE-2023-24382) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24382.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24382.svg)


## CVE-2023-24377
 Cross-Site Request Forgery (CSRF) vulnerability in Ecwid Ecommerce Ecwid Ecommerce Shopping Cart plugin &lt;= 6.11.3 versions.

- [https://github.com/Live-Hack-CVE/CVE-2023-24377](https://github.com/Live-Hack-CVE/CVE-2023-24377) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24377.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24377.svg)


## CVE-2023-24161
 TOTOLINK CA300-PoE V6.2c.884 was discovered to contain a command injection vulnerability via the webWlanIdx parameter in the setWebWlanIdx function.

- [https://github.com/Live-Hack-CVE/CVE-2023-24161](https://github.com/Live-Hack-CVE/CVE-2023-24161) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24161.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24161.svg)


## CVE-2023-24160
 TOTOLINK CA300-PoE V6.2c.884 was discovered to contain a command injection vulnerability via the admuser parameter in the setPasswordCfg function.

- [https://github.com/Live-Hack-CVE/CVE-2023-24160](https://github.com/Live-Hack-CVE/CVE-2023-24160) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24160.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24160.svg)


## CVE-2023-24159
 TOTOLINK CA300-PoE V6.2c.884 was discovered to contain a command injection vulnerability via the admpass parameter in the setPasswordCfg function.

- [https://github.com/Live-Hack-CVE/CVE-2023-24159](https://github.com/Live-Hack-CVE/CVE-2023-24159) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24159.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24159.svg)


## CVE-2023-23944
 Nextcloud mail is an email app for the nextcloud home server platform. In versions prior to 2.2.2 user's passwords were stored in cleartext in the database during the duration of OAuth2 setup procedure. Any attacker or malicious user with access to the database would have access to these user passwords until the OAuth setup has been completed. It is recommended that the Nextcloud Mail app is upgraded to 2.2.2. There are no known workarounds for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2023-23944](https://github.com/Live-Hack-CVE/CVE-2023-23944) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23944.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23944.svg)


## CVE-2023-23860
 SAP NetWeaver AS for ABAP and ABAP Platform - versions 740, 750, 751, 752, 753, 754, 755, 756, 757, 789, 790, allows an unauthenticated attacker to craft a link, which when clicked by an unsuspecting user can be used to redirect a user to a malicious site which could read or modify some sensitive information or expose the victim to a phishing attack.

- [https://github.com/Live-Hack-CVE/CVE-2023-23860](https://github.com/Live-Hack-CVE/CVE-2023-23860) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23860.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23860.svg)


## CVE-2023-23859
 SAP NetWeaver AS for ABAP and ABAP Platform - versions 740, 750, 751, 752, 753, 754, 755, 756, 757, 789, 790, allows an unauthenticated attacker to craft a malicious link, which when clicked by an unsuspecting user, can be used to read or modify some sensitive information.

- [https://github.com/Live-Hack-CVE/CVE-2023-23859](https://github.com/Live-Hack-CVE/CVE-2023-23859) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23859.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23859.svg)


## CVE-2023-23858
 Due to insufficient input validation, SAP NetWeaver AS for ABAP and ABAP Platform - versions 740, 750, 751, 752, 753, 754, 755, 756, 757, 789, 790, allows an unauthenticated attacker to send a crafted URL to a user, and by clicking the URL, the tricked user accesses SAP and might be directed with the response to somewhere out-side SAP and enter sensitive data. This could cause a limited impact on confidentiality and integrity of the application.

- [https://github.com/Live-Hack-CVE/CVE-2023-23858](https://github.com/Live-Hack-CVE/CVE-2023-23858) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23858.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23858.svg)


## CVE-2023-23856
 In SAP BusinessObjects Business Intelligence (Web Intelligence user interface) - version 430, some calls return json with wrong content type in the header of the response. As a result, a custom application that calls directly the jsp of Web Intelligence DHTML may be vulnerable to XSS attacks. On successful exploitation an attacker can cause a low impact on integrity of the application.

- [https://github.com/Live-Hack-CVE/CVE-2023-23856](https://github.com/Live-Hack-CVE/CVE-2023-23856) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23856.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23856.svg)


## CVE-2023-23855
 SAP Solution Manager - version 720, allows an authenticated attacker to redirect users to a malicious site due to insufficient URL validation. A successful attack could lead an attacker to read or modify the information or expose the user to a phishing attack. As a result, it has a low impact to confidentiality, integrity and availability.

- [https://github.com/Live-Hack-CVE/CVE-2023-23855](https://github.com/Live-Hack-CVE/CVE-2023-23855) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23855.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23855.svg)


## CVE-2023-23854
 SAP NetWeaver Application Server for ABAP and ABAP Platform - versions 700, 701, 702, 731, 740, 750, 751, 752, does not perform necessary authorization checks for an authenticated user, resulting in escalation of privileges.

- [https://github.com/Live-Hack-CVE/CVE-2023-23854](https://github.com/Live-Hack-CVE/CVE-2023-23854) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23854.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23854.svg)


## CVE-2023-23853
 An unauthenticated attacker in AP NetWeaver Application Server for ABAP and ABAP Platform - versions 700, 702, 731, 740, 750, 751, 752, 753, 754, 755, 756, 757, 789, 790, can craft a link which when clicked by an unsuspecting user can be used to redirect a user to a malicious site which could read or modify some sensitive information or expose the victim to a phishing attack. Vulnerability has no direct impact on availability.

- [https://github.com/Live-Hack-CVE/CVE-2023-23853](https://github.com/Live-Hack-CVE/CVE-2023-23853) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23853.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23853.svg)


## CVE-2023-23852
 SAP Solution Manager (System Monitoring) - version 720, does not sufficiently encode user-controlled inputs, resulting in Cross-Site Scripting (XSS) vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-23852](https://github.com/Live-Hack-CVE/CVE-2023-23852) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23852.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23852.svg)


## CVE-2023-23851
 SAP Business Planning and Consolidation - versions 200, 300, allows an attacker with business authorization to upload any files (including web pages) without the proper file format validation. If other users visit the uploaded malicious web page, the attacker may perform actions on behalf of the users without their consent impacting the confidentiality and integrity of the system.

- [https://github.com/Live-Hack-CVE/CVE-2023-23851](https://github.com/Live-Hack-CVE/CVE-2023-23851) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23851.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23851.svg)


## CVE-2023-23835
 A vulnerability has been identified in Mendix Applications using Mendix 7 (All versions &lt; V7.23.34), Mendix Applications using Mendix 8 (All versions &lt; V8.18.23), Mendix Applications using Mendix 9 (All versions &lt; V9.22.0), Mendix Applications using Mendix 9 (V9.12) (All versions &lt; V9.12.10), Mendix Applications using Mendix 9 (V9.18) (All versions &lt; V9.18.4), Mendix Applications using Mendix 9 (V9.6) (All versions &lt; V9.6.15). Some of the Mendix runtime API&#8217;s allow attackers to bypass XPath constraints and retrieve information using XPath queries that trigger errors.

- [https://github.com/Live-Hack-CVE/CVE-2023-23835](https://github.com/Live-Hack-CVE/CVE-2023-23835) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23835.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23835.svg)


## CVE-2023-23618
 Git for Windows is the Windows port of the revision control system Git. Prior to Git for Windows version 2.39.2, when `gitk` is run on Windows, it potentially runs executables from the current directory inadvertently, which can be exploited with some social engineering to trick users into running untrusted code. A patch is available in version 2.39.2. As a workaround, avoid using `gitk` (or Git GUI's &quot;Visualize History&quot; functionality) in clones of untrusted repositories.

- [https://github.com/Live-Hack-CVE/CVE-2023-23618](https://github.com/Live-Hack-CVE/CVE-2023-23618) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23618.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23618.svg)


## CVE-2023-23381
 Visual Studio Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-23381](https://github.com/Live-Hack-CVE/CVE-2023-23381) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23381.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23381.svg)


## CVE-2023-23074
 Cross site scripting (XSS) vulnerability in Zoho ManageEngine ServiceDesk Plus 14 via embedding videos in the language component.

- [https://github.com/Live-Hack-CVE/CVE-2023-23074](https://github.com/Live-Hack-CVE/CVE-2023-23074) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23074.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23074.svg)


## CVE-2023-22942
 In Splunk Enterprise versions below 8.1.13, 8.2.10, and 9.0.4, a cross-site request forgery in the Splunk Secure Gateway (SSG) app in the &#8216;kvstore_client&#8217; REST endpoint lets a potential attacker update SSG [App Key Value Store (KV store)](https://docs.splunk.com/Documentation/Splunk/latest/Admin/AboutKVstore) collections using an HTTP GET request. SSG is a Splunk-built app that comes with Splunk Enterprise. The vulnerability affects instances with SSG and Splunk Web enabled.

- [https://github.com/Live-Hack-CVE/CVE-2023-22942](https://github.com/Live-Hack-CVE/CVE-2023-22942) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22942.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22942.svg)


## CVE-2023-22941
 In Splunk Enterprise versions below 8.1.13, 8.2.10, and 9.0.4, an improperly-formatted &#8216;INGEST_EVAL&#8217; parameter in a [Field Transformation](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Managefieldtransforms) crashes the Splunk daemon (splunkd).

- [https://github.com/Live-Hack-CVE/CVE-2023-22941](https://github.com/Live-Hack-CVE/CVE-2023-22941) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22941.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22941.svg)


## CVE-2023-22940
 In Splunk Enterprise versions below 8.1.13, 8.2.10, and 9.0.4, aliases of the &#8216;collect&#8217; search processing language (SPL) command, including &#8216;summaryindex&#8217;, &#8216;sumindex&#8217;, &#8216;stash&#8217;,&#8217; mcollect&#8217;, and &#8216;meventcollect&#8217;, were not designated as safeguarded commands. The commands could potentially allow for the exposing of data to a summary index that unprivileged users could access. The vulnerability requires a higher privileged user to initiate a request within their browser, and only affects instances with Splunk Web enabled.

- [https://github.com/Live-Hack-CVE/CVE-2023-22940](https://github.com/Live-Hack-CVE/CVE-2023-22940) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22940.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22940.svg)


## CVE-2023-22939
 In Splunk Enterprise versions below 8.1.13, 8.2.10, and 9.0.4, the &#8216;map&#8217; search processing language (SPL) command lets a search [bypass SPL safeguards for risky commands](https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards). The vulnerability requires a higher privileged user to initiate a request within their browser and only affects instances with Splunk Web enabled.

- [https://github.com/Live-Hack-CVE/CVE-2023-22939](https://github.com/Live-Hack-CVE/CVE-2023-22939) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22939.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22939.svg)


## CVE-2023-22938
 In Splunk Enterprise versions below 8.1.13, 8.2.10, and 9.0.4, the &#8216;sendemail&#8217; REST API endpoint lets any authenticated user send an email as the Splunk instance. The endpoint is now restricted to the &#8216;splunk-system-user&#8217; account on the local instance.

- [https://github.com/Live-Hack-CVE/CVE-2023-22938](https://github.com/Live-Hack-CVE/CVE-2023-22938) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22938.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22938.svg)


## CVE-2023-22937
 In Splunk Enterprise versions below 8.1.13, 8.2.10, and 9.0.4, the lookup table upload feature let a user upload lookup tables with unnecessary filename extensions. Lookup table file extensions may now be one of the following only: .csv, .csv.gz, .kmz, .kml, .mmdb, or .mmdb.gzl. For more information on lookup table files, see [About lookups](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutlookupsandfieldactions).

- [https://github.com/Live-Hack-CVE/CVE-2023-22937](https://github.com/Live-Hack-CVE/CVE-2023-22937) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22937.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22937.svg)


## CVE-2023-22936
 In Splunk Enterprise versions below 8.1.13, 8.2.10, and 9.0.4, the &#8216;search_listener&#8217; parameter in a search allows for a blind server-side request forgery (SSRF) by an authenticated user. The initiator of the request cannot see the response without the presence of an additional vulnerability within the environment.

- [https://github.com/Live-Hack-CVE/CVE-2023-22936](https://github.com/Live-Hack-CVE/CVE-2023-22936) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22936.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22936.svg)


## CVE-2023-22935
 In Splunk Enterprise versions below 8.1.13, 8.2.10, and 9.0.4, the &#8216;display.page.search.patterns.sensitivity&#8217; search parameter lets a search bypass [SPL safeguards for risky commands](https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards). The vulnerability requires a higher privileged user to initiate a request within their browser and only affects instances with Splunk Web enabled.

- [https://github.com/Live-Hack-CVE/CVE-2023-22935](https://github.com/Live-Hack-CVE/CVE-2023-22935) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22935.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22935.svg)


## CVE-2023-22934
 In Splunk Enterprise versions below 8.1.13, 8.2.10, and 9.0.4, the &#8216;pivot&#8217; search processing language (SPL) command lets a search bypass [SPL safeguards for risky commands](https://docs.splunk.com/Documentation/Splunk/latest/Security/SPLsafeguards) using a saved search job. The vulnerability requires an authenticated user to craft the saved job and a higher privileged user to initiate a request within their browser. The vulnerability affects instances with Splunk Web enabled.

- [https://github.com/Live-Hack-CVE/CVE-2023-22934](https://github.com/Live-Hack-CVE/CVE-2023-22934) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22934.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22934.svg)


## CVE-2023-22933
 In Splunk Enterprise versions below 8.1.13, 8.2.10, and 9.0.4, a View allows for Cross-Site Scripting (XSS) in an extensible mark-up language (XML) View through the &#8216;layoutPanel&#8217; attribute in the &#8216;module&#8217; tag&#8217;. The vulnerability affects instances with Splunk Web enabled.

- [https://github.com/Live-Hack-CVE/CVE-2023-22933](https://github.com/Live-Hack-CVE/CVE-2023-22933) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22933.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22933.svg)


## CVE-2023-22932
 In Splunk Enterprise 9.0 versions before 9.0.4, a View allows for Cross-Site Scripting (XSS) through the error message in a Base64-encoded image. The vulnerability affects instances with Splunk Web enabled. It does not affect Splunk Enterprise versions below 9.0.

- [https://github.com/Live-Hack-CVE/CVE-2023-22932](https://github.com/Live-Hack-CVE/CVE-2023-22932) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22932.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22932.svg)


## CVE-2023-22931
 In Splunk Enterprise versions below 8.1.13 and 8.2.10, the &#8216;createrss&#8217; external search command overwrites existing Resource Description Format Site Summary (RSS) feeds without verifying permissions. This feature has been deprecated and disabled by default.

- [https://github.com/Live-Hack-CVE/CVE-2023-22931](https://github.com/Live-Hack-CVE/CVE-2023-22931) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22931.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22931.svg)


## CVE-2023-22743
 Git for Windows is the Windows port of the revision control system Git. Prior to Git for Windows version 2.39.2, by carefully crafting DLL and putting into a subdirectory of a specific name living next to the Git for Windows installer, Windows can be tricked into side-loading said DLL. This potentially allows users with local write access to place malicious payloads in a location where automated upgrades might run the Git for Windows installer with elevation. Version 2.39.2 contains a patch for this issue. Some workarounds are available. Never leave untrusted files in the Downloads folder or its sub-folders before executing the Git for Windows installer, or move the installer into a different directory before executing it.

- [https://github.com/Live-Hack-CVE/CVE-2023-22743](https://github.com/Live-Hack-CVE/CVE-2023-22743) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22743.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22743.svg)


## CVE-2023-22375
 ** UNSUPPORTED WHEN ASSIGNED ** Cross-site request forgery (CSRF) vulnerability in Wired/Wireless LAN Pan/Tilt Network Camera CS-WMV02G all versions allows a remote unauthenticated attacker to hijack the authentication and conduct arbitrary operations by having a logged-in user to view a malicious page. NOTE: This vulnerability only affects products that are no longer supported by the developer.

- [https://github.com/Live-Hack-CVE/CVE-2023-22375](https://github.com/Live-Hack-CVE/CVE-2023-22375) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22375.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22375.svg)


## CVE-2023-22370
 ** UNSUPPORTED WHEN ASSIGNED ** Stored cross-site scripting vulnerability in Wired/Wireless LAN Pan/Tilt Network Camera CS-WMV02G all versions allows a network-adjacent authenticated attacker to inject an arbitrary script. NOTE: This vulnerability only affects products that are no longer supported by the developer.

- [https://github.com/Live-Hack-CVE/CVE-2023-22370](https://github.com/Live-Hack-CVE/CVE-2023-22370) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22370.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22370.svg)


## CVE-2023-21823
 Windows Graphics Component Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21823](https://github.com/Live-Hack-CVE/CVE-2023-21823) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21823.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21823.svg)


## CVE-2023-21815
 Visual Studio Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21815](https://github.com/Live-Hack-CVE/CVE-2023-21815) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21815.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21815.svg)


## CVE-2023-21808
 .NET and Visual Studio Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21808](https://github.com/Live-Hack-CVE/CVE-2023-21808) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21808.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21808.svg)


## CVE-2023-21778
 Microsoft Dynamics Unified Service Desk Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21778](https://github.com/Live-Hack-CVE/CVE-2023-21778) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21778.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21778.svg)


## CVE-2023-21699
 Windows Internet Storage Name Service (iSNS) Server Information Disclosure Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21699](https://github.com/Live-Hack-CVE/CVE-2023-21699) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21699.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21699.svg)


## CVE-2023-21697
 Windows Internet Storage Name Service (iSNS) Server Information Disclosure Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21697](https://github.com/Live-Hack-CVE/CVE-2023-21697) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21697.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21697.svg)


## CVE-2023-21695
 Microsoft Protected Extensible Authentication Protocol (PEAP) Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21695](https://github.com/Live-Hack-CVE/CVE-2023-21695) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21695.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21695.svg)


## CVE-2023-21694
 Windows Fax Service Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21694](https://github.com/Live-Hack-CVE/CVE-2023-21694) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21694.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21694.svg)


## CVE-2023-21693
 Microsoft PostScript Printer Driver Information Disclosure Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21693](https://github.com/Live-Hack-CVE/CVE-2023-21693) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21693.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21693.svg)


## CVE-2023-21692
 Microsoft Protected Extensible Authentication Protocol (PEAP) Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21692](https://github.com/Live-Hack-CVE/CVE-2023-21692) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21692.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21692.svg)


## CVE-2023-21691
 Microsoft Protected Extensible Authentication Protocol (PEAP) Information Disclosure Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21691](https://github.com/Live-Hack-CVE/CVE-2023-21691) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21691.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21691.svg)


## CVE-2023-21690
 Microsoft Protected Extensible Authentication Protocol (PEAP) Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21690](https://github.com/Live-Hack-CVE/CVE-2023-21690) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21690.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21690.svg)


## CVE-2023-21689
 Microsoft Protected Extensible Authentication Protocol (PEAP) Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21689](https://github.com/Live-Hack-CVE/CVE-2023-21689) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21689.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21689.svg)


## CVE-2023-21688
 NT OS Kernel Elevation of Privilege Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21688](https://github.com/Live-Hack-CVE/CVE-2023-21688) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21688.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21688.svg)


## CVE-2023-21687
 HTTP.sys Information Disclosure Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21687](https://github.com/Live-Hack-CVE/CVE-2023-21687) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21687.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21687.svg)


## CVE-2023-21686
 Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21686](https://github.com/Live-Hack-CVE/CVE-2023-21686) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21686.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21686.svg)


## CVE-2023-21685
 Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21685](https://github.com/Live-Hack-CVE/CVE-2023-21685) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21685.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21685.svg)


## CVE-2023-21684
 Microsoft PostScript Printer Driver Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21684](https://github.com/Live-Hack-CVE/CVE-2023-21684) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21684.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21684.svg)


## CVE-2023-21573
 Microsoft Dynamics 365 (on-premises) Cross-site Scripting Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21573](https://github.com/Live-Hack-CVE/CVE-2023-21573) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21573.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21573.svg)


## CVE-2023-21572
 Microsoft Dynamics 365 (on-premises) Cross-site Scripting Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21572](https://github.com/Live-Hack-CVE/CVE-2023-21572) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21572.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21572.svg)


## CVE-2023-21571
 Microsoft Dynamics 365 (on-premises) Cross-site Scripting Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21571](https://github.com/Live-Hack-CVE/CVE-2023-21571) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21571.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21571.svg)


## CVE-2023-21570
 Microsoft Dynamics 365 (on-premises) Cross-site Scripting Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21570](https://github.com/Live-Hack-CVE/CVE-2023-21570) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21570.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21570.svg)


## CVE-2023-21568
 Microsoft SQL Server Integration Service (VS extension) Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21568](https://github.com/Live-Hack-CVE/CVE-2023-21568) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21568.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21568.svg)


## CVE-2023-21567
 Visual Studio Denial of Service Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21567](https://github.com/Live-Hack-CVE/CVE-2023-21567) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21567.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21567.svg)


## CVE-2023-21566
 Visual Studio Elevation of Privilege Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21566](https://github.com/Live-Hack-CVE/CVE-2023-21566) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21566.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21566.svg)


## CVE-2023-21564
 Azure DevOps Server Cross-Site Scripting Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21564](https://github.com/Live-Hack-CVE/CVE-2023-21564) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21564.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21564.svg)


## CVE-2023-21553
 Azure DevOps Server Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21553](https://github.com/Live-Hack-CVE/CVE-2023-21553) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21553.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21553.svg)


## CVE-2023-21529
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21529](https://github.com/Live-Hack-CVE/CVE-2023-21529) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21529.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21529.svg)


## CVE-2023-21528
 Microsoft SQL Server Remote Code Execution Vulnerability

- [https://github.com/Live-Hack-CVE/CVE-2023-21528](https://github.com/Live-Hack-CVE/CVE-2023-21528) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21528.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21528.svg)


## CVE-2023-0827
 Cross-site Scripting (XSS) - Stored in GitHub repository pimcore/pimcore prior to 1.5.17.

- [https://github.com/Live-Hack-CVE/CVE-2023-0827](https://github.com/Live-Hack-CVE/CVE-2023-0827) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0827.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0827.svg)


## CVE-2023-0687
 A vulnerability was found in GNU C Library 2.38. It has been declared as critical. This vulnerability affects the function __monstartup of the file gmon.c of the component Call Graph Monitor. The manipulation leads to buffer overflow. It is recommended to apply a patch to fix this issue. VDB-220246 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0687](https://github.com/Live-Hack-CVE/CVE-2023-0687) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0687.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0687.svg)


## CVE-2023-0655
 SonicWall Email Security contains a vulnerability that could permit a remote unauthenticated attacker access to an error page that includes sensitive information about users email addresses.

- [https://github.com/Live-Hack-CVE/CVE-2023-0655](https://github.com/Live-Hack-CVE/CVE-2023-0655) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0655.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0655.svg)


## CVE-2023-0236
 The Tutor LMS WordPress plugin before 2.0.10 does not sanitise and escape the reset_key and user_id parameters before outputting then back in attributes, leading to Reflected Cross-Site Scripting which could be used against high privilege users such as admin

- [https://github.com/Live-Hack-CVE/CVE-2023-0236](https://github.com/Live-Hack-CVE/CVE-2023-0236) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0236.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0236.svg)


## CVE-2023-0178
 The Annual Archive WordPress plugin before 1.6.0 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2023-0178](https://github.com/Live-Hack-CVE/CVE-2023-0178) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0178.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0178.svg)


## CVE-2023-0176
 The Giveaways and Contests by RafflePress WordPress plugin before 1.11.3 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2023-0176](https://github.com/Live-Hack-CVE/CVE-2023-0176) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0176.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0176.svg)


## CVE-2023-0174
 The WP VR WordPress plugin before 8.2.7 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2023-0174](https://github.com/Live-Hack-CVE/CVE-2023-0174) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0174.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0174.svg)


## CVE-2023-0173
 The Drag &amp; Drop Sales Funnel Builder for WordPress plugin before 2.6.9 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2023-0173](https://github.com/Live-Hack-CVE/CVE-2023-0173) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0173.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0173.svg)


## CVE-2023-0171
 The jQuery T(-) Countdown Widget WordPress plugin before 2.3.24 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2023-0171](https://github.com/Live-Hack-CVE/CVE-2023-0171) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0171.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0171.svg)


## CVE-2023-0025
 SAP Solution Manager (BSP Application) - version 720, allows an authenticated attacker to craft a malicious link, which when clicked by an unsuspecting user, can be used to read or modify some sensitive information or craft a payload which may restrict access to the desired resources.

- [https://github.com/Live-Hack-CVE/CVE-2023-0025](https://github.com/Live-Hack-CVE/CVE-2023-0025) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0025.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0025.svg)


## CVE-2023-0024
 SAP Solution Manager (BSP Application) - version 720, allows an authenticated attacker to craft a malicious link, which when clicked by an unsuspecting user, can be used to read or modify some sensitive information or craft a payload which may restrict access to the desired resources, resulting in Cross-Site Scripting vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0024](https://github.com/Live-Hack-CVE/CVE-2023-0024) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0024.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0024.svg)


## CVE-2023-0020
 SAP BusinessObjects Business Intelligence platform - versions 420, 430, allows an authenticated attacker to access sensitive information which is otherwise restricted. On successful exploitation, there could be a high impact on confidentiality and limited impact on integrity of the application.

- [https://github.com/Live-Hack-CVE/CVE-2023-0020](https://github.com/Live-Hack-CVE/CVE-2023-0020) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0020.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0020.svg)


## CVE-2023-0019
 In SAP GRC (Process Control) - versions GRCFND_A V1200, GRCFND_A V8100, GRCPINW V1100_700, GRCPINW V1100_731, GRCPINW V1200_750, remote-enabled function module in the proprietary SAP solution enables an authenticated attacker with minimal privileges to access all the confidential data stored in the database. Successful exploitation of this vulnerability can expose user credentials from client-specific tables of the database, leading to high impact on confidentiality.

- [https://github.com/Live-Hack-CVE/CVE-2023-0019](https://github.com/Live-Hack-CVE/CVE-2023-0019) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0019.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0019.svg)


## CVE-2022-47977
 A vulnerability has been identified in JT Open (All versions &lt; V11.2.3.0), JT Utilities (All versions &lt; V13.2.3.0). The affected application contains a memory corruption vulnerability while parsing specially crafted JT files. This could allow an attacker to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2022-47977](https://github.com/Live-Hack-CVE/CVE-2022-47977) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47977.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47977.svg)


## CVE-2022-47936
 A vulnerability has been identified in JT Open (All versions &lt; V11.2.3.0), JT Utilities (All versions &lt; V13.2.3.0), Parasolid V34.0 (All versions &lt; V34.0.252), Parasolid V34.1 (All versions &lt; V34.1.242), Parasolid V35.0 (All versions &lt; V35.0.170), Parasolid V35.1 (All versions &lt; V35.1.150). The affected application contains a stack overflow vulnerability while parsing specially crafted JT files. This could allow an attacker to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2022-47936](https://github.com/Live-Hack-CVE/CVE-2022-47936) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47936.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47936.svg)


## CVE-2022-47373
 Reflected Cross Site Scripting in Search Functionality of Module Library in Pandora FMS Console v766 and lower. This vulnerability arises on the forget password functionality in which parameter username does not proper input validation/sanitization thus results in executing malicious JavaScript payload.

- [https://github.com/Live-Hack-CVE/CVE-2022-47373](https://github.com/Live-Hack-CVE/CVE-2022-47373) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47373.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47373.svg)


## CVE-2022-47372
 Stored cross-site scripting vulnerability in the Create event section in Pandora FMS Console v766 and lower. An attacker typically exploits this vulnerability by injecting XSS payloads on popular pages of a site or passing a link to a victim, tricking them into viewing the page that contains the stored XSS payload.

- [https://github.com/Live-Hack-CVE/CVE-2022-47372](https://github.com/Live-Hack-CVE/CVE-2022-47372) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47372.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47372.svg)


## CVE-2022-46862
 Cross-Site Request Forgery (CSRF) vulnerability in ExpressTech Quiz And Survey Master &#8211; Best Quiz, Exam and Survey Plugin for WordPress plugin &lt;= 8.0.7 versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-46862](https://github.com/Live-Hack-CVE/CVE-2022-46862) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46862.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46862.svg)


## CVE-2022-45437
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Artica PFMS Pandora FMS v765 on all allows Cross-Site Scripting (XSS). A user with edition privileges can create a Payload in the reporting dashboard module. An admin user can observe the Payload without interaction and attacker can get information.

- [https://github.com/Live-Hack-CVE/CVE-2022-45437](https://github.com/Live-Hack-CVE/CVE-2022-45437) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45437.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45437.svg)


## CVE-2022-45436
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Artica PFMS Pandora FMS v765 on all platforms, allows Cross-Site Scripting (XSS). As a manager privilege user , create a network map containing name as xss payload. Once created, admin user must click on the edit network maps and XSS payload will be executed, which could be used for stealing admin users cookie value.

- [https://github.com/Live-Hack-CVE/CVE-2022-45436](https://github.com/Live-Hack-CVE/CVE-2022-45436) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45436.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45436.svg)


## CVE-2022-43469
 Cross-Site Request Forgery (CSRF) vulnerability in Orchestrated Corona Virus (COVID-19) Banner &amp; Live Data plugin &lt;= 1.7.0.6 versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-43469](https://github.com/Live-Hack-CVE/CVE-2022-43469) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43469.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43469.svg)


## CVE-2022-42439
 IBM App Connect Enterprise 11.0.0.17 through 11.0.0.19 and 12.0.4.0 and 12.0.5.0 contains an unspecified vulnerability in the Discovery Connector nodes which may cause a 3rd party system&#8217;s credentials to be exposed to a privileged attacker. IBM X-Force ID: 238211.

- [https://github.com/Live-Hack-CVE/CVE-2022-42439](https://github.com/Live-Hack-CVE/CVE-2022-42439) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42439.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42439.svg)


## CVE-2022-41564
 The Hawk Console component of TIBCO Software Inc.'s TIBCO Hawk and TIBCO Operational Intelligence Hawk RedTail contains a vulnerability that will return the EMS transport password and EMS SSL password to a privileged user. Affected releases are TIBCO Software Inc.'s TIBCO Hawk: versions 6.2.1 and below and TIBCO Operational Intelligence Hawk RedTail: versions 7.2.0 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-41564](https://github.com/Live-Hack-CVE/CVE-2022-41564) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41564.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41564.svg)


## CVE-2022-41342
 Improper buffer restrictions the Intel(R) C++ Compiler Classic before version 2021.7.1. for some Intel(R) oneAPI Toolkits before version 2022.3.1 may allow a privileged user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-41342](https://github.com/Live-Hack-CVE/CVE-2022-41342) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41342.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41342.svg)


## CVE-2022-40196
 Improper access control in the Intel(R) oneAPI DPC++/C++ Compiler before version 2022.2.1 for some Intel(R) oneAPI Toolkits before version 2022.3.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-40196](https://github.com/Live-Hack-CVE/CVE-2022-40196) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40196.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40196.svg)


## CVE-2022-38136
 Uncontrolled search path in the Intel(R) oneAPI DPC++/C++ Compiler before version 2022.2.1 for some Intel(R) oneAPI Toolkits before version 2022.3.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

- [https://github.com/Live-Hack-CVE/CVE-2022-38136](https://github.com/Live-Hack-CVE/CVE-2022-38136) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38136.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38136.svg)


## CVE-2022-35868
 A vulnerability has been identified in TIA Multiuser Server V14 (All versions), TIA Multiuser Server V15 (All versions &lt; V15.1 Update 8), TIA Project-Server (All versions &lt; V1.1), TIA Project-Server V16 (All versions), TIA Project-Server V17 (All versions). Affected applications contain an untrusted search path vulnerability that could allow an attacker to escalate privileges, when tricking a legitimate user to start the service from an attacker controlled path.

- [https://github.com/Live-Hack-CVE/CVE-2022-35868](https://github.com/Live-Hack-CVE/CVE-2022-35868) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-35868.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-35868.svg)


## CVE-2022-32656
 In Wi-Fi driver, there is a possible undefined behavior due to incorrect error handling. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: GN20220705035; Issue ID: GN20220705035.

- [https://github.com/Live-Hack-CVE/CVE-2022-32656](https://github.com/Live-Hack-CVE/CVE-2022-32656) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32656.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32656.svg)


## CVE-2022-31808
 A vulnerability has been identified in SiPass integrated AC5102 (ACC-G2) (All versions &lt; V2.85.44), SiPass integrated ACC-AP (All versions &lt; V2.85.43). Affected devices improperly sanitize user input on the telnet command line interface. This could allow an authenticated user to escalate privileges by injecting arbitrary commands that are executed with root privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-31808](https://github.com/Live-Hack-CVE/CVE-2022-31808) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31808.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31808.svg)


## CVE-2022-29557
 LexisNexis Firco Compliance Link 3.7 allows CSRF.

- [https://github.com/Live-Hack-CVE/CVE-2022-29557](https://github.com/Live-Hack-CVE/CVE-2022-29557) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29557.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29557.svg)


## CVE-2022-29109
 Microsoft Excel Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-29110.

- [https://github.com/Live-Hack-CVE/CVE-2022-29109](https://github.com/Live-Hack-CVE/CVE-2022-29109) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-29109.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-29109.svg)


## CVE-2022-28845
 Adobe Bridge version 12.0.1 (and earlier versions) is affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Live-Hack-CVE/CVE-2022-28845](https://github.com/Live-Hack-CVE/CVE-2022-28845) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-28845.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-28845.svg)


## CVE-2022-28368
 Dompdf 1.2.1 allows remote code execution via a .php file in the src:url field of an @font-face Cascading Style Sheets (CSS) statement (within an HTML input file).

- [https://github.com/rvizx/CVE-2022-28368](https://github.com/rvizx/CVE-2022-28368) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2022-28368.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2022-28368.svg)


## CVE-2022-22564
 Dell EMC Unity versions before 5.2.0.0.5.173 , use(es) broken cryptographic algorithm. A remote unauthenticated attacker could potentially exploit this vulnerability by performing MitM attacks and let attackers obtain sensitive information.

- [https://github.com/Live-Hack-CVE/CVE-2022-22564](https://github.com/Live-Hack-CVE/CVE-2022-22564) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22564.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22564.svg)


## CVE-2022-4902
 A vulnerability classified as problematic has been found in eXo Chat Application. Affected is an unknown function of the file application/src/main/webapp/vue-app/components/ExoChatMessageComposer.vue of the component Mention Handler. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 3.3.0-20220417 is able to address this issue. The name of the patch is 26bf307d3658d1403cfd5c3ad423ce4c4d1cb2dc. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-220212.

- [https://github.com/Live-Hack-CVE/CVE-2022-4902](https://github.com/Live-Hack-CVE/CVE-2022-4902) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4902.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4902.svg)


## CVE-2022-4612
 A vulnerability has been found in Click Studios Passwordstate and Passwordstate Browser Extension Chrome and classified as problematic. This vulnerability affects unknown code. The manipulation leads to insufficiently protected credentials. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. It is recommended to upgrade the affected component. VDB-216274 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4612](https://github.com/Live-Hack-CVE/CVE-2022-4612) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4612.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4612.svg)


## CVE-2022-4496
 The SAML SSO Standard WordPress plugin version 16.0.0 before 16.0.8, SAML SSO Premium WordPress plugin version 12.0.0 before 12.1.0 and SAML SSO Premium Multisite WordPress plugin version 20.0.0 before 20.0.7 does not validate that the redirect parameter to its SSO login endpoint points to an internal site URL, making it vulnerable to an Open Redirect issue when the user is already logged in.

- [https://github.com/Live-Hack-CVE/CVE-2022-4496](https://github.com/Live-Hack-CVE/CVE-2022-4496) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4496.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4496.svg)


## CVE-2022-4377
 A vulnerability was found in S-CMS 5.0 Build 20220328. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the component Contact Information Page. The manipulation of the argument Make a Call leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-215197 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4377](https://github.com/Live-Hack-CVE/CVE-2022-4377) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4377.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4377.svg)


## CVE-2022-4286
 A reflected cross-site scripting (XSS) vulnerability exists in System Diagnostics Manager of B&amp;R Automation Runtime versions &gt;=3.00 and &lt;=C4.93 that enables a remote attacker to execute arbitrary JavaScript in the context of the users browser session.

- [https://github.com/Live-Hack-CVE/CVE-2022-4286](https://github.com/Live-Hack-CVE/CVE-2022-4286) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4286.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4286.svg)


## CVE-2022-3987
 The Responsive Lightbox2 WordPress plugin before 1.0.4 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks

- [https://github.com/Live-Hack-CVE/CVE-2022-3987](https://github.com/Live-Hack-CVE/CVE-2022-3987) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3987.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3987.svg)


## CVE-2022-3806
 Inconsistent handling of error cases in bluetooth hci may lead to a double free condition of a network buffer.

- [https://github.com/Live-Hack-CVE/CVE-2022-3806](https://github.com/Live-Hack-CVE/CVE-2022-3806) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3806.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3806.svg)


## CVE-2022-3204
 A vulnerability named 'Non-Responsive Delegation Attack' (NRDelegation Attack) has been discovered in various DNS resolving software. The NRDelegation Attack works by having a malicious delegation with a considerable number of non responsive nameservers. The attack starts by querying a resolver for a record that relies on those unresponsive nameservers. The attack can cause a resolver to spend a lot of time/resources resolving records under a malicious delegation point where a considerable number of unresponsive NS records reside. It can trigger high CPU usage in some resolver implementations that continually look in the cache for resolved NS records in that delegation. This can lead to degraded performance and eventually denial of service in orchestrated attacks. Unbound does not suffer from high CPU usage, but resources are still needed for resolving the malicious delegation. Unbound will keep trying to resolve the record until hard limits are reached. Based on the nature of the attack and the replies, different limits could be reached. From version 1.16.3 on, Unbound introduces fixes for better performance when under load, by cutting opportunistic queries for nameserver discovery and DNSKEY prefetching and limiting the number of times a delegation point can issue a cache lookup for missing records.

- [https://github.com/Live-Hack-CVE/CVE-2022-3204](https://github.com/Live-Hack-CVE/CVE-2022-3204) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3204.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3204.svg)


## CVE-2022-2933
 The 0mk Shortener plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 0.2. This is due to missing or incorrect nonce validation on the zeromk_options_page function. This makes it possible for unauthenticated attackers to inject malicious web scripts via the 'zeromk_user' and 'zeromk_apikluc' parameters through a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Live-Hack-CVE/CVE-2022-2933](https://github.com/Live-Hack-CVE/CVE-2022-2933) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2933.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2933.svg)


## CVE-2022-2344
 Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0045.

- [https://github.com/Live-Hack-CVE/CVE-2022-2344](https://github.com/Live-Hack-CVE/CVE-2022-2344) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2344.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2344.svg)


## CVE-2022-2206
 Out-of-bounds Read in GitHub repository vim/vim prior to 8.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-2206](https://github.com/Live-Hack-CVE/CVE-2022-2206) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2206.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2206.svg)


## CVE-2021-46023
 An Untrusted Pointer Dereference was discovered in function mrb_vm_exec in mruby before 3.1.0-rc. The vulnerability causes a segmentation fault and application crash.

- [https://github.com/Live-Hack-CVE/CVE-2021-46023](https://github.com/Live-Hack-CVE/CVE-2021-46023) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-46023.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-46023.svg)


## CVE-2021-43391
 An Out-of-Bounds Read vulnerability exists when reading a DXF file using Open Design Alliance Drawings SDK before 2022.11. The specific issue exists within the parsing of DXF files. Crafted data in a DXF file (an invalid dash counter in line types) can trigger a read past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2021-43391](https://github.com/Live-Hack-CVE/CVE-2021-43391) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-43391.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-43391.svg)


## CVE-2021-43336
 An Out-of-Bounds Write vulnerability exists when reading a DXF or DWG file using Open Design Alliance Drawings SDK before 2022.11. The specific issue exists within the parsing of DXF and DWG files. Crafted data in a DXF or DWG file (an invalid number of properties) can trigger a write operation past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2021-43336](https://github.com/Live-Hack-CVE/CVE-2021-43336) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-43336.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-43336.svg)


## CVE-2021-40360
 A vulnerability has been identified in SIMATIC PCS 7 V8.2 (All versions), SIMATIC PCS 7 V9.0 (All versions), SIMATIC PCS 7 V9.1 (All versions &lt; V9.1 SP1), SIMATIC WinCC V15 and earlier (All versions &lt; V15 SP1 Update 7), SIMATIC WinCC V16 (All versions &lt; V16 Update 5), SIMATIC WinCC V17 (All versions &lt; V17 Update 2), SIMATIC WinCC V7.4 (All versions &lt; V7.4 SP1 Update 19), SIMATIC WinCC V7.5 (All versions &lt; V7.5 SP2 Update 6). The password hash of a local user account in the remote server could be granted via public API to a user on the affected system. An authenticated attacker could brute force the password hash and use it to login to the server.

- [https://github.com/Live-Hack-CVE/CVE-2021-40360](https://github.com/Live-Hack-CVE/CVE-2021-40360) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-40360.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-40360.svg)


## CVE-2021-32936
 An out-of-bounds write issue exists in the DXF file-recovering procedure in the Drawings SDK (All versions prior to 2022.4) resulting from the lack of proper validation of user-supplied data. This can result in a write past the end of an allocated buffer and allow attackers to cause a denial-of-service condition or execute code in the context of the current process.

- [https://github.com/Live-Hack-CVE/CVE-2021-32936](https://github.com/Live-Hack-CVE/CVE-2021-32936) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-32936.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-32936.svg)


## CVE-2021-31727
 Incorrect access control in zam64.sys, zam32.sys in MalwareFox AntiMalware 2.74.0.150 where IOCTL's 0x80002014, 0x80002018 expose unrestricted disk read/write capabilities respectively. A non-privileged process can open a handle to \.\ZemanaAntiMalware, register with the driver using IOCTL 0x80002010 and send these IOCTL's to escalate privileges by overwriting the boot sector or overwriting critical code in the pagefile.

- [https://github.com/irql0/CVE-2021-31728](https://github.com/irql0/CVE-2021-31728) :  ![starts](https://img.shields.io/github/stars/irql0/CVE-2021-31728.svg) ![forks](https://img.shields.io/github/forks/irql0/CVE-2021-31728.svg)


## CVE-2021-29841
 IBM Financial Transaction Manager 3.2.4 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 205045.

- [https://github.com/Live-Hack-CVE/CVE-2021-29841](https://github.com/Live-Hack-CVE/CVE-2021-29841) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-29841.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-29841.svg)


## CVE-2021-29728
 IBM Sterling Secure Proxy 6.0.1, 6.0.2, 2.4.3.2, and 3.4.3.2 contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. IBM X-Force ID: 201160.

- [https://github.com/Live-Hack-CVE/CVE-2021-29728](https://github.com/Live-Hack-CVE/CVE-2021-29728) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-29728.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-29728.svg)


## CVE-2021-29723
 IBM Sterling Secure Proxy 6.0.1, 6.0.2, 2.4.3.2, and 3.4.3.2 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-ForceID: 201100.

- [https://github.com/Live-Hack-CVE/CVE-2021-29723](https://github.com/Live-Hack-CVE/CVE-2021-29723) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-29723.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-29723.svg)


## CVE-2021-29722
 IBM Sterling Secure Proxy 6.0.1, 6.0.2, 2.4.3.2, and 3.4.3.2 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 201095.

- [https://github.com/Live-Hack-CVE/CVE-2021-29722](https://github.com/Live-Hack-CVE/CVE-2021-29722) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-29722.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-29722.svg)


## CVE-2021-24487
 The St-Daily-Tip WordPress plugin through 4.7 does not have any CSRF check in place when saving its 'Default Text to Display if no tips' setting, and was also lacking sanitisation as well as escaping before outputting it the page. This could allow attacker to make logged in administrators set a malicious payload in it, leading to a Stored Cross-Site Scripting issue

- [https://github.com/Live-Hack-CVE/CVE-2021-24487](https://github.com/Live-Hack-CVE/CVE-2021-24487) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-24487.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-24487.svg)


## CVE-2021-24388
 In the VikRentCar Car Rental Management System WordPress plugin before 1.1.7, there is a custom filed option by which we can manage all the fields that the users will have to fill in before saving the order. However, the field name is not sanitised or escaped before being output back in the page, leading to a stored Cross-Site Scripting issue. There is also no CSRF check done before saving the setting, allowing attackers to make a logged in admin set arbitrary Custom Fields, including one with XSS payload in it.

- [https://github.com/Live-Hack-CVE/CVE-2021-24388](https://github.com/Live-Hack-CVE/CVE-2021-24388) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-24388.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-24388.svg)


## CVE-2021-4286
 A vulnerability, which was classified as problematic, has been found in cocagne pysrp up to 1.0.16. This issue affects the function calculate_x of the file srp/_ctsrp.py. The manipulation leads to information exposure through discrepancy. Upgrading to version 1.0.17 is able to address this issue. The name of the patch is dba52642f5e95d3da7af1780561213ee6053195f. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-216875.

- [https://github.com/Live-Hack-CVE/CVE-2021-4286](https://github.com/Live-Hack-CVE/CVE-2021-4286) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4286.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4286.svg)


## CVE-2020-36660
 A vulnerability was found in paxswill EVE Ship Replacement Program 0.12.11. It has been rated as problematic. This issue affects some unknown processing of the file src/evesrp/views/api.py of the component User Information Handler. The manipulation leads to information disclosure. The attack may be initiated remotely. Upgrading to version 0.12.12 is able to address this issue. The name of the patch is 9e03f68e46e85ca9c9694a6971859b3ee66f0240. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-220211.

- [https://github.com/Live-Hack-CVE/CVE-2020-36660](https://github.com/Live-Hack-CVE/CVE-2020-36660) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36660.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36660.svg)


## CVE-2020-9484
 When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter=&quot;null&quot; (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.

- [https://github.com/d3fudd/CVE-2020-9484_Exploit](https://github.com/d3fudd/CVE-2020-9484_Exploit) :  ![starts](https://img.shields.io/github/stars/d3fudd/CVE-2020-9484_Exploit.svg) ![forks](https://img.shields.io/github/forks/d3fudd/CVE-2020-9484_Exploit.svg)


## CVE-2020-4870
 IBM MQ 9.2 CD and LTS are vulnerable to a denial of service attack caused by an error processing connecting applications. IBM X-Force ID: 190833.

- [https://github.com/Live-Hack-CVE/CVE-2020-4870](https://github.com/Live-Hack-CVE/CVE-2020-4870) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-4870.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-4870.svg)


## CVE-2020-4675
 IBM InfoSphere Master Data Management Server 11.6 is vulnerable to cross-site request forgery which could allow an attacker to execute malicious and unauthorized actions transmitted from a user that the website trusts. IBM X-Force ID: 186324.

- [https://github.com/Live-Hack-CVE/CVE-2020-4675](https://github.com/Live-Hack-CVE/CVE-2020-4675) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-4675.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-4675.svg)


## CVE-2019-19774
 An issue was discovered in Zoho ManageEngine EventLog Analyzer 10.0 SP1 before Build 12110. By running &quot;select hostdetails from hostdetails&quot; at the /event/runquery.do endpoint, it is possible to bypass the security restrictions that prevent even administrative users from viewing credential data stored in the database, and recover the MD5 hashes of the accounts used to authenticate the ManageEngine platform to the managed machines on the network (most often administrative accounts). Specifically, this bypasses these restrictions: a query cannot mention password, and a query result cannot have a password column.

- [https://github.com/Live-Hack-CVE/CVE-2019-19774](https://github.com/Live-Hack-CVE/CVE-2019-19774) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-19774.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-19774.svg)


## CVE-2019-15023
 A security vulnerability exists in Zingbox Inspector versions 1.294 and earlier, that results in passwords for 3rd party integrations being stored in cleartext in device configuration.

- [https://github.com/Live-Hack-CVE/CVE-2019-15023](https://github.com/Live-Hack-CVE/CVE-2019-15023) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15023.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15023.svg)


## CVE-2019-15022
 A security vulnerability exists in Zingbox Inspector versions 1.294 and earlier, that allows for the Inspector to be susceptible to ARP spoofing.

- [https://github.com/Live-Hack-CVE/CVE-2019-15022](https://github.com/Live-Hack-CVE/CVE-2019-15022) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15022.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15022.svg)


## CVE-2019-15020
 A security vulnerability exists in the Zingbox Inspector versions 1.293 and earlier, that could allow an attacker to supply an invalid software update image to the Zingbox Inspector that could result in command injection.

- [https://github.com/Live-Hack-CVE/CVE-2019-15020](https://github.com/Live-Hack-CVE/CVE-2019-15020) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15020.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15020.svg)


## CVE-2019-15019
 A security vulnerability exists in the Zingbox Inspector versions 1.294 and earlier, that could allow an attacker to supply an invalid software update image to the Zingbox Inspector.

- [https://github.com/Live-Hack-CVE/CVE-2019-15019](https://github.com/Live-Hack-CVE/CVE-2019-15019) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15019.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15019.svg)


## CVE-2019-15018
 A security vulnerability exists in the Zingbox Inspector versions 1.280 and earlier, where authentication is not required when binding the Inspector instance to a different customer tenant.

- [https://github.com/Live-Hack-CVE/CVE-2019-15018](https://github.com/Live-Hack-CVE/CVE-2019-15018) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15018.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15018.svg)


## CVE-2019-11932
 A double free vulnerability in the DDGifSlurp function in decoding.c in the android-gif-drawable library before version 1.2.18, as used in WhatsApp for Android before version 2.19.244 and many other Android applications, allows remote attackers to execute arbitrary code or cause a denial of service when the library is used to parse a specially crafted GIF image.

- [https://github.com/awakened1712/CVE-2019-11932](https://github.com/awakened1712/CVE-2019-11932) :  ![starts](https://img.shields.io/github/stars/awakened1712/CVE-2019-11932.svg) ![forks](https://img.shields.io/github/forks/awakened1712/CVE-2019-11932.svg)


## CVE-2019-11281
 Pivotal RabbitMQ, versions prior to v3.7.18, and RabbitMQ for PCF, versions 1.15.x prior to 1.15.13, versions 1.16.x prior to 1.16.6, and versions 1.17.x prior to 1.17.3, contain two components, the virtual host limits page, and the federation management UI, which do not properly sanitize user input. A remote authenticated malicious user with administrative access could craft a cross site scripting attack that would gain access to virtual hosts and policy management information.

- [https://github.com/Live-Hack-CVE/CVE-2019-11281](https://github.com/Live-Hack-CVE/CVE-2019-11281) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-11281.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-11281.svg)


## CVE-2019-9978
 The social-warfare plugin before 3.5.3 for WordPress has stored XSS via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, as exploited in the wild in March 2019. This affects Social Warfare and Social Warfare Pro.

- [https://github.com/d3fudd/CVE-2019-9978_Exploit](https://github.com/d3fudd/CVE-2019-9978_Exploit) :  ![starts](https://img.shields.io/github/stars/d3fudd/CVE-2019-9978_Exploit.svg) ![forks](https://img.shields.io/github/forks/d3fudd/CVE-2019-9978_Exploit.svg)


## CVE-2019-1584
 A security vulnerability exists in Zingbox Inspector version 1.293 and earlier, that allows for remote code execution if the Inspector were sent a malicious command from the Zingbox cloud, or if the Zingbox Inspector were tampered with to connect to an attacker's cloud endpoint.

- [https://github.com/Live-Hack-CVE/CVE-2019-1584](https://github.com/Live-Hack-CVE/CVE-2019-1584) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-1584.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-1584.svg)


## CVE-2018-19518
 University of Washington IMAP Toolkit 2007f on UNIX, as used in imap_open() in PHP and other products, launches an rsh command (by means of the imap_rimap function in c-client/imap4r1.c and the tcp_aopen function in osdep/unix/tcp_unix.c) without preventing argument injection, which might allow remote attackers to execute arbitrary OS commands if the IMAP server name is untrusted input (e.g., entered by a user of a web application) and if rsh has been replaced by a program with different argument semantics. For example, if rsh is a link to ssh (as seen on Debian and Ubuntu systems), then the attack can use an IMAP server name containing a &quot;-oProxyCommand&quot; argument.

- [https://github.com/houqe/POC_CVE-2018-19518](https://github.com/houqe/POC_CVE-2018-19518) :  ![starts](https://img.shields.io/github/stars/houqe/POC_CVE-2018-19518.svg) ![forks](https://img.shields.io/github/forks/houqe/POC_CVE-2018-19518.svg)


## CVE-2018-19321
 The GPCIDrv and GDrv low-level drivers in GIGABYTE APP Center v1.05.21 and earlier, AORUS GRAPHICS ENGINE before 1.57, XTREME GAMING ENGINE before 1.26, and OC GURU II v2.08 expose functionality to read and write arbitrary physical memory. This could be leveraged by a local attacker to elevate privileges.

- [https://github.com/nanabingies/Driver-RW](https://github.com/nanabingies/Driver-RW) :  ![starts](https://img.shields.io/github/stars/nanabingies/Driver-RW.svg) ![forks](https://img.shields.io/github/forks/nanabingies/Driver-RW.svg)


## CVE-2017-15944
 Palo Alto Networks PAN-OS before 6.1.19, 7.0.x before 7.0.19, 7.1.x before 7.1.14, and 8.0.x before 8.0.6 allows remote attackers to execute arbitrary code via vectors involving the management interface.

- [https://github.com/CKevens/PaloAlto_EXP](https://github.com/CKevens/PaloAlto_EXP) :  ![starts](https://img.shields.io/github/stars/CKevens/PaloAlto_EXP.svg) ![forks](https://img.shields.io/github/forks/CKevens/PaloAlto_EXP.svg)


## CVE-2017-7541
 The brcmf_cfg80211_mgmt_tx function in drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c in the Linux kernel before 4.12.3 allows local users to cause a denial of service (buffer overflow and system crash) or possibly gain privileges via a crafted NL80211_CMD_FRAME Netlink packet.

- [https://github.com/Live-Hack-CVE/CVE-2017-7541](https://github.com/Live-Hack-CVE/CVE-2017-7541) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-7541.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-7541.svg)


## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.

- [https://github.com/d3fudd/CVE-2017-7494_SambaCry](https://github.com/d3fudd/CVE-2017-7494_SambaCry) :  ![starts](https://img.shields.io/github/stars/d3fudd/CVE-2017-7494_SambaCry.svg) ![forks](https://img.shields.io/github/forks/d3fudd/CVE-2017-7494_SambaCry.svg)


## CVE-2017-7487
 The ipxitf_ioctl function in net/ipx/af_ipx.c in the Linux kernel through 4.11.1 mishandles reference counts, which allows local users to cause a denial of service (use-after-free) or possibly have unspecified other impact via a failed SIOCGIFADDR ioctl call for an IPX interface.

- [https://github.com/Live-Hack-CVE/CVE-2017-7487](https://github.com/Live-Hack-CVE/CVE-2017-7487) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-7487.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-7487.svg)


## CVE-2017-7482
 In the Linux kernel before version 4.12, Kerberos 5 tickets decoded when using the RXRPC keys incorrectly assumes the size of a field. This could lead to the size-remaining variable wrapping and the data pointer going over the end of the buffer. This could possibly lead to memory corruption and possible privilege escalation.

- [https://github.com/Live-Hack-CVE/CVE-2017-7482](https://github.com/Live-Hack-CVE/CVE-2017-7482) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-7482.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-7482.svg)


## CVE-2017-7374
 Use-after-free vulnerability in fs/crypto/ in the Linux kernel before 4.10.7 allows local users to cause a denial of service (NULL pointer dereference) or possibly gain privileges by revoking keyring keys being used for ext4, f2fs, or ubifs encryption, causing cryptographic transform objects to be freed prematurely.

- [https://github.com/Live-Hack-CVE/CVE-2017-7374](https://github.com/Live-Hack-CVE/CVE-2017-7374) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-7374.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-7374.svg)


## CVE-2017-7308
 The packet_set_ring function in net/packet/af_packet.c in the Linux kernel through 4.10.6 does not properly validate certain block-size data, which allows local users to cause a denial of service (integer signedness error and out-of-bounds write), or gain privileges (if the CAP_NET_RAW capability is held), via crafted system calls.

- [https://github.com/Live-Hack-CVE/CVE-2017-7308](https://github.com/Live-Hack-CVE/CVE-2017-7308) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-7308.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-7308.svg)

