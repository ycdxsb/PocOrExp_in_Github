# Update 2021-11-23
## CVE-2021-41277
 Metabase is an open source data analytics platform. In affected versions a security issue has been discovered with the custom GeoJSON map (`admin-&gt;settings-&gt;maps-&gt;custom maps-&gt;add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded. This issue is fixed in a new maintenance release (0.40.5 and 1.40.5), and any subsequent release after that. If you&#8217;re unable to upgrade immediately, you can mitigate this by including rules in your reverse proxy or load balancer or WAF to provide a validation filter before the application.

- [https://github.com/tahtaciburak/CVE-2021-41277](https://github.com/tahtaciburak/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/tahtaciburak/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/tahtaciburak/CVE-2021-41277.svg)
- [https://github.com/Seals6/CVE-2021-41277](https://github.com/Seals6/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/Seals6/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/Seals6/CVE-2021-41277.svg)
- [https://github.com/Henry4E36/Metabase-cve-2021-41277](https://github.com/Henry4E36/Metabase-cve-2021-41277) :  ![starts](https://img.shields.io/github/stars/Henry4E36/Metabase-cve-2021-41277.svg) ![forks](https://img.shields.io/github/forks/Henry4E36/Metabase-cve-2021-41277.svg)


## CVE-2021-36749
 In the Druid ingestion system, the InputSource is used for reading data from a certain data source. However, the HTTP InputSource allows authenticated users to read data from other sources than intended, such as the local file system, with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly, since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP InputSource. This issue was previously mentioned as being fixed in 0.21.0 as per CVE-2021-26920 but was not fixed in 0.21.0 or 0.21.1.

- [https://github.com/Sma11New/PocList](https://github.com/Sma11New/PocList) :  ![starts](https://img.shields.io/github/stars/Sma11New/PocList.svg) ![forks](https://img.shields.io/github/forks/Sma11New/PocList.svg)


## CVE-2021-22053
 Applications using both `spring-cloud-netflix-hystrix-dashboard` and `spring-boot-starter-thymeleaf` expose a way to execute code submitted within the request URI path during the resolution of view templates. When a request is made at `/hystrix/monitor;[user-provided data]`, the path elements following `hystrix/monitor` are being evaluated as SpringEL expressions, which can lead to code execution.

- [https://github.com/SecCoder-Security-Lab/spring-cloud-netflix-hystrix-dashboard-cve-2021-22053](https://github.com/SecCoder-Security-Lab/spring-cloud-netflix-hystrix-dashboard-cve-2021-22053) :  ![starts](https://img.shields.io/github/stars/SecCoder-Security-Lab/spring-cloud-netflix-hystrix-dashboard-cve-2021-22053.svg) ![forks](https://img.shields.io/github/forks/SecCoder-Security-Lab/spring-cloud-netflix-hystrix-dashboard-cve-2021-22053.svg)


## CVE-2021-21315
 The System Information Library for Node.JS (npm package &quot;systeminformation&quot;) is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected.

- [https://github.com/Ki11i0n4ir3/CVE-2021-21315](https://github.com/Ki11i0n4ir3/CVE-2021-21315) :  ![starts](https://img.shields.io/github/stars/Ki11i0n4ir3/CVE-2021-21315.svg) ![forks](https://img.shields.io/github/forks/Ki11i0n4ir3/CVE-2021-21315.svg)


## CVE-2020-9484
 When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter=&quot;null&quot; (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.

- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/sidhawkss/ES-File-Explorer-Vulnerability](https://github.com/sidhawkss/ES-File-Explorer-Vulnerability) :  ![starts](https://img.shields.io/github/stars/sidhawkss/ES-File-Explorer-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/sidhawkss/ES-File-Explorer-Vulnerability.svg)

