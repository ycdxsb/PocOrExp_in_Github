# Update 2023-06-08
## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/deepinstinct/MOVEit_CVE-2023-34362_IOCs](https://github.com/deepinstinct/MOVEit_CVE-2023-34362_IOCs) :  ![starts](https://img.shields.io/github/stars/deepinstinct/MOVEit_CVE-2023-34362_IOCs.svg) ![forks](https://img.shields.io/github/forks/deepinstinct/MOVEit_CVE-2023-34362_IOCs.svg)
- [https://github.com/a3cipher/CVE-2023-34362](https://github.com/a3cipher/CVE-2023-34362) :  ![starts](https://img.shields.io/github/stars/a3cipher/CVE-2023-34362.svg) ![forks](https://img.shields.io/github/forks/a3cipher/CVE-2023-34362.svg)


## CVE-2023-33977
 Kiwi TCMS is an open source test management system for both manual and automated testing. Kiwi TCMS allows users to upload attachments to test plans, test cases, etc. Earlier versions of Kiwi TCMS had introduced upload validators in order to prevent potentially dangerous files from being uploaded and Content-Security-Policy definition to prevent cross-site-scripting attacks. The upload validation checks were not 100% robust which left the possibility to circumvent them and upload a potentially dangerous file which allows execution of arbitrary JavaScript in the browser. Additionally we've discovered that Nginx's `proxy_pass` directive will strip some headers negating protections built into Kiwi TCMS when served behind a reverse proxy. This issue has been addressed in version 12.4. Users are advised to upgrade. Users unable to upgrade who are serving Kiwi TCMS behind a reverse proxy should make sure that additional header values are still passed to the client browser. If they aren't redefining them inside the proxy configuration.

- [https://github.com/mnqazi/CVE-2023-33977](https://github.com/mnqazi/CVE-2023-33977) :  ![starts](https://img.shields.io/github/stars/mnqazi/CVE-2023-33977.svg) ![forks](https://img.shields.io/github/forks/mnqazi/CVE-2023-33977.svg)


## CVE-2023-33829
 A stored cross-site scripting (XSS) vulnerability in Cloudogu GmbH SCM Manager v1.2 to v1.60 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Description text field.

- [https://github.com/CKevens/CVE-2023-33829-POC](https://github.com/CKevens/CVE-2023-33829-POC) :  ![starts](https://img.shields.io/github/stars/CKevens/CVE-2023-33829-POC.svg) ![forks](https://img.shields.io/github/forks/CKevens/CVE-2023-33829-POC.svg)


## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/Serendipity-Lucky/CVE-2023-33246](https://github.com/Serendipity-Lucky/CVE-2023-33246) :  ![starts](https://img.shields.io/github/stars/Serendipity-Lucky/CVE-2023-33246.svg) ![forks](https://img.shields.io/github/forks/Serendipity-Lucky/CVE-2023-33246.svg)


## CVE-2023-28178
 A logic issue was addressed with improved validation. This issue is fixed in macOS Monterey 12.6.4, iOS 16.4 and iPadOS 16.4, macOS Ventura 13.3. An app may be able to bypass Privacy preferences

- [https://github.com/MacCVEResearch/CVE-2023-28178-patch](https://github.com/MacCVEResearch/CVE-2023-28178-patch) :  ![starts](https://img.shields.io/github/stars/MacCVEResearch/CVE-2023-28178-patch.svg) ![forks](https://img.shields.io/github/forks/MacCVEResearch/CVE-2023-28178-patch.svg)


## CVE-2023-25157
 GeoServer is an open source software server written in Java that allows users to share and edit geospatial data. GeoServer includes support for the OGC Filter expression language and the OGC Common Query Language (CQL) as part of the Web Feature Service (WFS) and Web Map Service (WMS) protocols. CQL is also supported through the Web Coverage Service (WCS) protocol for ImageMosaic coverages. Users are advised to upgrade to either version 2.21.4, or version 2.22.2 to resolve this issue. Users unable to upgrade should disable the PostGIS Datastore *encode functions* setting to mitigate ``strEndsWith``, ``strStartsWith`` and ``PropertyIsLike `` misuse and enable the PostGIS DataStore *preparedStatements* setting to mitigate the ``FeatureId`` misuse.

- [https://github.com/win3zz/CVE-2023-25157](https://github.com/win3zz/CVE-2023-25157) :  ![starts](https://img.shields.io/github/stars/win3zz/CVE-2023-25157.svg) ![forks](https://img.shields.io/github/forks/win3zz/CVE-2023-25157.svg)


## CVE-2022-32532
 Apache Shiro before 1.9.1, A RegexRequestMatcher can be misconfigured to be bypassed on some servlet containers. Applications using RegExPatternMatcher with `.` in the regular expression are possibly vulnerable to an authorization bypass.

- [https://github.com/Lay0us1/CVE-2022-32532](https://github.com/Lay0us1/CVE-2022-32532) :  ![starts](https://img.shields.io/github/stars/Lay0us1/CVE-2022-32532.svg) ![forks](https://img.shields.io/github/forks/Lay0us1/CVE-2022-32532.svg)


## CVE-2022-23773
 cmd/go in Go before 1.16.14 and 1.17.x before 1.17.7 can misinterpret branch names that falsely appear to be version tags. This can lead to incorrect access control if an actor is supposed to be able to create branches but not tags.

- [https://github.com/YouShengLiu/CVE-2022-23773-Reproduce](https://github.com/YouShengLiu/CVE-2022-23773-Reproduce) :  ![starts](https://img.shields.io/github/stars/YouShengLiu/CVE-2022-23773-Reproduce.svg) ![forks](https://img.shields.io/github/forks/YouShengLiu/CVE-2022-23773-Reproduce.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)


## CVE-2021-34045
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/MzzdToT/CVE-2021-34045](https://github.com/MzzdToT/CVE-2021-34045) :  ![starts](https://img.shields.io/github/stars/MzzdToT/CVE-2021-34045.svg) ![forks](https://img.shields.io/github/forks/MzzdToT/CVE-2021-34045.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/laolisafe/CVE-2020-1938](https://github.com/laolisafe/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/laolisafe/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/laolisafe/CVE-2020-1938.svg)
- [https://github.com/YounesTasra-R4z3rSw0rd/CVE-2020-1938](https://github.com/YounesTasra-R4z3rSw0rd/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/YounesTasra-R4z3rSw0rd/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/YounesTasra-R4z3rSw0rd/CVE-2020-1938.svg)


## CVE-2018-20250
 In WinRAR versions prior to and including 5.61, There is path traversal vulnerability when crafting the filename field of the ACE format (in UNACEV2.dll). When the filename field is manipulated with specific patterns, the destination (extraction) folder is ignored, thus treating the filename as an absolute path.

- [https://github.com/easis/CVE-2018-20250-WinRAR-ACE](https://github.com/easis/CVE-2018-20250-WinRAR-ACE) :  ![starts](https://img.shields.io/github/stars/easis/CVE-2018-20250-WinRAR-ACE.svg) ![forks](https://img.shields.io/github/forks/easis/CVE-2018-20250-WinRAR-ACE.svg)


## CVE-2018-1324
 A specially crafted ZIP archive can be used to cause an infinite loop inside of Apache Commons Compress' extra field parser used by the ZipFile and ZipArchiveInputStream classes in versions 1.11 to 1.15. This can be used to mount a denial of service attack against services that use Compress' zip package.

- [https://github.com/tafamace/CVE-2018-1324](https://github.com/tafamace/CVE-2018-1324) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1324.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1324.svg)


## CVE-2018-1112
 glusterfs server before versions 3.10.12, 4.0.2 is vulnerable when using 'auth.allow' option which allows any unauthenticated gluster client to connect from any network to mount gluster storage volumes. NOTE: this vulnerability exists because of a CVE-2018-1088 regression.

- [https://github.com/MauroEldritch/GEVAUDAN](https://github.com/MauroEldritch/GEVAUDAN) :  ![starts](https://img.shields.io/github/stars/MauroEldritch/GEVAUDAN.svg) ![forks](https://img.shields.io/github/forks/MauroEldritch/GEVAUDAN.svg)


## CVE-2018-0824
 A remote code execution vulnerability exists in &quot;Microsoft COM for Windows&quot; when it fails to properly handle serialized objects, aka &quot;Microsoft COM for Windows Remote Code Execution Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.

- [https://github.com/codewhitesec/UnmarshalPwn](https://github.com/codewhitesec/UnmarshalPwn) :  ![starts](https://img.shields.io/github/stars/codewhitesec/UnmarshalPwn.svg) ![forks](https://img.shields.io/github/forks/codewhitesec/UnmarshalPwn.svg)


## CVE-2017-7308
 The packet_set_ring function in net/packet/af_packet.c in the Linux kernel through 4.10.6 does not properly validate certain block-size data, which allows local users to cause a denial of service (integer signedness error and out-of-bounds write), or gain privileges (if the CAP_NET_RAW capability is held), via crafted system calls.

- [https://github.com/Nigmaz/CVE-2017-7308](https://github.com/Nigmaz/CVE-2017-7308) :  ![starts](https://img.shields.io/github/stars/Nigmaz/CVE-2017-7308.svg) ![forks](https://img.shields.io/github/forks/Nigmaz/CVE-2017-7308.svg)

