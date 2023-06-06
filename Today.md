# Update 2023-06-06
## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/Le1a/CVE-2023-33246](https://github.com/Le1a/CVE-2023-33246) :  ![starts](https://img.shields.io/github/stars/Le1a/CVE-2023-33246.svg) ![forks](https://img.shields.io/github/forks/Le1a/CVE-2023-33246.svg)


## CVE-2023-32784
 In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

- [https://github.com/hau-zy/KeePass-dump-py](https://github.com/hau-zy/KeePass-dump-py) :  ![starts](https://img.shields.io/github/stars/hau-zy/KeePass-dump-py.svg) ![forks](https://img.shields.io/github/forks/hau-zy/KeePass-dump-py.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/BAdithyaHSCS/Exchange-0-Day](https://github.com/BAdithyaHSCS/Exchange-0-Day) :  ![starts](https://img.shields.io/github/stars/BAdithyaHSCS/Exchange-0-Day.svg) ![forks](https://img.shields.io/github/forks/BAdithyaHSCS/Exchange-0-Day.svg)


## CVE-2021-46074
 A Stored Cross Site Scripting (XSS) vulnerability exists in Sourcecodester Vehicle Service Management System 1.0 via the Settings Section in login panel.

- [https://github.com/plsanu/Vehicle-Service-Management-System-Settings-Stored-Cross-Site-Scripting-XSS](https://github.com/plsanu/Vehicle-Service-Management-System-Settings-Stored-Cross-Site-Scripting-XSS) :  ![starts](https://img.shields.io/github/stars/plsanu/Vehicle-Service-Management-System-Settings-Stored-Cross-Site-Scripting-XSS.svg) ![forks](https://img.shields.io/github/forks/plsanu/Vehicle-Service-Management-System-Settings-Stored-Cross-Site-Scripting-XSS.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/BAdithyaHSCS/Exchange-0-Day](https://github.com/BAdithyaHSCS/Exchange-0-Day) :  ![starts](https://img.shields.io/github/stars/BAdithyaHSCS/Exchange-0-Day.svg) ![forks](https://img.shields.io/github/forks/BAdithyaHSCS/Exchange-0-Day.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/MrCl0wnLab/SimplesApachePathTraversal](https://github.com/MrCl0wnLab/SimplesApachePathTraversal) :  ![starts](https://img.shields.io/github/stars/MrCl0wnLab/SimplesApachePathTraversal.svg) ![forks](https://img.shields.io/github/forks/MrCl0wnLab/SimplesApachePathTraversal.svg)
- [https://github.com/Zeop-CyberSec/apache_normalize_path](https://github.com/Zeop-CyberSec/apache_normalize_path) :  ![starts](https://img.shields.io/github/stars/Zeop-CyberSec/apache_normalize_path.svg) ![forks](https://img.shields.io/github/forks/Zeop-CyberSec/apache_normalize_path.svg)
- [https://github.com/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution](https://github.com/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/blackn0te/Apache-HTTP-Server-2.4.49-2.4.50-Path-Traversal-Remote-Code-Execution.svg)
- [https://github.com/TheLastVvV/CVE-2021-42013](https://github.com/TheLastVvV/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)


## CVE-2021-40444
 Microsoft MSHTML Remote Code Execution Vulnerability

- [https://github.com/hqdat809/CVE-2021-40444](https://github.com/hqdat809/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/hqdat809/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/hqdat809/CVE-2021-40444.svg)


## CVE-2021-38314
 The Gutenberg Template Library &amp; Redux Framework plugin &lt;= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site&#8217;s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.

- [https://github.com/orangmuda/CVE-2021-38314](https://github.com/orangmuda/CVE-2021-38314) :  ![starts](https://img.shields.io/github/stars/orangmuda/CVE-2021-38314.svg) ![forks](https://img.shields.io/github/forks/orangmuda/CVE-2021-38314.svg)


## CVE-2021-31956
 Windows NTFS Elevation of Privilege Vulnerability

- [https://github.com/hoangprod/CVE-2021-31956-POC](https://github.com/hoangprod/CVE-2021-31956-POC) :  ![starts](https://img.shields.io/github/stars/hoangprod/CVE-2021-31956-POC.svg) ![forks](https://img.shields.io/github/forks/hoangprod/CVE-2021-31956-POC.svg)


## CVE-2021-4191
 An issue has been discovered in GitLab CE/EE affecting versions 13.0 to 14.6.5, 14.7 to 14.7.4, and 14.8 to 14.8.2. Private GitLab instances with restricted sign-ups may be vulnerable to user enumeration to unauthenticated users through the GraphQL API.

- [https://github.com/Adelittle/CVE-2021-4191_Exploits](https://github.com/Adelittle/CVE-2021-4191_Exploits) :  ![starts](https://img.shields.io/github/stars/Adelittle/CVE-2021-4191_Exploits.svg) ![forks](https://img.shields.io/github/forks/Adelittle/CVE-2021-4191_Exploits.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/inspiringz/CVE-2021-3493](https://github.com/inspiringz/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/inspiringz/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/inspiringz/CVE-2021-3493.svg)


## CVE-2019-17558
 Apache Solr 5.0.0 to Apache Solr 8.3.1 are vulnerable to a Remote Code Execution through the VelocityResponseWriter. A Velocity template can be provided through Velocity templates in a configset `velocity/` directory or as a parameter. A user defined configset could contain renderable, potentially malicious, templates. Parameter provided templates are disabled by default, but can be enabled by setting `params.resource.loader.enabled` by defining a response writer with that setting set to `true`. Defining a response writer requires configuration API access. Solr 8.4 removed the params resource loader entirely, and only enables the configset-provided template rendering when the configset is `trusted` (has been uploaded by an authenticated user).

- [https://github.com/narrowinxt/CVE-2019-17558](https://github.com/narrowinxt/CVE-2019-17558) :  ![starts](https://img.shields.io/github/stars/narrowinxt/CVE-2019-17558.svg) ![forks](https://img.shields.io/github/forks/narrowinxt/CVE-2019-17558.svg)


## CVE-2017-9248
 Telerik.Web.UI.dll in Progress Telerik UI for ASP.NET AJAX before R2 2017 SP1 and Sitefinity before 10.0.6412.0 does not properly protect Telerik.Web.UI.DialogParametersEncryptionKey or the MachineKey, which makes it easier for remote attackers to defeat cryptographic protection mechanisms, leading to a MachineKey leak, arbitrary file uploads or downloads, XSS, or ASP.NET ViewState compromise.

- [https://github.com/cehamod/UI_CVE-2017-9248](https://github.com/cehamod/UI_CVE-2017-9248) :  ![starts](https://img.shields.io/github/stars/cehamod/UI_CVE-2017-9248.svg) ![forks](https://img.shields.io/github/forks/cehamod/UI_CVE-2017-9248.svg)


## CVE-2016-7255
 The kernel-mode drivers in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, and 1607, and Windows Server 2016 allow local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot;

- [https://github.com/FSecureLABS/CVE-2016-7255](https://github.com/FSecureLABS/CVE-2016-7255) :  ![starts](https://img.shields.io/github/stars/FSecureLABS/CVE-2016-7255.svg) ![forks](https://img.shields.io/github/forks/FSecureLABS/CVE-2016-7255.svg)


## CVE-2015-8088
 Heap-based buffer overflow in the HIFI driver in Huawei Mate 7 phones with software MT7-UL00 before MT7-UL00C17B354, MT7-TL10 before MT7-TL10C00B354, MT7-TL00 before MT7-TL00C01B354, and MT7-CL00 before MT7-CL00C92B354 and P8 phones with software GRA-TL00 before GRA-TL00C01B220SP01, GRA-CL00 before GRA-CL00C92B220, GRA-CL10 before GRA-CL10C92B220, GRA-UL00 before GRA-UL00C00B220, and GRA-UL10 before GRA-UL10C00B220 allows attackers to cause a denial of service (reboot) or execute arbitrary code via a crafted application.

- [https://github.com/Pray3r/CVE-2015-8088](https://github.com/Pray3r/CVE-2015-8088) :  ![starts](https://img.shields.io/github/stars/Pray3r/CVE-2015-8088.svg) ![forks](https://img.shields.io/github/forks/Pray3r/CVE-2015-8088.svg)


## CVE-2014-0224
 OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the &quot;CCS Injection&quot; vulnerability.

- [https://github.com/secretnonempty/CVE-2014-0224](https://github.com/secretnonempty/CVE-2014-0224) :  ![starts](https://img.shields.io/github/stars/secretnonempty/CVE-2014-0224.svg) ![forks](https://img.shields.io/github/forks/secretnonempty/CVE-2014-0224.svg)
- [https://github.com/iph0n3/CVE-2014-0224](https://github.com/iph0n3/CVE-2014-0224) :  ![starts](https://img.shields.io/github/stars/iph0n3/CVE-2014-0224.svg) ![forks](https://img.shields.io/github/forks/iph0n3/CVE-2014-0224.svg)


## CVE-2012-5613
 ** DISPUTED ** MySQL 5.5.19 and possibly other versions, and MariaDB 5.5.28a and possibly other versions, when configured to assign the FILE privilege to users who should not have administrative privileges, allows remote authenticated users to gain privileges by leveraging the FILE privilege to create files as the MySQL administrator. NOTE: the vendor disputes this issue, stating that this is only a vulnerability when the administrator does not follow recommendations in the product's installation documentation. NOTE: it could be argued that this should not be included in CVE because it is a configuration issue.

- [https://github.com/Hood3dRob1n/MySQL-Fu.rb](https://github.com/Hood3dRob1n/MySQL-Fu.rb) :  ![starts](https://img.shields.io/github/stars/Hood3dRob1n/MySQL-Fu.rb.svg) ![forks](https://img.shields.io/github/forks/Hood3dRob1n/MySQL-Fu.rb.svg)

