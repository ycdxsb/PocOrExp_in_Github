# Update 2023-12-04
## CVE-2023-49103
 An issue was discovered in ownCloud owncloud/graphapi 0.2.x before 0.2.1 and 0.3.x before 0.3.1. The graphapi app relies on a third-party GetPhpInfo.php library that provides a URL. When this URL is accessed, it reveals the configuration details of the PHP environment (phpinfo). This information includes all the environment variables of the webserver. In containerized deployments, these environment variables may include sensitive data such as the ownCloud admin password, mail server credentials, and license key. Simply disabling the graphapi app does not eliminate the vulnerability. Additionally, phpinfo exposes various other potentially sensitive configuration details that could be exploited by an attacker to gather information about the system. Therefore, even if ownCloud is not running in a containerized environment, this vulnerability should still be a cause for concern. Note that Docker containers from before February 2023 are not vulnerable to the credential disclosure.

- [https://github.com/MixColumns/CVE-2023-49103](https://github.com/MixColumns/CVE-2023-49103) :  ![starts](https://img.shields.io/github/stars/MixColumns/CVE-2023-49103.svg) ![forks](https://img.shields.io/github/forks/MixColumns/CVE-2023-49103.svg)


## CVE-2023-48842
 D-Link Go-RT-AC750 revA_v101b03 was discovered to contain a command injection vulnerability via the service parameter at hedwig.cgi.

- [https://github.com/creacitysec/CVE-2023-48842](https://github.com/creacitysec/CVE-2023-48842) :  ![starts](https://img.shields.io/github/stars/creacitysec/CVE-2023-48842.svg) ![forks](https://img.shields.io/github/forks/creacitysec/CVE-2023-48842.svg)


## CVE-2023-34034
 Using &quot;**&quot; as a pattern in Spring Security configuration for WebFlux creates a mismatch in pattern matching between Spring Security and Spring WebFlux, and the potential for a security bypass.

- [https://github.com/hotblac/cve-2023-34034](https://github.com/hotblac/cve-2023-34034) :  ![starts](https://img.shields.io/github/stars/hotblac/cve-2023-34034.svg) ![forks](https://img.shields.io/github/forks/hotblac/cve-2023-34034.svg)


## CVE-2023-24034
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/hotblac/cve-2023-34034](https://github.com/hotblac/cve-2023-34034) :  ![starts](https://img.shields.io/github/stars/hotblac/cve-2023-34034.svg) ![forks](https://img.shields.io/github/forks/hotblac/cve-2023-34034.svg)


## CVE-2020-1048
 An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system, aka 'Windows Print Spooler Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1070.

- [https://github.com/neofito/CVE-2020-1337](https://github.com/neofito/CVE-2020-1337) :  ![starts](https://img.shields.io/github/stars/neofito/CVE-2020-1337.svg) ![forks](https://img.shields.io/github/forks/neofito/CVE-2020-1337.svg)


## CVE-2019-17558
 Apache Solr 5.0.0 to Apache Solr 8.3.1 are vulnerable to a Remote Code Execution through the VelocityResponseWriter. A Velocity template can be provided through Velocity templates in a configset `velocity/` directory or as a parameter. A user defined configset could contain renderable, potentially malicious, templates. Parameter provided templates are disabled by default, but can be enabled by setting `params.resource.loader.enabled` by defining a response writer with that setting set to `true`. Defining a response writer requires configuration API access. Solr 8.4 removed the params resource loader entirely, and only enables the configset-provided template rendering when the configset is `trusted` (has been uploaded by an authenticated user).

- [https://github.com/thelostworldFree/CVE-2019-17558_Solr_Vul_Tool](https://github.com/thelostworldFree/CVE-2019-17558_Solr_Vul_Tool) :  ![starts](https://img.shields.io/github/stars/thelostworldFree/CVE-2019-17558_Solr_Vul_Tool.svg) ![forks](https://img.shields.io/github/forks/thelostworldFree/CVE-2019-17558_Solr_Vul_Tool.svg)


## CVE-2017-0213
 Windows COM Aggregate Marshaler in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation privilege vulnerability when an attacker runs a specially crafted application, aka &quot;Windows COM Elevation of Privilege Vulnerability&quot;. This CVE ID is unique from CVE-2017-0214.

- [https://github.com/likescam/CVE-2017-0213](https://github.com/likescam/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-0213.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/cowsecurity/CVE-2011-2523](https://github.com/cowsecurity/CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/cowsecurity/CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/cowsecurity/CVE-2011-2523.svg)

