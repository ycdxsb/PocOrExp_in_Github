# Update 2022-10-21
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/kljunowsky/CVE-2022-42889-text4shell](https://github.com/kljunowsky/CVE-2022-42889-text4shell) :  ![starts](https://img.shields.io/github/stars/kljunowsky/CVE-2022-42889-text4shell.svg) ![forks](https://img.shields.io/github/forks/kljunowsky/CVE-2022-42889-text4shell.svg)
- [https://github.com/securekomodo/text4shell-scan](https://github.com/securekomodo/text4shell-scan) :  ![starts](https://img.shields.io/github/stars/securekomodo/text4shell-scan.svg) ![forks](https://img.shields.io/github/forks/securekomodo/text4shell-scan.svg)
- [https://github.com/eunomie/cve-2022-42889-check](https://github.com/eunomie/cve-2022-42889-check) :  ![starts](https://img.shields.io/github/stars/eunomie/cve-2022-42889-check.svg) ![forks](https://img.shields.io/github/forks/eunomie/cve-2022-42889-check.svg)
- [https://github.com/neerazz/CVE-2022-42889](https://github.com/neerazz/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/neerazz/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/neerazz/CVE-2022-42889.svg)
- [https://github.com/Afrouper/MavenDependencyCVE-Scanner](https://github.com/Afrouper/MavenDependencyCVE-Scanner) :  ![starts](https://img.shields.io/github/stars/Afrouper/MavenDependencyCVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/Afrouper/MavenDependencyCVE-Scanner.svg)


## CVE-2022-41040
 Microsoft Exchange Server Elevation of Privilege Vulnerability.

- [https://github.com/TaroballzChen/CVE-2022-41040-metasploit-ProxyNotShell](https://github.com/TaroballzChen/CVE-2022-41040-metasploit-ProxyNotShell) :  ![starts](https://img.shields.io/github/stars/TaroballzChen/CVE-2022-41040-metasploit-ProxyNotShell.svg) ![forks](https://img.shields.io/github/forks/TaroballzChen/CVE-2022-41040-metasploit-ProxyNotShell.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/und3sc0n0c1d0/CVE-2022-40684](https://github.com/und3sc0n0c1d0/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/und3sc0n0c1d0/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/und3sc0n0c1d0/CVE-2022-40684.svg)


## CVE-2022-40674
 libexpat before 2.4.9 has a use-after-free in the doContent function in xmlparse.c.

- [https://github.com/nidhi7598/-expat_2.1.0_CVE-2022-40674](https://github.com/nidhi7598/-expat_2.1.0_CVE-2022-40674) :  ![starts](https://img.shields.io/github/stars/nidhi7598/-expat_2.1.0_CVE-2022-40674.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/-expat_2.1.0_CVE-2022-40674.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/UUFR/CVE-2022-29464](https://github.com/UUFR/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/UUFR/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/UUFR/CVE-2022-29464.svg)


## CVE-2022-27925
 Zimbra Collaboration (aka ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. An authenticated user with administrator rights has the ability to upload arbitrary files to the system, leading to directory traversal.

- [https://github.com/onlyHerold22/CVE-2022-27925-PoC](https://github.com/onlyHerold22/CVE-2022-27925-PoC) :  ![starts](https://img.shields.io/github/stars/onlyHerold22/CVE-2022-27925-PoC.svg) ![forks](https://img.shields.io/github/forks/onlyHerold22/CVE-2022-27925-PoC.svg)


## CVE-2022-27414
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/lus33rr/CVE-2022-27414](https://github.com/lus33rr/CVE-2022-27414) :  ![starts](https://img.shields.io/github/stars/lus33rr/CVE-2022-27414.svg) ![forks](https://img.shields.io/github/forks/lus33rr/CVE-2022-27414.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/pwnsac/CVE-2022-22965](https://github.com/pwnsac/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/pwnsac/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/pwnsac/CVE-2022-22965.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/trhacknon/CVE-2022-22954_](https://github.com/trhacknon/CVE-2022-22954_) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2022-22954_.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2022-22954_.svg)
- [https://github.com/amit-pathak009/CVE-2022-22954](https://github.com/amit-pathak009/CVE-2022-22954) :  ![starts](https://img.shields.io/github/stars/amit-pathak009/CVE-2022-22954.svg) ![forks](https://img.shields.io/github/forks/amit-pathak009/CVE-2022-22954.svg)


## CVE-2022-3236
 A code injection vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v19.0 MR1 and older.

- [https://github.com/n0npro/CVE-2022-3236-RCE-POC](https://github.com/n0npro/CVE-2022-3236-RCE-POC) :  ![starts](https://img.shields.io/github/stars/n0npro/CVE-2022-3236-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/n0npro/CVE-2022-3236-RCE-POC.svg)


## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

- [https://github.com/Afrouper/MavenDependencyCVE-Scanner](https://github.com/Afrouper/MavenDependencyCVE-Scanner) :  ![starts](https://img.shields.io/github/stars/Afrouper/MavenDependencyCVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/Afrouper/MavenDependencyCVE-Scanner.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/Afrouper/MavenDependencyCVE-Scanner](https://github.com/Afrouper/MavenDependencyCVE-Scanner) :  ![starts](https://img.shields.io/github/stars/Afrouper/MavenDependencyCVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/Afrouper/MavenDependencyCVE-Scanner.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/Reclu3a/CVE-2021-26084-Confluence-OGNL](https://github.com/Reclu3a/CVE-2021-26084-Confluence-OGNL) :  ![starts](https://img.shields.io/github/stars/Reclu3a/CVE-2021-26084-Confluence-OGNL.svg) ![forks](https://img.shields.io/github/forks/Reclu3a/CVE-2021-26084-Confluence-OGNL.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/b1cat/CVE_2020_1938_ajp_poc](https://github.com/b1cat/CVE_2020_1938_ajp_poc) :  ![starts](https://img.shields.io/github/stars/b1cat/CVE_2020_1938_ajp_poc.svg) ![forks](https://img.shields.io/github/forks/b1cat/CVE_2020_1938_ajp_poc.svg)
- [https://github.com/haerin7427/CVE_2020_1938](https://github.com/haerin7427/CVE_2020_1938) :  ![starts](https://img.shields.io/github/stars/haerin7427/CVE_2020_1938.svg) ![forks](https://img.shields.io/github/forks/haerin7427/CVE_2020_1938.svg)


## CVE-2020-1362
 An elevation of privilege vulnerability exists in the way that the Windows WalletService handles objects in memory, aka 'Windows WalletService Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1344, CVE-2020-1369.

- [https://github.com/Al1ex/WindowsElevation](https://github.com/Al1ex/WindowsElevation) :  ![starts](https://img.shields.io/github/stars/Al1ex/WindowsElevation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/WindowsElevation.svg)


## CVE-2020-0688
 A remote code execution vulnerability exists in Microsoft Exchange software when the software fails to properly handle objects in memory, aka 'Microsoft Exchange Memory Corruption Vulnerability'.

- [https://github.com/TheKickPuncher/CVE-2020-0688-Python3](https://github.com/TheKickPuncher/CVE-2020-0688-Python3) :  ![starts](https://img.shields.io/github/stars/TheKickPuncher/CVE-2020-0688-Python3.svg) ![forks](https://img.shields.io/github/forks/TheKickPuncher/CVE-2020-0688-Python3.svg)


## CVE-2019-1388
 An elevation of privilege vulnerability exists in the Windows Certificate Dialog when it does not properly enforce user privileges, aka 'Windows Certificate Dialog Elevation of Privilege Vulnerability'.

- [https://github.com/suprise4u/CVE-2019-1388](https://github.com/suprise4u/CVE-2019-1388) :  ![starts](https://img.shields.io/github/stars/suprise4u/CVE-2019-1388.svg) ![forks](https://img.shields.io/github/forks/suprise4u/CVE-2019-1388.svg)


## CVE-2017-17485
 FasterXML jackson-databind through 2.8.10 and 2.9.x through 2.9.3 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the Spring libraries are available in the classpath.

- [https://github.com/mattysaints/CVE-2017-17485](https://github.com/mattysaints/CVE-2017-17485) :  ![starts](https://img.shields.io/github/stars/mattysaints/CVE-2017-17485.svg) ![forks](https://img.shields.io/github/forks/mattysaints/CVE-2017-17485.svg)


## CVE-2017-9248
 Telerik.Web.UI.dll in Progress Telerik UI for ASP.NET AJAX before R2 2017 SP1 and Sitefinity before 10.0.6412.0 does not properly protect Telerik.Web.UI.DialogParametersEncryptionKey or the MachineKey, which makes it easier for remote attackers to defeat cryptographic protection mechanisms, leading to a MachineKey leak, arbitrary file uploads or downloads, XSS, or ASP.NET ViewState compromise.

- [https://github.com/blacklanternsecurity/dp_cryptomg](https://github.com/blacklanternsecurity/dp_cryptomg) :  ![starts](https://img.shields.io/github/stars/blacklanternsecurity/dp_cryptomg.svg) ![forks](https://img.shields.io/github/forks/blacklanternsecurity/dp_cryptomg.svg)

