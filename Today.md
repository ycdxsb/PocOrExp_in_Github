# Update 2023-04-27
## CVE-2023-27524
 Session Validation attacks in Apache Superset versions up to and including 2.0.1. Installations that have not altered the default configured SECRET_KEY according to installation instructions allow for an attacker to authenticate and access unauthorized resources. This does not affect Superset administrators who have changed the default value for SECRET_KEY config.

- [https://github.com/horizon3ai/CVE-2023-27524](https://github.com/horizon3ai/CVE-2023-27524) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2023-27524.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2023-27524.svg)


## CVE-2023-27350
 This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.

- [https://github.com/adhikara13/CVE-2023-27350](https://github.com/adhikara13/CVE-2023-27350) :  ![starts](https://img.shields.io/github/stars/adhikara13/CVE-2023-27350.svg) ![forks](https://img.shields.io/github/forks/adhikara13/CVE-2023-27350.svg)


## CVE-2023-25690
 Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow a HTTP Request Smuggling attack. Configurations are affected when mod_proxy is enabled along with some form of RewriteRule or ProxyPassMatch in which a non-specific pattern matches some portion of the user-supplied request-target (URL) data and is then re-inserted into the proxied request-target using variable substitution. For example, something like: RewriteEngine on RewriteRule &quot;^/here/(.*)&quot; &quot;http://example.com:8080/elsewhere?$1&quot;; [P] ProxyPassReverse /here/ http://example.com:8080/ Request splitting/smuggling could result in bypass of access controls in the proxy server, proxying unintended URLs to existing origin servers, and cache poisoning. Users are recommended to update to at least version 2.4.56 of Apache HTTP Server.

- [https://github.com/tbachvarova/linux-apache-fix-mod_rewrite-spaceInURL](https://github.com/tbachvarova/linux-apache-fix-mod_rewrite-spaceInURL) :  ![starts](https://img.shields.io/github/stars/tbachvarova/linux-apache-fix-mod_rewrite-spaceInURL.svg) ![forks](https://img.shields.io/github/forks/tbachvarova/linux-apache-fix-mod_rewrite-spaceInURL.svg)


## CVE-2023-25292
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/brainkok/CVE-2023-25292](https://github.com/brainkok/CVE-2023-25292) :  ![starts](https://img.shields.io/github/stars/brainkok/CVE-2023-25292.svg) ![forks](https://img.shields.io/github/forks/brainkok/CVE-2023-25292.svg)


## CVE-2023-22621
 Strapi through 4.5.5 allows authenticated Server-Side Template Injection (SSTI) that can be exploited to execute arbitrary code on the server. A remote attacker with access to the Strapi admin panel can inject a crafted payload that executes code on the server into an email template that bypasses the validation checks that should prevent code execution.

- [https://github.com/sofianeelhor/CVE-2023-22621-POC](https://github.com/sofianeelhor/CVE-2023-22621-POC) :  ![starts](https://img.shields.io/github/stars/sofianeelhor/CVE-2023-22621-POC.svg) ![forks](https://img.shields.io/github/forks/sofianeelhor/CVE-2023-22621-POC.svg)


## CVE-2023-2114
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/SchmidAlex/nex-forms_SQL-Injection-CVE-2023-2114](https://github.com/SchmidAlex/nex-forms_SQL-Injection-CVE-2023-2114) :  ![starts](https://img.shields.io/github/stars/SchmidAlex/nex-forms_SQL-Injection-CVE-2023-2114.svg) ![forks](https://img.shields.io/github/forks/SchmidAlex/nex-forms_SQL-Injection-CVE-2023-2114.svg)


## CVE-2023-1671
 A pre-auth command injection vulnerability in the warn-proceed handler of Sophos Web Appliance older than version 4.3.10.4 allows execution of arbitrary code.

- [https://github.com/behnamvanda/CVE-2023-1671](https://github.com/behnamvanda/CVE-2023-1671) :  ![starts](https://img.shields.io/github/stars/behnamvanda/CVE-2023-1671.svg) ![forks](https://img.shields.io/github/forks/behnamvanda/CVE-2023-1671.svg)


## CVE-2022-37706
 enlightenment_sys in Enlightenment before 0.25.4 allows local users to gain privileges because it is setuid root, and the system library function mishandles pathnames that begin with a /dev/.. substring.

- [https://github.com/GrayHatZone/CVE-2022-37706-LPE-exploit](https://github.com/GrayHatZone/CVE-2022-37706-LPE-exploit) :  ![starts](https://img.shields.io/github/stars/GrayHatZone/CVE-2022-37706-LPE-exploit.svg) ![forks](https://img.shields.io/github/forks/GrayHatZone/CVE-2022-37706-LPE-exploit.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/Pari-Malam/CVE-2022-29464](https://github.com/Pari-Malam/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/Pari-Malam/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/Pari-Malam/CVE-2022-29464.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/Axx8/CVE-2022-22947_Rce_Exp](https://github.com/Axx8/CVE-2022-22947_Rce_Exp) :  ![starts](https://img.shields.io/github/stars/Axx8/CVE-2022-22947_Rce_Exp.svg) ![forks](https://img.shields.io/github/forks/Axx8/CVE-2022-22947_Rce_Exp.svg)
- [https://github.com/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE](https://github.com/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE) :  ![starts](https://img.shields.io/github/stars/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE.svg) ![forks](https://img.shields.io/github/forks/j-jasson/CVE-2022-22947-Spring-Cloud-Gateway-SpelRCE.svg)
- [https://github.com/kmahyyg/CVE-2022-22947](https://github.com/kmahyyg/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/kmahyyg/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/kmahyyg/CVE-2022-22947.svg)
- [https://github.com/Vancomycin-g/CVE-2022-22947](https://github.com/Vancomycin-g/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/Vancomycin-g/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/Vancomycin-g/CVE-2022-22947.svg)


## CVE-2022-22733
 Exposure of Sensitive Information to an Unauthorized Actor vulnerability in Apache ShardingSphere ElasticJob-UI allows an attacker who has guest account to do privilege escalation. This issue affects Apache ShardingSphere ElasticJob-UI Apache ShardingSphere ElasticJob-UI 3.x version 3.0.0 and prior versions.

- [https://github.com/Zeyad-Azima/CVE-2022-22733](https://github.com/Zeyad-Azima/CVE-2022-22733) :  ![starts](https://img.shields.io/github/stars/Zeyad-Azima/CVE-2022-22733.svg) ![forks](https://img.shields.io/github/forks/Zeyad-Azima/CVE-2022-22733.svg)


## CVE-2021-3378
 FortiLogger 4.4.2.2 is affected by Arbitrary File Upload by sending a &quot;Content-Type: image/png&quot; header to Config/SaveUploadedHotspotLogoFile and then visiting Assets/temp/hotspot/img/logohotspot.asp.

- [https://github.com/erberkan/fortilogger_arbitrary_fileupload](https://github.com/erberkan/fortilogger_arbitrary_fileupload) :  ![starts](https://img.shields.io/github/stars/erberkan/fortilogger_arbitrary_fileupload.svg) ![forks](https://img.shields.io/github/forks/erberkan/fortilogger_arbitrary_fileupload.svg)


## CVE-2020-1948
 This vulnerability can affect all Dubbo users stay on version 2.7.6 or lower. An attacker can send RPC requests with unrecognized service name or method name along with some malicious parameter payloads. When the malicious parameter is deserialized, it will execute some malicious code. More details can be found below.

- [https://github.com/L0kiii/Dubbo-deserialization](https://github.com/L0kiii/Dubbo-deserialization) :  ![starts](https://img.shields.io/github/stars/L0kiii/Dubbo-deserialization.svg) ![forks](https://img.shields.io/github/forks/L0kiii/Dubbo-deserialization.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/NAXG/CVE-2020-1472](https://github.com/NAXG/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/NAXG/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/NAXG/CVE-2020-1472.svg)
- [https://github.com/Fa1c0n35/CVE-2020-1472](https://github.com/Fa1c0n35/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2020-1472.svg)
- [https://github.com/hell-moon/ZeroLogon-Exploit](https://github.com/hell-moon/ZeroLogon-Exploit) :  ![starts](https://img.shields.io/github/stars/hell-moon/ZeroLogon-Exploit.svg) ![forks](https://img.shields.io/github/forks/hell-moon/ZeroLogon-Exploit.svg)


## CVE-2019-17633
 For Eclipse Che versions 6.16 to 7.3.0, with both authentication and TLS disabled, visiting a malicious web site could trigger the start of an arbitrary Che workspace. Che with no authentication and no TLS is not usually deployed on a public network but is often used for local installations (e.g. on personal laptops). In that case, even if the Che API is not exposed externally, some javascript running in the local browser is able to send requests to it.

- [https://github.com/mgrube/CVE-2019-17633](https://github.com/mgrube/CVE-2019-17633) :  ![starts](https://img.shields.io/github/stars/mgrube/CVE-2019-17633.svg) ![forks](https://img.shields.io/github/forks/mgrube/CVE-2019-17633.svg)


## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka &quot;Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API.&quot;

- [https://github.com/mzakyz666/PoC-CVE-2017-0199](https://github.com/mzakyz666/PoC-CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/mzakyz666/PoC-CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/mzakyz666/PoC-CVE-2017-0199.svg)


## CVE-2016-3510
 Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.3.6.0, 12.1.3.0, and 12.2.1.0 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to WLS Core Components, a different vulnerability than CVE-2016-3586.

- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/chancej715/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution](https://github.com/chancej715/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution) :  ![starts](https://img.shields.io/github/stars/chancej715/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution.svg) ![forks](https://img.shields.io/github/forks/chancej715/UnrealIRCd-3.2.8.1-Backdoor-Command-Execution.svg)


## CVE-2003-0264
 Multiple buffer overflows in SLMail 5.1.0.4420 allows remote attackers to execute arbitrary code via (1) a long EHLO argument to slmail.exe, (2) a long XTRN argument to slmail.exe, (3) a long string to POPPASSWD, or (4) a long password to the POP3 server.

- [https://github.com/nobodyatall648/CVE-2003-0264](https://github.com/nobodyatall648/CVE-2003-0264) :  ![starts](https://img.shields.io/github/stars/nobodyatall648/CVE-2003-0264.svg) ![forks](https://img.shields.io/github/forks/nobodyatall648/CVE-2003-0264.svg)

