# Update 2021-10-09
## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/Vulnmachines/cve-2021-42013](https://github.com/Vulnmachines/cve-2021-42013) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/cve-2021-42013.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/cve-2021-42013.svg)
- [https://github.com/andrea-mattioli/apache-exploit-CVE-2021-42013](https://github.com/andrea-mattioli/apache-exploit-CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/andrea-mattioli/apache-exploit-CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/andrea-mattioli/apache-exploit-CVE-2021-42013.svg)
- [https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt](https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt) :  ![starts](https://img.shields.io/github/stars/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt.svg) ![forks](https://img.shields.io/github/forks/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by &quot;require all denied&quot; these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions.

- [https://github.com/htrgouvea/lab-cve-2021-41773](https://github.com/htrgouvea/lab-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/htrgouvea/lab-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/htrgouvea/lab-cve-2021-41773.svg)
- [https://github.com/justakazh/mass_cve-2021-41773](https://github.com/justakazh/mass_cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/justakazh/mass_cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/justakazh/mass_cve-2021-41773.svg)
- [https://github.com/jheeree/Simple-CVE-2021-41773-checker](https://github.com/jheeree/Simple-CVE-2021-41773-checker) :  ![starts](https://img.shields.io/github/stars/jheeree/Simple-CVE-2021-41773-checker.svg) ![forks](https://img.shields.io/github/forks/jheeree/Simple-CVE-2021-41773-checker.svg)
- [https://github.com/vinhjaxt/CVE-2021-41773-exploit](https://github.com/vinhjaxt/CVE-2021-41773-exploit) :  ![starts](https://img.shields.io/github/stars/vinhjaxt/CVE-2021-41773-exploit.svg) ![forks](https://img.shields.io/github/forks/vinhjaxt/CVE-2021-41773-exploit.svg)
- [https://github.com/LetouRaphael/Poc-CVE-2021-41773](https://github.com/LetouRaphael/Poc-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LetouRaphael/Poc-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LetouRaphael/Poc-CVE-2021-41773.svg)
- [https://github.com/shellreaper/CVE-2021-41773](https://github.com/shellreaper/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shellreaper/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shellreaper/CVE-2021-41773.svg)
- [https://github.com/AssassinUKG/CVE-2021-41773](https://github.com/AssassinUKG/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/AssassinUKG/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/AssassinUKG/CVE-2021-41773.svg)
- [https://github.com/0xRar/CVE-2021-41773](https://github.com/0xRar/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xRar/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xRar/CVE-2021-41773.svg)
- [https://github.com/oxctdev/CVE-2021-41773](https://github.com/oxctdev/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/oxctdev/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/oxctdev/CVE-2021-41773.svg)
- [https://github.com/Sakura-nee/CVE-2021-41773](https://github.com/Sakura-nee/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Sakura-nee/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Sakura-nee/CVE-2021-41773.svg)
- [https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt](https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt) :  ![starts](https://img.shields.io/github/stars/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt.svg) ![forks](https://img.shields.io/github/forks/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt.svg)


## CVE-2021-41381
 Payara Micro Community 5.2021.6 and below allows Directory Traversal.

- [https://github.com/Net-hunter121/CVE-2021-41381](https://github.com/Net-hunter121/CVE-2021-41381) :  ![starts](https://img.shields.io/github/stars/Net-hunter121/CVE-2021-41381.svg) ![forks](https://img.shields.io/github/forks/Net-hunter121/CVE-2021-41381.svg)


## CVE-2021-40870
 An issue was discovered in Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal.

- [https://github.com/oxctdev/CVE-2021-40870](https://github.com/oxctdev/CVE-2021-40870) :  ![starts](https://img.shields.io/github/stars/oxctdev/CVE-2021-40870.svg) ![forks](https://img.shields.io/github/forks/oxctdev/CVE-2021-40870.svg)
- [https://github.com/JoyGhoshs/CVE-2021-40870](https://github.com/JoyGhoshs/CVE-2021-40870) :  ![starts](https://img.shields.io/github/stars/JoyGhoshs/CVE-2021-40870.svg) ![forks](https://img.shields.io/github/forks/JoyGhoshs/CVE-2021-40870.svg)
- [https://github.com/0xAgun/CVE-2021-40870](https://github.com/0xAgun/CVE-2021-40870) :  ![starts](https://img.shields.io/github/stars/0xAgun/CVE-2021-40870.svg) ![forks](https://img.shields.io/github/forks/0xAgun/CVE-2021-40870.svg)


## CVE-2021-26086
 Affected versions of Atlassian Jira Server and Data Center allow remote attackers to read particular files via a path traversal vulnerability in the /WEB-INF/web.xml endpoint. The affected versions are before version 8.5.14, from version 8.6.0 before 8.13.6, and from version 8.14.0 before 8.16.1.

- [https://github.com/ColdFusionX/CVE-2021-26086](https://github.com/ColdFusionX/CVE-2021-26086) :  ![starts](https://img.shields.io/github/stars/ColdFusionX/CVE-2021-26086.svg) ![forks](https://img.shields.io/github/forks/ColdFusionX/CVE-2021-26086.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/oxctdev/CVE-2021-26084](https://github.com/oxctdev/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/oxctdev/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/oxctdev/CVE-2021-26084.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/einzbernnn/CVE-2020-1938Scan](https://github.com/einzbernnn/CVE-2020-1938Scan) :  ![starts](https://img.shields.io/github/stars/einzbernnn/CVE-2020-1938Scan.svg) ![forks](https://img.shields.io/github/forks/einzbernnn/CVE-2020-1938Scan.svg)


## CVE-2019-17502
 Hydra through 0.1.8 has a NULL pointer dereference and daemon crash when processing POST requests that lack a Content-Length header. read.c, request.c, and util.c contribute to this. The process_header_end() function calls boa_atoi(), which ultimately calls atoi() on a NULL pointer.

- [https://github.com/shrug-security/hydra-0.1.8](https://github.com/shrug-security/hydra-0.1.8) :  ![starts](https://img.shields.io/github/stars/shrug-security/hydra-0.1.8.svg) ![forks](https://img.shields.io/github/forks/shrug-security/hydra-0.1.8.svg)

