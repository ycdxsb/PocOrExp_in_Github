# Update 2025-02-17
## CVE-2025-25064
 SQL injection vulnerability in the ZimbraSync Service SOAP endpoint in Zimbra Collaboration 10.0.x before 10.0.12 and 10.1.x before 10.1.4 due to insufficient sanitization of a user-supplied parameter. Authenticated attackers can exploit this vulnerability by manipulating a specific parameter in the request, allowing them to inject arbitrary SQL queries that could retrieve email metadata.

- [https://github.com/yelang123/Zimbra10_SQL_Injection](https://github.com/yelang123/Zimbra10_SQL_Injection) :  ![starts](https://img.shields.io/github/stars/yelang123/Zimbra10_SQL_Injection.svg) ![forks](https://img.shields.io/github/forks/yelang123/Zimbra10_SQL_Injection.svg)


## CVE-2025-22467
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.6 allows a remote authenticated attacker to achieve remote code execution.

- [https://github.com/NyxanGoat/CVE-2025-22467-PoC](https://github.com/NyxanGoat/CVE-2025-22467-PoC) :  ![starts](https://img.shields.io/github/stars/NyxanGoat/CVE-2025-22467-PoC.svg) ![forks](https://img.shields.io/github/forks/NyxanGoat/CVE-2025-22467-PoC.svg)


## CVE-2024-49113
 Windows Lightweight Directory Access Protocol (LDAP) Denial of Service Vulnerability

- [https://github.com/0xMetr0/metasploit-ldapnightmare](https://github.com/0xMetr0/metasploit-ldapnightmare) :  ![starts](https://img.shields.io/github/stars/0xMetr0/metasploit-ldapnightmare.svg) ![forks](https://img.shields.io/github/forks/0xMetr0/metasploit-ldapnightmare.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/hashdr1ft/SOC_287](https://github.com/hashdr1ft/SOC_287) :  ![starts](https://img.shields.io/github/stars/hashdr1ft/SOC_287.svg) ![forks](https://img.shields.io/github/forks/hashdr1ft/SOC_287.svg)


## CVE-2024-7985
 The FileOrganizer – Manage WordPress and Website Files plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the "fileorganizer_ajax_handler" function in all versions up to, and including, 1.0.9. This makes it possible for authenticated attackers, with Subscriber-level access and above, and permissions granted by an administrator, to upload arbitrary files on the affected site's server which may make remote code execution possible. NOTE: The FileOrganizer Pro plugin must be installed and active to allow Subscriber+ users to upload files.

- [https://github.com/Nxploited/CVE-2024-7985-PoC](https://github.com/Nxploited/CVE-2024-7985-PoC) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-7985-PoC.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-7985-PoC.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/hashdr1ft/SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400](https://github.com/hashdr1ft/SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400) :  ![starts](https://img.shields.io/github/stars/hashdr1ft/SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400.svg) ![forks](https://img.shields.io/github/forks/hashdr1ft/SOC274-Palo-Alto-Networks-PAN-OS-Command-Injection-Vulnerability-Exploitation-CVE-2024-3400.svg)


## CVE-2023-3824
 In PHP version 8.0.* before 8.0.30,  8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length checking may lead to a stack buffer overflow, leading potentially to memory corruption or RCE.

- [https://github.com/exploitdevelop/CVE-2023-3824](https://github.com/exploitdevelop/CVE-2023-3824) :  ![starts](https://img.shields.io/github/stars/exploitdevelop/CVE-2023-3824.svg) ![forks](https://img.shields.io/github/forks/exploitdevelop/CVE-2023-3824.svg)
- [https://github.com/fr33c0d3/poc-cve-2023-3824](https://github.com/fr33c0d3/poc-cve-2023-3824) :  ![starts](https://img.shields.io/github/stars/fr33c0d3/poc-cve-2023-3824.svg) ![forks](https://img.shields.io/github/forks/fr33c0d3/poc-cve-2023-3824.svg)
- [https://github.com/jhonnybonny/CVE-2023-3824](https://github.com/jhonnybonny/CVE-2023-3824) :  ![starts](https://img.shields.io/github/stars/jhonnybonny/CVE-2023-3824.svg) ![forks](https://img.shields.io/github/forks/jhonnybonny/CVE-2023-3824.svg)
- [https://github.com/bluefish3r/poc-cve](https://github.com/bluefish3r/poc-cve) :  ![starts](https://img.shields.io/github/stars/bluefish3r/poc-cve.svg) ![forks](https://img.shields.io/github/forks/bluefish3r/poc-cve.svg)
- [https://github.com/s1mpl3c0d3/cvepoc](https://github.com/s1mpl3c0d3/cvepoc) :  ![starts](https://img.shields.io/github/stars/s1mpl3c0d3/cvepoc.svg) ![forks](https://img.shields.io/github/forks/s1mpl3c0d3/cvepoc.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ch4os443/CVE-2021-41773](https://github.com/ch4os443/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ch4os443/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ch4os443/CVE-2021-41773.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/hopsypopsy8/CVE-2020-1938-Exploitation](https://github.com/hopsypopsy8/CVE-2020-1938-Exploitation) :  ![starts](https://img.shields.io/github/stars/hopsypopsy8/CVE-2020-1938-Exploitation.svg) ![forks](https://img.shields.io/github/forks/hopsypopsy8/CVE-2020-1938-Exploitation.svg)


## CVE-2019-0567
 A remote code execution vulnerability exists in the way that the Chakra scripting engine handles objects in memory in Microsoft Edge, aka "Chakra Scripting Engine Memory Corruption Vulnerability." This affects Microsoft Edge, ChakraCore. This CVE ID is unique from CVE-2019-0539, CVE-2019-0568.

- [https://github.com/ntdelta/chakra-exploit-framework](https://github.com/ntdelta/chakra-exploit-framework) :  ![starts](https://img.shields.io/github/stars/ntdelta/chakra-exploit-framework.svg) ![forks](https://img.shields.io/github/forks/ntdelta/chakra-exploit-framework.svg)

