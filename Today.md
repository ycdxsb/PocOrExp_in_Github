# Update 2023-07-09
## CVE-2023-37191
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sahiloj/CVE-2023-37191](https://github.com/sahiloj/CVE-2023-37191) :  ![starts](https://img.shields.io/github/stars/sahiloj/CVE-2023-37191.svg) ![forks](https://img.shields.io/github/forks/sahiloj/CVE-2023-37191.svg)


## CVE-2023-37190
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sahiloj/CVE-2023-37190](https://github.com/sahiloj/CVE-2023-37190) :  ![starts](https://img.shields.io/github/stars/sahiloj/CVE-2023-37190.svg) ![forks](https://img.shields.io/github/forks/sahiloj/CVE-2023-37190.svg)


## CVE-2023-37189
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sahiloj/CVE-2023-37189](https://github.com/sahiloj/CVE-2023-37189) :  ![starts](https://img.shields.io/github/stars/sahiloj/CVE-2023-37189.svg) ![forks](https://img.shields.io/github/forks/sahiloj/CVE-2023-37189.svg)


## CVE-2023-32315
 Openfire is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0. The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0). Users are advised to upgrade. If an Openfire upgrade isn&#8217;t available for a specific release, or isn&#8217;t quickly actionable, users may see the linked github advisory (GHSA-gw42-f939-fhvm) for mitigation advice.

- [https://github.com/izzz0/CVE-2023-32315-POC](https://github.com/izzz0/CVE-2023-32315-POC) :  ![starts](https://img.shields.io/github/stars/izzz0/CVE-2023-32315-POC.svg) ![forks](https://img.shields.io/github/forks/izzz0/CVE-2023-32315-POC.svg)


## CVE-2023-3460
 The Ultimate Member WordPress plugin before 2.6.7 does not prevent visitors from creating user accounts with arbitrary capabilities, effectively allowing attackers to create administrator accounts at will. This is actively being exploited in the wild.

- [https://github.com/rizqimaulanaa/CVE-2023-3460](https://github.com/rizqimaulanaa/CVE-2023-3460) :  ![starts](https://img.shields.io/github/stars/rizqimaulanaa/CVE-2023-3460.svg) ![forks](https://img.shields.io/github/forks/rizqimaulanaa/CVE-2023-3460.svg)


## CVE-2023-2982
 The WordPress Social Login and Register (Discord, Google, Twitter, LinkedIn) plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 7.6.4. This is due to insufficient encryption on the user being supplied during a login validated through the plugin. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they know the email address associated with that user. This was partially patched in version 7.6.4 and fully patched in version 7.6.5.

- [https://github.com/hheeyywweellccoommee/CVE-2023-2982-ugdqh](https://github.com/hheeyywweellccoommee/CVE-2023-2982-ugdqh) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2023-2982-ugdqh.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2023-2982-ugdqh.svg)


## CVE-2022-3786
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects.

- [https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc](https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc) :  ![starts](https://img.shields.io/github/stars/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg) ![forks](https://img.shields.io/github/forks/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)


## CVE-2021-40374
 A stored cross-site scripting (XSS) vulnerability was identified in Apperta Foundation OpenEyes 3.5.1. Updating a patient's details allows remote attackers to inject arbitrary web script or HTML via the Address1 parameter. This JavaScript then executes when the patient profile is loaded, which could be used in a XSS attack.

- [https://github.com/DCKento/CVE-2021-40374](https://github.com/DCKento/CVE-2021-40374) :  ![starts](https://img.shields.io/github/stars/DCKento/CVE-2021-40374.svg) ![forks](https://img.shields.io/github/forks/DCKento/CVE-2021-40374.svg)


## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-1698.

- [https://github.com/4dp/CVE-2021-1732](https://github.com/4dp/CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/4dp/CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/4dp/CVE-2021-1732.svg)


## CVE-2020-13957
 Apache Solr versions 6.6.0 to 6.6.6, 7.0.0 to 7.7.3 and 8.0.0 to 8.6.2 prevents some features considered dangerous (which could be used for remote code execution) to be configured in a ConfigSet that's uploaded via API without authentication/authorization. The checks in place to prevent such features can be circumvented by using a combination of UPLOAD/CREATE actions.

- [https://github.com/s-index/CVE-2020-13957](https://github.com/s-index/CVE-2020-13957) :  ![starts](https://img.shields.io/github/stars/s-index/CVE-2020-13957.svg) ![forks](https://img.shields.io/github/forks/s-index/CVE-2020-13957.svg)


## CVE-2020-2556
 Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction and Engineering (component: Core). Supported versions that are affected are 16.2.0.0-16.2.19.0, 17.12.0.0-17.12.16.0, 18.8.0.0-18.8.16.0, 19.12.0.0 and 20.1.0.0. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Primavera P6 Enterprise Project Portfolio Management executes to compromise Primavera P6 Enterprise Project Portfolio Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Primavera P6 Enterprise Project Portfolio Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Primavera P6 Enterprise Project Portfolio Management accessible data as well as unauthorized read access to a subset of Primavera P6 Enterprise Project Portfolio Management accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Primavera P6 Enterprise Project Portfolio Management. CVSS 3.0 Base Score 7.3 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L).

- [https://github.com/5l1v3r1/CVE-2020-2556](https://github.com/5l1v3r1/CVE-2020-2556) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-2556.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-2556.svg)


## CVE-2020-0001
 In getProcessRecordLocked of ActivityManagerService.java isolated apps are not handled correctly. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-140055304

- [https://github.com/Zachinio/CVE-2020-0001](https://github.com/Zachinio/CVE-2020-0001) :  ![starts](https://img.shields.io/github/stars/Zachinio/CVE-2020-0001.svg) ![forks](https://img.shields.io/github/forks/Zachinio/CVE-2020-0001.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/JoaoPedroMoreira02/CVE-2014-6271](https://github.com/JoaoPedroMoreira02/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/JoaoPedroMoreira02/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/JoaoPedroMoreira02/CVE-2014-6271.svg)

