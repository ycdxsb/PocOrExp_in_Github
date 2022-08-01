# Update 2022-08-01
## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/AmoloHT/CVE-2022-33891](https://github.com/AmoloHT/CVE-2022-33891) :  ![starts](https://img.shields.io/github/stars/AmoloHT/CVE-2022-33891.svg) ![forks](https://img.shields.io/github/forks/AmoloHT/CVE-2022-33891.svg)


## CVE-2022-26159
 The auto-completion plugin in Ametys CMS before 4.5.0 allows a remote unauthenticated attacker to read documents such as plugins/web/service/search/auto-completion/&lt;domain&gt;/en.xml (and similar pathnames for other languages), which contain all characters typed by all users, including the content of private pages. For example, a private page may contain usernames, e-mail addresses, and possibly passwords.

- [https://github.com/p0dalirius/CVE-2022-26159-Ametys-Autocompletion-XML](https://github.com/p0dalirius/CVE-2022-26159-Ametys-Autocompletion-XML) :  ![starts](https://img.shields.io/github/stars/p0dalirius/CVE-2022-26159-Ametys-Autocompletion-XML.svg) ![forks](https://img.shields.io/github/forks/p0dalirius/CVE-2022-26159-Ametys-Autocompletion-XML.svg)


## CVE-2022-26138
 The Atlassian Questions For Confluence app for Confluence Server and Data Center creates a Confluence user account in the confluence-users group with the username disabledsystemuser and a hardcoded password. A remote, unauthenticated attacker with knowledge of the hardcoded password could exploit this to log into Confluence and access all content accessible to users in the confluence-users group. This user account is created when installing versions 2.7.34, 2.7.35, and 3.0.2 of the app.

- [https://github.com/z92g/CVE-2022-26138](https://github.com/z92g/CVE-2022-26138) :  ![starts](https://img.shields.io/github/stars/z92g/CVE-2022-26138.svg) ![forks](https://img.shields.io/github/forks/z92g/CVE-2022-26138.svg)


## CVE-2021-41349
 Microsoft Exchange Server Spoofing Vulnerability This CVE ID is unique from CVE-2021-42305.

- [https://github.com/0xrobiul/CVE-2021-41349](https://github.com/0xrobiul/CVE-2021-41349) :  ![starts](https://img.shields.io/github/stars/0xrobiul/CVE-2021-41349.svg) ![forks](https://img.shields.io/github/forks/0xrobiul/CVE-2021-41349.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/xindongzhuaizhuai/CVE-2020-1938](https://github.com/xindongzhuaizhuai/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/xindongzhuaizhuai/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/xindongzhuaizhuai/CVE-2020-1938.svg)
- [https://github.com/woaiqiukui/CVE-2020-1938TomcatAjpScanner](https://github.com/woaiqiukui/CVE-2020-1938TomcatAjpScanner) :  ![starts](https://img.shields.io/github/stars/woaiqiukui/CVE-2020-1938TomcatAjpScanner.svg) ![forks](https://img.shields.io/github/forks/woaiqiukui/CVE-2020-1938TomcatAjpScanner.svg)
- [https://github.com/fairyming/CVE-2020-1938](https://github.com/fairyming/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/fairyming/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/fairyming/CVE-2020-1938.svg)
- [https://github.com/dacade/CVE-2020-1938](https://github.com/dacade/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/dacade/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/dacade/CVE-2020-1938.svg)
- [https://github.com/Just1ceP4rtn3r/CVE-2020-1938-Tool](https://github.com/Just1ceP4rtn3r/CVE-2020-1938-Tool) :  ![starts](https://img.shields.io/github/stars/Just1ceP4rtn3r/CVE-2020-1938-Tool.svg) ![forks](https://img.shields.io/github/forks/Just1ceP4rtn3r/CVE-2020-1938-Tool.svg)
- [https://github.com/Umesh2807/Ghostcat](https://github.com/Umesh2807/Ghostcat) :  ![starts](https://img.shields.io/github/stars/Umesh2807/Ghostcat.svg) ![forks](https://img.shields.io/github/forks/Umesh2807/Ghostcat.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/maxpl0it/CVE-2020-1350-DoS](https://github.com/maxpl0it/CVE-2020-1350-DoS) :  ![starts](https://img.shields.io/github/stars/maxpl0it/CVE-2020-1350-DoS.svg) ![forks](https://img.shields.io/github/forks/maxpl0it/CVE-2020-1350-DoS.svg)


## CVE-2019-17026
 Incorrect alias information in IonMonkey JIT compiler for setting array elements could lead to a type confusion. We are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects Firefox ESR &lt; 68.4.1, Thunderbird &lt; 68.4.1, and Firefox &lt; 72.0.1.

- [https://github.com/forrest-orr/Exploits](https://github.com/forrest-orr/Exploits) :  ![starts](https://img.shields.io/github/stars/forrest-orr/Exploits.svg) ![forks](https://img.shields.io/github/forks/forrest-orr/Exploits.svg)


## CVE-2018-1042
 Moodle 3.x has Server Side Request Forgery in the filepicker.

- [https://github.com/UDPsycho/Moodle-CVE-2018-1042](https://github.com/UDPsycho/Moodle-CVE-2018-1042) :  ![starts](https://img.shields.io/github/stars/UDPsycho/Moodle-CVE-2018-1042.svg) ![forks](https://img.shields.io/github/forks/UDPsycho/Moodle-CVE-2018-1042.svg)


## CVE-2017-1000251
 The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.

- [https://github.com/istanescu/CVE-2017-1000251_Exploit](https://github.com/istanescu/CVE-2017-1000251_Exploit) :  ![starts](https://img.shields.io/github/stars/istanescu/CVE-2017-1000251_Exploit.svg) ![forks](https://img.shields.io/github/forks/istanescu/CVE-2017-1000251_Exploit.svg)

