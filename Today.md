# Update 2022-12-06
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/0xst4n/CVE-2022-42889](https://github.com/0xst4n/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/0xst4n/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/0xst4n/CVE-2022-42889.svg)


## CVE-2022-25765
 The package pdfkit from 0.0.0 are vulnerable to Command Injection where the URL is not properly sanitized.

- [https://github.com/CyberArchitect1/CVE-2022-25765-pdfkit-Exploit-Reverse-Shell](https://github.com/CyberArchitect1/CVE-2022-25765-pdfkit-Exploit-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/CyberArchitect1/CVE-2022-25765-pdfkit-Exploit-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/CyberArchitect1/CVE-2022-25765-pdfkit-Exploit-Reverse-Shell.svg)


## CVE-2022-2588
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/BassamGraini/CVE-2022-2588](https://github.com/BassamGraini/CVE-2022-2588) :  ![starts](https://img.shields.io/github/stars/BassamGraini/CVE-2022-2588.svg) ![forks](https://img.shields.io/github/forks/BassamGraini/CVE-2022-2588.svg)


## CVE-2021-38314
 The Gutenberg Template Library &amp; Redux Framework plugin &lt;= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site&#8217;s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.

- [https://github.com/phrantom/cve-2021-38314](https://github.com/phrantom/cve-2021-38314) :  ![starts](https://img.shields.io/github/stars/phrantom/cve-2021-38314.svg) ![forks](https://img.shields.io/github/forks/phrantom/cve-2021-38314.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/ArkAngeL43/CVE-2021-4034](https://github.com/ArkAngeL43/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ArkAngeL43/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ArkAngeL43/CVE-2021-4034.svg)


## CVE-2021-2119
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.0 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N).

- [https://github.com/chatbottesisgmailh/Sauercloude](https://github.com/chatbottesisgmailh/Sauercloude) :  ![starts](https://img.shields.io/github/stars/chatbottesisgmailh/Sauercloude.svg) ![forks](https://img.shields.io/github/forks/chatbottesisgmailh/Sauercloude.svg)


## CVE-2019-1132
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.

- [https://github.com/Vlad-tri/CVE-2019-1132](https://github.com/Vlad-tri/CVE-2019-1132) :  ![starts](https://img.shields.io/github/stars/Vlad-tri/CVE-2019-1132.svg) ![forks](https://img.shields.io/github/forks/Vlad-tri/CVE-2019-1132.svg)


## CVE-2018-1311
 The Apache Xerces-C 3.0.0 to 3.2.3 XML parser contains a use-after-free error triggered during the scanning of external DTDs. This flaw has not been addressed in the maintained version of the library and has no current mitigation other than to disable DTD processing. This can be accomplished via the DOM using a standard parser feature, or via SAX using the XERCES_DISABLE_DTD environment variable.

- [https://github.com/johnjamesmccann/xerces-3.2.3-DTD-hotfix](https://github.com/johnjamesmccann/xerces-3.2.3-DTD-hotfix) :  ![starts](https://img.shields.io/github/stars/johnjamesmccann/xerces-3.2.3-DTD-hotfix.svg) ![forks](https://img.shields.io/github/forks/johnjamesmccann/xerces-3.2.3-DTD-hotfix.svg)


## CVE-2017-0785
 A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.

- [https://github.com/CarlosDelRosario7/sploit-bX](https://github.com/CarlosDelRosario7/sploit-bX) :  ![starts](https://img.shields.io/github/stars/CarlosDelRosario7/sploit-bX.svg) ![forks](https://img.shields.io/github/forks/CarlosDelRosario7/sploit-bX.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/passionchenjianyegmail8/scumjrs](https://github.com/passionchenjianyegmail8/scumjrs) :  ![starts](https://img.shields.io/github/stars/passionchenjianyegmail8/scumjrs.svg) ![forks](https://img.shields.io/github/forks/passionchenjianyegmail8/scumjrs.svg)


## CVE-2010-1622
 SpringSource Spring Framework 2.5.x before 2.5.6.SEC02, 2.5.7 before 2.5.7.SR01, and 3.0.x before 3.0.3 allows remote attackers to execute arbitrary code via an HTTP request containing class.classLoader.URLs[0]=jar: followed by a URL of a crafted .jar file.

- [https://github.com/HandsomeCat00/Spring-CVE-2010-1622](https://github.com/HandsomeCat00/Spring-CVE-2010-1622) :  ![starts](https://img.shields.io/github/stars/HandsomeCat00/Spring-CVE-2010-1622.svg) ![forks](https://img.shields.io/github/forks/HandsomeCat00/Spring-CVE-2010-1622.svg)

