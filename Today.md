# Update 2023-12-24
## CVE-2023-51281
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/geraldoalcantara/CVE-2023-51281](https://github.com/geraldoalcantara/CVE-2023-51281) :  ![starts](https://img.shields.io/github/stars/geraldoalcantara/CVE-2023-51281.svg) ![forks](https://img.shields.io/github/forks/geraldoalcantara/CVE-2023-51281.svg)


## CVE-2023-50254
 Deepin Linux's default document reader `deepin-reader` software suffers from a serious vulnerability in versions prior to 6.0.7 due to a design flaw that leads to remote command execution via crafted docx document. This is a file overwrite vulnerability. Remote code execution (RCE) can be achieved by overwriting files like .bash_rc, .bash_login, etc. RCE will be triggered when the user opens the terminal. Version 6.0.7 contains a patch for the issue.

- [https://github.com/febinrev/deepin-linux_reader_RCE-exploit](https://github.com/febinrev/deepin-linux_reader_RCE-exploit) :  ![starts](https://img.shields.io/github/stars/febinrev/deepin-linux_reader_RCE-exploit.svg) ![forks](https://img.shields.io/github/forks/febinrev/deepin-linux_reader_RCE-exploit.svg)


## CVE-2023-49438
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/brandon-t-elliott/CVE-2023-49438](https://github.com/brandon-t-elliott/CVE-2023-49438) :  ![starts](https://img.shields.io/github/stars/brandon-t-elliott/CVE-2023-49438.svg) ![forks](https://img.shields.io/github/forks/brandon-t-elliott/CVE-2023-49438.svg)


## CVE-2023-29357
 Microsoft SharePoint Server Elevation of Privilege Vulnerability

- [https://github.com/Guillaume-Risch/cve-2023-29357-Sharepoint](https://github.com/Guillaume-Risch/cve-2023-29357-Sharepoint) :  ![starts](https://img.shields.io/github/stars/Guillaume-Risch/cve-2023-29357-Sharepoint.svg) ![forks](https://img.shields.io/github/forks/Guillaume-Risch/cve-2023-29357-Sharepoint.svg)


## CVE-2023-4357
 Insufficient validation of untrusted input in XML in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to bypass file access restrictions via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/passwa11/CVE-2023-4357-APT-Style-exploitation](https://github.com/passwa11/CVE-2023-4357-APT-Style-exploitation) :  ![starts](https://img.shields.io/github/stars/passwa11/CVE-2023-4357-APT-Style-exploitation.svg) ![forks](https://img.shields.io/github/forks/passwa11/CVE-2023-4357-APT-Style-exploitation.svg)


## CVE-2022-44276
 In Responsive Filemanager &lt; 9.12.0, an attacker can bypass upload restrictions resulting in RCE.

- [https://github.com/HerrLeStrate/CVE-2022-44276-PoC](https://github.com/HerrLeStrate/CVE-2022-44276-PoC) :  ![starts](https://img.shields.io/github/stars/HerrLeStrate/CVE-2022-44276-PoC.svg) ![forks](https://img.shields.io/github/forks/HerrLeStrate/CVE-2022-44276-PoC.svg)


## CVE-2021-43891
 Visual Studio Code Remote Code Execution Vulnerability

- [https://github.com/parsiya/code-wsl-rce](https://github.com/parsiya/code-wsl-rce) :  ![starts](https://img.shields.io/github/stars/parsiya/code-wsl-rce.svg) ![forks](https://img.shields.io/github/forks/parsiya/code-wsl-rce.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/m96dg/CVE-2021-41773-exercise](https://github.com/m96dg/CVE-2021-41773-exercise) :  ![starts](https://img.shields.io/github/stars/m96dg/CVE-2021-41773-exercise.svg) ![forks](https://img.shields.io/github/forks/m96dg/CVE-2021-41773-exercise.svg)
- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)


## CVE-2021-25461
 An improper length check in APAService prior to SMR Sep-2021 Release 1 results in stack based Buffer Overflow.

- [https://github.com/bkojusner/CVE-2021-25461](https://github.com/bkojusner/CVE-2021-25461) :  ![starts](https://img.shields.io/github/stars/bkojusner/CVE-2021-25461.svg) ![forks](https://img.shields.io/github/forks/bkojusner/CVE-2021-25461.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/darkerego/pwnkit](https://github.com/darkerego/pwnkit) :  ![starts](https://img.shields.io/github/stars/darkerego/pwnkit.svg) ![forks](https://img.shields.io/github/forks/darkerego/pwnkit.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/xindongzhuaizhuai/CVE-2020-1938](https://github.com/xindongzhuaizhuai/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/xindongzhuaizhuai/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/xindongzhuaizhuai/CVE-2020-1938.svg)
- [https://github.com/woaiqiukui/CVE-2020-1938TomcatAjpScanner](https://github.com/woaiqiukui/CVE-2020-1938TomcatAjpScanner) :  ![starts](https://img.shields.io/github/stars/woaiqiukui/CVE-2020-1938TomcatAjpScanner.svg) ![forks](https://img.shields.io/github/forks/woaiqiukui/CVE-2020-1938TomcatAjpScanner.svg)
- [https://github.com/fairyming/CVE-2020-1938](https://github.com/fairyming/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/fairyming/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/fairyming/CVE-2020-1938.svg)
- [https://github.com/dacade/CVE-2020-1938](https://github.com/dacade/CVE-2020-1938) :  ![starts](https://img.shields.io/github/stars/dacade/CVE-2020-1938.svg) ![forks](https://img.shields.io/github/forks/dacade/CVE-2020-1938.svg)
- [https://github.com/Just1ceP4rtn3r/CVE-2020-1938-Tool](https://github.com/Just1ceP4rtn3r/CVE-2020-1938-Tool) :  ![starts](https://img.shields.io/github/stars/Just1ceP4rtn3r/CVE-2020-1938-Tool.svg) ![forks](https://img.shields.io/github/forks/Just1ceP4rtn3r/CVE-2020-1938-Tool.svg)
- [https://github.com/Umesh2807/Ghostcat](https://github.com/Umesh2807/Ghostcat) :  ![starts](https://img.shields.io/github/stars/Umesh2807/Ghostcat.svg) ![forks](https://img.shields.io/github/forks/Umesh2807/Ghostcat.svg)


## CVE-2020-1048
 An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system, aka 'Windows Print Spooler Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1070.

- [https://github.com/Y3A/cve-2020-1048](https://github.com/Y3A/cve-2020-1048) :  ![starts](https://img.shields.io/github/stars/Y3A/cve-2020-1048.svg) ![forks](https://img.shields.io/github/forks/Y3A/cve-2020-1048.svg)


## CVE-2019-17382
 An issue was discovered in zabbix.php?action=dashboard.view&amp;dashboardid=1 in Zabbix through 4.4. An attacker can bypass the login page and access the dashboard page, and then create a Dashboard, Report, Screen, or Map without any Username/Password (i.e., anonymously). All created elements (Dashboard/Report/Screen/Map) are accessible by other users and by an admin.

- [https://github.com/K3ysTr0K3R/CVE-2019-17382-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2019-17382-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2019-17382-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2019-17382-EXPLOIT.svg)


## CVE-2017-16748
 An attacker can log into the local Niagara platform (Niagara AX Framework Versions 3.8 and prior or Niagara 4 Framework Versions 4.4 and prior) using a disabled account name and a blank password, granting the attacker administrator access to the Niagara system.

- [https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara](https://github.com/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara) :  ![starts](https://img.shields.io/github/stars/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg) ![forks](https://img.shields.io/github/forks/GainSec/CVE-2017-16744-and-CVE-2017-16748-Tridium-Niagara.svg)

