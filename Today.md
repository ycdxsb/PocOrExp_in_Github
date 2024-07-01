# Update 2024-07-01
## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/cmsec423/CVE-2024-34102](https://github.com/cmsec423/CVE-2024-34102) :  ![starts](https://img.shields.io/github/stars/cmsec423/CVE-2024-34102.svg) ![forks](https://img.shields.io/github/forks/cmsec423/CVE-2024-34102.svg)


## CVE-2024-28995
 SolarWinds Serv-U was susceptible to a directory transversal vulnerability that would allow access to read sensitive files on the host machine.

- [https://github.com/0xc4t/CVE-2024-28995](https://github.com/0xc4t/CVE-2024-28995) :  ![starts](https://img.shields.io/github/stars/0xc4t/CVE-2024-28995.svg) ![forks](https://img.shields.io/github/forks/0xc4t/CVE-2024-28995.svg)


## CVE-2024-22853
 D-LINK Go-RT-AC750 GORTAC750_A1_FW_v101b03 has a hardcoded password for the Alphanetworks account, which allows remote attackers to obtain root access via a telnet session.

- [https://github.com/FaLLenSKiLL1/CVE-2024-22853](https://github.com/FaLLenSKiLL1/CVE-2024-22853) :  ![starts](https://img.shields.io/github/stars/FaLLenSKiLL1/CVE-2024-22853.svg) ![forks](https://img.shields.io/github/forks/FaLLenSKiLL1/CVE-2024-22853.svg)


## CVE-2023-45866
 Bluetooth HID Hosts in BlueZ may permit an unauthenticated Peripheral role HID Device to initiate and establish an encrypted connection, and accept HID keyboard reports, potentially permitting injection of HID messages when no user interaction has occurred in the Central role to authorize such access. An example affected package is bluez 5.64-0ubuntu1 in Ubuntu 22.04LTS. NOTE: in some cases, a CVE-2020-0556 mitigation would have already addressed this Bluetooth HID Hosts issue.

- [https://github.com/cisnarfu/Bluepop](https://github.com/cisnarfu/Bluepop) :  ![starts](https://img.shields.io/github/stars/cisnarfu/Bluepop.svg) ![forks](https://img.shields.io/github/forks/cisnarfu/Bluepop.svg)


## CVE-2022-29455
 DOM-based Reflected Cross-Site Scripting (XSS) vulnerability in Elementor's Elementor Website Builder plugin &lt;= 3.5.5 versions.

- [https://github.com/0xc4t/CVE-2022-29455](https://github.com/0xc4t/CVE-2022-29455) :  ![starts](https://img.shields.io/github/stars/0xc4t/CVE-2022-29455.svg) ![forks](https://img.shields.io/github/forks/0xc4t/CVE-2022-29455.svg)


## CVE-2022-24112
 An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.

- [https://github.com/CrackerCat/CVE-2022-24112](https://github.com/CrackerCat/CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2022-24112.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/CPT-Jack-A-Castle/CVE-2022-0847](https://github.com/CPT-Jack-A-Castle/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/CPT-Jack-A-Castle/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/CPT-Jack-A-Castle/CVE-2022-0847.svg)


## CVE-2021-41091
 Moby is an open-source project created by Docker to enable software containerization. A bug was found in Moby (Docker Engine) where the data directory (typically `/var/lib/docker`) contained subdirectories with insufficiently restricted permissions, allowing otherwise unprivileged Linux users to traverse directory contents and execute programs. When containers included executable programs with extended permission bits (such as `setuid`), unprivileged Linux users could discover and execute those programs. When the UID of an unprivileged Linux user on the host collided with the file owner or group inside a container, the unprivileged Linux user on the host could discover, read, and modify those files. This bug has been fixed in Moby (Docker Engine) 20.10.9. Users should update to this version as soon as possible. Running containers should be stopped and restarted for the permissions to be fixed. For users unable to upgrade limit access to the host to trusted users. Limit access to host volumes to trusted containers.

- [https://github.com/SNE-M23-SN/Vulnerable-Docker-Engine](https://github.com/SNE-M23-SN/Vulnerable-Docker-Engine) :  ![starts](https://img.shields.io/github/stars/SNE-M23-SN/Vulnerable-Docker-Engine.svg) ![forks](https://img.shields.io/github/forks/SNE-M23-SN/Vulnerable-Docker-Engine.svg)


## CVE-2021-40444
 &lt;p&gt;Microsoft is investigating reports of a remote code execution vulnerability in MSHTML that affects Microsoft Windows. Microsoft is aware of targeted attacks that attempt to exploit this vulnerability by using specially-crafted Microsoft Office documents.&lt;/p&gt; &lt;p&gt;An attacker could craft a malicious ActiveX control to be used by a Microsoft Office document that hosts the browser rendering engine. The attacker would then have to convince the user to open the malicious document. Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who operate with administrative user rights.&lt;/p&gt; &lt;p&gt;Microsoft Defender Antivirus and Microsoft Defender for Endpoint both provide detection and protections for the known vulnerability. Customers should keep antimalware products up to date. Customers who utilize automatic updates do not need to take additional action. Enterprise customers who manage updates should select the detection build 1.349.22.0 or newer and deploy it across their environments. Microsoft Defender for Endpoint alerts will be displayed as: &#8220;Suspicious Cpl File Execution&#8221;.&lt;/p&gt; &lt;p&gt;Upon completion of this investigation, Microsoft will take the appropriate action to help protect our customers. This may include providing a security update through our monthly release process or providing an out-of-cycle security update, depending on customer needs.&lt;/p&gt; &lt;p&gt;Please see the &lt;strong&gt;Mitigations&lt;/strong&gt; and &lt;strong&gt;Workaround&lt;/strong&gt; sections for important information about steps you can take to protect your system from this vulnerability.&lt;/p&gt; &lt;p&gt;&lt;strong&gt;UPDATE&lt;/strong&gt; September 14, 2021: Microsoft has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. Please see the FAQ for important information about which updates are applicable to your system.&lt;/p&gt;

- [https://github.com/Phuong39/CVE-2021-40444-CAB](https://github.com/Phuong39/CVE-2021-40444-CAB) :  ![starts](https://img.shields.io/github/stars/Phuong39/CVE-2021-40444-CAB.svg) ![forks](https://img.shields.io/github/forks/Phuong39/CVE-2021-40444-CAB.svg)
- [https://github.com/k4k4/CVE-2021-40444-Sample](https://github.com/k4k4/CVE-2021-40444-Sample) :  ![starts](https://img.shields.io/github/stars/k4k4/CVE-2021-40444-Sample.svg) ![forks](https://img.shields.io/github/forks/k4k4/CVE-2021-40444-Sample.svg)


## CVE-2021-31167
 Windows Container Manager Service Elevation of Privilege Vulnerability

- [https://github.com/5l1v3r1/CVE-2021-31167](https://github.com/5l1v3r1/CVE-2021-31167) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2021-31167.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2021-31167.svg)


## CVE-2021-26119
 Smarty before 3.1.39 allows a Sandbox Escape because $smarty.template_object can be accessed in sandbox mode.

- [https://github.com/5l1v3r1/CVE-2021-26119](https://github.com/5l1v3r1/CVE-2021-26119) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2021-26119.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2021-26119.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/CrackerCat/CVE-2021-26084](https://github.com/CrackerCat/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2021-26084.svg)


## CVE-2021-22986
 On BIG-IP versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x before 14.1.4, 13.1.x before 13.1.3.6, and 12.1.x before 12.1.5.3 amd BIG-IQ 7.1.0.x before 7.1.0.3 and 7.0.0.x before 7.0.0.2, the iControl REST interface has an unauthenticated remote command execution vulnerability. Note: Software versions which have reached End of Software Development (EoSD) are not evaluated.

- [https://github.com/microvorld/CVE-2021-22986](https://github.com/microvorld/CVE-2021-22986) :  ![starts](https://img.shields.io/github/stars/microvorld/CVE-2021-22986.svg) ![forks](https://img.shields.io/github/forks/microvorld/CVE-2021-22986.svg)


## CVE-2021-21972
 The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

- [https://github.com/TAI-REx/CVE-2021-21972](https://github.com/TAI-REx/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/TAI-REx/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/TAI-REx/CVE-2021-21972.svg)


## CVE-2020-10148
 The SolarWinds Orion API is vulnerable to an authentication bypass that could allow a remote attacker to execute API commands. This vulnerability could allow a remote attacker to bypass authentication and execute API commands which may result in a compromise of the SolarWinds instance. SolarWinds Orion Platform versions 2019.4 HF 5, 2020.2 with no hotfix installed, and 2020.2 HF 1 are affected.

- [https://github.com/5l1v3r1/CVE-2020-10148-Solarwinds-Orion](https://github.com/5l1v3r1/CVE-2020-10148-Solarwinds-Orion) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-10148-Solarwinds-Orion.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-10148-Solarwinds-Orion.svg)


## CVE-2020-7961
 Deserialization of Untrusted Data in Liferay Portal prior to 7.2.1 CE GA2 allows remote attackers to execute arbitrary code via JSON web services (JSONWS).

- [https://github.com/CrackerCat/CVE-2020-7961-Mass](https://github.com/CrackerCat/CVE-2020-7961-Mass) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2020-7961-Mass.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2020-7961-Mass.svg)


## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/uartu0/nodejshell](https://github.com/uartu0/nodejshell) :  ![starts](https://img.shields.io/github/stars/uartu0/nodejshell.svg) ![forks](https://img.shields.io/github/forks/uartu0/nodejshell.svg)

