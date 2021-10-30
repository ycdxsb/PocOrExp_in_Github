# Update 2021-10-30
## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/walnutsecurity/cve-2021-42013](https://github.com/walnutsecurity/cve-2021-42013) :  ![starts](https://img.shields.io/github/stars/walnutsecurity/cve-2021-42013.svg) ![forks](https://img.shields.io/github/forks/walnutsecurity/cve-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)


## CVE-2021-41728
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Dir0x/CVE-2021-41728](https://github.com/Dir0x/CVE-2021-41728) :  ![starts](https://img.shields.io/github/stars/Dir0x/CVE-2021-41728.svg) ![forks](https://img.shields.io/github/forks/Dir0x/CVE-2021-41728.svg)


## CVE-2021-37152
 Multiple XSS issues exist in Sonatype Nexus Repository Manager 3 before 3.33.0. An authenticated attacker with the ability to add HTML files to a repository could redirect users to Nexus Repository Manager&#8217;s pages with code modifications.

- [https://github.com/SecurityAnalysts/CVE-2021-37152](https://github.com/SecurityAnalysts/CVE-2021-37152) :  ![starts](https://img.shields.io/github/stars/SecurityAnalysts/CVE-2021-37152.svg) ![forks](https://img.shields.io/github/forks/SecurityAnalysts/CVE-2021-37152.svg)


## CVE-2021-36260
 A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.

- [https://github.com/Aiminsun/CVE-2021-36260](https://github.com/Aiminsun/CVE-2021-36260) :  ![starts](https://img.shields.io/github/stars/Aiminsun/CVE-2021-36260.svg) ![forks](https://img.shields.io/github/forks/Aiminsun/CVE-2021-36260.svg)


## CVE-2021-34486
 Windows Event Tracing Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-26425, CVE-2021-34487.

- [https://github.com/b1tg/CVE-2021-34486-exp](https://github.com/b1tg/CVE-2021-34486-exp) :  ![starts](https://img.shields.io/github/stars/b1tg/CVE-2021-34486-exp.svg) ![forks](https://img.shields.io/github/forks/b1tg/CVE-2021-34486-exp.svg)


## CVE-2021-31862
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/RobertDra/CVE-2021-31862](https://github.com/RobertDra/CVE-2021-31862) :  ![starts](https://img.shields.io/github/stars/RobertDra/CVE-2021-31862.svg) ![forks](https://img.shields.io/github/forks/RobertDra/CVE-2021-31862.svg)


## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

- [https://github.com/Jun-5heng/CVE-2021-22005](https://github.com/Jun-5heng/CVE-2021-22005) :  ![starts](https://img.shields.io/github/stars/Jun-5heng/CVE-2021-22005.svg) ![forks](https://img.shields.io/github/forks/Jun-5heng/CVE-2021-22005.svg)


## CVE-2021-21972
 The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

- [https://github.com/Ma1Dong/vcenter_rce](https://github.com/Ma1Dong/vcenter_rce) :  ![starts](https://img.shields.io/github/stars/Ma1Dong/vcenter_rce.svg) ![forks](https://img.shields.io/github/forks/Ma1Dong/vcenter_rce.svg)


## CVE-2021-3281
 In Django 2.2 before 2.2.18, 3.0 before 3.0.12, and 3.1 before 3.1.6, the django.utils.archive.extract method (used by &quot;startapp --template&quot; and &quot;startproject --template&quot;) allows directory traversal via an archive with absolute paths or relative paths with dot segments.

- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)


## CVE-2021-2064
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). The supported version that is affected is 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/F6JO/CVE-2020-0796-Batch-scanning](https://github.com/F6JO/CVE-2020-0796-Batch-scanning) :  ![starts](https://img.shields.io/github/stars/F6JO/CVE-2020-0796-Batch-scanning.svg) ![forks](https://img.shields.io/github/forks/F6JO/CVE-2020-0796-Batch-scanning.svg)


## CVE-2020-0668
 An elevation of privilege vulnerability exists in the way that the Windows Kernel handles objects in memory, aka 'Windows Kernel Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0669, CVE-2020-0670, CVE-2020-0671, CVE-2020-0672.

- [https://github.com/ycdxsb/CVE-2020-0668](https://github.com/ycdxsb/CVE-2020-0668) :  ![starts](https://img.shields.io/github/stars/ycdxsb/CVE-2020-0668.svg) ![forks](https://img.shields.io/github/forks/ycdxsb/CVE-2020-0668.svg)


## CVE-2019-17558
 Apache Solr 5.0.0 to Apache Solr 8.3.1 are vulnerable to a Remote Code Execution through the VelocityResponseWriter. A Velocity template can be provided through Velocity templates in a configset `velocity/` directory or as a parameter. A user defined configset could contain renderable, potentially malicious, templates. Parameter provided templates are disabled by default, but can be enabled by setting `params.resource.loader.enabled` by defining a response writer with that setting set to `true`. Defining a response writer requires configuration API access. Solr 8.4 removed the params resource loader entirely, and only enables the configset-provided template rendering when the configset is `trusted` (has been uploaded by an authenticated user).

- [https://github.com/Ma1Dong/Solr_CVE-2019-17558](https://github.com/Ma1Dong/Solr_CVE-2019-17558) :  ![starts](https://img.shields.io/github/stars/Ma1Dong/Solr_CVE-2019-17558.svg) ![forks](https://img.shields.io/github/forks/Ma1Dong/Solr_CVE-2019-17558.svg)


## CVE-2019-11358
 jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable __proto__ property, it could extend the native Object.prototype.

- [https://github.com/chrisneagu/FTC-Skystone-Dark-Angels-Romania-2020](https://github.com/chrisneagu/FTC-Skystone-Dark-Angels-Romania-2020) :  ![starts](https://img.shields.io/github/stars/chrisneagu/FTC-Skystone-Dark-Angels-Romania-2020.svg) ![forks](https://img.shields.io/github/forks/chrisneagu/FTC-Skystone-Dark-Angels-Romania-2020.svg)


## CVE-2018-1235
 Dell EMC RecoverPoint versions prior to 5.1.2 and RecoverPoint for VMs versions prior to 5.1.1.3, contain a command injection vulnerability. An unauthenticated remote attacker may potentially exploit this vulnerability to execute arbitrary commands on the affected system with root privilege.

- [https://github.com/AbsoZed/CVE-2018-1235](https://github.com/AbsoZed/CVE-2018-1235) :  ![starts](https://img.shields.io/github/stars/AbsoZed/CVE-2018-1235.svg) ![forks](https://img.shields.io/github/forks/AbsoZed/CVE-2018-1235.svg)


## CVE-2016-3088
 The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.

- [https://github.com/Ma1Dong/ActiveMQ_putshell-CVE-2016-3088](https://github.com/Ma1Dong/ActiveMQ_putshell-CVE-2016-3088) :  ![starts](https://img.shields.io/github/stars/Ma1Dong/ActiveMQ_putshell-CVE-2016-3088.svg) ![forks](https://img.shields.io/github/forks/Ma1Dong/ActiveMQ_putshell-CVE-2016-3088.svg)


## CVE-2015-5254
 Apache ActiveMQ 5.x before 5.13.0 does not restrict the classes that can be serialized in the broker, which allows remote attackers to execute arbitrary code via a crafted serialized Java Message Service (JMS) ObjectMessage object.

- [https://github.com/Ma1Dong/ActiveMQ_CVE-2015-5254](https://github.com/Ma1Dong/ActiveMQ_CVE-2015-5254) :  ![starts](https://img.shields.io/github/stars/Ma1Dong/ActiveMQ_CVE-2015-5254.svg) ![forks](https://img.shields.io/github/forks/Ma1Dong/ActiveMQ_CVE-2015-5254.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/JowardBince/ShellShock](https://github.com/JowardBince/ShellShock) :  ![starts](https://img.shields.io/github/stars/JowardBince/ShellShock.svg) ![forks](https://img.shields.io/github/forks/JowardBince/ShellShock.svg)

