# Update 2022-11-19
## CVE-2022-43096
 Mediatrix 4102 before v48.5.2718 allows local attackers to gain root access via the UART port.

- [https://github.com/ProxyStaffy/Mediatrix-CVE-2022-43096](https://github.com/ProxyStaffy/Mediatrix-CVE-2022-43096) :  ![starts](https://img.shields.io/github/stars/ProxyStaffy/Mediatrix-CVE-2022-43096.svg) ![forks](https://img.shields.io/github/forks/ProxyStaffy/Mediatrix-CVE-2022-43096.svg)


## CVE-2022-31691
 Spring Tools 4 for Eclipse version 4.16.0 and below as well as VSCode extensions such as Spring Boot Tools, Concourse CI Pipeline Editor, Bosh Editor and Cloudfoundry Manifest YML Support version 1.39.0 and below all use Snakeyaml library for YAML editing support. This library allows for some special syntax in the YAML that under certain circumstances allows for potentially harmful remote code execution by the attacker.

- [https://github.com/SpindleSec/CVE-2022-31691](https://github.com/SpindleSec/CVE-2022-31691) :  ![starts](https://img.shields.io/github/stars/SpindleSec/CVE-2022-31691.svg) ![forks](https://img.shields.io/github/forks/SpindleSec/CVE-2022-31691.svg)


## CVE-2022-24706
 In Apache CouchDB prior to 3.2.2, an attacker can access an improperly secured default installation without authenticating and gain admin privileges. The CouchDB documentation has always made recommendations for properly securing an installation, including recommending using a firewall in front of all CouchDB installations.

- [https://github.com/LightningGod7/CVE-2022-24706-POC](https://github.com/LightningGod7/CVE-2022-24706-POC) :  ![starts](https://img.shields.io/github/stars/LightningGod7/CVE-2022-24706-POC.svg) ![forks](https://img.shields.io/github/forks/LightningGod7/CVE-2022-24706-POC.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/iyamroshan/CVE-2022-22965](https://github.com/iyamroshan/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/iyamroshan/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/iyamroshan/CVE-2022-22965.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/mhurts/CVE-2022-22954-POC](https://github.com/mhurts/CVE-2022-22954-POC) :  ![starts](https://img.shields.io/github/stars/mhurts/CVE-2022-22954-POC.svg) ![forks](https://img.shields.io/github/forks/mhurts/CVE-2022-22954-POC.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/siholley/CVE-2022-0847-Dirty-Pipe-Vulnerability-](https://github.com/siholley/CVE-2022-0847-Dirty-Pipe-Vulnerability-) :  ![starts](https://img.shields.io/github/stars/siholley/CVE-2022-0847-Dirty-Pipe-Vulnerability-.svg) ![forks](https://img.shields.io/github/forks/siholley/CVE-2022-0847-Dirty-Pipe-Vulnerability-.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/trhacknon/exploit-grafana-CVE-2021-43798](https://github.com/trhacknon/exploit-grafana-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/trhacknon/exploit-grafana-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/trhacknon/exploit-grafana-CVE-2021-43798.svg)


## CVE-2021-31805
 The fix issued for CVE-2020-17530 was incomplete. So from Apache Struts 2.0.0 to 2.5.29, still some of the tag&#8217;s attributes could perform a double evaluation if a developer applied forced OGNL evaluation by using the %{...} syntax. Using forced OGNL evaluation on untrusted user input can lead to a Remote Code Execution and security degradation.

- [https://github.com/fleabane1/CVE-2021-31805-POC](https://github.com/fleabane1/CVE-2021-31805-POC) :  ![starts](https://img.shields.io/github/stars/fleabane1/CVE-2021-31805-POC.svg) ![forks](https://img.shields.io/github/forks/fleabane1/CVE-2021-31805-POC.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/Abdulazizalsewedy/CVE-2021-29447](https://github.com/Abdulazizalsewedy/CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/Abdulazizalsewedy/CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/Abdulazizalsewedy/CVE-2021-29447.svg)


## CVE-2021-21972
 The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

- [https://github.com/trhacknon/VMware_vCenter_UNAuthorized_RCE_CVE-2021-21972](https://github.com/trhacknon/VMware_vCenter_UNAuthorized_RCE_CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/trhacknon/VMware_vCenter_UNAuthorized_RCE_CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/trhacknon/VMware_vCenter_UNAuthorized_RCE_CVE-2021-21972.svg)
- [https://github.com/trhacknon/CVE-2021-21972-vCenter-6.5-7.0-RCE-POC](https://github.com/trhacknon/CVE-2021-21972-vCenter-6.5-7.0-RCE-POC) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2021-21972-vCenter-6.5-7.0-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2021-21972-vCenter-6.5-7.0-RCE-POC.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/hackingyseguridad/CVE-2021-4034](https://github.com/hackingyseguridad/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/CVE-2021-4034.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/SNCKER/CVE-2021-3129](https://github.com/SNCKER/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/SNCKER/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/SNCKER/CVE-2021-3129.svg)


## CVE-2018-6606
 An issue was discovered in MalwareFox AntiMalware 2.74.0.150. Improper access control in zam32.sys and zam64.sys allows a non-privileged process to register itself with the driver by sending IOCTL 0x80002010 and then using IOCTL 0x8000204C to \\.\ZemanaAntiMalware to elevate privileges.

- [https://github.com/hfiref0x/KDU](https://github.com/hfiref0x/KDU) :  ![starts](https://img.shields.io/github/stars/hfiref0x/KDU.svg) ![forks](https://img.shields.io/github/forks/hfiref0x/KDU.svg)


## CVE-2016-10033
 The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \&quot; (backslash double quote) in a crafted Sender property.

- [https://github.com/CAOlvchonger/CVE-2016-10033](https://github.com/CAOlvchonger/CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/CAOlvchonger/CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/CAOlvchonger/CVE-2016-10033.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/daai1/CVE-2012-1823](https://github.com/daai1/CVE-2012-1823) :  ![starts](https://img.shields.io/github/stars/daai1/CVE-2012-1823.svg) ![forks](https://img.shields.io/github/forks/daai1/CVE-2012-1823.svg)

