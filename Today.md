# Update 2022-03-23
## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/Enokiy/cve-2022-22947-springcloud-gateway](https://github.com/Enokiy/cve-2022-22947-springcloud-gateway) :  ![starts](https://img.shields.io/github/stars/Enokiy/cve-2022-22947-springcloud-gateway.svg) ![forks](https://img.shields.io/github/forks/Enokiy/cve-2022-22947-springcloud-gateway.svg)


## CVE-2022-0824
 Improper Access Control to Remote Code Execution in GitHub repository webmin/webmin prior to 1.990.

- [https://github.com/cryst4lliz3/CVE-2022-0824](https://github.com/cryst4lliz3/CVE-2022-0824) :  ![starts](https://img.shields.io/github/stars/cryst4lliz3/CVE-2022-0824.svg) ![forks](https://img.shields.io/github/forks/cryst4lliz3/CVE-2022-0824.svg)


## CVE-2022-0811
 A flaw was found in CRI-O in the way it set kernel options for a pod. This issue allows anyone with rights to deploy a pod on a Kubernetes cluster that uses the CRI-O runtime to achieve a container escape and arbitrary code execution as root on the cluster node, where the malicious pod was deployed.

- [https://github.com/spiarh/webhook-cve-2022-0811](https://github.com/spiarh/webhook-cve-2022-0811) :  ![starts](https://img.shields.io/github/stars/spiarh/webhook-cve-2022-0811.svg) ![forks](https://img.shields.io/github/forks/spiarh/webhook-cve-2022-0811.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/Qerim-iseni09/ByeLog4Shell](https://github.com/Qerim-iseni09/ByeLog4Shell) :  ![starts](https://img.shields.io/github/stars/Qerim-iseni09/ByeLog4Shell.svg) ![forks](https://img.shields.io/github/forks/Qerim-iseni09/ByeLog4Shell.svg)


## CVE-2021-43530
 A Universal XSS vulnerability was present in Firefox for Android resulting from improper sanitization when processing a URL scanned from a QR code. *This bug only affects Firefox for Android. Other operating systems are unaffected.*. This vulnerability affects Firefox &lt; 94.

- [https://github.com/hfh86/CVE-2021-43530-UXSS-On-QRcode-Reader-](https://github.com/hfh86/CVE-2021-43530-UXSS-On-QRcode-Reader-) :  ![starts](https://img.shields.io/github/stars/hfh86/CVE-2021-43530-UXSS-On-QRcode-Reader-.svg) ![forks](https://img.shields.io/github/forks/hfh86/CVE-2021-43530-UXSS-On-QRcode-Reader-.svg)


## CVE-2021-42237
 Sitecore XP 7.5 Initial Release to Sitecore XP 8.2 Update-7 is vulnerable to an insecure deserialization attack where it is possible to achieve remote command execution on the machine. No authentication or special configuration is required to exploit this vulnerability.

- [https://github.com/ItsIgnacioPortal/CVE-2021-42237](https://github.com/ItsIgnacioPortal/CVE-2021-42237) :  ![starts](https://img.shields.io/github/stars/ItsIgnacioPortal/CVE-2021-42237.svg) ![forks](https://img.shields.io/github/forks/ItsIgnacioPortal/CVE-2021-42237.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/rvizz/CVE-2021-4034](https://github.com/rvizz/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/rvizz/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/rvizz/CVE-2021-4034.svg)
- [https://github.com/defhacks/cve-2021-4034](https://github.com/defhacks/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/defhacks/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/defhacks/cve-2021-4034.svg)
- [https://github.com/k4u5h41/CVE-2021-4034](https://github.com/k4u5h41/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/k4u5h41/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/k4u5h41/CVE-2021-4034.svg)


## CVE-2020-36518
 jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.

- [https://github.com/ghillert/boot-jackson-cve](https://github.com/ghillert/boot-jackson-cve) :  ![starts](https://img.shields.io/github/stars/ghillert/boot-jackson-cve.svg) ![forks](https://img.shields.io/github/forks/ghillert/boot-jackson-cve.svg)


## CVE-2020-6418
 Type confusion in V8 in Google Chrome prior to 80.0.3987.122 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/SivaPriyaRanganatha/CVE-2020-6418](https://github.com/SivaPriyaRanganatha/CVE-2020-6418) :  ![starts](https://img.shields.io/github/stars/SivaPriyaRanganatha/CVE-2020-6418.svg) ![forks](https://img.shields.io/github/forks/SivaPriyaRanganatha/CVE-2020-6418.svg)


## CVE-2019-16278
 Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.

- [https://github.com/k4u5h41/CVE-2019-16278](https://github.com/k4u5h41/CVE-2019-16278) :  ![starts](https://img.shields.io/github/stars/k4u5h41/CVE-2019-16278.svg) ![forks](https://img.shields.io/github/forks/k4u5h41/CVE-2019-16278.svg)


## CVE-2019-14287
 In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a &quot;sudo -u \#$((0xffffffff))&quot; command.

- [https://github.com/k4u5h41/CVE-2019-14287](https://github.com/k4u5h41/CVE-2019-14287) :  ![starts](https://img.shields.io/github/stars/k4u5h41/CVE-2019-14287.svg) ![forks](https://img.shields.io/github/forks/k4u5h41/CVE-2019-14287.svg)


## CVE-2019-1388
 An elevation of privilege vulnerability exists in the Windows Certificate Dialog when it does not properly enforce user privileges, aka 'Windows Certificate Dialog Elevation of Privilege Vulnerability'.

- [https://github.com/jas502n/CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2019-1388.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2019-1388.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/secmode/enumpossible](https://github.com/secmode/enumpossible) :  ![starts](https://img.shields.io/github/stars/secmode/enumpossible.svg) ![forks](https://img.shields.io/github/forks/secmode/enumpossible.svg)
- [https://github.com/pyperanger/CVE-2018-15473_exploit](https://github.com/pyperanger/CVE-2018-15473_exploit) :  ![starts](https://img.shields.io/github/stars/pyperanger/CVE-2018-15473_exploit.svg) ![forks](https://img.shields.io/github/forks/pyperanger/CVE-2018-15473_exploit.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/trustsect/HTC](https://github.com/trustsect/HTC) :  ![starts](https://img.shields.io/github/stars/trustsect/HTC.svg) ![forks](https://img.shields.io/github/forks/trustsect/HTC.svg)


## CVE-2017-1000004
 ATutor version 2.2.1 and earlier are vulnerable to a SQL injection in the Assignment Dropbox, BasicLTI, Blog Post, Blog, Group Course Email, Course Alumni, Course Enrolment, Group Membership, Course unenrolment, Course Enrolment List Search, Glossary, Social Group Member Search, Social Friend Search, Social Group Search, File Comment, Gradebook Test Title, User Group Membership, Inbox/Sent Items, Sent Messages, Links, Photo Album, Poll, Social Application, Social Profile, Test, Content Menu, Auto-Login, and Gradebook components resulting in information disclosure, database modification, or potential code execution.

- [https://github.com/yazan828/CVE-2017-1000004](https://github.com/yazan828/CVE-2017-1000004) :  ![starts](https://img.shields.io/github/stars/yazan828/CVE-2017-1000004.svg) ![forks](https://img.shields.io/github/forks/yazan828/CVE-2017-1000004.svg)


## CVE-2017-14262
 On Samsung NVR devices, remote attackers can read the MD5 password hash of the 'admin' account via certain szUserName JSON data to cgi-bin/main-cgi, and login to the device with that hash in the szUserPasswd parameter.

- [https://github.com/zzz66686/CVE-2017-14262](https://github.com/zzz66686/CVE-2017-14262) :  ![starts](https://img.shields.io/github/stars/zzz66686/CVE-2017-14262.svg) ![forks](https://img.shields.io/github/forks/zzz66686/CVE-2017-14262.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/Ali-Imangholi/EternalBlueTrojan](https://github.com/Ali-Imangholi/EternalBlueTrojan) :  ![starts](https://img.shields.io/github/stars/Ali-Imangholi/EternalBlueTrojan.svg) ![forks](https://img.shields.io/github/forks/Ali-Imangholi/EternalBlueTrojan.svg)

