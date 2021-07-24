# Update 2021-07-24
## CVE-2021-36934
 Windows Elevation of Privilege Vulnerability

- [https://github.com/romarroca/SeriousSam](https://github.com/romarroca/SeriousSam) :  ![starts](https://img.shields.io/github/stars/romarroca/SeriousSam.svg) ![forks](https://img.shields.io/github/forks/romarroca/SeriousSam.svg)
- [https://github.com/tda90/CVE-2021-36934](https://github.com/tda90/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/tda90/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/tda90/CVE-2021-36934.svg)
- [https://github.com/bytesizedalex/CVE-2021-36934](https://github.com/bytesizedalex/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/bytesizedalex/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/bytesizedalex/CVE-2021-36934.svg)
- [https://github.com/VertigoRay/CVE-2021-36934](https://github.com/VertigoRay/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/VertigoRay/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/VertigoRay/CVE-2021-36934.svg)
- [https://github.com/WiredPulse/Invoke-HiveDreams](https://github.com/WiredPulse/Invoke-HiveDreams) :  ![starts](https://img.shields.io/github/stars/WiredPulse/Invoke-HiveDreams.svg) ![forks](https://img.shields.io/github/forks/WiredPulse/Invoke-HiveDreams.svg)


## CVE-2021-34527
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/0xirison/PrintNightmare-Patcher](https://github.com/0xirison/PrintNightmare-Patcher) :  ![starts](https://img.shields.io/github/stars/0xirison/PrintNightmare-Patcher.svg) ![forks](https://img.shields.io/github/forks/0xirison/PrintNightmare-Patcher.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/1111one/laravel-CVE-2021-3129-EXP](https://github.com/1111one/laravel-CVE-2021-3129-EXP) :  ![starts](https://img.shields.io/github/stars/1111one/laravel-CVE-2021-3129-EXP.svg) ![forks](https://img.shields.io/github/forks/1111one/laravel-CVE-2021-3129-EXP.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/hahaleyile/my-CVE-2021-1675](https://github.com/hahaleyile/my-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/hahaleyile/my-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/hahaleyile/my-CVE-2021-1675.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/haerin7427/CVE_2020_1938](https://github.com/haerin7427/CVE_2020_1938) :  ![starts](https://img.shields.io/github/stars/haerin7427/CVE_2020_1938.svg) ![forks](https://img.shields.io/github/forks/haerin7427/CVE_2020_1938.svg)


## CVE-2019-11933
 A heap buffer overflow bug in libpl_droidsonroids_gif before 1.2.19, as used in WhatsApp for Android before version 2.19.291 could allow remote attackers to execute arbitrary code or cause a denial of service.

- [https://github.com/KISH84172/CVE-2019-11933](https://github.com/KISH84172/CVE-2019-11933) :  ![starts](https://img.shields.io/github/stars/KISH84172/CVE-2019-11933.svg) ![forks](https://img.shields.io/github/forks/KISH84172/CVE-2019-11933.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the &quot;username map script&quot; smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/3t4n/samba-3.0.24-CVE-2007-2447-vunerable-](https://github.com/3t4n/samba-3.0.24-CVE-2007-2447-vunerable-) :  ![starts](https://img.shields.io/github/stars/3t4n/samba-3.0.24-CVE-2007-2447-vunerable-.svg) ![forks](https://img.shields.io/github/forks/3t4n/samba-3.0.24-CVE-2007-2447-vunerable-.svg)

