# Update 2022-05-08
## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/LinJacck/CVE-2022-29464](https://github.com/LinJacck/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/LinJacck/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/LinJacck/CVE-2022-29464.svg)


## CVE-2022-25236
 xmlparse.c in Expat (aka libexpat) before 2.4.5 allows attackers to insert namespace-separator characters into namespace URIs.

- [https://github.com/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25236](https://github.com/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25236) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25236.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25236.svg)


## CVE-2022-21984
 Windows DNS Server Remote Code Execution Vulnerability.

- [https://github.com/u201424348/CVE-2022-21984](https://github.com/u201424348/CVE-2022-21984) :  ![starts](https://img.shields.io/github/stars/u201424348/CVE-2022-21984.svg) ![forks](https://img.shields.io/github/forks/u201424348/CVE-2022-21984.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/MrCl0wnLab/Nuclei-Template-CVE-2022-1388-BIG-IP-iControl-REST-Exposed](https://github.com/MrCl0wnLab/Nuclei-Template-CVE-2022-1388-BIG-IP-iControl-REST-Exposed) :  ![starts](https://img.shields.io/github/stars/MrCl0wnLab/Nuclei-Template-CVE-2022-1388-BIG-IP-iControl-REST-Exposed.svg) ![forks](https://img.shields.io/github/forks/MrCl0wnLab/Nuclei-Template-CVE-2022-1388-BIG-IP-iControl-REST-Exposed.svg)


## CVE-2022-1040
 An authentication bypass vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v18.5 MR3 and older.

- [https://github.com/killvxk/CVE-2022-1040](https://github.com/killvxk/CVE-2022-1040) :  ![starts](https://img.shields.io/github/stars/killvxk/CVE-2022-1040.svg) ![forks](https://img.shields.io/github/forks/killvxk/CVE-2022-1040.svg)


## CVE-2022-0441
 The MasterStudy LMS WordPress plugin before 2.7.6 does to validate some parameters given when registering a new account, allowing unauthenticated users to register as an admin

- [https://github.com/biulove0x/CVE-2022-0441](https://github.com/biulove0x/CVE-2022-0441) :  ![starts](https://img.shields.io/github/stars/biulove0x/CVE-2022-0441.svg) ![forks](https://img.shields.io/github/forks/biulove0x/CVE-2022-0441.svg)


## CVE-2022-0440
 The Catch Themes Demo Import WordPress plugin before 2.1.1 does not validate one of the file to be imported, which could allow high privivilege admin to upload an arbitrary PHP file and gain RCE even in the case of an hardened blog (ie DISALLOW_UNFILTERED_HTML, DISALLOW_FILE_EDIT and DISALLOW_FILE_MODS constants set to true)

- [https://github.com/qerogram/BUG_WEB](https://github.com/qerogram/BUG_WEB) :  ![starts](https://img.shields.io/github/stars/qerogram/BUG_WEB.svg) ![forks](https://img.shields.io/github/forks/qerogram/BUG_WEB.svg)


## CVE-2021-43287
 An issue was discovered in ThoughtWorks GoCD before 21.3.0. The business continuity add-on, which is enabled by default, leaks all secrets known to the GoCD server to unauthenticated attackers.

- [https://github.com/Wrin9/CVE-2021-43287](https://github.com/Wrin9/CVE-2021-43287) :  ![starts](https://img.shields.io/github/stars/Wrin9/CVE-2021-43287.svg) ![forks](https://img.shields.io/github/forks/Wrin9/CVE-2021-43287.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Ph4nt0mh4x0r/auto-CVE-2021-4034](https://github.com/Ph4nt0mh4x0r/auto-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Ph4nt0mh4x0r/auto-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Ph4nt0mh4x0r/auto-CVE-2021-4034.svg)


## CVE-2020-10977
 GitLab EE/CE 8.5 to 12.9 is vulnerable to a an path traversal when moving an issue between projects.

- [https://github.com/Bin4xin/bin4xin.github.io](https://github.com/Bin4xin/bin4xin.github.io) :  ![starts](https://img.shields.io/github/stars/Bin4xin/bin4xin.github.io.svg) ![forks](https://img.shields.io/github/forks/Bin4xin/bin4xin.github.io.svg)


## CVE-2020-3452
 A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.

- [https://github.com/iveresk/cve-2020-3452](https://github.com/iveresk/cve-2020-3452) :  ![starts](https://img.shields.io/github/stars/iveresk/cve-2020-3452.svg) ![forks](https://img.shields.io/github/forks/iveresk/cve-2020-3452.svg)


## CVE-2018-3191
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/m00zh33/CVE-2018-3191](https://github.com/m00zh33/CVE-2018-3191) :  ![starts](https://img.shields.io/github/stars/m00zh33/CVE-2018-3191.svg) ![forks](https://img.shields.io/github/forks/m00zh33/CVE-2018-3191.svg)


## CVE-2018-1112
 glusterfs server before versions 3.10.12, 4.0.2 is vulnerable when using 'auth.allow' option which allows any unauthenticated gluster client to connect from any network to mount gluster storage volumes. NOTE: this vulnerability exists because of a CVE-2018-1088 regression.

- [https://github.com/MauroEldritch/GEVAUDAN](https://github.com/MauroEldritch/GEVAUDAN) :  ![starts](https://img.shields.io/github/stars/MauroEldritch/GEVAUDAN.svg) ![forks](https://img.shields.io/github/forks/MauroEldritch/GEVAUDAN.svg)


## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.

- [https://github.com/eulercode/exploit-CVE-2017-7494](https://github.com/eulercode/exploit-CVE-2017-7494) :  ![starts](https://img.shields.io/github/stars/eulercode/exploit-CVE-2017-7494.svg) ![forks](https://img.shields.io/github/forks/eulercode/exploit-CVE-2017-7494.svg)


## CVE-2016-10190
 Heap-based buffer overflow in libavformat/http.c in FFmpeg before 2.8.10, 3.0.x before 3.0.5, 3.1.x before 3.1.6, and 3.2.x before 3.2.2 allows remote web servers to execute arbitrary code via a negative chunk size in an HTTP response.

- [https://github.com/muzalam/FFMPEG-exploit](https://github.com/muzalam/FFMPEG-exploit) :  ![starts](https://img.shields.io/github/stars/muzalam/FFMPEG-exploit.svg) ![forks](https://img.shields.io/github/forks/muzalam/FFMPEG-exploit.svg)


## CVE-2014-3704
 The expandArguments function in the database abstraction API in Drupal core 7.x before 7.32 does not properly construct prepared statements, which allows remote attackers to conduct SQL injection attacks via an array containing crafted keys.

- [https://github.com/WTSTiNy/CVE-2014-3704](https://github.com/WTSTiNy/CVE-2014-3704) :  ![starts](https://img.shields.io/github/stars/WTSTiNy/CVE-2014-3704.svg) ![forks](https://img.shields.io/github/forks/WTSTiNy/CVE-2014-3704.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/GardeniaWhite/fuzzing](https://github.com/GardeniaWhite/fuzzing) :  ![starts](https://img.shields.io/github/stars/GardeniaWhite/fuzzing.svg) ![forks](https://img.shields.io/github/forks/GardeniaWhite/fuzzing.svg)

