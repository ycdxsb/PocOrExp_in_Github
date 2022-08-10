# Update 2022-08-10
## CVE-2022-30333
 RARLAB UnRAR before 6.12 on Linux and UNIX allows directory traversal to write to files during an extract (aka unpack) operation, as demonstrated by creating a ~/.ssh/authorized_keys file. NOTE: WinRAR and Android RAR are unaffected.

- [https://github.com/rbowes-r7/unrar-cve-2022-30333-poc](https://github.com/rbowes-r7/unrar-cve-2022-30333-poc) :  ![starts](https://img.shields.io/github/stars/rbowes-r7/unrar-cve-2022-30333-poc.svg) ![forks](https://img.shields.io/github/forks/rbowes-r7/unrar-cve-2022-30333-poc.svg)
- [https://github.com/aslitsecurity/Zimbra-CVE-2022-30333](https://github.com/aslitsecurity/Zimbra-CVE-2022-30333) :  ![starts](https://img.shields.io/github/stars/aslitsecurity/Zimbra-CVE-2022-30333.svg) ![forks](https://img.shields.io/github/forks/aslitsecurity/Zimbra-CVE-2022-30333.svg)
- [https://github.com/J0hnbX/CVE-2022-30333](https://github.com/J0hnbX/CVE-2022-30333) :  ![starts](https://img.shields.io/github/stars/J0hnbX/CVE-2022-30333.svg) ![forks](https://img.shields.io/github/forks/J0hnbX/CVE-2022-30333.svg)
- [https://github.com/TheL1ghtVn/CVE-2022-30333-PoC](https://github.com/TheL1ghtVn/CVE-2022-30333-PoC) :  ![starts](https://img.shields.io/github/stars/TheL1ghtVn/CVE-2022-30333-PoC.svg) ![forks](https://img.shields.io/github/forks/TheL1ghtVn/CVE-2022-30333-PoC.svg)


## CVE-2022-22620
 A use after free issue was addressed with improved memory management. This issue is fixed in macOS Monterey 12.2.1, iOS 15.3.1 and iPadOS 15.3.1, Safari 15.3 (v. 16612.4.9.1.8 and 15612.4.9.1.8). Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited..

- [https://github.com/springsec/CVE-2022-22620](https://github.com/springsec/CVE-2022-22620) :  ![starts](https://img.shields.io/github/stars/springsec/CVE-2022-22620.svg) ![forks](https://img.shields.io/github/forks/springsec/CVE-2022-22620.svg)


## CVE-2021-38602
 PluXML 5.8.7 allows Article Editing stored XSS via Headline or Content.

- [https://github.com/KielVaughn/CVE-2021-38602](https://github.com/KielVaughn/CVE-2021-38602) :  ![starts](https://img.shields.io/github/stars/KielVaughn/CVE-2021-38602.svg) ![forks](https://img.shields.io/github/forks/KielVaughn/CVE-2021-38602.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/tuhinGsg/CVE-2021-22204-exiftool](https://github.com/tuhinGsg/CVE-2021-22204-exiftool) :  ![starts](https://img.shields.io/github/stars/tuhinGsg/CVE-2021-22204-exiftool.svg) ![forks](https://img.shields.io/github/forks/tuhinGsg/CVE-2021-22204-exiftool.svg)


## CVE-2021-3492
 Shiftfs, an out-of-tree stacking file system included in Ubuntu Linux kernels, did not properly handle faults occurring during copy_from_user() correctly. These could lead to either a double-free situation or memory not being freed at all. An attacker could use this to cause a denial of service (kernel memory exhaustion) or gain privileges via executing arbitrary code. AKA ZDI-CAN-13562.

- [https://github.com/synacktiv/CVE-2021-3492](https://github.com/synacktiv/CVE-2021-3492) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2021-3492.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2021-3492.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/bkfish/CNVD-2020-10487-Tomcat-Ajp-lfi-Scanner](https://github.com/bkfish/CNVD-2020-10487-Tomcat-Ajp-lfi-Scanner) :  ![starts](https://img.shields.io/github/stars/bkfish/CNVD-2020-10487-Tomcat-Ajp-lfi-Scanner.svg) ![forks](https://img.shields.io/github/forks/bkfish/CNVD-2020-10487-Tomcat-Ajp-lfi-Scanner.svg)
- [https://github.com/shaunmclernon/ghostcat-verification](https://github.com/shaunmclernon/ghostcat-verification) :  ![starts](https://img.shields.io/github/stars/shaunmclernon/ghostcat-verification.svg) ![forks](https://img.shields.io/github/forks/shaunmclernon/ghostcat-verification.svg)


## CVE-2019-9787
 WordPress before 5.1.1 does not properly filter comment content, leading to Remote Code Execution by unauthenticated users in a default configuration. This occurs because CSRF protection is mishandled, and because Search Engine Optimization of A elements is performed incorrectly, leading to XSS. The XSS results in administrative access, which allows arbitrary changes to .php files. This is related to wp-admin/includes/ajax-actions.php and wp-includes/comment.php.

- [https://github.com/dexXxed/CVE-2019-9787](https://github.com/dexXxed/CVE-2019-9787) :  ![starts](https://img.shields.io/github/stars/dexXxed/CVE-2019-9787.svg) ![forks](https://img.shields.io/github/forks/dexXxed/CVE-2019-9787.svg)
- [https://github.com/PalmTreeForest/CodePath_Week_7-8](https://github.com/PalmTreeForest/CodePath_Week_7-8) :  ![starts](https://img.shields.io/github/stars/PalmTreeForest/CodePath_Week_7-8.svg) ![forks](https://img.shields.io/github/forks/PalmTreeForest/CodePath_Week_7-8.svg)


## CVE-2019-1351
 A tampering vulnerability exists when Git for Visual Studio improperly handles virtual drive paths, aka 'Git for Visual Studio Tampering Vulnerability'.

- [https://github.com/JonasDL/PruebaCVE20191351](https://github.com/JonasDL/PruebaCVE20191351) :  ![starts](https://img.shields.io/github/stars/JonasDL/PruebaCVE20191351.svg) ![forks](https://img.shields.io/github/forks/JonasDL/PruebaCVE20191351.svg)


## CVE-2018-14083
 LICA miniCMTS E8K(u/i/...) devices allow remote attackers to obtain sensitive information via a direct POST request for the inc/user.ini file, leading to discovery of a password hash.

- [https://github.com/pudding2/CVE-2018-14083](https://github.com/pudding2/CVE-2018-14083) :  ![starts](https://img.shields.io/github/stars/pudding2/CVE-2018-14083.svg) ![forks](https://img.shields.io/github/forks/pudding2/CVE-2018-14083.svg)


## CVE-2018-5234
 The Norton Core router prior to v237 may be susceptible to a command injection exploit. This is a type of attack in which the goal is execution of arbitrary commands on the host system via vulnerable software.

- [https://github.com/embedi/ble_norton_core](https://github.com/embedi/ble_norton_core) :  ![starts](https://img.shields.io/github/stars/embedi/ble_norton_core.svg) ![forks](https://img.shields.io/github/forks/embedi/ble_norton_core.svg)


## CVE-2017-9805
 The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.

- [https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805](https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/Lone-Ranger/apache-struts-pwn_CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/Lone-Ranger/apache-struts-pwn_CVE-2017-9805.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/D2550/CVE_2017_7921_EXP](https://github.com/D2550/CVE_2017_7921_EXP) :  ![starts](https://img.shields.io/github/stars/D2550/CVE_2017_7921_EXP.svg) ![forks](https://img.shields.io/github/forks/D2550/CVE_2017_7921_EXP.svg)


## CVE-2015-1328
 The overlayfs implementation in the linux (aka Linux kernel) package before 3.19.0-21.21 in Ubuntu through 15.04 does not properly check permissions for file creation in the upper filesystem directory, which allows local users to obtain root access by leveraging a configuration in which overlayfs is permitted in an arbitrary mount namespace.

- [https://github.com/poxicity/CVE-2015-1328](https://github.com/poxicity/CVE-2015-1328) :  ![starts](https://img.shields.io/github/stars/poxicity/CVE-2015-1328.svg) ![forks](https://img.shields.io/github/forks/poxicity/CVE-2015-1328.svg)

