# Update 2024-04-27
## CVE-2024-2876
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/c0d3zilla/CVE-2024-2876](https://github.com/c0d3zilla/CVE-2024-2876) :  ![starts](https://img.shields.io/github/stars/c0d3zilla/CVE-2024-2876.svg) ![forks](https://img.shields.io/github/forks/c0d3zilla/CVE-2024-2876.svg)


## CVE-2023-50164
 An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution. Users are recommended to upgrade to versions Struts 2.5.33 or Struts 6.3.0.2 or greater to fix this issue.

- [https://github.com/minhbao15677/CVE-2023-50164](https://github.com/minhbao15677/CVE-2023-50164) :  ![starts](https://img.shields.io/github/stars/minhbao15677/CVE-2023-50164.svg) ![forks](https://img.shields.io/github/forks/minhbao15677/CVE-2023-50164.svg)


## CVE-2023-43364
 main.py in Searchor before 2.4.2 uses eval on CLI input, which may cause unexpected code execution.

- [https://github.com/libertycityhacker/CVE-2023-43364-Exploit-CVE](https://github.com/libertycityhacker/CVE-2023-43364-Exploit-CVE) :  ![starts](https://img.shields.io/github/stars/libertycityhacker/CVE-2023-43364-Exploit-CVE.svg) ![forks](https://img.shields.io/github/forks/libertycityhacker/CVE-2023-43364-Exploit-CVE.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/AlissonFaoli/CVE-2023-23752](https://github.com/AlissonFaoli/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/AlissonFaoli/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/AlissonFaoli/CVE-2023-23752.svg)


## CVE-2023-20198
 Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-2023-20198 to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system. Cisco has assigned CVE-2023-20273 to this issue. CVE-2023-20198 has been assigned a CVSS Score of 10.0. CVE-2023-20273 has been assigned a CVSS Score of 7.2. Both of these CVEs are being tracked by CSCwh87343.

- [https://github.com/W01fh4cker/CVE-2023-20198-RCE](https://github.com/W01fh4cker/CVE-2023-20198-RCE) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/CVE-2023-20198-RCE.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/CVE-2023-20198-RCE.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/A1vinSmith/CVE-2021-4034](https://github.com/A1vinSmith/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/A1vinSmith/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/A1vinSmith/CVE-2021-4034.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/aamfrk/Webmin-CVE-2019-15107](https://github.com/aamfrk/Webmin-CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/aamfrk/Webmin-CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/aamfrk/Webmin-CVE-2019-15107.svg)


## CVE-2018-25031
 Swagger UI before 4.1.3 could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions.

- [https://github.com/nullbyter19/CVE-2018-25031](https://github.com/nullbyter19/CVE-2018-25031) :  ![starts](https://img.shields.io/github/stars/nullbyter19/CVE-2018-25031.svg) ![forks](https://img.shields.io/github/forks/nullbyter19/CVE-2018-25031.svg)


## CVE-2018-20250
 In WinRAR versions prior to and including 5.61, There is path traversal vulnerability when crafting the filename field of the ACE format (in UNACEV2.dll). When the filename field is manipulated with specific patterns, the destination (extraction) folder is ignored, thus treating the filename as an absolute path.

- [https://github.com/LamSonBinh/CVE-2018-20250](https://github.com/LamSonBinh/CVE-2018-20250) :  ![starts](https://img.shields.io/github/stars/LamSonBinh/CVE-2018-20250.svg) ![forks](https://img.shields.io/github/forks/LamSonBinh/CVE-2018-20250.svg)


## CVE-2015-20107
 In Python (aka CPython) up to 3.10.8, the mailcap module does not add escape characters into commands discovered in the system mailcap file. This may allow attackers to inject shell commands into applications that call mailcap.findmatch with untrusted input (if they lack validation of user-provided filenames or arguments). The fix is also back-ported to 3.7, 3.8, 3.9

- [https://github.com/codeskipper/python-patrol](https://github.com/codeskipper/python-patrol) :  ![starts](https://img.shields.io/github/stars/codeskipper/python-patrol.svg) ![forks](https://img.shields.io/github/forks/codeskipper/python-patrol.svg)


## CVE-2001-0934
 Cooolsoft PowerFTP Server 2.03 allows remote attackers to obtain the physical path of the server root via the pwd command, which lists the full pathname.

- [https://github.com/alt3kx/CVE-2001-0934](https://github.com/alt3kx/CVE-2001-0934) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2001-0934.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2001-0934.svg)


## CVE-2001-0931
 Directory traversal vulnerability in Cooolsoft PowerFTP Server 2.03 allows attackers to list or read arbitrary files and directories via a .. (dot dot) in (1) LS or (2) GET.

- [https://github.com/alt3kx/CVE-2001-0931](https://github.com/alt3kx/CVE-2001-0931) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2001-0931.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2001-0931.svg)


## CVE-2001-0758
 Directory traversal vulnerability in Shambala 4.5 allows remote attackers to escape the FTP root directory via &quot;CWD ...&quot;  command.

- [https://github.com/alt3kx/CVE-2001-0758](https://github.com/alt3kx/CVE-2001-0758) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2001-0758.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2001-0758.svg)


## CVE-2001-0680
 Directory traversal vulnerability in ftpd in QPC QVT/Net 4.0 and AVT/Term 5.0 allows a remote attacker to traverse directories on the web server via a &quot;dot dot&quot; attack in a LIST (ls) command.

- [https://github.com/alt3kx/CVE-2001-0680](https://github.com/alt3kx/CVE-2001-0680) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2001-0680.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2001-0680.svg)


## CVE-2001-0550
 wu-ftpd 2.6.1 allows remote attackers to execute arbitrary commands via a &quot;~{&quot; argument to commands such as CWD, which is not properly handled by the glob function (ftpglob).

- [https://github.com/gilberto47831/Network-Filesystem-Forensics](https://github.com/gilberto47831/Network-Filesystem-Forensics) :  ![starts](https://img.shields.io/github/stars/gilberto47831/Network-Filesystem-Forensics.svg) ![forks](https://img.shields.io/github/forks/gilberto47831/Network-Filesystem-Forensics.svg)

