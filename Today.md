# Update 2021-10-06
## CVE-2021-39433
 A local file inclusion (LFI) vulnerability exists in version BIQS IT Biqs-drive v1.83 and below when sending a specific payload as the file parameter to download/index.php. This allows the attacker to read arbitrary files from the server with the permissions of the configured web-user.

- [https://github.com/PinkDraconian/CVE-2021-39433](https://github.com/PinkDraconian/CVE-2021-39433) :  ![starts](https://img.shields.io/github/stars/PinkDraconian/CVE-2021-39433.svg) ![forks](https://img.shields.io/github/forks/PinkDraconian/CVE-2021-39433.svg)


## CVE-2021-28476
 Hyper-V Remote Code Execution Vulnerability

- [https://github.com/LaCeeKa/CVE-2021-28476-tools-env](https://github.com/LaCeeKa/CVE-2021-28476-tools-env) :  ![starts](https://img.shields.io/github/stars/LaCeeKa/CVE-2021-28476-tools-env.svg) ![forks](https://img.shields.io/github/forks/LaCeeKa/CVE-2021-28476-tools-env.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/usr2r00t/patches](https://github.com/usr2r00t/patches) :  ![starts](https://img.shields.io/github/stars/usr2r00t/patches.svg) ![forks](https://img.shields.io/github/forks/usr2r00t/patches.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/Opensitoo/cve-2020-0796](https://github.com/Opensitoo/cve-2020-0796) :  ![starts](https://img.shields.io/github/stars/Opensitoo/cve-2020-0796.svg) ![forks](https://img.shields.io/github/forks/Opensitoo/cve-2020-0796.svg)


## CVE-2019-25052
 In Linaro OP-TEE before 3.7.0, by using inconsistent or malformed data, it is possible to call update and final cryptographic functions directly, causing a crash that could leak sensitive information.

- [https://github.com/AIPOCAI/CVE-2019-25052](https://github.com/AIPOCAI/CVE-2019-25052) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2019-25052.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2019-25052.svg)


## CVE-2019-19797
 read_colordef in read.c in Xfig fig2dev 3.2.7b has an out-of-bounds write.

- [https://github.com/AIPOCAI/CVE-2019-19797](https://github.com/AIPOCAI/CVE-2019-19797) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2019-19797.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2019-19797.svg)


## CVE-2019-17571
 Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget when listening to untrusted network traffic for log data. This affects Log4j versions up to 1.2 up to 1.2.17.

- [https://github.com/AIPOCAI/CVE-2019-17571](https://github.com/AIPOCAI/CVE-2019-17571) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2019-17571.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2019-17571.svg)


## CVE-2019-17495
 A Cascading Style Sheets (CSS) injection vulnerability in Swagger UI before 3.23.11 allows attackers to use the Relative Path Overwrite (RPO) technique to perform CSS-based input field value exfiltration, such as exfiltration of a CSRF token value. In other words, this product intentionally allows the embedding of untrusted JSON data from remote servers, but it was not previously known that &lt;style&gt;@import within the JSON data was a functional attack method.

- [https://github.com/AIPOCAI/CVE-2019-17495](https://github.com/AIPOCAI/CVE-2019-17495) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2019-17495.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2019-17495.svg)


## CVE-2019-14904
 A flaw was found in the solaris_zone module from the Ansible Community modules. When setting the name for the zone on the Solaris host, the zone name is checked by listing the process with the 'ps' bare command on the remote machine. An attacker could take advantage of this flaw by crafting the name of the zone and executing arbitrary commands in the remote host. Ansible Engine 2.7.15, 2.8.7, and 2.9.2 as well as previous versions are affected.

- [https://github.com/AIPOCAI/CVE-2019-14904](https://github.com/AIPOCAI/CVE-2019-14904) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2019-14904.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2019-14904.svg)


## CVE-2019-14864
 Ansible, versions 2.9.x before 2.9.1, 2.8.x before 2.8.7 and Ansible versions 2.7.x before 2.7.15, is not respecting the flag no_log set it to True when Sumologic and Splunk callback plugins are used send tasks results events to collectors. This would discloses and collects any sensitive data.

- [https://github.com/AIPOCAI/CVE-2019-14864](https://github.com/AIPOCAI/CVE-2019-14864) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2019-14864.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2019-14864.svg)


## CVE-2019-14846
 In Ansible, all Ansible Engine versions up to ansible-engine 2.8.5, ansible-engine 2.7.13, ansible-engine 2.6.19, were logging at the DEBUG level which lead to a disclosure of credentials if a plugin used a library that logged credentials at the DEBUG level. This flaw does not affect Ansible modules, as those are executed in a separate process.

- [https://github.com/AIPOCAI/CVE-2019-14846](https://github.com/AIPOCAI/CVE-2019-14846) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2019-14846.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2019-14846.svg)


## CVE-2019-9060
 An issue was discovered in CMS Made Simple 2.2.8. It is possible to achieve unauthenticated path traversal in the CGExtensions module (in the file action.setdefaulttemplate.php) with the m1_filename parameter; and through the action.showmessage.php file, it is possible to read arbitrary file content (by using that path traversal with m1_prefname set to cg_errormsg and m1_resettodefault=1).

- [https://github.com/AIPOCAI/CVE-2019-9060](https://github.com/AIPOCAI/CVE-2019-9060) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2019-9060.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2019-9060.svg)


## CVE-2019-7254
 Linear eMerge E3-Series devices allow File Inclusion.

- [https://github.com/AIPOCAI/CVE-2019-7254](https://github.com/AIPOCAI/CVE-2019-7254) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2019-7254.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2019-7254.svg)


## CVE-2019-6820
 A CWE-306: Missing Authentication for Critical Function vulnerability exists which could cause a modification of device IP configuration (IP address, network mask and gateway IP address) when a specific Ethernet frame is received in all versions of: Modicon M100, Modicon M200, Modicon M221, ATV IMC drive controller, Modicon M241, Modicon M251, Modicon M258, Modicon LMC058, Modicon LMC078, PacDrive Eco ,PacDrive Pro, PacDrive Pro2

- [https://github.com/AIPOCAI/CVE-2019-6820](https://github.com/AIPOCAI/CVE-2019-6820) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2019-6820.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2019-6820.svg)


## CVE-2019-3820
 It was discovered that the gnome-shell lock screen since version 3.15.91 did not properly restrict all contextual actions. An attacker with physical access to a locked workstation could invoke certain keyboard shortcuts, and potentially other actions.

- [https://github.com/AIPOCAI/CVE-2019-3820](https://github.com/AIPOCAI/CVE-2019-3820) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2019-3820.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2019-3820.svg)


## CVE-2018-20217
 A Reachable Assertion issue was discovered in the KDC in MIT Kerberos 5 (aka krb5) before 1.17. If an attacker can obtain a krbtgt ticket using an older encryption type (single-DES, triple-DES, or RC4), the attacker can crash the KDC by making an S4U2Self request.

- [https://github.com/AIPOCAI/CVE-2018-20217](https://github.com/AIPOCAI/CVE-2018-20217) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2018-20217.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2018-20217.svg)


## CVE-2018-16871
 A flaw was found in the Linux kernel's NFS implementation, all versions 3.x and all versions 4.x up to 4.20. An attacker, who is able to mount an exported NFS filesystem, is able to trigger a null pointer dereference by using an invalid NFS sequence. This can panic the machine and deny access to the NFS server. Any outstanding disk writes to the NFS server will be lost.

- [https://github.com/AIPOCAI/CVE-2018-16871](https://github.com/AIPOCAI/CVE-2018-16871) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2018-16871.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2018-16871.svg)


## CVE-2018-16177
 Untrusted search path vulnerability in The installer of Windows 10 Fall Creators Update Modify module for Security Measures tool allows an attacker to gain privileges via a Trojan horse DLL in an unspecified directory.

- [https://github.com/AIPOCAI/CVE-2018-16177](https://github.com/AIPOCAI/CVE-2018-16177) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2018-16177.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2018-16177.svg)


## CVE-2018-14773
 An issue was discovered in Http Foundation in Symfony 2.7.0 through 2.7.48, 2.8.0 through 2.8.43, 3.3.0 through 3.3.17, 3.4.0 through 3.4.13, 4.0.0 through 4.0.13, and 4.1.0 through 4.1.2. It arises from support for a (legacy) IIS header that lets users override the path in the request URL via the X-Original-URL or X-Rewrite-URL HTTP request header. These headers are designed for IIS support, but it's not verified that the server is in fact running IIS, which means anybody who can send these requests to an application can trigger this. This affects \Symfony\Component\HttpFoundation\Request::prepareRequestUri() where X-Original-URL and X_REWRITE_URL are both used. The fix drops support for these methods so that they cannot be used as attack vectors such as web cache poisoning.

- [https://github.com/AIPOCAI/CVE-2018-14773](https://github.com/AIPOCAI/CVE-2018-14773) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2018-14773.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2018-14773.svg)


## CVE-2018-11439
 The TagLib::Ogg::FLAC::File::scan function in oggflacfile.cpp in TagLib 1.11.1 allows remote attackers to cause information disclosure (heap-based buffer over-read) via a crafted audio file.

- [https://github.com/AIPOCAI/CVE-2018-11439](https://github.com/AIPOCAI/CVE-2018-11439) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2018-11439.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2018-11439.svg)


## CVE-2018-10023
 Catfish CMS V4.7.21 allows XSS via the pinglun parameter to cat/index/index/pinglun (aka an authenticated comment).

- [https://github.com/AIPOCAI/CVE-2018-10023](https://github.com/AIPOCAI/CVE-2018-10023) :  ![starts](https://img.shields.io/github/stars/AIPOCAI/CVE-2018-10023.svg) ![forks](https://img.shields.io/github/forks/AIPOCAI/CVE-2018-10023.svg)


## CVE-2018-8256
 A remote code execution vulnerability exists when PowerShell improperly handles specially crafted files, aka &quot;Microsoft PowerShell Remote Code Execution Vulnerability.&quot; This affects Windows RT 8.1, PowerShell Core 6.0, Microsoft.PowerShell.Archive 1.2.2.0, Windows Server 2016, Windows Server 2012, Windows Server 2008 R2, Windows Server 2019, Windows 7, Windows Server 2012 R2, PowerShell Core 6.1, Windows 10 Servers, Windows 10, Windows 8.1.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-8256](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-8256) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2018-8256.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2018-8256.svg)


## CVE-2018-7842
 A CWE-290: Authentication Bypass by Spoofing vulnerability exists in all versions of the Modicon M580, Modicon M340, Modicon Quantum, and Modicon Premium which could cause an elevation of privilege by conducting a brute force attack on Modbus parameters sent to the controller.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-7842](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-7842) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2018-7842.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2018-7842.svg)


## CVE-2018-7821
 An Environment (CWE-2) vulnerability exists in SoMachine Basic, all versions, and Modicon M221(all references, all versions prior to firmware V1.10.0.0) which could cause cycle time impact when flooding the M221 ethernet interface while the Ethernet/IP adapter is activated.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-7821](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-7821) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2018-7821.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2018-7821.svg)


## CVE-2018-7790
 An Information Management Error vulnerability exists in Schneider Electric's Modicon M221 product (all references, all versions prior to firmware V1.6.2.0). The vulnerability allows unauthorized users to replay authentication sequences. If an attacker exploits this vulnerability and connects to a Modicon M221, the attacker can upload the original program from the PLC.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-7790](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-7790) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2018-7790.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2018-7790.svg)


## CVE-2018-7789
 An Improper Check for Unusual or Exceptional Conditions vulnerability exists in Schneider Electric's Modicon M221 product (all references, all versions prior to firmware V1.6.2.0). The vulnerability allows unauthorized users to remotely reboot Modicon M221 using crafted programing protocol frames.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-7789](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-7789) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2018-7789.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2018-7789.svg)


## CVE-2018-5730
 MIT krb5 1.6 or later allows an authenticated kadmin with permission to add principals to an LDAP Kerberos database to circumvent a DN containership check by supplying both a &quot;linkdn&quot; and &quot;containerdn&quot; database argument, or by supplying a DN string which is a left extension of a container DN string but is not hierarchically within the container DN.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-5730](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-5730) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2018-5730.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2018-5730.svg)


## CVE-2018-5729
 MIT krb5 1.6 or later allows an authenticated kadmin with permission to add principals to an LDAP Kerberos database to cause a denial of service (NULL pointer dereference) or bypass a DN container check by supplying tagged data that is internal to the database module.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-5729](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2018-5729) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2018-5729.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2018-5729.svg)


## CVE-2017-14121
 The DecodeNumber function in unrarlib.c in unrar 0.0.1 (aka unrar-free or unrar-gpl) suffers from a NULL pointer dereference flaw triggered by a crafted RAR archive. NOTE: this may be the same as one of the several test cases in the CVE-2017-11189 references.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-14121](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-14121) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2017-14121.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2017-14121.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-11189](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-11189) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2017-11189.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2017-11189.svg)


## CVE-2017-12678
 In TagLib 1.11.1, the rebuildAggregateFrames function in id3v2framefactory.cpp has a pointer to cast vulnerability, which allows remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted audio file.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-12678](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-12678) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2017-12678.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2017-12678.svg)


## CVE-2017-12613
 When apr_time_exp*() or apr_os_exp_time*() functions are invoked with an invalid month field value in Apache Portable Runtime APR 1.6.2 and prior, out of bounds memory may be accessed in converting this value to an apr_time_exp_t value, potentially revealing the contents of a different static heap value or resulting in program termination, and may represent an information disclosure or denial of service vulnerability to applications which call these APR functions with unvalidated external input.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35940](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2021-35940) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2021-35940.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2021-35940.svg)


## CVE-2017-11189
 unrarlib.c in unrar-free 0.0.1 might allow remote attackers to cause a denial of service (NULL pointer dereference and application crash), which could be relevant if unrarlib is used as library code for a long-running application. NOTE: one of the several test cases in the references may be the same as what was separately reported as CVE-2017-14121.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-11189](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-11189) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2017-11189.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2017-11189.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-14121](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-14121) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2017-14121.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2017-14121.svg)


## CVE-2017-6030
 A Predictable Value Range from Previous Values issue was discovered in Schneider Electric Modicon PLCs Modicon M221, firmware versions prior to Version 1.5.0.0, Modicon M241, firmware versions prior to Version 4.0.5.11, and Modicon M251, firmware versions prior to Version 4.0.5.11. The affected products generate insufficiently random TCP initial sequence numbers that may allow an attacker to predict the numbers from previous values. This may allow an attacker to spoof or disrupt TCP connections.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-6030](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-6030) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2017-6030.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2017-6030.svg)


## CVE-2017-6028
 An Insufficiently Protected Credentials issue was discovered in Schneider Electric Modicon PLCs Modicon M241, all firmware versions, and Modicon M251, all firmware versions. Log-in credentials are sent over the network with Base64 encoding leaving them susceptible to sniffing. Sniffed credentials could then be used to log into the web application.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-6028](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-6028) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2017-6028.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2017-6028.svg)


## CVE-2017-6026
 A Use of Insufficiently Random Values issue was discovered in Schneider Electric Modicon PLCs Modicon M241, firmware versions prior to Version 4.0.5.11, and Modicon M251, firmware versions prior to Version 4.0.5.11. The session numbers generated by the web application are lacking randomization and are shared between several users. This may allow a current session to be compromised.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-6026](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2017-6026) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2017-6026.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2017-6026.svg)


## CVE-2016-20012
 OpenSSH through 8.7 allows remote attackers, who have a suspicion that a certain combination of username and public key is known to an SSH server, to test whether this suspicion is correct. This occurs because a challenge is sent only when that combination could be valid for a login session.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-20012](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-20012) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2016-20012.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2016-20012.svg)


## CVE-2016-10045
 The isMail transport in PHPMailer before 5.2.20 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code by leveraging improper interaction between the escapeshellarg function and internal escaping performed in the mail function in PHP. NOTE: this vulnerability exists because of an incorrect fix for CVE-2016-10033.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-10045](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-10045) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2016-10045.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2016-10045.svg)


## CVE-2016-10033
 The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \&quot; (backslash double quote) in a crafted Sender property.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-10033](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2016-10033.svg)
- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-10045](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-10045) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2016-10045.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2016-10045.svg)


## CVE-2016-6556
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-6556](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-6556) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2016-6556.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2016-6556.svg)


## CVE-2016-6555
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-6555](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-6555) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2016-6555.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2016-6555.svg)


## CVE-2016-5385
 PHP through 7.0.8 does not attempt to address RFC 3875 section 4.1.18 namespace conflicts and therefore does not protect applications from the presence of untrusted client data in the HTTP_PROXY environment variable, which might allow remote attackers to redirect an application's outbound HTTP traffic to an arbitrary proxy server via a crafted Proxy header in an HTTP request, as demonstrated by (1) an application that makes a getenv('HTTP_PROXY') call or (2) a CGI configuration of PHP, aka an &quot;httpoxy&quot; issue.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-5385](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-5385) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2016-5385.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2016-5385.svg)


## CVE-2016-4529
 An unspecified ActiveX control in Schneider Electric SoMachine HVAC Programming Software for M171/M172 Controllers before 2.1.0 allows remote attackers to execute arbitrary code via unknown vectors, related to the INTERFACESAFE_FOR_UNTRUSTED_CALLER (aka safe for scripting) flag.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-4529](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-4529) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2016-4529.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2016-4529.svg)


## CVE-2016-3720
 XML external entity (XXE) vulnerability in XmlMapper in the Data format extension for Jackson (aka jackson-dataformat-xml) allows attackers to have unspecified impact via unknown vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10172](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2019-10172) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2019-10172.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2019-10172.svg)


## CVE-2016-2568
 pkexec, when used with --user nonpriv, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-2568](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-2568) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2016-2568.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2016-2568.svg)


## CVE-2016-1234
 Stack-based buffer overflow in the glob implementation in GNU C Library (aka glibc) before 2.24, when GLOB_ALTDIRFUNC is used, allows context-dependent attackers to cause a denial of service (crash) via a long name.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-1234](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2016-1234) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2016-1234.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2016-1234.svg)


## CVE-2015-7547
 Multiple stack-based buffer overflows in the (1) send_dg and (2) send_vc functions in the libresolv library in the GNU C Library (aka glibc or libc6) before 2.23 allow remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted DNS response that triggers a call to the getaddrinfo function with the AF_UNSPEC or AF_INET6 address family, related to performing &quot;dual A/AAAA DNS queries&quot; and the libnss_dns.so.2 NSS module.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2015-7547](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2015-7547) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2015-7547.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2015-7547.svg)


## CVE-2015-0235
 Heap-based buffer overflow in the __nss_hostname_digits_dots function in glibc 2.2, and other 2.x versions before 2.18, allows context-dependent attackers to execute arbitrary code via vectors related to the (1) gethostbyname or (2) gethostbyname2 function, aka &quot;GHOST.&quot;

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2015-0235](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2015-0235) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2015-0235.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2015-0235.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/0bfxgh0st/shellshock-scan](https://github.com/0bfxgh0st/shellshock-scan) :  ![starts](https://img.shields.io/github/stars/0bfxgh0st/shellshock-scan.svg) ![forks](https://img.shields.io/github/forks/0bfxgh0st/shellshock-scan.svg)


## CVE-2014-4715
 Yann Collet LZ4 before r119, when used on certain 32-bit platforms that allocate memory beyond 0x80000000, does not properly detect integer overflows, which allows context-dependent attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via a crafted Literal Run, a different vulnerability than CVE-2014-4611.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2014-4611](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2014-4611) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2014-4611.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2014-4611.svg)


## CVE-2014-4611
 Integer overflow in the LZ4 algorithm implementation, as used in Yann Collet LZ4 before r118 and in the lz4_uncompress function in lib/lz4/lz4_decompress.c in the Linux kernel before 3.15.2, on 32-bit platforms might allow context-dependent attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via a crafted Literal Run that would be improperly handled by programs not complying with an API limitation, a different vulnerability than CVE-2014-4715.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2014-4611](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2014-4611) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2014-4611.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2014-4611.svg)


## CVE-2014-3704
 The expandArguments function in the database abstraction API in Drupal core 7.x before 7.32 does not properly construct prepared statements, which allows remote attackers to conduct SQL injection attacks via an array containing crafted keys.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2014-3704](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2014-3704) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2014-3704.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2014-3704.svg)


## CVE-2013-7423
 The send_dg function in resolv/res_send.c in GNU C Library (aka glibc or libc6) before 2.20 does not properly reuse file descriptors, which allows remote attackers to send DNS queries to unintended locations via a large number of requests that trigger a call to the getaddrinfo function.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2013-7423](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2013-7423) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2013-7423.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2013-7423.svg)


## CVE-2013-6276
 ** UNSUPPORTED WHEN ASSIGNED ** QNAP F_VioCard 2312 and F_VioGate 2308 have hardcoded entries in authorized_keys files. NOTE: 1. All active models are not affected. The last affected model was EOL since 2010. 2. The legacy authorization mechanism is no longer adopted in all active models.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2013-6276](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2013-6276) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2013-6276.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2013-6276.svg)


## CVE-2013-2763
 ** DISPUTED ** The Schneider Electric M340 PLC modules allow remote attackers to cause a denial of service (resource consumption) via unspecified vectors.  NOTE: the vendor reportedly disputes this issue because it &quot;could not be duplicated&quot; and &quot;an attacker could not remotely exploit this observed behavior to deny PLC control functions.&quot;

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2013-2763](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2013-2763) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2013-2763.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2013-2763.svg)


## CVE-2013-1914
 Stack-based buffer overflow in the getaddrinfo function in sysdeps/posix/getaddrinfo.c in GNU C Library (aka glibc or libc6) 2.17 and earlier allows remote attackers to cause a denial of service (crash) via a (1) hostname or (2) IP address that triggers a large number of domain conversion results.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2013-1914](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2013-1914) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2013-1914.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2013-1914.svg)


## CVE-2013-0340
 expat 2.1.0 and earlier does not properly handle entities expansion unless an application developer uses the XML_SetEntityDeclHandler function, which allows remote attackers to cause a denial of service (resource consumption), send HTTP requests to intranet servers, or read arbitrary files via a crafted XML document, aka an XML External Entity (XXE) issue.  NOTE: it could be argued that because expat already provides the ability to disable external entity expansion, the responsibility for resolving this issue lies with application developers; according to this argument, this entry should be REJECTed, and each affected application would need its own CVE.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2013-0340](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2013-0340) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2013-0340.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2013-0340.svg)


## CVE-2012-0881
 Apache Xerces2 Java Parser before 2.12.0 allows remote attackers to cause a denial of service (CPU consumption) via a crafted message to an XML service, which triggers hash table collisions.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2012-0881](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2012-0881) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2012-0881.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2012-0881.svg)


## CVE-2010-4756
 The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2010-4756](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2010-4756) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2010-4756.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2010-4756.svg)


## CVE-2010-2632
 Unspecified vulnerability in the FTP Server in Oracle Solaris 8, 9, 10, and 11 Express allows remote attackers to affect availability. NOTE: the previous information was obtained from the January 2011 CPU. Oracle has not commented on claims from a reliable researcher that this is an issue in the glob implementation in libc that allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2010-4756](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2010-4756) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2010-4756.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2010-4756.svg)


## CVE-2008-4796
 The _httpsrequest function (Snoopy/Snoopy.class.php) in Snoopy 1.2.3 and earlier, as used in (1) ampache, (2) libphp-snoopy, (3) mahara, (4) mediamate, (5) opendb, (6) pixelpost, and possibly other products, allows remote attackers to execute arbitrary commands via shell metacharacters in https URLs.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2008-4796](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2008-4796) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2008-4796.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2008-4796.svg)


## CVE-2007-5577
 Multiple cross-site scripting (XSS) vulnerabilities in Joomla! before 1.0.13 (aka Sunglow) allow remote attackers to inject arbitrary web script or HTML via the (1) Title or (2) Section Name form fields in the Section Manager component, or (3) multiple unspecified fields in New Menu Item.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2007-5577](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2007-5577) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2007-5577.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2007-5577.svg)


## CVE-2007-4190
 CRLF injection vulnerability in Joomla! before 1.0.13 (aka Sunglow) allows remote attackers to inject arbitrary HTTP headers and probably conduct HTTP response splitting attacks via CRLF sequences in the url parameter.  NOTE: this can be leveraged for cross-site scripting (XSS) attacks.  NOTE: some of these details are obtained from third party information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2007-4190](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2007-4190) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2007-4190.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2007-4190.svg)


## CVE-2007-4189
 Multiple cross-site scripting (XSS) vulnerabilities in Joomla! before 1.0.13 (aka Sunglow) allow remote attackers to inject arbitrary web script or HTML via unspecified vectors in the (1) com_search, (2) com_content, and (3) mod_login components.  NOTE: some of these details are obtained from third party information.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2007-4189](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2007-4189) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2007-4189.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2007-4189.svg)


## CVE-2007-4188
 Session fixation vulnerability in Joomla! before 1.0.13 (aka Sunglow) allows remote attackers to hijack administrative web sessions via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2007-4188](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2007-4188) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2007-4188.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2007-4188.svg)


## CVE-2006-4472
 Multiple unspecified vulnerabilities in Joomla! before 1.0.11 allow attackers to bypass user authentication via unknown vectors involving the (1) do_pdf command and the (2) emailform com_content task.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2006-4472](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2006-4472) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2006-4472.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2006-4472.svg)


## CVE-2006-4471
 The Admin Upload Image functionality in Joomla! before 1.0.11 allows remote authenticated users to upload files outside of the /images/stories/ directory via unspecified vectors.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2006-4471](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2006-4471) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2006-4471.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2006-4471.svg)


## CVE-2006-4470
 Joomla! before 1.0.11 omits some checks for whether _VALID_MOS is defined, which allows attackers to have an unknown impact, possibly resulting in PHP remote file inclusion.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2006-4470](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2006-4470) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2006-4470.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2006-4470.svg)


## CVE-2006-4469
 Unspecified vulnerability in PEAR.php in Joomla! before 1.0.11 allows remote attackers to perform &quot;remote execution,&quot; related to &quot;Injection Flaws.&quot;

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2006-4469](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2006-4469) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2006-4469.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2006-4469.svg)


## CVE-2006-4468
 Multiple unspecified vulnerabilities in Joomla! before 1.0.11, related to unvalidated input, allow attackers to have an unknown impact via unspecified vectors involving the (1) mosMail, (2) JosIsValidEmail, and (3) josSpoofValue functions; (4) the lack of inclusion of globals.php in administrator/index.php; (5) the Admin User Manager; and (6) the poll module.

- [https://github.com/AKIA27TACKEDYE76PUGU/CVE-2006-4468](https://github.com/AKIA27TACKEDYE76PUGU/CVE-2006-4468) :  ![starts](https://img.shields.io/github/stars/AKIA27TACKEDYE76PUGU/CVE-2006-4468.svg) ![forks](https://img.shields.io/github/forks/AKIA27TACKEDYE76PUGU/CVE-2006-4468.svg)

