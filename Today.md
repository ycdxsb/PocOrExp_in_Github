# Update 2023-05-23
## CVE-2023-32784
 In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

- [https://github.com/z-jxy/keepass_dump](https://github.com/z-jxy/keepass_dump) :  ![starts](https://img.shields.io/github/stars/z-jxy/keepass_dump.svg) ![forks](https://img.shields.io/github/forks/z-jxy/keepass_dump.svg)
- [https://github.com/und3sc0n0c1d0/BruteForce-to-KeePass](https://github.com/und3sc0n0c1d0/BruteForce-to-KeePass) :  ![starts](https://img.shields.io/github/stars/und3sc0n0c1d0/BruteForce-to-KeePass.svg) ![forks](https://img.shields.io/github/forks/und3sc0n0c1d0/BruteForce-to-KeePass.svg)


## CVE-2023-25690
 Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow a HTTP Request Smuggling attack. Configurations are affected when mod_proxy is enabled along with some form of RewriteRule or ProxyPassMatch in which a non-specific pattern matches some portion of the user-supplied request-target (URL) data and is then re-inserted into the proxied request-target using variable substitution. For example, something like: RewriteEngine on RewriteRule &quot;^/here/(.*)&quot; &quot;http://example.com:8080/elsewhere?$1&quot;; [P] ProxyPassReverse /here/ http://example.com:8080/ Request splitting/smuggling could result in bypass of access controls in the proxy server, proxying unintended URLs to existing origin servers, and cache poisoning. Users are recommended to update to at least version 2.4.56 of Apache HTTP Server.

- [https://github.com/dhmosfunk/CVE-2023-25690-POC](https://github.com/dhmosfunk/CVE-2023-25690-POC) :  ![starts](https://img.shields.io/github/stars/dhmosfunk/CVE-2023-25690-POC.svg) ![forks](https://img.shields.io/github/forks/dhmosfunk/CVE-2023-25690-POC.svg)


## CVE-2023-24055
 ** DISPUTED ** KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.

- [https://github.com/attackNdefend/CVE-2023-24055](https://github.com/attackNdefend/CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/attackNdefend/CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/attackNdefend/CVE-2023-24055.svg)


## CVE-2023-2822
 A vulnerability was found in Ellucian Ethos Identity up to 5.10.5. It has been classified as problematic. Affected is an unknown function of the file /cas/logout. The manipulation of the argument url leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 5.10.6 is able to address this issue. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-229596.

- [https://github.com/cberman/CVE-2023-2822-demo](https://github.com/cberman/CVE-2023-2822-demo) :  ![starts](https://img.shields.io/github/stars/cberman/CVE-2023-2822-demo.svg) ![forks](https://img.shields.io/github/forks/cberman/CVE-2023-2822-demo.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel&#8217;s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/veritas501/CVE-2023-0386](https://github.com/veritas501/CVE-2023-0386) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2023-0386.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2023-0386.svg)


## CVE-2023-0297
 Code Injection in GitHub repository pyload/pyload prior to 0.5.0b3.dev31.

- [https://github.com/JacobEbben/CVE-2023-0297](https://github.com/JacobEbben/CVE-2023-0297) :  ![starts](https://img.shields.io/github/stars/JacobEbben/CVE-2023-0297.svg) ![forks](https://img.shields.io/github/forks/JacobEbben/CVE-2023-0297.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)
- [https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main](https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.1-main.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.1-main.svg)
- [https://github.com/Chocapikk/CVE-2022-29464](https://github.com/Chocapikk/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2022-29464.svg)
- [https://github.com/Lidong-io/cve-2022-29464](https://github.com/Lidong-io/cve-2022-29464) :  ![starts](https://img.shields.io/github/stars/Lidong-io/cve-2022-29464.svg) ![forks](https://img.shields.io/github/forks/Lidong-io/cve-2022-29464.svg)
- [https://github.com/h3v0x/CVE-2022-29464](https://github.com/h3v0x/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/h3v0x/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/h3v0x/CVE-2022-29464.svg)
- [https://github.com/LinJacck/CVE-2022-29464](https://github.com/LinJacck/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/LinJacck/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/LinJacck/CVE-2022-29464.svg)
- [https://github.com/jimidk/Better-CVE-2022-29464](https://github.com/jimidk/Better-CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/jimidk/Better-CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/jimidk/Better-CVE-2022-29464.svg)


## CVE-2022-3910
 Use After Free vulnerability in Linux Kernel allows Privilege Escalation. An improper Update of Reference Count in io_uring leads to Use-After-Free and Local Privilege Escalation. When io_msg_ring was invoked with a fixed file, it called io_fput_file() which improperly decreased its reference count (leading to Use-After-Free and Local Privilege Escalation). Fixed files are permanently registered to the ring, and should not be put separately. We recommend upgrading past commit https://github.com/torvalds/linux/commit/fc7222c3a9f56271fba02aabbfbae999042f1679 https://github.com/torvalds/linux/commit/fc7222c3a9f56271fba02aabbfbae999042f1679

- [https://github.com/veritas501/CVE-2022-3910](https://github.com/veritas501/CVE-2022-3910) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2022-3910.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2022-3910.svg)


## CVE-2022-2588
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/veritas501/CVE-2022-2588](https://github.com/veritas501/CVE-2022-2588) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2022-2588.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2022-2588.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)


## CVE-2021-4154
 A use-after-free flaw was found in cgroup1_parse_param in kernel/cgroup/cgroup-v1.c in the Linux kernel's cgroup v1 parser. A local attacker with a user privilege could cause a privilege escalation by exploiting the fsconfig syscall parameter leading to a container breakout and a denial of service on the system.

- [https://github.com/veritas501/CVE-2021-4154](https://github.com/veritas501/CVE-2021-4154) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2021-4154.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2021-4154.svg)


## CVE-2019-25137
 Umbraco CMS 4.11.8 through 7.15.10, and 7.12.4, allows Remote Code Execution by authenticated administrators via msxsl:script in an xsltSelection to developer/Xslt/xsltVisualize.aspx.

- [https://github.com/Ickarah/CVE-2019-25137-Version-Research](https://github.com/Ickarah/CVE-2019-25137-Version-Research) :  ![starts](https://img.shields.io/github/stars/Ickarah/CVE-2019-25137-Version-Research.svg) ![forks](https://img.shields.io/github/forks/Ickarah/CVE-2019-25137-Version-Research.svg)


## CVE-2019-1458
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.

- [https://github.com/rip1s/CVE-2019-1458](https://github.com/rip1s/CVE-2019-1458) :  ![starts](https://img.shields.io/github/stars/rip1s/CVE-2019-1458.svg) ![forks](https://img.shields.io/github/forks/rip1s/CVE-2019-1458.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/m-kis/ssh-enum-cve2018-15473](https://github.com/m-kis/ssh-enum-cve2018-15473) :  ![starts](https://img.shields.io/github/stars/m-kis/ssh-enum-cve2018-15473.svg) ![forks](https://img.shields.io/github/forks/m-kis/ssh-enum-cve2018-15473.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/drone789/CVE-2012-1823](https://github.com/drone789/CVE-2012-1823) :  ![starts](https://img.shields.io/github/stars/drone789/CVE-2012-1823.svg) ![forks](https://img.shields.io/github/forks/drone789/CVE-2012-1823.svg)


## CVE-2007-5962
 Memory leak in a certain Red Hat patch, applied to vsftpd 2.0.5 on Red Hat Enterprise Linux (RHEL) 5 and Fedora 6 through 8, and on Foresight Linux and rPath appliances, allows remote attackers to cause a denial of service (memory consumption) via a large number of CWD commands, as demonstrated by an attack on a daemon with the deny_file configuration option.

- [https://github.com/antogit-sys/CVE-2007-5962](https://github.com/antogit-sys/CVE-2007-5962) :  ![starts](https://img.shields.io/github/stars/antogit-sys/CVE-2007-5962.svg) ![forks](https://img.shields.io/github/forks/antogit-sys/CVE-2007-5962.svg)

