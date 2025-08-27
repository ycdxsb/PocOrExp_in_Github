# Update 2025-08-27
## CVE-2025-55575
 SQL Injection vulnerability in SMM Panel 3.1 allowing remote attackers to gain sensitive information via a crafted HTTP request with action=service_detail.

- [https://github.com/Aether-0/CVE-2025-55575](https://github.com/Aether-0/CVE-2025-55575) :  ![starts](https://img.shields.io/github/stars/Aether-0/CVE-2025-55575.svg) ![forks](https://img.shields.io/github/forks/Aether-0/CVE-2025-55575.svg)


## CVE-2025-50383
 alextselegidis Easy!Appointments v1.5.1 was discovered to contain a SQL injection vulnerability via the order_by parameter.

- [https://github.com/Abdullah4eb/CVE-2025-50383](https://github.com/Abdullah4eb/CVE-2025-50383) :  ![starts](https://img.shields.io/github/stars/Abdullah4eb/CVE-2025-50383.svg) ![forks](https://img.shields.io/github/forks/Abdullah4eb/CVE-2025-50383.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/eliox01/CVE-2025-48384](https://github.com/eliox01/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/eliox01/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/eliox01/CVE-2025-48384.svg)


## CVE-2025-43960
 Adminer 4.8.1, when using Monolog for logging, allows a Denial of Service (memory consumption) via a crafted serialized payload (e.g., using s:1000000000), leading to a PHP Object Injection issue. Remote, unauthenticated attackers can trigger this by sending a malicious serialized object, which forces excessive memory usage, rendering Adminer’s interface unresponsive and causing a server-level DoS. While the server may recover after several minutes, multiple simultaneous requests can cause a complete crash requiring manual intervention.

- [https://github.com/far00t01/CVE-2025-43960](https://github.com/far00t01/CVE-2025-43960) :  ![starts](https://img.shields.io/github/stars/far00t01/CVE-2025-43960.svg) ![forks](https://img.shields.io/github/forks/far00t01/CVE-2025-43960.svg)


## CVE-2025-38001
[5] https://lore.kernel.org/netdev/8DuRWwfqjoRDLDmBMlIfbrsZg9Gx50DHJc1ilxsEBNe2D6NMoigR_eIRIG0LOjMc3r10nUUZtArXx4oZBIdUfZQrwjcQhdinnMis_0G7VEk=@willsroot.io/T/#u

- [https://github.com/khoatran107/cve-2025-38001](https://github.com/khoatran107/cve-2025-38001) :  ![starts](https://img.shields.io/github/stars/khoatran107/cve-2025-38001.svg) ![forks](https://img.shields.io/github/forks/khoatran107/cve-2025-38001.svg)


## CVE-2025-34030
 An OS command injection vulnerability exists in sar2html version 3.2.2 and prior via the plot parameter in index.php. The application fails to sanitize user-supplied input before using it in a system-level context. Remote, unauthenticated attackers can inject shell commands by appending them to the plot parameter (e.g., ?plot=;id) in a crafted GET request. The output of the command is displayed in the application's interface after interacting with the host selection UI. Successful exploitation leads to arbitrary command execution on the underlying system.

- [https://github.com/HackerTyperAbuser/CVE-2025-34030-PoC](https://github.com/HackerTyperAbuser/CVE-2025-34030-PoC) :  ![starts](https://img.shields.io/github/stars/HackerTyperAbuser/CVE-2025-34030-PoC.svg) ![forks](https://img.shields.io/github/forks/HackerTyperAbuser/CVE-2025-34030-PoC.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/zenzue/CVE-2025-9074](https://github.com/zenzue/CVE-2025-9074) :  ![starts](https://img.shields.io/github/stars/zenzue/CVE-2025-9074.svg) ![forks](https://img.shields.io/github/forks/zenzue/CVE-2025-9074.svg)


## CVE-2025-5419
 Out of bounds read and write in V8 in Google Chrome prior to 137.0.7151.68 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/mistymntncop/CVE-2025-5419](https://github.com/mistymntncop/CVE-2025-5419) :  ![starts](https://img.shields.io/github/stars/mistymntncop/CVE-2025-5419.svg) ![forks](https://img.shields.io/github/forks/mistymntncop/CVE-2025-5419.svg)


## CVE-2024-32019
 Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/x0da6h/POC-for-CVE-2024-32019](https://github.com/x0da6h/POC-for-CVE-2024-32019) :  ![starts](https://img.shields.io/github/stars/x0da6h/POC-for-CVE-2024-32019.svg) ![forks](https://img.shields.io/github/forks/x0da6h/POC-for-CVE-2024-32019.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/a1ex-var1amov/ctf-cve-2024-4577](https://github.com/a1ex-var1amov/ctf-cve-2024-4577) :  ![starts](https://img.shields.io/github/stars/a1ex-var1amov/ctf-cve-2024-4577.svg) ![forks](https://img.shields.io/github/forks/a1ex-var1amov/ctf-cve-2024-4577.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/1337rokudenashi/Odoo_PDFjs_CVE-2024-4367.pdf](https://github.com/1337rokudenashi/Odoo_PDFjs_CVE-2024-4367.pdf) :  ![starts](https://img.shields.io/github/stars/1337rokudenashi/Odoo_PDFjs_CVE-2024-4367.pdf.svg) ![forks](https://img.shields.io/github/forks/1337rokudenashi/Odoo_PDFjs_CVE-2024-4367.pdf.svg)


## CVE-2024-0762
SecureCore™ for Intel Meteor Lake: from 4.5.1.1 before 4.5.1.15.

- [https://github.com/abandon1337/CVE-2024-0762](https://github.com/abandon1337/CVE-2024-0762) :  ![starts](https://img.shields.io/github/stars/abandon1337/CVE-2024-0762.svg) ![forks](https://img.shields.io/github/forks/abandon1337/CVE-2024-0762.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/lainonz/CVE-2023-23752](https://github.com/lainonz/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/lainonz/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/lainonz/CVE-2023-23752.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability

- [https://github.com/radoi-teodor/CVE-2023-21768](https://github.com/radoi-teodor/CVE-2023-21768) :  ![starts](https://img.shields.io/github/stars/radoi-teodor/CVE-2023-21768.svg) ![forks](https://img.shields.io/github/forks/radoi-teodor/CVE-2023-21768.svg)


## CVE-2023-6275
 A vulnerability was found in TOTVS Fluig Platform 1.6.x/1.7.x/1.8.0/1.8.1. It has been rated as problematic. Affected by this issue is some unknown functionality of the file /mobileredir/openApp.jsp of the component mobileredir. The manipulation of the argument redirectUrl/user with the input "scriptalert(document.domain)/script leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 1.7.1-231128, 1.8.0-231127 and 1.8.1-231127 is able to address this issue. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-246104.

- [https://github.com/LelioCosta/FLUIG-Vulnerabilidade-CVE-2023-6275](https://github.com/LelioCosta/FLUIG-Vulnerabilidade-CVE-2023-6275) :  ![starts](https://img.shields.io/github/stars/LelioCosta/FLUIG-Vulnerabilidade-CVE-2023-6275.svg) ![forks](https://img.shields.io/github/forks/LelioCosta/FLUIG-Vulnerabilidade-CVE-2023-6275.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/ayushx007/CVE-2022-0847-dirty-pipe-checker](https://github.com/ayushx007/CVE-2022-0847-dirty-pipe-checker) :  ![starts](https://img.shields.io/github/stars/ayushx007/CVE-2022-0847-dirty-pipe-checker.svg) ![forks](https://img.shields.io/github/forks/ayushx007/CVE-2022-0847-dirty-pipe-checker.svg)


## CVE-2021-4191
 An issue has been discovered in GitLab CE/EE affecting versions 13.0 to 14.6.5, 14.7 to 14.7.4, and 14.8 to 14.8.2. Private GitLab instances with restricted sign-ups may be vulnerable to user enumeration to unauthenticated users through the GraphQL API.

- [https://github.com/K3ysTr0K3R/CVE-2021-4191-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-4191-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-4191-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-4191-EXPLOIT.svg)
- [https://github.com/Adelittle/CVE-2021-4191_Exploits](https://github.com/Adelittle/CVE-2021-4191_Exploits) :  ![starts](https://img.shields.io/github/stars/Adelittle/CVE-2021-4191_Exploits.svg) ![forks](https://img.shields.io/github/forks/Adelittle/CVE-2021-4191_Exploits.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/HuzaifaTariqAfzalKhan/CVE-Exploit-Research-Development-ITSOLERA](https://github.com/HuzaifaTariqAfzalKhan/CVE-Exploit-Research-Development-ITSOLERA) :  ![starts](https://img.shields.io/github/stars/HuzaifaTariqAfzalKhan/CVE-Exploit-Research-Development-ITSOLERA.svg) ![forks](https://img.shields.io/github/forks/HuzaifaTariqAfzalKhan/CVE-Exploit-Research-Development-ITSOLERA.svg)


## CVE-2019-6693
 Use of a hard-coded cryptographic key to cipher sensitive data in FortiOS configuration backup file may allow an attacker with access to the backup file to decipher the sensitive data, via knowledge of the hard-coded key. The aforementioned sensitive data includes users' passwords (except the administrator's password), private keys' passphrases and High Availability password (when set).

- [https://github.com/Real4XoR/CVE-2019-6693](https://github.com/Real4XoR/CVE-2019-6693) :  ![starts](https://img.shields.io/github/stars/Real4XoR/CVE-2019-6693.svg) ![forks](https://img.shields.io/github/forks/Real4XoR/CVE-2019-6693.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka "Microsoft Office Memory Corruption Vulnerability". This CVE ID is unique from CVE-2017-11884.

- [https://github.com/futureFfff/CVE-2017](https://github.com/futureFfff/CVE-2017) :  ![starts](https://img.shields.io/github/stars/futureFfff/CVE-2017.svg) ![forks](https://img.shields.io/github/forks/futureFfff/CVE-2017.svg)


## CVE-2017-8481
 The kernel in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows an authenticated attacker to obtain information via a specially crafted application. aka "Windows Kernel Information Disclosure Vulnerability," a different vulnerability than CVE-2017-8491, CVE-2017-8490, CVE-2017-8489, CVE-2017-8488, CVE-2017-8485, CVE-2017-8483, CVE-2017-8482, CVE-2017-8480, CVE-2017-8479, CVE-2017-8478, CVE-2017-8476, CVE-2017-8474, CVE-2017-8469, CVE-2017-8462, CVE-2017-0300, CVE-2017-0299, and CVE-2017-0297.

- [https://github.com/TamatahYT/CVE-2017-8481](https://github.com/TamatahYT/CVE-2017-8481) :  ![starts](https://img.shields.io/github/stars/TamatahYT/CVE-2017-8481.svg) ![forks](https://img.shields.io/github/forks/TamatahYT/CVE-2017-8481.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/iampetru/PoC-CVE-2017-5638](https://github.com/iampetru/PoC-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/iampetru/PoC-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/iampetru/PoC-CVE-2017-5638.svg)

