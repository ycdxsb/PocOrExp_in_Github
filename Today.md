# Update 2022-08-06
## CVE-2022-34970
 Crow before v1.0+4 was discovered to contain a buffer overflow via the function qs_parse at query_string.h. This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted input.

- [https://github.com/0xhebi/CVE-2022-34970](https://github.com/0xhebi/CVE-2022-34970) :  ![starts](https://img.shields.io/github/stars/0xhebi/CVE-2022-34970.svg) ![forks](https://img.shields.io/github/forks/0xhebi/CVE-2022-34970.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/jeffymcjeffface/five-nights-at-follina-s](https://github.com/jeffymcjeffface/five-nights-at-follina-s) :  ![starts](https://img.shields.io/github/stars/jeffymcjeffface/five-nights-at-follina-s.svg) ![forks](https://img.shields.io/github/forks/jeffymcjeffface/five-nights-at-follina-s.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/PentesterSoham/CVE-2021-4034-exploit](https://github.com/PentesterSoham/CVE-2021-4034-exploit) :  ![starts](https://img.shields.io/github/stars/PentesterSoham/CVE-2021-4034-exploit.svg) ![forks](https://img.shields.io/github/forks/PentesterSoham/CVE-2021-4034-exploit.svg)


## CVE-2019-10778
 devcert-sanscache before 0.4.7 allows remote attackers to execute arbitrary code or cause a Command Injection via the exec function. The variable `commonName` controlled by user input is used as part of the `exec` function without any sanitization.

- [https://github.com/ossf-cve-benchmark/CVE-2019-10778](https://github.com/ossf-cve-benchmark/CVE-2019-10778) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2019-10778.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2019-10778.svg)


## CVE-2019-1477
 An elevation of privilege vulnerability exists when the Windows Printer Service improperly validates file paths while loading printer drivers, aka 'Windows Printer Service Elevation of Privilege Vulnerability'.

- [https://github.com/2yong1/CVE-2019-1477](https://github.com/2yong1/CVE-2019-1477) :  ![starts](https://img.shields.io/github/stars/2yong1/CVE-2019-1477.svg) ![forks](https://img.shields.io/github/forks/2yong1/CVE-2019-1477.svg)


## CVE-2019-1385
 An elevation of privilege vulnerability exists when the Windows AppX Deployment Extensions improperly performs privilege management, resulting in access to system files.To exploit this vulnerability, an authenticated attacker would need to run a specially crafted application to elevate privileges.The security update addresses the vulnerability by correcting how AppX Deployment Extensions manages privileges., aka 'Windows AppX Deployment Extensions Elevation of Privilege Vulnerability'.

- [https://github.com/klinix5/CVE-2019-1385](https://github.com/klinix5/CVE-2019-1385) :  ![starts](https://img.shields.io/github/stars/klinix5/CVE-2019-1385.svg) ![forks](https://img.shields.io/github/forks/klinix5/CVE-2019-1385.svg)
- [https://github.com/0x413x4/CVE-2019-1385](https://github.com/0x413x4/CVE-2019-1385) :  ![starts](https://img.shields.io/github/stars/0x413x4/CVE-2019-1385.svg) ![forks](https://img.shields.io/github/forks/0x413x4/CVE-2019-1385.svg)


## CVE-2019-1351
 A tampering vulnerability exists when Git for Visual Studio improperly handles virtual drive paths, aka 'Git for Visual Studio Tampering Vulnerability'.

- [https://github.com/JonasDL/PruebaCVE20191351](https://github.com/JonasDL/PruebaCVE20191351) :  ![starts](https://img.shields.io/github/stars/JonasDL/PruebaCVE20191351.svg) ![forks](https://img.shields.io/github/forks/JonasDL/PruebaCVE20191351.svg)


## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka &quot;Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API.&quot;

- [https://github.com/bhdresh/CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/bhdresh/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/bhdresh/CVE-2017-0199.svg)
- [https://github.com/haibara3839/CVE-2017-0199-master](https://github.com/haibara3839/CVE-2017-0199-master) :  ![starts](https://img.shields.io/github/stars/haibara3839/CVE-2017-0199-master.svg) ![forks](https://img.shields.io/github/forks/haibara3839/CVE-2017-0199-master.svg)
- [https://github.com/NotAwful/CVE-2017-0199-Fix](https://github.com/NotAwful/CVE-2017-0199-Fix) :  ![starts](https://img.shields.io/github/stars/NotAwful/CVE-2017-0199-Fix.svg) ![forks](https://img.shields.io/github/forks/NotAwful/CVE-2017-0199-Fix.svg)
- [https://github.com/SyFi/cve-2017-0199](https://github.com/SyFi/cve-2017-0199) :  ![starts](https://img.shields.io/github/stars/SyFi/cve-2017-0199.svg) ![forks](https://img.shields.io/github/forks/SyFi/cve-2017-0199.svg)
- [https://github.com/Exploit-install/CVE-2017-0199](https://github.com/Exploit-install/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/Exploit-install/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/Exploit-install/CVE-2017-0199.svg)
- [https://github.com/SwordSheath/CVE-2017-8570](https://github.com/SwordSheath/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/SwordSheath/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/SwordSheath/CVE-2017-8570.svg)
- [https://github.com/n1shant-sinha/CVE-2017-0199](https://github.com/n1shant-sinha/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/n1shant-sinha/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/n1shant-sinha/CVE-2017-0199.svg)
- [https://github.com/herbiezimmerman/2017-11-17-Maldoc-Using-CVE-2017-0199](https://github.com/herbiezimmerman/2017-11-17-Maldoc-Using-CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/herbiezimmerman/2017-11-17-Maldoc-Using-CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/herbiezimmerman/2017-11-17-Maldoc-Using-CVE-2017-0199.svg)
- [https://github.com/kn0wm4d/htattack](https://github.com/kn0wm4d/htattack) :  ![starts](https://img.shields.io/github/stars/kn0wm4d/htattack.svg) ![forks](https://img.shields.io/github/forks/kn0wm4d/htattack.svg)
- [https://github.com/nicpenning/RTF-Cleaner](https://github.com/nicpenning/RTF-Cleaner) :  ![starts](https://img.shields.io/github/stars/nicpenning/RTF-Cleaner.svg) ![forks](https://img.shields.io/github/forks/nicpenning/RTF-Cleaner.svg)
- [https://github.com/jacobsoo/RTF-Cleaner](https://github.com/jacobsoo/RTF-Cleaner) :  ![starts](https://img.shields.io/github/stars/jacobsoo/RTF-Cleaner.svg) ![forks](https://img.shields.io/github/forks/jacobsoo/RTF-Cleaner.svg)
- [https://github.com/sUbc0ol/Microsoft-Word-CVE-2017-0199-](https://github.com/sUbc0ol/Microsoft-Word-CVE-2017-0199-) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/Microsoft-Word-CVE-2017-0199-.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/Microsoft-Word-CVE-2017-0199-.svg)
- [https://github.com/mzakyz666/PoC-CVE-2017-0199](https://github.com/mzakyz666/PoC-CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/mzakyz666/PoC-CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/mzakyz666/PoC-CVE-2017-0199.svg)
- [https://github.com/Nacromencer/cve2017-0199-in-python](https://github.com/Nacromencer/cve2017-0199-in-python) :  ![starts](https://img.shields.io/github/stars/Nacromencer/cve2017-0199-in-python.svg) ![forks](https://img.shields.io/github/forks/Nacromencer/cve2017-0199-in-python.svg)
- [https://github.com/joke998/Cve-2017-0199-](https://github.com/joke998/Cve-2017-0199-) :  ![starts](https://img.shields.io/github/stars/joke998/Cve-2017-0199-.svg) ![forks](https://img.shields.io/github/forks/joke998/Cve-2017-0199-.svg)
- [https://github.com/viethdgit/CVE-2017-0199](https://github.com/viethdgit/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/viethdgit/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/viethdgit/CVE-2017-0199.svg)
- [https://github.com/Phantomlancer123/CVE-2017-0199](https://github.com/Phantomlancer123/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/Phantomlancer123/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/Phantomlancer123/CVE-2017-0199.svg)
- [https://github.com/BRAINIAC22/CVE-2017-0199](https://github.com/BRAINIAC22/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/BRAINIAC22/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/BRAINIAC22/CVE-2017-0199.svg)
- [https://github.com/joke998/Cve-2017-0199](https://github.com/joke998/Cve-2017-0199) :  ![starts](https://img.shields.io/github/stars/joke998/Cve-2017-0199.svg) ![forks](https://img.shields.io/github/forks/joke998/Cve-2017-0199.svg)
- [https://github.com/likescam/CVE-2017-0199](https://github.com/likescam/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-0199.svg)
- [https://github.com/ryhanson/CVE-2017-0199](https://github.com/ryhanson/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/ryhanson/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/ryhanson/CVE-2017-0199.svg)
- [https://github.com/Winter3un/cve_2017_0199](https://github.com/Winter3un/cve_2017_0199) :  ![starts](https://img.shields.io/github/stars/Winter3un/cve_2017_0199.svg) ![forks](https://img.shields.io/github/forks/Winter3un/cve_2017_0199.svg)
- [https://github.com/stealth-ronin/CVE-2017-0199-PY-KIT](https://github.com/stealth-ronin/CVE-2017-0199-PY-KIT) :  ![starts](https://img.shields.io/github/stars/stealth-ronin/CVE-2017-0199-PY-KIT.svg) ![forks](https://img.shields.io/github/forks/stealth-ronin/CVE-2017-0199-PY-KIT.svg)


## CVE-2016-10033
 The mailSend function in the isMail transport in PHPMailer before 5.2.18 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code via a \&quot; (backslash double quote) in a crafted Sender property.

- [https://github.com/zeeshanbhattined/exploit-CVE-2016-10033](https://github.com/zeeshanbhattined/exploit-CVE-2016-10033) :  ![starts](https://img.shields.io/github/stars/zeeshanbhattined/exploit-CVE-2016-10033.svg) ![forks](https://img.shields.io/github/forks/zeeshanbhattined/exploit-CVE-2016-10033.svg)


## CVE-2010-3437
 Integer signedness error in the pkt_find_dev_from_minor function in drivers/block/pktcdvd.c in the Linux kernel before 2.6.36-rc6 allows local users to obtain sensitive information from kernel memory or cause a denial of service (invalid pointer dereference and system crash) via a crafted index value in a PKT_CTRL_CMD_STATUS ioctl call.

- [https://github.com/huang-emily/CVE-2010-3437](https://github.com/huang-emily/CVE-2010-3437) :  ![starts](https://img.shields.io/github/stars/huang-emily/CVE-2010-3437.svg) ![forks](https://img.shields.io/github/forks/huang-emily/CVE-2010-3437.svg)

