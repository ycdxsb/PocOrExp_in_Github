# Update 2023-03-26
## CVE-2023-28432
 Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/acheiii/CVE-2023-28432](https://github.com/acheiii/CVE-2023-28432) :  ![starts](https://img.shields.io/github/stars/acheiii/CVE-2023-28432.svg) ![forks](https://img.shields.io/github/forks/acheiii/CVE-2023-28432.svg)
- [https://github.com/MzzdToT/CVE-2023-28432](https://github.com/MzzdToT/CVE-2023-28432) :  ![starts](https://img.shields.io/github/stars/MzzdToT/CVE-2023-28432.svg) ![forks](https://img.shields.io/github/forks/MzzdToT/CVE-2023-28432.svg)


## CVE-2023-25610
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/PSIRT-REPO/CVE-2023-25610](https://github.com/PSIRT-REPO/CVE-2023-25610) :  ![starts](https://img.shields.io/github/stars/PSIRT-REPO/CVE-2023-25610.svg) ![forks](https://img.shields.io/github/forks/PSIRT-REPO/CVE-2023-25610.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/Acceis/exploit-CVE-2023-23752](https://github.com/Acceis/exploit-CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/Acceis/exploit-CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/Acceis/exploit-CVE-2023-23752.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/madelynadams9/CVE-2023-23397-Report](https://github.com/madelynadams9/CVE-2023-23397-Report) :  ![starts](https://img.shields.io/github/stars/madelynadams9/CVE-2023-23397-Report.svg) ![forks](https://img.shields.io/github/forks/madelynadams9/CVE-2023-23397-Report.svg)
- [https://github.com/Zeppperoni/CVE-2023-23397-Patch](https://github.com/Zeppperoni/CVE-2023-23397-Patch) :  ![starts](https://img.shields.io/github/stars/Zeppperoni/CVE-2023-23397-Patch.svg) ![forks](https://img.shields.io/github/forks/Zeppperoni/CVE-2023-23397-Patch.svg)


## CVE-2023-21716
 Microsoft Word Remote Code Execution Vulnerability

- [https://github.com/hv0l/CVE-2023-21716_exploit](https://github.com/hv0l/CVE-2023-21716_exploit) :  ![starts](https://img.shields.io/github/stars/hv0l/CVE-2023-21716_exploit.svg) ![forks](https://img.shields.io/github/forks/hv0l/CVE-2023-21716_exploit.svg)


## CVE-2023-20860
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/limo520/CVE-2023-20860](https://github.com/limo520/CVE-2023-20860) :  ![starts](https://img.shields.io/github/stars/limo520/CVE-2023-20860.svg) ![forks](https://img.shields.io/github/forks/limo520/CVE-2023-20860.svg)


## CVE-2022-47529
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/hyp3rlinx/CVE-2022-47529](https://github.com/hyp3rlinx/CVE-2022-47529) :  ![starts](https://img.shields.io/github/stars/hyp3rlinx/CVE-2022-47529.svg) ![forks](https://img.shields.io/github/forks/hyp3rlinx/CVE-2022-47529.svg)


## CVE-2022-45934
 An issue was discovered in the Linux kernel through 6.0.10. l2cap_config_req in net/bluetooth/l2cap_core.c has an integer wraparound via L2CAP_CONF_REQ packets.

- [https://github.com/Satheesh575555/linux-4.1.15_CVE-2022-45934](https://github.com/Satheesh575555/linux-4.1.15_CVE-2022-45934) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/linux-4.1.15_CVE-2022-45934.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/linux-4.1.15_CVE-2022-45934.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/rodrigosilvaluz/CVE_2022_0847](https://github.com/rodrigosilvaluz/CVE_2022_0847) :  ![starts](https://img.shields.io/github/stars/rodrigosilvaluz/CVE_2022_0847.svg) ![forks](https://img.shields.io/github/forks/rodrigosilvaluz/CVE_2022_0847.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/nobelh/CVE-2021-4034](https://github.com/nobelh/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/nobelh/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/nobelh/CVE-2021-4034.svg)


## CVE-2019-13764
 Type confusion in JavaScript in Google Chrome prior to 79.0.3945.79 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/HaboobLab/CVE-2019-13764](https://github.com/HaboobLab/CVE-2019-13764) :  ![starts](https://img.shields.io/github/stars/HaboobLab/CVE-2019-13764.svg) ![forks](https://img.shields.io/github/forks/HaboobLab/CVE-2019-13764.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/Brandaoo/CVE-2014-6271](https://github.com/Brandaoo/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/Brandaoo/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/Brandaoo/CVE-2014-6271.svg)

