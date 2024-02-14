# Update 2024-02-14
## CVE-2024-22567
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/labesterOct/CVE-2024-22567](https://github.com/labesterOct/CVE-2024-22567) :  ![starts](https://img.shields.io/github/stars/labesterOct/CVE-2024-22567.svg) ![forks](https://img.shields.io/github/forks/labesterOct/CVE-2024-22567.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2021-34527
 &lt;p&gt;A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.&lt;/p&gt; &lt;p&gt;UPDATE July 7, 2021: The security update for Windows Server 2012, Windows Server 2016 and Windows 10, Version 1607 have been released. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. If you are unable to install these updates, see the FAQ and Workaround sections in this CVE for information on how to help protect your system from this vulnerability.&lt;/p&gt; &lt;p&gt;In addition to installing the updates, in order to secure your system, you must confirm that the following registry settings are set to 0 (zero) or are not defined (&lt;strong&gt;Note&lt;/strong&gt;: These registry keys do not exist by default, and therefore are already at the secure setting.), also that your Group Policy setting are correct (see FAQ):&lt;/p&gt; &lt;ul&gt; &lt;li&gt;HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint&lt;/li&gt; &lt;li&gt;NoWarningNoElevationOnInstall = 0 (DWORD) or not defined (default setting)&lt;/li&gt; &lt;li&gt;UpdatePromptSettings = 0 (DWORD) or not defined (default setting)&lt;/li&gt; &lt;/ul&gt; &lt;p&gt;&lt;strong&gt;Having NoWarningNoElevationOnInstall set to 1 makes your system vulnerable by design.&lt;/strong&gt;&lt;/p&gt; &lt;p&gt;UPDATE July 6, 2021: Microsoft has completed the investigation and has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. If you are unable to install these updates, see the FAQ and Workaround sections in this CVE for information on how to help protect your system from this vulnerability. See also &lt;a href=&quot;https://support.microsoft.com/topic/31b91c02-05bc-4ada-a7ea-183b129578a7&quot;&gt;KB5005010: Restricting installation of new printer drivers after applying the July 6, 2021 updates&lt;/a&gt;.&lt;/p&gt; &lt;p&gt;Note that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as &#8220;PrintNightmare&#8221;, documented in CVE-2021-34527.&lt;/p&gt;

- [https://github.com/whoami-chmod777/CVE-2021-1675-CVE-2021-34527](https://github.com/whoami-chmod777/CVE-2021-1675-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/whoami-chmod777/CVE-2021-1675-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/whoami-chmod777/CVE-2021-1675-CVE-2021-34527.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/azazelm3dj3d/CVE-2021-4034](https://github.com/azazelm3dj3d/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/azazelm3dj3d/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/azazelm3dj3d/CVE-2021-4034.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/SamTruss/LMU-CVE-2021-3156](https://github.com/SamTruss/LMU-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/SamTruss/LMU-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/SamTruss/LMU-CVE-2021-3156.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/whoami-chmod777/CVE-2021-1675-CVE-2021-34527](https://github.com/whoami-chmod777/CVE-2021-1675-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/whoami-chmod777/CVE-2021-1675-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/whoami-chmod777/CVE-2021-1675-CVE-2021-34527.svg)
- [https://github.com/whoami-chmod777/CVE-2021-1675---PrintNightmare-LPE-PowerShell-](https://github.com/whoami-chmod777/CVE-2021-1675---PrintNightmare-LPE-PowerShell-) :  ![starts](https://img.shields.io/github/stars/whoami-chmod777/CVE-2021-1675---PrintNightmare-LPE-PowerShell-.svg) ![forks](https://img.shields.io/github/forks/whoami-chmod777/CVE-2021-1675---PrintNightmare-LPE-PowerShell-.svg)


## CVE-2017-0089
 Uniscribe in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, and Windows 7 SP1 allows remote attackers to execute arbitrary code via a crafted web site, aka &quot;Uniscribe Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0072, CVE-2017-0083, CVE-2017-0084, CVE-2017-0086, CVE-2017-0087, CVE-2017-0088, and CVE-2017-0090.

- [https://github.com/rainhawk13/Added-Pentest-Ground-to-vulnerable-websites-for-training](https://github.com/rainhawk13/Added-Pentest-Ground-to-vulnerable-websites-for-training) :  ![starts](https://img.shields.io/github/stars/rainhawk13/Added-Pentest-Ground-to-vulnerable-websites-for-training.svg) ![forks](https://img.shields.io/github/forks/rainhawk13/Added-Pentest-Ground-to-vulnerable-websites-for-training.svg)

