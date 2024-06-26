# Update 2024-06-26
## CVE-2024-33113
 D-LINK DIR-845L &lt;=v1.01KRb03 is vulnerable to Information disclosurey via bsc_sms_inbox.php.

- [https://github.com/FaLLenSKiLL1/CVE-2024-33113](https://github.com/FaLLenSKiLL1/CVE-2024-33113) :  ![starts](https://img.shields.io/github/stars/FaLLenSKiLL1/CVE-2024-33113.svg) ![forks](https://img.shields.io/github/forks/FaLLenSKiLL1/CVE-2024-33113.svg)


## CVE-2024-32030
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/huseyinstif/CVE-2024-32030-Nuclei-Template](https://github.com/huseyinstif/CVE-2024-32030-Nuclei-Template) :  ![starts](https://img.shields.io/github/stars/huseyinstif/CVE-2024-32030-Nuclei-Template.svg) ![forks](https://img.shields.io/github/forks/huseyinstif/CVE-2024-32030-Nuclei-Template.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/sreevatsa1997/test_cve_32002](https://github.com/sreevatsa1997/test_cve_32002) :  ![starts](https://img.shields.io/github/stars/sreevatsa1997/test_cve_32002.svg) ![forks](https://img.shields.io/github/forks/sreevatsa1997/test_cve_32002.svg)


## CVE-2024-30956
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/leoCottret/CVE-2024-30956](https://github.com/leoCottret/CVE-2024-30956) :  ![starts](https://img.shields.io/github/stars/leoCottret/CVE-2024-30956.svg) ![forks](https://img.shields.io/github/forks/leoCottret/CVE-2024-30956.svg)


## CVE-2024-30088
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/tykawaii98/CVE-2024-30088](https://github.com/tykawaii98/CVE-2024-30088) :  ![starts](https://img.shields.io/github/stars/tykawaii98/CVE-2024-30088.svg) ![forks](https://img.shields.io/github/forks/tykawaii98/CVE-2024-30088.svg)


## CVE-2024-23828
 Nginx-UI is a web interface to manage Nginx configurations. It is vulnerable to an authenticated arbitrary command execution via CRLF attack when changing the value of test_config_cmd or start_cmd. This vulnerability exists due to an incomplete fix for CVE-2024-22197 and CVE-2024-22198. This vulnerability has been patched in version 2.0.0.beta.12.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2024-4577
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/PhinehasNarh/CVE-2024-4577-Defend](https://github.com/PhinehasNarh/CVE-2024-4577-Defend) :  ![starts](https://img.shields.io/github/stars/PhinehasNarh/CVE-2024-4577-Defend.svg) ![forks](https://img.shields.io/github/forks/PhinehasNarh/CVE-2024-4577-Defend.svg)


## CVE-2023-50029
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/absholi7ly/PHP-Injection-in-M4-PDF-Extensions](https://github.com/absholi7ly/PHP-Injection-in-M4-PDF-Extensions) :  ![starts](https://img.shields.io/github/stars/absholi7ly/PHP-Injection-in-M4-PDF-Extensions.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/PHP-Injection-in-M4-PDF-Extensions.svg)


## CVE-2023-47108
 OpenTelemetry-Go Contrib is a collection of third-party packages for OpenTelemetry-Go. Prior to version 0.46.0, the grpc Unary Server Interceptor out of the box adds labels `net.peer.sock.addr` and `net.peer.sock.port` that have unbound cardinality. It leads to the server's potential memory exhaustion when many malicious requests are sent. An attacker can easily flood the peer address and port for requests. Version 0.46.0 contains a fix for this issue. As a workaround to stop being affected, a view removing the attributes can be used. The other possibility is to disable grpc metrics instrumentation by passing `otelgrpc.WithMeterProvider` option with `noop.NewMeterProvider`.

- [https://github.com/bahe-msft/govuln-CVE-2023-47108](https://github.com/bahe-msft/govuln-CVE-2023-47108) :  ![starts](https://img.shields.io/github/stars/bahe-msft/govuln-CVE-2023-47108.svg) ![forks](https://img.shields.io/github/forks/bahe-msft/govuln-CVE-2023-47108.svg)


## CVE-2023-38941
 django-sspanel v2022.2.2 was discovered to contain a remote command execution (RCE) vulnerability via the component sspanel/admin_view.py -&gt; GoodsCreateView._post.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784](https://github.com/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784) :  ![starts](https://img.shields.io/github/stars/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784.svg) ![forks](https://img.shields.io/github/forks/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784.svg)


## CVE-2023-32784
 In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

- [https://github.com/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784](https://github.com/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784) :  ![starts](https://img.shields.io/github/stars/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784.svg) ![forks](https://img.shields.io/github/forks/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784.svg)


## CVE-2023-30253
 Dolibarr before 17.0.1 allows remote code execution by an authenticated user via an uppercase manipulation: &lt;?PHP instead of &lt;?php in injected data.

- [https://github.com/dollarboysushil/Dolibarr-17.0.0-Exploit-CVE-2023-30253](https://github.com/dollarboysushil/Dolibarr-17.0.0-Exploit-CVE-2023-30253) :  ![starts](https://img.shields.io/github/stars/dollarboysushil/Dolibarr-17.0.0-Exploit-CVE-2023-30253.svg) ![forks](https://img.shields.io/github/forks/dollarboysushil/Dolibarr-17.0.0-Exploit-CVE-2023-30253.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-34527
 &lt;p&gt;A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.&lt;/p&gt; &lt;p&gt;UPDATE July 7, 2021: The security update for Windows Server 2012, Windows Server 2016 and Windows 10, Version 1607 have been released. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. If you are unable to install these updates, see the FAQ and Workaround sections in this CVE for information on how to help protect your system from this vulnerability.&lt;/p&gt; &lt;p&gt;In addition to installing the updates, in order to secure your system, you must confirm that the following registry settings are set to 0 (zero) or are not defined (&lt;strong&gt;Note&lt;/strong&gt;: These registry keys do not exist by default, and therefore are already at the secure setting.), also that your Group Policy setting are correct (see FAQ):&lt;/p&gt; &lt;ul&gt; &lt;li&gt;HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint&lt;/li&gt; &lt;li&gt;NoWarningNoElevationOnInstall = 0 (DWORD) or not defined (default setting)&lt;/li&gt; &lt;li&gt;UpdatePromptSettings = 0 (DWORD) or not defined (default setting)&lt;/li&gt; &lt;/ul&gt; &lt;p&gt;&lt;strong&gt;Having NoWarningNoElevationOnInstall set to 1 makes your system vulnerable by design.&lt;/strong&gt;&lt;/p&gt; &lt;p&gt;UPDATE July 6, 2021: Microsoft has completed the investigation and has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. If you are unable to install these updates, see the FAQ and Workaround sections in this CVE for information on how to help protect your system from this vulnerability. See also &lt;a href=&quot;https://support.microsoft.com/topic/31b91c02-05bc-4ada-a7ea-183b129578a7&quot;&gt;KB5005010: Restricting installation of new printer drivers after applying the July 6, 2021 updates&lt;/a&gt;.&lt;/p&gt; &lt;p&gt;Note that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as &#8220;PrintNightmare&#8221;, documented in CVE-2021-34527.&lt;/p&gt;

- [https://github.com/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784](https://github.com/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784) :  ![starts](https://img.shields.io/github/stars/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784.svg) ![forks](https://img.shields.io/github/forks/Hirusha-N/CVE-2021-34527-CVE-2023-38831-and-CVE-2023-32784.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/TeymurNovruzov/CVE-2019-9053-python3-remastered](https://github.com/TeymurNovruzov/CVE-2019-9053-python3-remastered) :  ![starts](https://img.shields.io/github/stars/TeymurNovruzov/CVE-2019-9053-python3-remastered.svg) ![forks](https://img.shields.io/github/forks/TeymurNovruzov/CVE-2019-9053-python3-remastered.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/Z-0ne/ScanS2-045-Nmap](https://github.com/Z-0ne/ScanS2-045-Nmap) :  ![starts](https://img.shields.io/github/stars/Z-0ne/ScanS2-045-Nmap.svg) ![forks](https://img.shields.io/github/forks/Z-0ne/ScanS2-045-Nmap.svg)

