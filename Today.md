# Update 2024-07-30
## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/daemon-reconfig/CVE-2024-32002](https://github.com/daemon-reconfig/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/daemon-reconfig/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/daemon-reconfig/CVE-2024-32002.svg)
- [https://github.com/HexDoesRandomShit/CVE-2024-32002](https://github.com/HexDoesRandomShit/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/HexDoesRandomShit/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/HexDoesRandomShit/CVE-2024-32002.svg)


## CVE-2024-5217
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/NoTsPepino/CVE-2024-4879-CVE-2024-5217-ServiceNow-RCE-Scanning](https://github.com/NoTsPepino/CVE-2024-4879-CVE-2024-5217-ServiceNow-RCE-Scanning) :  ![starts](https://img.shields.io/github/stars/NoTsPepino/CVE-2024-4879-CVE-2024-5217-ServiceNow-RCE-Scanning.svg) ![forks](https://img.shields.io/github/forks/NoTsPepino/CVE-2024-4879-CVE-2024-5217-ServiceNow-RCE-Scanning.svg)


## CVE-2024-4879
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/NoTsPepino/CVE-2024-4879-CVE-2024-5217-ServiceNow-RCE-Scanning](https://github.com/NoTsPepino/CVE-2024-4879-CVE-2024-5217-ServiceNow-RCE-Scanning) :  ![starts](https://img.shields.io/github/stars/NoTsPepino/CVE-2024-4879-CVE-2024-5217-ServiceNow-RCE-Scanning.svg) ![forks](https://img.shields.io/github/forks/NoTsPepino/CVE-2024-4879-CVE-2024-5217-ServiceNow-RCE-Scanning.svg)


## CVE-2023-31634
 In TeslaMate before 1.27.2, there is unauthorized access to port 4000 for remote viewing and operation of user data. After accessing the IP address for the TeslaMate instance, an attacker can switch the port to 3000 to enter Grafana for remote operations. At that time, the default username and password can be used to enter the Grafana management console without logging in, a related issue to CVE-2022-23126.

- [https://github.com/iSee857/CVE-2023-31634](https://github.com/iSee857/CVE-2023-31634) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2023-31634.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2023-31634.svg)


## CVE-2023-29374
 In LangChain through 0.0.131, the LLMMathChain chain allows prompt injection attacks that can execute arbitrary code via the Python exec method.

- [https://github.com/ckloh720/cve2023-29374](https://github.com/ckloh720/cve2023-29374) :  ![starts](https://img.shields.io/github/stars/ckloh720/cve2023-29374.svg) ![forks](https://img.shields.io/github/forks/ckloh720/cve2023-29374.svg)


## CVE-2023-3824
 In PHP version 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length checking may lead to a stack buffer overflow, leading potentially to memory corruption or RCE.

- [https://github.com/o2vi1te/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK](https://github.com/o2vi1te/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK) :  ![starts](https://img.shields.io/github/stars/o2vi1te/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK.svg) ![forks](https://img.shields.io/github/forks/o2vi1te/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK.svg)


## CVE-2021-45428
 TLR-2005KSH is affected by an incorrect access control vulnerability. THe PUT method is enabled so an attacker can upload arbitrary files including HTML and CGI formats.

- [https://github.com/projectforsix/CVE-2021-45428-Defacer](https://github.com/projectforsix/CVE-2021-45428-Defacer) :  ![starts](https://img.shields.io/github/stars/projectforsix/CVE-2021-45428-Defacer.svg) ![forks](https://img.shields.io/github/forks/projectforsix/CVE-2021-45428-Defacer.svg)


## CVE-2021-44910
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/dockern/CVE-2021-44910_SpringBlade](https://github.com/dockern/CVE-2021-44910_SpringBlade) :  ![starts](https://img.shields.io/github/stars/dockern/CVE-2021-44910_SpringBlade.svg) ![forks](https://img.shields.io/github/forks/dockern/CVE-2021-44910_SpringBlade.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-40444
 &lt;p&gt;Microsoft is investigating reports of a remote code execution vulnerability in MSHTML that affects Microsoft Windows. Microsoft is aware of targeted attacks that attempt to exploit this vulnerability by using specially-crafted Microsoft Office documents.&lt;/p&gt; &lt;p&gt;An attacker could craft a malicious ActiveX control to be used by a Microsoft Office document that hosts the browser rendering engine. The attacker would then have to convince the user to open the malicious document. Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who operate with administrative user rights.&lt;/p&gt; &lt;p&gt;Microsoft Defender Antivirus and Microsoft Defender for Endpoint both provide detection and protections for the known vulnerability. Customers should keep antimalware products up to date. Customers who utilize automatic updates do not need to take additional action. Enterprise customers who manage updates should select the detection build 1.349.22.0 or newer and deploy it across their environments. Microsoft Defender for Endpoint alerts will be displayed as: &#8220;Suspicious Cpl File Execution&#8221;.&lt;/p&gt; &lt;p&gt;Upon completion of this investigation, Microsoft will take the appropriate action to help protect our customers. This may include providing a security update through our monthly release process or providing an out-of-cycle security update, depending on customer needs.&lt;/p&gt; &lt;p&gt;Please see the &lt;strong&gt;Mitigations&lt;/strong&gt; and &lt;strong&gt;Workaround&lt;/strong&gt; sections for important information about steps you can take to protect your system from this vulnerability.&lt;/p&gt; &lt;p&gt;&lt;strong&gt;UPDATE&lt;/strong&gt; September 14, 2021: Microsoft has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. Please see the FAQ for important information about which updates are applicable to your system.&lt;/p&gt;

- [https://github.com/basim-ahmad/Follina-CVE-and-CVE-2021-40444](https://github.com/basim-ahmad/Follina-CVE-and-CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/basim-ahmad/Follina-CVE-and-CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/basim-ahmad/Follina-CVE-and-CVE-2021-40444.svg)


## CVE-2017-8529
 Internet Explorer in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8.1 and Windows RT 8.1, and Windows Server 2012 and R2 allow an attacker to detect specific files on the user's computer when affected Microsoft scripting engines do not properly handle objects in memory, aka &quot;Microsoft Browser Information Disclosure Vulnerability&quot;.

- [https://github.com/kaddirov/windows2016fixCVE-2017-8529](https://github.com/kaddirov/windows2016fixCVE-2017-8529) :  ![starts](https://img.shields.io/github/stars/kaddirov/windows2016fixCVE-2017-8529.svg) ![forks](https://img.shields.io/github/forks/kaddirov/windows2016fixCVE-2017-8529.svg)


## CVE-2004-1151
 Multiple buffer overflows in the (1) sys32_ni_syscall and (2) sys32_vm86_warning functions in sys_ia32.c for Linux 2.6.x may allow local attackers to modify kernel memory and gain privileges.

- [https://github.com/lulugelian/CVE_TEST](https://github.com/lulugelian/CVE_TEST) :  ![starts](https://img.shields.io/github/stars/lulugelian/CVE_TEST.svg) ![forks](https://img.shields.io/github/forks/lulugelian/CVE_TEST.svg)

