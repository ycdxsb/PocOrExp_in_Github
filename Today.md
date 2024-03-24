# Update 2024-03-24
## CVE-2024-25175
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jet-pentest/CVE-2024-25175](https://github.com/jet-pentest/CVE-2024-25175) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2024-25175.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2024-25175.svg)


## CVE-2024-1709
 ConnectWise ScreenConnect 23.9.7 and prior are affected by an Authentication Bypass Using an Alternate Path or Channel vulnerability, which may allow an attacker direct access to confidential information or critical systems.

- [https://github.com/sxyrxyy/CVE-2024-1709-ConnectWise-ScreenConnect-Authentication-Bypass](https://github.com/sxyrxyy/CVE-2024-1709-ConnectWise-ScreenConnect-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/sxyrxyy/CVE-2024-1709-ConnectWise-ScreenConnect-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/sxyrxyy/CVE-2024-1709-ConnectWise-ScreenConnect-Authentication-Bypass.svg)


## CVE-2023-48788
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/TheRedDevil1/CVE-2023-48788-exploit](https://github.com/TheRedDevil1/CVE-2023-48788-exploit) :  ![starts](https://img.shields.io/github/stars/TheRedDevil1/CVE-2023-48788-exploit.svg) ![forks](https://img.shields.io/github/forks/TheRedDevil1/CVE-2023-48788-exploit.svg)


## CVE-2023-48084
 Nagios XI before version 5.11.3 was discovered to contain a SQL injection vulnerability via the bulk modification tool.

- [https://github.com/bucketcat/CVE-2023-48084](https://github.com/bucketcat/CVE-2023-48084) :  ![starts](https://img.shields.io/github/stars/bucketcat/CVE-2023-48084.svg) ![forks](https://img.shields.io/github/forks/bucketcat/CVE-2023-48084.svg)


## CVE-2023-41064
 A buffer overflow issue was addressed with improved memory handling. This issue is fixed in iOS 16.6.1 and iPadOS 16.6.1, macOS Monterey 12.6.9, macOS Ventura 13.5.2, iOS 15.7.9 and iPadOS 15.7.9, macOS Big Sur 11.7.10. Processing a maliciously crafted image may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

- [https://github.com/alsaeroth/CVE-2023-41064-POC](https://github.com/alsaeroth/CVE-2023-41064-POC) :  ![starts](https://img.shields.io/github/stars/alsaeroth/CVE-2023-41064-POC.svg) ![forks](https://img.shields.io/github/forks/alsaeroth/CVE-2023-41064-POC.svg)


## CVE-2022-23093
 ping reads raw IP packets from the network to process responses in the pr_pack() function. As part of processing a response ping has to reconstruct the IP header, the ICMP header and if present a &quot;quoted packet,&quot; which represents the packet that generated an ICMP error. The quoted packet again has an IP header and an ICMP header. The pr_pack() copies received IP and ICMP headers into stack buffers for further processing. In so doing, it fails to take into account the possible presence of IP option headers following the IP header in either the response or the quoted packet. When IP options are present, pr_pack() overflows the destination buffer by up to 40 bytes. The memory safety bugs described above can be triggered by a remote host, causing the ping program to crash. The ping process runs in a capability mode sandbox on all affected versions of FreeBSD and is thus very constrained in how it can interact with the rest of the system at the point where the bug can occur.

- [https://github.com/Symbolexe/DrayTek-Exploit](https://github.com/Symbolexe/DrayTek-Exploit) :  ![starts](https://img.shields.io/github/stars/Symbolexe/DrayTek-Exploit.svg) ![forks](https://img.shields.io/github/forks/Symbolexe/DrayTek-Exploit.svg)


## CVE-2021-40444
 &lt;p&gt;Microsoft is investigating reports of a remote code execution vulnerability in MSHTML that affects Microsoft Windows. Microsoft is aware of targeted attacks that attempt to exploit this vulnerability by using specially-crafted Microsoft Office documents.&lt;/p&gt; &lt;p&gt;An attacker could craft a malicious ActiveX control to be used by a Microsoft Office document that hosts the browser rendering engine. The attacker would then have to convince the user to open the malicious document. Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who operate with administrative user rights.&lt;/p&gt; &lt;p&gt;Microsoft Defender Antivirus and Microsoft Defender for Endpoint both provide detection and protections for the known vulnerability. Customers should keep antimalware products up to date. Customers who utilize automatic updates do not need to take additional action. Enterprise customers who manage updates should select the detection build 1.349.22.0 or newer and deploy it across their environments. Microsoft Defender for Endpoint alerts will be displayed as: &#8220;Suspicious Cpl File Execution&#8221;.&lt;/p&gt; &lt;p&gt;Upon completion of this investigation, Microsoft will take the appropriate action to help protect our customers. This may include providing a security update through our monthly release process or providing an out-of-cycle security update, depending on customer needs.&lt;/p&gt; &lt;p&gt;Please see the &lt;strong&gt;Mitigations&lt;/strong&gt; and &lt;strong&gt;Workaround&lt;/strong&gt; sections for important information about steps you can take to protect your system from this vulnerability.&lt;/p&gt; &lt;p&gt;&lt;strong&gt;UPDATE&lt;/strong&gt; September 14, 2021: Microsoft has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. Please see the FAQ for important information about which updates are applicable to your system.&lt;/p&gt;

- [https://github.com/kagura-maru/CVE-2021-40444-POC](https://github.com/kagura-maru/CVE-2021-40444-POC) :  ![starts](https://img.shields.io/github/stars/kagura-maru/CVE-2021-40444-POC.svg) ![forks](https://img.shields.io/github/forks/kagura-maru/CVE-2021-40444-POC.svg)


## CVE-2016-3861
 LibUtils in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, 6.x before 2016-09-01, and 7.0 before 2016-09-01 mishandles conversions between Unicode character encodings with different encoding widths, which allows remote attackers to execute arbitrary code or cause a denial of service (heap-based buffer overflow) via a crafted file, aka internal bug 29250543.

- [https://github.com/zxkevn/CVE-2016-3861](https://github.com/zxkevn/CVE-2016-3861) :  ![starts](https://img.shields.io/github/stars/zxkevn/CVE-2016-3861.svg) ![forks](https://img.shields.io/github/forks/zxkevn/CVE-2016-3861.svg)

