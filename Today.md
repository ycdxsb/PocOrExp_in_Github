# Update 2024-10-23
## CVE-2024-35250
 Windows Kernel-Mode Driver Elevation of Privilege Vulnerability

- [https://github.com/0xjiefeng/CVE-2024-35250-BOF](https://github.com/0xjiefeng/CVE-2024-35250-BOF) :  ![starts](https://img.shields.io/github/stars/0xjiefeng/CVE-2024-35250-BOF.svg) ![forks](https://img.shields.io/github/forks/0xjiefeng/CVE-2024-35250-BOF.svg)


## CVE-2024-35133
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Ozozuz/Ozozuz-IBM-Security-Verify-CVE-2024-35133](https://github.com/Ozozuz/Ozozuz-IBM-Security-Verify-CVE-2024-35133) :  ![starts](https://img.shields.io/github/stars/Ozozuz/Ozozuz-IBM-Security-Verify-CVE-2024-35133.svg) ![forks](https://img.shields.io/github/forks/Ozozuz/Ozozuz-IBM-Security-Verify-CVE-2024-35133.svg)


## CVE-2024-23113
 A use of externally-controlled format string in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, FortiPAM versions 1.2.0, 1.1.0 through 1.1.2, 1.0.0 through 1.0.3, FortiSwitchManager versions 7.2.0 through 7.2.3, 7.0.0 through 7.0.3 allows attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/p33d/CVE-2024-23113](https://github.com/p33d/CVE-2024-23113) :  ![starts](https://img.shields.io/github/stars/p33d/CVE-2024-23113.svg) ![forks](https://img.shields.io/github/forks/p33d/CVE-2024-23113.svg)


## CVE-2024-4891
 The Essential Blocks &#8211; Page Builder Gutenberg Blocks, Patterns &amp; Templates plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the &#8216;tagName&#8217; parameter in versions up to, and including, 4.5.12 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with contributor-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/EQSTLab/CVE-2024-48914](https://github.com/EQSTLab/CVE-2024-48914) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2024-48914.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2024-48914.svg)


## CVE-2024-4543
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/pankass/CVE-2024-45436](https://github.com/pankass/CVE-2024-45436) :  ![starts](https://img.shields.io/github/stars/pankass/CVE-2024-45436.svg) ![forks](https://img.shields.io/github/forks/pankass/CVE-2024-45436.svg)


## CVE-2024-1086
 A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation. The nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error which resembles NF_ACCEPT. We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.

- [https://github.com/matrixvk/CVE-2024-1086-aarch64](https://github.com/matrixvk/CVE-2024-1086-aarch64) :  ![starts](https://img.shields.io/github/stars/matrixvk/CVE-2024-1086-aarch64.svg) ![forks](https://img.shields.io/github/forks/matrixvk/CVE-2024-1086-aarch64.svg)


## CVE-2023-42115
 Exim AUTH Out-Of-Bounds Write Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Exim. Authentication is not required to exploit this vulnerability. The specific flaw exists within the smtp service, which listens on TCP port 25 by default. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of a buffer. An attacker can leverage this vulnerability to execute code in the context of the service account. Was ZDI-CAN-17434.

- [https://github.com/kirinse/cve-2023-42115](https://github.com/kirinse/cve-2023-42115) :  ![starts](https://img.shields.io/github/stars/kirinse/cve-2023-42115.svg) ![forks](https://img.shields.io/github/forks/kirinse/cve-2023-42115.svg)


## CVE-2022-48656
 In the Linux kernel, the following vulnerability has been resolved: dmaengine: ti: k3-udma-private: Fix refcount leak bug in of_xudma_dev_get() We should call of_node_put() for the reference returned by of_parse_phandle() in fail path or when it is not used anymore. Here we only need to move the of_node_put() before the check.

- [https://github.com/Einstein2150/CVE-2022-48656-POC](https://github.com/Einstein2150/CVE-2022-48656-POC) :  ![starts](https://img.shields.io/github/stars/Einstein2150/CVE-2022-48656-POC.svg) ![forks](https://img.shields.io/github/forks/Einstein2150/CVE-2022-48656-POC.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)

