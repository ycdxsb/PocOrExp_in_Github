# Update 2023-05-20
## CVE-2023-21554
 Microsoft Message Queuing Remote Code Execution Vulnerability

- [https://github.com/zoemurmure/CVE-2023-21554-PoC](https://github.com/zoemurmure/CVE-2023-21554-PoC) :  ![starts](https://img.shields.io/github/stars/zoemurmure/CVE-2023-21554-PoC.svg) ![forks](https://img.shields.io/github/forks/zoemurmure/CVE-2023-21554-PoC.svg)


## CVE-2022-2185
 A critical issue has been discovered in GitLab affecting all versions starting from 14.0 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 where an authenticated user authorized to import projects could import a maliciously crafted project leading to remote code execution.

- [https://github.com/safe3s/CVE-2022-2185-poc](https://github.com/safe3s/CVE-2022-2185-poc) :  ![starts](https://img.shields.io/github/stars/safe3s/CVE-2022-2185-poc.svg) ![forks](https://img.shields.io/github/forks/safe3s/CVE-2022-2185-poc.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/M0ge/CVE-2021-43798-grafana_fileread](https://github.com/M0ge/CVE-2021-43798-grafana_fileread) :  ![starts](https://img.shields.io/github/stars/M0ge/CVE-2021-43798-grafana_fileread.svg) ![forks](https://img.shields.io/github/forks/M0ge/CVE-2021-43798-grafana_fileread.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/walnutsecurity/cve-2021-42013](https://github.com/walnutsecurity/cve-2021-42013) :  ![starts](https://img.shields.io/github/stars/walnutsecurity/cve-2021-42013.svg) ![forks](https://img.shields.io/github/forks/walnutsecurity/cve-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/CVE-2021-41773-L-](https://github.com/mightysai1997/CVE-2021-41773-L-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-L-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-L-.svg)


## CVE-2021-3138
 In Discourse 2.7.0 through beta1, a rate-limit bypass leads to a bypass of the 2FA requirement for certain forms.

- [https://github.com/Mesh3l911/CVE-2021-3138](https://github.com/Mesh3l911/CVE-2021-3138) :  ![starts](https://img.shields.io/github/stars/Mesh3l911/CVE-2021-3138.svg) ![forks](https://img.shields.io/github/forks/Mesh3l911/CVE-2021-3138.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/knqyf263/CVE-2021-3129](https://github.com/knqyf263/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2021-3129.svg)


## CVE-2019-17662
 ThinVNC 1.0b1 is vulnerable to arbitrary file read, which leads to a compromise of the VNC server. The vulnerability exists even when authentication is turned on during the deployment of the VNC server. The password for authentication is stored in cleartext in a file that can be read via a ../../ThinVnc.ini directory traversal attack vector.

- [https://github.com/thomas-osgood/CVE-2019-17662](https://github.com/thomas-osgood/CVE-2019-17662) :  ![starts](https://img.shields.io/github/stars/thomas-osgood/CVE-2019-17662.svg) ![forks](https://img.shields.io/github/forks/thomas-osgood/CVE-2019-17662.svg)


## CVE-2019-1458
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.

- [https://github.com/Eternit7/CVE-2019-1458](https://github.com/Eternit7/CVE-2019-1458) :  ![starts](https://img.shields.io/github/stars/Eternit7/CVE-2019-1458.svg) ![forks](https://img.shields.io/github/forks/Eternit7/CVE-2019-1458.svg)


## CVE-2017-7269
 Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.

- [https://github.com/c1ph3rm4st3r/CVE-2017-7269](https://github.com/c1ph3rm4st3r/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/c1ph3rm4st3r/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/c1ph3rm4st3r/CVE-2017-7269.svg)
- [https://github.com/xiaovpn/CVE-2017-7269](https://github.com/xiaovpn/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/xiaovpn/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/xiaovpn/CVE-2017-7269.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/LinuxKernelContent/DirtyCow](https://github.com/LinuxKernelContent/DirtyCow) :  ![starts](https://img.shields.io/github/stars/LinuxKernelContent/DirtyCow.svg) ![forks](https://img.shields.io/github/forks/LinuxKernelContent/DirtyCow.svg)


## CVE-2015-5531
 Directory traversal vulnerability in Elasticsearch before 1.6.1 allows remote attackers to read arbitrary files via unspecified vectors related to snapshot API calls.

- [https://github.com/M0ge/CVE-2015-5531-POC](https://github.com/M0ge/CVE-2015-5531-POC) :  ![starts](https://img.shields.io/github/stars/M0ge/CVE-2015-5531-POC.svg) ![forks](https://img.shields.io/github/forks/M0ge/CVE-2015-5531-POC.svg)

