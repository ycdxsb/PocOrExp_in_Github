# Update 2025-01-01
## CVE-2024-5481
 The Photo Gallery by 10Web &#8211; Mobile-Friendly Image Gallery plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 1.8.23 via the esc_dir function. This makes it possible for authenticated attackers to cut and paste (copy) the contents of arbitrary files on the server, which can contain sensitive information, and to cut (delete) arbitrary directories, including the root WordPress directory. By default this can be exploited by administrators only. In the premium version of the plugin, administrators can give gallery edit permissions to lower level users, which might make this exploitable by users as low as contributors.

- [https://github.com/partywavesec/CVE-2024-54819](https://github.com/partywavesec/CVE-2024-54819) :  ![starts](https://img.shields.io/github/stars/partywavesec/CVE-2024-54819.svg) ![forks](https://img.shields.io/github/forks/partywavesec/CVE-2024-54819.svg)


## CVE-2024-4573
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Castro-Ian/CVE-2024-4573-Mitigation-Script](https://github.com/Castro-Ian/CVE-2024-4573-Mitigation-Script) :  ![starts](https://img.shields.io/github/stars/Castro-Ian/CVE-2024-4573-Mitigation-Script.svg) ![forks](https://img.shields.io/github/forks/Castro-Ian/CVE-2024-4573-Mitigation-Script.svg)


## CVE-2024-4476
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/josephgodwinkimani/cloudpanel-2.4.2-CVE-2024-44765-recovery](https://github.com/josephgodwinkimani/cloudpanel-2.4.2-CVE-2024-44765-recovery) :  ![starts](https://img.shields.io/github/stars/josephgodwinkimani/cloudpanel-2.4.2-CVE-2024-44765-recovery.svg) ![forks](https://img.shields.io/github/forks/josephgodwinkimani/cloudpanel-2.4.2-CVE-2024-44765-recovery.svg)


## CVE-2023-40931
 A SQL injection vulnerability in Nagios XI from version 5.11.0 up to and including 5.11.1 allows authenticated attackers to execute arbitrary SQL commands via the ID parameter in the POST request to /nagiosxi/admin/banner_message-ajaxhelper.php

- [https://github.com/datboi6942/Nagios-XI-s-CVE-2023-40931-Exploit](https://github.com/datboi6942/Nagios-XI-s-CVE-2023-40931-Exploit) :  ![starts](https://img.shields.io/github/stars/datboi6942/Nagios-XI-s-CVE-2023-40931-Exploit.svg) ![forks](https://img.shields.io/github/forks/datboi6942/Nagios-XI-s-CVE-2023-40931-Exploit.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/kuyrathdaro/winrar-cve-2023-38831](https://github.com/kuyrathdaro/winrar-cve-2023-38831) :  ![starts](https://img.shields.io/github/stars/kuyrathdaro/winrar-cve-2023-38831.svg) ![forks](https://img.shields.io/github/forks/kuyrathdaro/winrar-cve-2023-38831.svg)


## CVE-2023-4147
 A use-after-free flaw was found in the Linux kernel&#8217;s Netfilter functionality when adding a rule with NFTA_RULE_CHAIN_ID. This flaw allows a local user to crash or escalate their privileges on the system.

- [https://github.com/murdok1982/Exploit-en-Python-para-CVE-2023-4147](https://github.com/murdok1982/Exploit-en-Python-para-CVE-2023-4147) :  ![starts](https://img.shields.io/github/stars/murdok1982/Exploit-en-Python-para-CVE-2023-4147.svg) ![forks](https://img.shields.io/github/forks/murdok1982/Exploit-en-Python-para-CVE-2023-4147.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)


## CVE-2021-21772
 A use-after-free vulnerability exists in the NMR::COpcPackageReader::releaseZIP() functionality of 3MF Consortium lib3mf 2.0.0. A specially crafted 3MF file can lead to code execution. An attacker can provide a malicious file to trigger this vulnerability.

- [https://github.com/3dluvr/New-lib3mf.dll-for-MeshMixer](https://github.com/3dluvr/New-lib3mf.dll-for-MeshMixer) :  ![starts](https://img.shields.io/github/stars/3dluvr/New-lib3mf.dll-for-MeshMixer.svg) ![forks](https://img.shields.io/github/forks/3dluvr/New-lib3mf.dll-for-MeshMixer.svg)


## CVE-2019-9193
 ** DISPUTED ** In PostgreSQL 9.3 through 11.2, the &quot;COPY TO/FROM PROGRAM&quot; function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for &#8216;COPY TO/FROM PROGRAM&#8217; is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the &#8216;COPY FROM PROGRAM&#8217;.

- [https://github.com/geniuszly/CVE-2019-9193](https://github.com/geniuszly/CVE-2019-9193) :  ![starts](https://img.shields.io/github/stars/geniuszly/CVE-2019-9193.svg) ![forks](https://img.shields.io/github/forks/geniuszly/CVE-2019-9193.svg)


## CVE-2017-7269
 Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.

- [https://github.com/geniuszly/CVE-2017-7269](https://github.com/geniuszly/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/geniuszly/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/geniuszly/CVE-2017-7269.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/jas502n/st2-046-poc](https://github.com/jas502n/st2-046-poc) :  ![starts](https://img.shields.io/github/stars/jas502n/st2-046-poc.svg) ![forks](https://img.shields.io/github/forks/jas502n/st2-046-poc.svg)

