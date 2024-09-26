# Update 2024-09-26
## CVE-2024-4706
 The WordPress + Microsoft Office 365 / Azure AD | LOGIN plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's 'pintra' shortcode in all versions up to, and including, 27.2 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/l8BL/CVE-2024-47066](https://github.com/l8BL/CVE-2024-47066) :  ![starts](https://img.shields.io/github/stars/l8BL/CVE-2024-47066.svg) ![forks](https://img.shields.io/github/forks/l8BL/CVE-2024-47066.svg)


## CVE-2024-4391
 The Happy Addons for Elementor plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's Event Calendar widget in all versions up to, and including, 3.10.7 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/KTN1990/CVE-2024-43918](https://github.com/KTN1990/CVE-2024-43918) :  ![starts](https://img.shields.io/github/stars/KTN1990/CVE-2024-43918.svg) ![forks](https://img.shields.io/github/forks/KTN1990/CVE-2024-43918.svg)


## CVE-2023-21987
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions that are affected are Prior to 6.1.44 and Prior to 7.0.8. Difficult to exploit vulnerability allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. CVSS 3.1 Base Score 7.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H).

- [https://github.com/chunzhennn/cve-2023-21987-poc](https://github.com/chunzhennn/cve-2023-21987-poc) :  ![starts](https://img.shields.io/github/stars/chunzhennn/cve-2023-21987-poc.svg) ![forks](https://img.shields.io/github/forks/chunzhennn/cve-2023-21987-poc.svg)


## CVE-2022-41544
 GetSimple CMS v3.3.16 was discovered to contain a remote code execution (RCE) vulnerability via the edited_file parameter in admin/theme-edit.php.

- [https://github.com/NyxByt3/CVE-2022-41544](https://github.com/NyxByt3/CVE-2022-41544) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2022-41544.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2022-41544.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.

- [https://github.com/NyxByt3/CVE-2022-29464](https://github.com/NyxByt3/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2022-29464.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-24959
 The WP Email Users WordPress plugin through 1.7.6 does not escape the data_raw parameter in the weu_selected_users_1 AJAX action, available to any authenticated users, allowing them to perform SQL injection attacks.

- [https://github.com/RandomRobbieBF/CVE-2021-24959](https://github.com/RandomRobbieBF/CVE-2021-24959) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2021-24959.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2021-24959.svg)


## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

- [https://github.com/24-2021/EXP-POC](https://github.com/24-2021/EXP-POC) :  ![starts](https://img.shields.io/github/stars/24-2021/EXP-POC.svg) ![forks](https://img.shields.io/github/forks/24-2021/EXP-POC.svg)


## CVE-2020-5377
 Dell EMC OpenManage Server Administrator (OMSA) versions 9.4 and prior contain multiple path traversal vulnerabilities. An unauthenticated remote attacker could potentially exploit these vulnerabilities by sending a crafted Web API request containing directory traversal character sequences to gain file system access on the compromised management station.

- [https://github.com/NyxByt3/CVE-2020-5377](https://github.com/NyxByt3/CVE-2020-5377) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2020-5377.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2020-5377.svg)


## CVE-2019-16278
 Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.

- [https://github.com/NyxByt3/CVE-2019-16278](https://github.com/NyxByt3/CVE-2019-16278) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2019-16278.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2019-16278.svg)


## CVE-2019-14287
 In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a &quot;sudo -u \#$((0xffffffff))&quot; command.

- [https://github.com/NyxByt3/CVE-2019-14287](https://github.com/NyxByt3/CVE-2019-14287) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2019-14287.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2019-14287.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/NyxByt3/CVE-2019-9053](https://github.com/NyxByt3/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2019-9053.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/NyxByt3/CVE-2019-6447](https://github.com/NyxByt3/CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2019-6447.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/NyxByt3/CVE-2019-5736](https://github.com/NyxByt3/CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2019-5736.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/NyxByt3/CVE-2018-16763](https://github.com/NyxByt3/CVE-2018-16763) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2018-16763.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2018-16763.svg)


## CVE-2017-7269
 Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.

- [https://github.com/NyxByt3/CVE-2017-7269](https://github.com/NyxByt3/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2017-7269.svg)


## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/NyxByt3/MS17-010_CVE-2017-0143](https://github.com/NyxByt3/MS17-010_CVE-2017-0143) :  ![starts](https://img.shields.io/github/stars/NyxByt3/MS17-010_CVE-2017-0143.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/MS17-010_CVE-2017-0143.svg)


## CVE-2016-1531
 Exim before 4.86.2, when installed setuid root, allows local users to gain privileges via the perl_startup argument.

- [https://github.com/NyxByt3/CVE-2016-1531](https://github.com/NyxByt3/CVE-2016-1531) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2016-1531.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2016-1531.svg)


## CVE-2015-6668
 The Job Manager plugin before 0.7.25 allows remote attackers to read arbitrary CV files via a brute force attack to the WordPress upload directory structure, related to an insecure direct object reference.

- [https://github.com/NyxByt3/CVE-2015-6668](https://github.com/NyxByt3/CVE-2015-6668) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2015-6668.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2015-6668.svg)


## CVE-2015-1635
 HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka &quot;HTTP.sys Remote Code Execution Vulnerability.&quot;

- [https://github.com/NyxByt3/CVE-2015-1635-POC](https://github.com/NyxByt3/CVE-2015-1635-POC) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2015-1635-POC.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2015-1635-POC.svg)
- [https://github.com/NyxByt3/CVE-2015-1635](https://github.com/NyxByt3/CVE-2015-1635) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2015-1635.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2015-1635.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/NyxByt3/CVE-2014-0160_Heartbleed](https://github.com/NyxByt3/CVE-2014-0160_Heartbleed) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2014-0160_Heartbleed.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2014-0160_Heartbleed.svg)


## CVE-2011-1249
 The Ancillary Function Driver (AFD) in afd.sys in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, R2, and R2 SP1, and Windows 7 Gold and SP1 does not properly validate user-mode input, which allows local users to gain privileges via a crafted application, aka &quot;Ancillary Function Driver Elevation of Privilege Vulnerability.&quot;

- [https://github.com/NyxByt3/CVE-2011-1249](https://github.com/NyxByt3/CVE-2011-1249) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2011-1249.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2011-1249.svg)


## CVE-2009-2265
 Multiple directory traversal vulnerabilities in FCKeditor before 2.6.4.1 allow remote attackers to create executable files in arbitrary directories via directory traversal sequences in the input to unspecified connector modules, as exploited in the wild for remote code execution in July 2009, related to the file browser and the editor/filemanager/connectors/ directory.

- [https://github.com/NyxByt3/CVE-2009-2265](https://github.com/NyxByt3/CVE-2009-2265) :  ![starts](https://img.shields.io/github/stars/NyxByt3/CVE-2009-2265.svg) ![forks](https://img.shields.io/github/forks/NyxByt3/CVE-2009-2265.svg)

