# Update 2025-08-10
## CVE-2025-53786
 On April 18th 2025, Microsoft announced Exchange Server Security Changes for Hybrid Deployments and accompanying non-security Hot Fix. Microsoft made these changes in the general interest of improving the security of hybrid Exchange deployments. Following further investigation, Microsoft identified specific security implications tied to the guidance and configuration steps outlined in the April announcement. Microsoft is issuing CVE-2025-53786 to document a vulnerability that is addressed by taking the steps documented with the April 18th announcement. Microsoft strongly recommends reading the information, installing the April 2025 (or later) Hot Fix and implementing the changes in your Exchange Server and hybrid environment.

- [https://github.com/barbaraeivyu/CVE-2025-53786](https://github.com/barbaraeivyu/CVE-2025-53786) :  ![starts](https://img.shields.io/github/stars/barbaraeivyu/CVE-2025-53786.svg) ![forks](https://img.shields.io/github/forks/barbaraeivyu/CVE-2025-53786.svg)


## CVE-2025-52914
 A vulnerability in the Suite Applications Services component of Mitel MiCollab 10.0 through SP1 FP1 (10.0.1.101) could allow an authenticated attacker to conduct a SQL Injection attack due to insufficient validation of user input. A successful exploit could allow an attacker to execute arbitrary SQL database commands.

- [https://github.com/rxerium/CVE-2025-52914](https://github.com/rxerium/CVE-2025-52914) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-52914.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-52914.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/Nowafen/CVE-2025-32463](https://github.com/Nowafen/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/Nowafen/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/Nowafen/CVE-2025-32463.svg)


## CVE-2025-31722
 In Jenkins Templating Engine Plugin 2.5.3 and earlier, libraries defined in folders are not subject to sandbox protection, allowing attackers with Item/Configure permission to execute arbitrary code in the context of the Jenkins controller JVM.

- [https://github.com/Nick6371/CVE-2025-31722](https://github.com/Nick6371/CVE-2025-31722) :  ![starts](https://img.shields.io/github/stars/Nick6371/CVE-2025-31722.svg) ![forks](https://img.shields.io/github/forks/Nick6371/CVE-2025-31722.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/Hex00-0x4/CVE-2025-24893-XWiki-RCE](https://github.com/Hex00-0x4/CVE-2025-24893-XWiki-RCE) :  ![starts](https://img.shields.io/github/stars/Hex00-0x4/CVE-2025-24893-XWiki-RCE.svg) ![forks](https://img.shields.io/github/forks/Hex00-0x4/CVE-2025-24893-XWiki-RCE.svg)
- [https://github.com/The-Red-Serpent/CVE-2025-24893](https://github.com/The-Red-Serpent/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/The-Red-Serpent/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/The-Red-Serpent/CVE-2025-24893.svg)
- [https://github.com/alaxar/CVE-2025-24893](https://github.com/alaxar/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/alaxar/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/alaxar/CVE-2025-24893.svg)


## CVE-2025-24354
 imgproxy is server for resizing, processing, and converting images. Imgproxy does not block the 0.0.0.0 address, even with IMGPROXY_ALLOW_LOOPBACK_SOURCE_ADDRESSES set to false. This can expose services on the local host. This vulnerability is fixed in 3.27.2.

- [https://github.com/Admin9961/CVE-2025-24354-PoC](https://github.com/Admin9961/CVE-2025-24354-PoC) :  ![starts](https://img.shields.io/github/stars/Admin9961/CVE-2025-24354-PoC.svg) ![forks](https://img.shields.io/github/forks/Admin9961/CVE-2025-24354-PoC.svg)


## CVE-2025-22963
 Teedy through 1.11 allows CSRF for account takeover via POST /api/user/admin.

- [https://github.com/gmh5225/CVE-2025-22963](https://github.com/gmh5225/CVE-2025-22963) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2025-22963.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2025-22963.svg)


## CVE-2025-8730
 A vulnerability was found in Belkin F9K1009 and F9K1010 2.00.04/2.00.09 and classified as critical. Affected by this issue is some unknown functionality of the component Web Interface. The manipulation leads to hard-coded credentials. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/byteReaper77/CVE-2025-8730](https://github.com/byteReaper77/CVE-2025-8730) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-8730.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-8730.svg)


## CVE-2025-6384
This issue affects CrafterCMS: from 4.0.0 through 4.2.2.

- [https://github.com/mbadanoiu/CVE-2025-6384](https://github.com/mbadanoiu/CVE-2025-6384) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2025-6384.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2025-6384.svg)


## CVE-2024-48990
 Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.

- [https://github.com/R0XDEADBEEF/CVE-2024-48990](https://github.com/R0XDEADBEEF/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/R0XDEADBEEF/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/R0XDEADBEEF/CVE-2024-48990.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/R0XDEADBEEF/CVE-2024-23897](https://github.com/R0XDEADBEEF/CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/R0XDEADBEEF/CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/R0XDEADBEEF/CVE-2024-23897.svg)


## CVE-2023-24055
 KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.

- [https://github.com/yosef0x01/CVE-2023-24055](https://github.com/yosef0x01/CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/yosef0x01/CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/yosef0x01/CVE-2023-24055.svg)


## CVE-2022-26757
 A use after free issue was addressed with improved memory management. This issue is fixed in tvOS 15.5, iOS 15.5 and iPadOS 15.5, Security Update 2022-004 Catalina, watchOS 8.6, macOS Big Sur 11.6.6, macOS Monterey 12.4. An application may be able to execute arbitrary code with kernel privileges.

- [https://github.com/Dylbin/flow_divert](https://github.com/Dylbin/flow_divert) :  ![starts](https://img.shields.io/github/stars/Dylbin/flow_divert.svg) ![forks](https://img.shields.io/github/forks/Dylbin/flow_divert.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/skysliently/CVE-2022-22947-pb-ai](https://github.com/skysliently/CVE-2022-22947-pb-ai) :  ![starts](https://img.shields.io/github/stars/skysliently/CVE-2022-22947-pb-ai.svg) ![forks](https://img.shields.io/github/forks/skysliently/CVE-2022-22947-pb-ai.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Scouserr/cve-2022-0847-poc-dockerimage](https://github.com/Scouserr/cve-2022-0847-poc-dockerimage) :  ![starts](https://img.shields.io/github/stars/Scouserr/cve-2022-0847-poc-dockerimage.svg) ![forks](https://img.shields.io/github/forks/Scouserr/cve-2022-0847-poc-dockerimage.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/R0XDEADBEEF/CVE-2021-26855](https://github.com/R0XDEADBEEF/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/R0XDEADBEEF/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/R0XDEADBEEF/CVE-2021-26855.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/rajaabdullahnasir/CVE-2018-7600-Remote-Code-Execution](https://github.com/rajaabdullahnasir/CVE-2018-7600-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/rajaabdullahnasir/CVE-2018-7600-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/rajaabdullahnasir/CVE-2018-7600-Remote-Code-Execution.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/RAJMadhusankha/Shellshock-CVE-2014-6271-Exploitation-and-Analysis](https://github.com/RAJMadhusankha/Shellshock-CVE-2014-6271-Exploitation-and-Analysis) :  ![starts](https://img.shields.io/github/stars/RAJMadhusankha/Shellshock-CVE-2014-6271-Exploitation-and-Analysis.svg) ![forks](https://img.shields.io/github/forks/RAJMadhusankha/Shellshock-CVE-2014-6271-Exploitation-and-Analysis.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/varppi/CVE-2012-2982](https://github.com/varppi/CVE-2012-2982) :  ![starts](https://img.shields.io/github/stars/varppi/CVE-2012-2982.svg) ![forks](https://img.shields.io/github/forks/varppi/CVE-2012-2982.svg)

