# Update 2025-03-08
## CVE-2025-25763
 crmeb CRMEB-KY v5.4.0 and before has a SQL Injection vulnerability at getRead() in /system/SystemDatabackupServices.php

- [https://github.com/J-0k3r/CVE-2025-25763](https://github.com/J-0k3r/CVE-2025-25763) :  ![starts](https://img.shields.io/github/stars/J-0k3r/CVE-2025-25763.svg) ![forks](https://img.shields.io/github/forks/J-0k3r/CVE-2025-25763.svg)


## CVE-2025-1306
 The Newscrunch theme for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 1.8.4. This is due to missing or incorrect nonce validation on the newscrunch_install_and_activate_plugin() function. This makes it possible for unauthenticated attackers to upload arbitrary files via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Nxploited/CVE-2025-1306](https://github.com/Nxploited/CVE-2025-1306) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-1306.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-1306.svg)


## CVE-2024-38014
 Windows Installer Elevation of Privilege Vulnerability

- [https://github.com/Anurag-Chevendra/CVE-2024-38014](https://github.com/Anurag-Chevendra/CVE-2024-38014) :  ![starts](https://img.shields.io/github/stars/Anurag-Chevendra/CVE-2024-38014.svg) ![forks](https://img.shields.io/github/forks/Anurag-Chevendra/CVE-2024-38014.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/ashutosh0408/CVE-2024-32002](https://github.com/ashutosh0408/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/ashutosh0408/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/ashutosh0408/CVE-2024-32002.svg)
- [https://github.com/ashutosh0408/Cve-2024-32002-poc](https://github.com/ashutosh0408/Cve-2024-32002-poc) :  ![starts](https://img.shields.io/github/stars/ashutosh0408/Cve-2024-32002-poc.svg) ![forks](https://img.shields.io/github/forks/ashutosh0408/Cve-2024-32002-poc.svg)


## CVE-2024-23692
 Rejetto HTTP File Server, up to and including version 2.3m, is vulnerable to a template injection vulnerability. This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the affected system by sending a specially crafted HTTP request. As of the CVE assignment date, Rejetto HFS 2.3m is no longer supported.

- [https://github.com/999gawkboyy/CVE-2024-23692_Exploit](https://github.com/999gawkboyy/CVE-2024-23692_Exploit) :  ![starts](https://img.shields.io/github/stars/999gawkboyy/CVE-2024-23692_Exploit.svg) ![forks](https://img.shields.io/github/forks/999gawkboyy/CVE-2024-23692_Exploit.svg)


## CVE-2024-7014
 versions 10.14.4 and older.

- [https://github.com/hexspectrum1/CVE-2024-7014](https://github.com/hexspectrum1/CVE-2024-7014) :  ![starts](https://img.shields.io/github/stars/hexspectrum1/CVE-2024-7014.svg) ![forks](https://img.shields.io/github/forks/hexspectrum1/CVE-2024-7014.svg)


## CVE-2023-40028
 Ghost is an open source content management system. Versions prior to 5.59.1 are subject to a vulnerability which allows authenticated users to upload files that are symlinks. This can be exploited to perform an arbitrary file read of any file on the host operating system. Site administrators can check for exploitation of this issue by looking for unknown symlinks within Ghost's `content/` folder. Version 5.59.1 contains a fix for this issue. All users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/syogod/CVE-2023-40028](https://github.com/syogod/CVE-2023-40028) :  ![starts](https://img.shields.io/github/stars/syogod/CVE-2023-40028.svg) ![forks](https://img.shields.io/github/forks/syogod/CVE-2023-40028.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/monke443/CVE-2021-43798-Grafana-Arbitrary-File-Read](https://github.com/monke443/CVE-2021-43798-Grafana-Arbitrary-File-Read) :  ![starts](https://img.shields.io/github/stars/monke443/CVE-2021-43798-Grafana-Arbitrary-File-Read.svg) ![forks](https://img.shields.io/github/forks/monke443/CVE-2021-43798-Grafana-Arbitrary-File-Read.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2020-1472
When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/PakwanSK/Simulating-and-preventing-Zerologon-CVE-2020-1472-vulnerability-attacks.](https://github.com/PakwanSK/Simulating-and-preventing-Zerologon-CVE-2020-1472-vulnerability-attacks.) :  ![starts](https://img.shields.io/github/stars/PakwanSK/Simulating-and-preventing-Zerologon-CVE-2020-1472-vulnerability-attacks..svg) ![forks](https://img.shields.io/github/forks/PakwanSK/Simulating-and-preventing-Zerologon-CVE-2020-1472-vulnerability-attacks..svg)


## CVE-2019-16920
 Unauthenticated remote code execution occurs in D-Link products such as DIR-655C, DIR-866L, DIR-652, and DHP-1565. The issue occurs when the attacker sends an arbitrary input to a "PingTest" device common gateway interface that could lead to common injection. An attacker who successfully triggers the command injection could achieve full system compromise. Later, it was independently found that these are also affected: DIR-855L, DAP-1533, DIR-862L, DIR-615, DIR-835, and DIR-825.

- [https://github.com/eniac888/CVE-2019-16920-MassPwn3r](https://github.com/eniac888/CVE-2019-16920-MassPwn3r) :  ![starts](https://img.shields.io/github/stars/eniac888/CVE-2019-16920-MassPwn3r.svg) ![forks](https://img.shields.io/github/forks/eniac888/CVE-2019-16920-MassPwn3r.svg)


## CVE-2019-15707
 An improper access control vulnerability in FortiMail admin webUI 6.2.0, 6.0.0 to 6.0.6, 5.4.10 and below may allow administrators to perform system backup config download they should not be authorized for.

- [https://github.com/cristianovisk/CVE-2019-15707](https://github.com/cristianovisk/CVE-2019-15707) :  ![starts](https://img.shields.io/github/stars/cristianovisk/CVE-2019-15707.svg) ![forks](https://img.shields.io/github/forks/cristianovisk/CVE-2019-15707.svg)


## CVE-2019-7214
 SmarterTools SmarterMail 16.x before build 6985 allows deserialization of untrusted data. An unauthenticated attacker could run commands on the server when port 17001 was remotely accessible. This port is not accessible remotely by default after applying the Build 6985 patch.

- [https://github.com/Drew-Alleman/CVE-2019-7214](https://github.com/Drew-Alleman/CVE-2019-7214) :  ![starts](https://img.shields.io/github/stars/Drew-Alleman/CVE-2019-7214.svg) ![forks](https://img.shields.io/github/forks/Drew-Alleman/CVE-2019-7214.svg)


## CVE-2005-0603
 viewtopic.php in phpBB 2.0.12 and earlier allows remote attackers to obtain sensitive information via a highlight parameter containing invalid regular expression syntax, which reveals the path in a PHP error message.

- [https://github.com/Parcer0/CVE-2005-0603-phpBB-2.0.12-Full-path-disclosure](https://github.com/Parcer0/CVE-2005-0603-phpBB-2.0.12-Full-path-disclosure) :  ![starts](https://img.shields.io/github/stars/Parcer0/CVE-2005-0603-phpBB-2.0.12-Full-path-disclosure.svg) ![forks](https://img.shields.io/github/forks/Parcer0/CVE-2005-0603-phpBB-2.0.12-Full-path-disclosure.svg)


## CVE-2004-2687
 distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.

- [https://github.com/k4miyo/CVE-2004-2687](https://github.com/k4miyo/CVE-2004-2687) :  ![starts](https://img.shields.io/github/stars/k4miyo/CVE-2004-2687.svg) ![forks](https://img.shields.io/github/forks/k4miyo/CVE-2004-2687.svg)
- [https://github.com/angelpimentell/distcc_cve_2004-2687_exploit](https://github.com/angelpimentell/distcc_cve_2004-2687_exploit) :  ![starts](https://img.shields.io/github/stars/angelpimentell/distcc_cve_2004-2687_exploit.svg) ![forks](https://img.shields.io/github/forks/angelpimentell/distcc_cve_2004-2687_exploit.svg)
- [https://github.com/n3rdh4x0r/distccd_rce_CVE-2004-2687](https://github.com/n3rdh4x0r/distccd_rce_CVE-2004-2687) :  ![starts](https://img.shields.io/github/stars/n3rdh4x0r/distccd_rce_CVE-2004-2687.svg) ![forks](https://img.shields.io/github/forks/n3rdh4x0r/distccd_rce_CVE-2004-2687.svg)
- [https://github.com/ss0wl/CVE-2004-2687_distcc_v1](https://github.com/ss0wl/CVE-2004-2687_distcc_v1) :  ![starts](https://img.shields.io/github/stars/ss0wl/CVE-2004-2687_distcc_v1.svg) ![forks](https://img.shields.io/github/forks/ss0wl/CVE-2004-2687_distcc_v1.svg)


## CVE-2004-2167
 Multiple buffer overflows in LaTeX2rtf 1.9.15, and possibly other versions, allow remote attackers to execute arbitrary code via (1) the expandmacro function, and possibly (2) Environments and (3) TranslateCommand.

- [https://github.com/uzzzval/cve-2004-2167](https://github.com/uzzzval/cve-2004-2167) :  ![starts](https://img.shields.io/github/stars/uzzzval/cve-2004-2167.svg) ![forks](https://img.shields.io/github/forks/uzzzval/cve-2004-2167.svg)


## CVE-2004-0558
 The Internet Printing Protocol (IPP) implementation in CUPS before 1.1.21 allows remote attackers to cause a denial of service (service hang) via a certain UDP packet to the IPP port.

- [https://github.com/fibonascii/CVE-2004-0558](https://github.com/fibonascii/CVE-2004-0558) :  ![starts](https://img.shields.io/github/stars/fibonascii/CVE-2004-0558.svg) ![forks](https://img.shields.io/github/forks/fibonascii/CVE-2004-0558.svg)

