# Update 2025-02-09
## CVE-2025-0994
 Trimble Cityworks versions prior to 15.8.9 and Cityworks with office companion versions prior to 23.10 are vulnerable to a deserialization vulnerability. This could allow an authenticated user to perform a remote code execution attack against a customer’s Microsoft Internet Information Services (IIS) web server.

- [https://github.com/rxerium/CVE-2025-0994](https://github.com/rxerium/CVE-2025-0994) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-0994.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-0994.svg)


## CVE-2024-55215
 An issue in trojan v.2.0.0 through v.2.15.3 allows a remote attacker to escalate privileges via the initialization interface /auth/register.

- [https://github.com/ainrm/Jrohy-trojan-unauth-poc](https://github.com/ainrm/Jrohy-trojan-unauth-poc) :  ![starts](https://img.shields.io/github/stars/ainrm/Jrohy-trojan-unauth-poc.svg) ![forks](https://img.shields.io/github/forks/ainrm/Jrohy-trojan-unauth-poc.svg)


## CVE-2024-50379
Users are recommended to upgrade to version 11.0.2, 10.1.34 or 9.0.98, which fixes the issue.

- [https://github.com/dkstar11q/CVE-2024-50379-nuclei](https://github.com/dkstar11q/CVE-2024-50379-nuclei) :  ![starts](https://img.shields.io/github/stars/dkstar11q/CVE-2024-50379-nuclei.svg) ![forks](https://img.shields.io/github/forks/dkstar11q/CVE-2024-50379-nuclei.svg)


## CVE-2024-43425
 A flaw was found in Moodle. Additional restrictions are required to avoid a remote code execution risk in calculated question types. Note: This requires the capability to add/update questions.

- [https://github.com/Snizi/Moodle-CVE-2024-43425-Exploit](https://github.com/Snizi/Moodle-CVE-2024-43425-Exploit) :  ![starts](https://img.shields.io/github/stars/Snizi/Moodle-CVE-2024-43425-Exploit.svg) ![forks](https://img.shields.io/github/forks/Snizi/Moodle-CVE-2024-43425-Exploit.svg)


## CVE-2024-39713
 A Server-Side Request Forgery (SSRF) affects Rocket.Chat's Twilio webhook endpoint before version 6.10.1.

- [https://github.com/typical-pashochek/CVE-2024-39713](https://github.com/typical-pashochek/CVE-2024-39713) :  ![starts](https://img.shields.io/github/stars/typical-pashochek/CVE-2024-39713.svg) ![forks](https://img.shields.io/github/forks/typical-pashochek/CVE-2024-39713.svg)


## CVE-2024-36404
 GeoTools is an open source Java library that provides tools for geospatial data. Prior to versions 31.2, 30.4, and 29.6, Remote Code Execution (RCE) is possible if an application uses certain GeoTools functionality to evaluate XPath expressions supplied by user input. Versions 31.2, 30.4, and 29.6 contain a fix for this issue. As a workaround, GeoTools can operate with reduced functionality by removing the `gt-complex` jar from one's application. As an example of the impact, application schema `datastore` would not function without the ability to use XPath expressions to query complex content. Alternatively, one may utilize a drop-in replacement GeoTools jar from SourceForge for versions 31.1, 30.3, 30.2, 29.2, 28.2, 27.5, 27.4, 26.7, 26.4, 25.2, and 24.0. These jars are for download only and are not available from maven central, intended to quickly provide a fix to affected applications.

- [https://github.com/whitebear-ch/GeoServerExploit](https://github.com/whitebear-ch/GeoServerExploit) :  ![starts](https://img.shields.io/github/stars/whitebear-ch/GeoServerExploit.svg) ![forks](https://img.shields.io/github/forks/whitebear-ch/GeoServerExploit.svg)


## CVE-2024-36401
Versions 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/whitebear-ch/GeoServerExploit](https://github.com/whitebear-ch/GeoServerExploit) :  ![starts](https://img.shields.io/github/stars/whitebear-ch/GeoServerExploit.svg) ![forks](https://img.shields.io/github/forks/whitebear-ch/GeoServerExploit.svg)


## CVE-2024-35106
 NEXTU FLETA AX1500 WIFI6 v1.0.3 was discovered to contain a buffer overflow at /boafrm/formIpQoS. This vulnerability allows attackers to cause a Denial of Service (DoS) or potentially arbitrary code execution via a crafted POST request.

- [https://github.com/laskdjlaskdj12/CVE-2024-35106-POC](https://github.com/laskdjlaskdj12/CVE-2024-35106-POC) :  ![starts](https://img.shields.io/github/stars/laskdjlaskdj12/CVE-2024-35106-POC.svg) ![forks](https://img.shields.io/github/forks/laskdjlaskdj12/CVE-2024-35106-POC.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/YukaFake/CVE-2024-32002-Reverse-Shell](https://github.com/YukaFake/CVE-2024-32002-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/YukaFake/CVE-2024-32002-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/YukaFake/CVE-2024-32002-Reverse-Shell.svg)
- [https://github.com/YukaFake/CVE-2024-32002](https://github.com/YukaFake/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/YukaFake/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/YukaFake/CVE-2024-32002.svg)
- [https://github.com/YukaFake/malicious-hook](https://github.com/YukaFake/malicious-hook) :  ![starts](https://img.shields.io/github/stars/YukaFake/malicious-hook.svg) ![forks](https://img.shields.io/github/forks/YukaFake/malicious-hook.svg)


## CVE-2024-5491
 Denial of Service in NetScaler ADC and NetScaler Gateway in NetScaler

- [https://github.com/SAHALLL/CVE-2024-54916](https://github.com/SAHALLL/CVE-2024-54916) :  ![starts](https://img.shields.io/github/stars/SAHALLL/CVE-2024-54916.svg) ![forks](https://img.shields.io/github/forks/SAHALLL/CVE-2024-54916.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/ML-K-eng/CVE-2023-38831-Exploit-and-Detection](https://github.com/ML-K-eng/CVE-2023-38831-Exploit-and-Detection) :  ![starts](https://img.shields.io/github/stars/ML-K-eng/CVE-2023-38831-Exploit-and-Detection.svg) ![forks](https://img.shields.io/github/forks/ML-K-eng/CVE-2023-38831-Exploit-and-Detection.svg)


## CVE-2023-28432
and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/BitWiz4rd/CVE-2023-28432](https://github.com/BitWiz4rd/CVE-2023-28432) :  ![starts](https://img.shields.io/github/stars/BitWiz4rd/CVE-2023-28432.svg) ![forks](https://img.shields.io/github/forks/BitWiz4rd/CVE-2023-28432.svg)


## CVE-2023-24932
 Secure Boot Security Feature Bypass Vulnerability

- [https://github.com/helleflo1312/Orchestrated-Powershell-for-CVE-2023-24932](https://github.com/helleflo1312/Orchestrated-Powershell-for-CVE-2023-24932) :  ![starts](https://img.shields.io/github/stars/helleflo1312/Orchestrated-Powershell-for-CVE-2023-24932.svg) ![forks](https://img.shields.io/github/forks/helleflo1312/Orchestrated-Powershell-for-CVE-2023-24932.svg)


## CVE-2022-45460
 Multiple Xiongmai NVR devices, including MBD6304T V4.02.R11.00000117.10001.131900.00000 and NBD6808T-PL V4.02.R11.C7431119.12001.130000.00000, allow an unauthenticated and remote user to exploit a stack-based buffer overflow and crash the web server, resulting in a system reboot. An unauthenticated and remote attacker can execute arbitrary code by sending a crafted HTTP request that triggers the overflow condition via a long URI passed to a sprintf call. NOTE: this is different than CVE-2018-10088, but this may overlap CVE-2017-16725.

- [https://github.com/born0monday/CVE-2022-45460](https://github.com/born0monday/CVE-2022-45460) :  ![starts](https://img.shields.io/github/stars/born0monday/CVE-2022-45460.svg) ![forks](https://img.shields.io/github/forks/born0monday/CVE-2022-45460.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)


## CVE-2020-8163
 The is a code injection vulnerability in versions of Rails prior to 5.0.1 that wouldallow an attacker who controlled the `locals` argument of a `render` call to perform a RCE.

- [https://github.com/RedBinaryRabbit/CVE-2020-8163](https://github.com/RedBinaryRabbit/CVE-2020-8163) :  ![starts](https://img.shields.io/github/stars/RedBinaryRabbit/CVE-2020-8163.svg) ![forks](https://img.shields.io/github/forks/RedBinaryRabbit/CVE-2020-8163.svg)


## CVE-2019-20372
 NGINX before 1.17.7, with certain error_page configurations, allows HTTP request smuggling, as demonstrated by the ability of an attacker to read unauthorized web pages in environments where NGINX is being fronted by a load balancer.

- [https://github.com/moften/cve_2019_20372](https://github.com/moften/cve_2019_20372) :  ![starts](https://img.shields.io/github/stars/moften/cve_2019_20372.svg) ![forks](https://img.shields.io/github/forks/moften/cve_2019_20372.svg)


## CVE-2001-1473
 The SSH-1 protocol allows remote servers to conduct man-in-the-middle attacks and replay a client challenge response to a target server by creating a Session ID that matches the Session ID of the target, but which uses a public key pair that is weaker than the target's public key, which allows the attacker to compute the corresponding private key and use the target's Session ID with the compromised key pair to masquerade as the target.

- [https://github.com/s1mpl3c0d3/cvepoc](https://github.com/s1mpl3c0d3/cvepoc) :  ![starts](https://img.shields.io/github/stars/s1mpl3c0d3/cvepoc.svg) ![forks](https://img.shields.io/github/forks/s1mpl3c0d3/cvepoc.svg)

