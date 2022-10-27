# Update 2022-10-27
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/Vulnmachines/text4shell-CVE-2022-42889](https://github.com/Vulnmachines/text4shell-CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/text4shell-CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/text4shell-CVE-2022-42889.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/qingsiweisan/CVE-2022-40684](https://github.com/qingsiweisan/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/qingsiweisan/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/qingsiweisan/CVE-2022-40684.svg)


## CVE-2022-2639
 An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size() function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639](https://github.com/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639) :  ![starts](https://img.shields.io/github/stars/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639.svg) ![forks](https://img.shields.io/github/forks/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639.svg)


## CVE-2022-1679
 A use-after-free flaw was found in the Linux kernel&#8217;s Atheros wireless adapter driver in the way a user forces the ath9k_htc_wait_for_target function to fail with some input messages. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/EkamSinghWalia/-Detection-and-Mitigation-for-CVE-2022-1679](https://github.com/EkamSinghWalia/-Detection-and-Mitigation-for-CVE-2022-1679) :  ![starts](https://img.shields.io/github/stars/EkamSinghWalia/-Detection-and-Mitigation-for-CVE-2022-1679.svg) ![forks](https://img.shields.io/github/forks/EkamSinghWalia/-Detection-and-Mitigation-for-CVE-2022-1679.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/OnCyberWar/CVE-2022-1388](https://github.com/OnCyberWar/CVE-2022-1388) :  ![starts](https://img.shields.io/github/stars/OnCyberWar/CVE-2022-1388.svg) ![forks](https://img.shields.io/github/forks/OnCyberWar/CVE-2022-1388.svg)
- [https://github.com/On-Cyber-War/CVE-2022-1388](https://github.com/On-Cyber-War/CVE-2022-1388) :  ![starts](https://img.shields.io/github/stars/On-Cyber-War/CVE-2022-1388.svg) ![forks](https://img.shields.io/github/forks/On-Cyber-War/CVE-2022-1388.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/0bfxgh0st/cve-2021-43798](https://github.com/0bfxgh0st/cve-2021-43798) :  ![starts](https://img.shields.io/github/stars/0bfxgh0st/cve-2021-43798.svg) ![forks](https://img.shields.io/github/forks/0bfxgh0st/cve-2021-43798.svg)


## CVE-2021-26414
 Windows DCOM Server Security Feature Bypass

- [https://github.com/Nels2/dcom_10036_Solver](https://github.com/Nels2/dcom_10036_Solver) :  ![starts](https://img.shields.io/github/stars/Nels2/dcom_10036_Solver.svg) ![forks](https://img.shields.io/github/forks/Nels2/dcom_10036_Solver.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/jj4152/cve-2021-1675](https://github.com/jj4152/cve-2021-1675) :  ![starts](https://img.shields.io/github/stars/jj4152/cve-2021-1675.svg) ![forks](https://img.shields.io/github/forks/jj4152/cve-2021-1675.svg)


## CVE-2019-1458
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.

- [https://github.com/DreamoneOnly/CVE-2019-1458-malware](https://github.com/DreamoneOnly/CVE-2019-1458-malware) :  ![starts](https://img.shields.io/github/stars/DreamoneOnly/CVE-2019-1458-malware.svg) ![forks](https://img.shields.io/github/forks/DreamoneOnly/CVE-2019-1458-malware.svg)

