# Update 2021-10-25
## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/TheLastVvV/CVE-2021-42013](https://github.com/TheLastVvV/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)


## CVE-2020-2978
 Vulnerability in the Oracle Database - Enterprise Edition component of Oracle Database Server. Supported versions that are affected are 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows high privileged attacker having DBA role account privilege with network access via Oracle Net to compromise Oracle Database - Enterprise Edition. While the vulnerability is in Oracle Database - Enterprise Edition, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Database - Enterprise Edition accessible data. CVSS 3.1 Base Score 4.1 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:N).

- [https://github.com/emad-almousa/CVE-2020-2978](https://github.com/emad-almousa/CVE-2020-2978) :  ![starts](https://img.shields.io/github/stars/emad-almousa/CVE-2020-2978.svg) ![forks](https://img.shields.io/github/forks/emad-almousa/CVE-2020-2978.svg)


## CVE-2020-2950
 Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Fusion Middleware (component: Analytics Web General). Supported versions that are affected are 5.5.0.0.0, 11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this vulnerability can result in takeover of Oracle Business Intelligence Enterprise Edition. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/tuo4n8/CVE-2020-2950](https://github.com/tuo4n8/CVE-2020-2950) :  ![starts](https://img.shields.io/github/stars/tuo4n8/CVE-2020-2950.svg) ![forks](https://img.shields.io/github/forks/tuo4n8/CVE-2020-2950.svg)


## CVE-2004-2687
 distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.

- [https://github.com/sukraken/distcc_exploit.py](https://github.com/sukraken/distcc_exploit.py) :  ![starts](https://img.shields.io/github/stars/sukraken/distcc_exploit.py.svg) ![forks](https://img.shields.io/github/forks/sukraken/distcc_exploit.py.svg)

