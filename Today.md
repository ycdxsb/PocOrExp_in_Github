# Update 2022-09-03
## CVE-2022-33174
 Power Distribution Units running on Powertek firmware (multiple brands) before 3.30.30 allows remote authorization bypass in the web interface. To exploit the vulnerability, an attacker must send an HTTP packet to the data retrieval interface (/cgi/get_param.cgi) with the tmpToken cookie set to an empty string followed by a semicolon. This bypasses an active session authorization check. This can be then used to fetch the values of protected sys.passwd and sys.su.name fields that contain the username and password in cleartext.

- [https://github.com/Henry4E36/CVE-2022-33174](https://github.com/Henry4E36/CVE-2022-33174) :  ![starts](https://img.shields.io/github/stars/Henry4E36/CVE-2022-33174.svg) ![forks](https://img.shields.io/github/forks/Henry4E36/CVE-2022-33174.svg)


## CVE-2022-30526
 A privilege escalation vulnerability was identified in the CLI command of Zyxel USG FLEX 100(W) firmware versions 4.50 through 5.30, USG FLEX 200 firmware versions 4.50 through 5.30, USG FLEX 500 firmware versions 4.50 through 5.30, USG FLEX 700 firmware versions 4.50 through 5.30, USG FLEX 50(W) firmware versions 4.16 through 5.30, USG20(W)-VPN firmware versions 4.16 through 5.30, ATP series firmware versions 4.32 through 5.30, VPN series firmware versions 4.30 through 5.30, USG/ZyWALL series firmware versions 4.09 through 4.72, which could allow a local attacker to execute some OS commands with root privileges in some directories on a vulnerable device.

- [https://github.com/greek0x0/CVE-2022-30526](https://github.com/greek0x0/CVE-2022-30526) :  ![starts](https://img.shields.io/github/stars/greek0x0/CVE-2022-30526.svg) ![forks](https://img.shields.io/github/forks/greek0x0/CVE-2022-30526.svg)


## CVE-2022-25845
 The package com.alibaba:fastjson before 1.2.83 are vulnerable to Deserialization of Untrusted Data by bypassing the default autoType shutdown restrictions, which is possible under certain conditions. Exploiting this vulnerability allows attacking remote servers. Workaround: If upgrading is not possible, you can enable [safeMode](https://github.com/alibaba/fastjson/wiki/fastjson_safemode).

- [https://github.com/hosch3n/FastjsonVulns](https://github.com/hosch3n/FastjsonVulns) :  ![starts](https://img.shields.io/github/stars/hosch3n/FastjsonVulns.svg) ![forks](https://img.shields.io/github/forks/hosch3n/FastjsonVulns.svg)


## CVE-2022-25260
 JetBrains Hub before 2021.1.14276 was vulnerable to blind Server-Side Request Forgery (SSRF).

- [https://github.com/yuriisanin/CVE-2022-25260](https://github.com/yuriisanin/CVE-2022-25260) :  ![starts](https://img.shields.io/github/stars/yuriisanin/CVE-2022-25260.svg) ![forks](https://img.shields.io/github/forks/yuriisanin/CVE-2022-25260.svg)


## CVE-2022-24637
 Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated remote attacker to obtain sensitive user information, which can be used to gain admin privileges by leveraging cache hashes. This occurs because files generated with '&lt;?php (instead of the intended &quot;&lt;?php sequence) aren't handled by the PHP interpreter.

- [https://github.com/Lay0us1/CVE-2022-24637](https://github.com/Lay0us1/CVE-2022-24637) :  ![starts](https://img.shields.io/github/stars/Lay0us1/CVE-2022-24637.svg) ![forks](https://img.shields.io/github/forks/Lay0us1/CVE-2022-24637.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/75ACOL/CVE-2022-22963](https://github.com/75ACOL/CVE-2022-22963) :  ![starts](https://img.shields.io/github/stars/75ACOL/CVE-2022-22963.svg) ![forks](https://img.shields.io/github/forks/75ACOL/CVE-2022-22963.svg)


## CVE-2022-1292
 The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n). Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd).

- [https://github.com/greek0x0/CVE-2022-1292](https://github.com/greek0x0/CVE-2022-1292) :  ![starts](https://img.shields.io/github/stars/greek0x0/CVE-2022-1292.svg) ![forks](https://img.shields.io/github/forks/greek0x0/CVE-2022-1292.svg)


## CVE-2022-0543
 It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

- [https://github.com/JacobEbben/CVE-2022-0543](https://github.com/JacobEbben/CVE-2022-0543) :  ![starts](https://img.shields.io/github/stars/JacobEbben/CVE-2022-0543.svg) ![forks](https://img.shields.io/github/forks/JacobEbben/CVE-2022-0543.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/Pajarraco4444/CVE-2021-22204](https://github.com/Pajarraco4444/CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/Pajarraco4444/CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/Pajarraco4444/CVE-2021-22204.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/1337Rin/CVE-2021-4034](https://github.com/1337Rin/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/1337Rin/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/1337Rin/CVE-2021-4034.svg)


## CVE-2020-8617
 Using a specially-crafted message, an attacker may potentially cause a BIND server to reach an inconsistent state if the attacker knows (or successfully guesses) the name of a TSIG key used by the server. Since BIND, by default, configures a local session key even on servers whose configuration does not otherwise make use of it, almost all current BIND servers are vulnerable. In releases of BIND dating from March 2018 and after, an assertion check in tsig.c detects this inconsistent state and deliberately exits. Prior to the introduction of the check the server would continue operating in an inconsistent state, with potentially harmful results.

- [https://github.com/knqyf263/CVE-2020-8617](https://github.com/knqyf263/CVE-2020-8617) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2020-8617.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2020-8617.svg)


## CVE-2020-1947
 In Apache ShardingSphere(incubator) 4.0.0-RC3 and 4.0.0, the ShardingSphere's web console uses the SnakeYAML library for parsing YAML inputs to load datasource configuration. SnakeYAML allows to unmarshal data to a Java type By using the YAML tag. Unmarshalling untrusted data can lead to security flaws of RCE.

- [https://github.com/CraigChristmas/CVE-2020-1947](https://github.com/CraigChristmas/CVE-2020-1947) :  ![starts](https://img.shields.io/github/stars/CraigChristmas/CVE-2020-1947.svg) ![forks](https://img.shields.io/github/forks/CraigChristmas/CVE-2020-1947.svg)


## CVE-2016-8776
 Huawei P9 phones with software EVA-AL10C00,EVA-CL10C00,EVA-DL10C00,EVA-TL10C00 and P9 Lite phones with software VNS-L21C185 allow attackers to bypass the factory reset protection (FRP) to enter some functional modules without authorization and perform operations to update the Google account.

- [https://github.com/akzedevops/CVE-2016-8776](https://github.com/akzedevops/CVE-2016-8776) :  ![starts](https://img.shields.io/github/stars/akzedevops/CVE-2016-8776.svg) ![forks](https://img.shields.io/github/forks/akzedevops/CVE-2016-8776.svg)

