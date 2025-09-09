# Update 2025-09-09
## CVE-2025-53772
 Deserialization of untrusted data in Web Deploy allows an authorized attacker to execute code over a network.

- [https://github.com/fortihack/CVE-2025-53772](https://github.com/fortihack/CVE-2025-53772) :  ![starts](https://img.shields.io/github/stars/fortihack/CVE-2025-53772.svg) ![forks](https://img.shields.io/github/forks/fortihack/CVE-2025-53772.svg)


## CVE-2025-53690
 Deserialization of Untrusted Data vulnerability in Sitecore Experience Manager (XM), Sitecore Experience Platform (XP) allows Code Injection.This issue affects Experience Manager (XM): through 9.0; Experience Platform (XP): through 9.0.

- [https://github.com/m0d0ri205/CVE-2025-53690-Analysis](https://github.com/m0d0ri205/CVE-2025-53690-Analysis) :  ![starts](https://img.shields.io/github/stars/m0d0ri205/CVE-2025-53690-Analysis.svg) ![forks](https://img.shields.io/github/forks/m0d0ri205/CVE-2025-53690-Analysis.svg)


## CVE-2025-52970
 A improper handling of parameters in Fortinet FortiWeb versions 7.6.3 and below, versions 7.4.7 and below, versions 7.2.10 and below, and 7.0.10 and below may allow an unauthenticated remote attacker with non-public information pertaining to the device and targeted user to gain admin privileges on the device via a specially crafted request.

- [https://github.com/34zY/CVE-2025-52970](https://github.com/34zY/CVE-2025-52970) :  ![starts](https://img.shields.io/github/stars/34zY/CVE-2025-52970.svg) ![forks](https://img.shields.io/github/forks/34zY/CVE-2025-52970.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/CTY-Research-1/CVE-2025-47812_Lab_environment](https://github.com/CTY-Research-1/CVE-2025-47812_Lab_environment) :  ![starts](https://img.shields.io/github/stars/CTY-Research-1/CVE-2025-47812_Lab_environment.svg) ![forks](https://img.shields.io/github/forks/CTY-Research-1/CVE-2025-47812_Lab_environment.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/dollarboysushil/CVE-2025-32433-Erlang-OTP-SSH-Unauthenticated-RCE](https://github.com/dollarboysushil/CVE-2025-32433-Erlang-OTP-SSH-Unauthenticated-RCE) :  ![starts](https://img.shields.io/github/stars/dollarboysushil/CVE-2025-32433-Erlang-OTP-SSH-Unauthenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/dollarboysushil/CVE-2025-32433-Erlang-OTP-SSH-Unauthenticated-RCE.svg)


## CVE-2025-23266
 NVIDIA Container Toolkit for all platforms contains a vulnerability in some hooks used to initialize the container, where an attacker could execute arbitrary code with elevated permissions. A successful exploit of this vulnerability might lead to escalation of privileges, data tampering, information disclosure, and denial of service.

- [https://github.com/mrk336/CVE-2025-23266](https://github.com/mrk336/CVE-2025-23266) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2025-23266.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2025-23266.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/Demoo1337/ThrottleStop](https://github.com/Demoo1337/ThrottleStop) :  ![starts](https://img.shields.io/github/stars/Demoo1337/ThrottleStop.svg) ![forks](https://img.shields.io/github/forks/Demoo1337/ThrottleStop.svg)


## CVE-2023-51770
We recommend users to upgrade Apache DolphinScheduler to version 3.2.1, which fixes the issue.

- [https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3_2_1_fixed](https://github.com/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3_2_1_fixed) :  ![starts](https://img.shields.io/github/stars/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3_2_1_fixed.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/apache__dolphinscheduler_CVE-2023-51770_3_2_1_fixed.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/AzK-os-dev/CVE-2021-41773](https://github.com/AzK-os-dev/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/AzK-os-dev/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/AzK-os-dev/CVE-2021-41773.svg)
- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/boritopalito/CVE-2012-2982](https://github.com/boritopalito/CVE-2012-2982) :  ![starts](https://img.shields.io/github/stars/boritopalito/CVE-2012-2982.svg) ![forks](https://img.shields.io/github/forks/boritopalito/CVE-2012-2982.svg)

