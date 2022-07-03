# Update 2022-07-03
## CVE-2022-34298
 The NT auth module in OpenAM before 14.6.6 allows a &quot;replace Samba username attack.&quot;

- [https://github.com/watchtowrlabs/CVE-2022-34298](https://github.com/watchtowrlabs/CVE-2022-34298) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/CVE-2022-34298.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/CVE-2022-34298.svg)


## CVE-2022-29885
 The documentation of Apache Tomcat 10.1.0-M1 to 10.1.0-M14, 10.0.0-M1 to 10.0.20, 9.0.13 to 9.0.62 and 8.5.38 to 8.5.78 for the EncryptInterceptor incorrectly stated it enabled Tomcat clustering to run over an untrusted network. This was not correct. While the EncryptInterceptor does provide confidentiality and integrity protection, it does not protect against all risks associated with running over any untrusted network, particularly DoS risks.

- [https://github.com/iveresk/CVE-2022-29885](https://github.com/iveresk/CVE-2022-29885) :  ![starts](https://img.shields.io/github/stars/iveresk/CVE-2022-29885.svg) ![forks](https://img.shields.io/github/forks/iveresk/CVE-2022-29885.svg)


## CVE-2022-20130
 In transportDec_OutOfBandConfig of tpdec_lib.cpp, there is a possible out of bounds write due to a heap buffer overflow. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-224314979

- [https://github.com/Satheesh575555/external_aac_AOSP10_r33_CVE-2022-20130](https://github.com/Satheesh575555/external_aac_AOSP10_r33_CVE-2022-20130) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/external_aac_AOSP10_r33_CVE-2022-20130.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/external_aac_AOSP10_r33_CVE-2022-20130.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/Luchoane/CVE-2022-1388_refresh](https://github.com/Luchoane/CVE-2022-1388_refresh) :  ![starts](https://img.shields.io/github/stars/Luchoane/CVE-2022-1388_refresh.svg) ![forks](https://img.shields.io/github/forks/Luchoane/CVE-2022-1388_refresh.svg)


## CVE-2021-44158
 ASUS RT-AX56U Wi-Fi Router is vulnerable to stack-based buffer overflow due to improper validation for httpd parameter length. An authenticated local area network attacker can launch arbitrary code execution to control the system or disrupt service.

- [https://github.com/Expl0desploit/CVE-2021-44158](https://github.com/Expl0desploit/CVE-2021-44158) :  ![starts](https://img.shields.io/github/stars/Expl0desploit/CVE-2021-44158.svg) ![forks](https://img.shields.io/github/forks/Expl0desploit/CVE-2021-44158.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/PentesterSoham/CVE-2021-4034-exploit](https://github.com/PentesterSoham/CVE-2021-4034-exploit) :  ![starts](https://img.shields.io/github/stars/PentesterSoham/CVE-2021-4034-exploit.svg) ![forks](https://img.shields.io/github/forks/PentesterSoham/CVE-2021-4034-exploit.svg)
- [https://github.com/luckythandel/CVE-2021-4034](https://github.com/luckythandel/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/luckythandel/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/luckythandel/CVE-2021-4034.svg)


## CVE-2020-7246
 A remote code execution (RCE) vulnerability exists in qdPM 9.1 and earlier. An attacker can upload a malicious PHP code file via the profile photo functionality, by leveraging a path traversal vulnerability in the users['photop_preview'] delete photo feature, allowing bypass of .htaccess protection. NOTE: this issue exists because of an incomplete fix for CVE-2015-3884.

- [https://github.com/j0hn30n/CVE-2020-7246](https://github.com/j0hn30n/CVE-2020-7246) :  ![starts](https://img.shields.io/github/stars/j0hn30n/CVE-2020-7246.svg) ![forks](https://img.shields.io/github/forks/j0hn30n/CVE-2020-7246.svg)


## CVE-2020-2655
 Vulnerability in the Java SE product of Oracle Java SE (component: JSSE). Supported versions that are affected are Java SE: 11.0.5 and 13.0.1. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Java SE. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Java SE accessible data as well as unauthorized read access to a subset of Java SE accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).

- [https://github.com/RUB-NDS/CVE-2020-2655-DemoServer](https://github.com/RUB-NDS/CVE-2020-2655-DemoServer) :  ![starts](https://img.shields.io/github/stars/RUB-NDS/CVE-2020-2655-DemoServer.svg) ![forks](https://img.shields.io/github/forks/RUB-NDS/CVE-2020-2655-DemoServer.svg)


## CVE-2019-15231
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2019-15107. Reason: This candidate is a duplicate of CVE-2019-15107. Notes: All CVE users should reference CVE-2019-15107 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.

- [https://github.com/NullBrunk/CVE-2019-15107](https://github.com/NullBrunk/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/NullBrunk/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/NullBrunk/CVE-2019-15107.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/NullBrunk/CVE-2019-15107](https://github.com/NullBrunk/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/NullBrunk/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/NullBrunk/CVE-2019-15107.svg)


## CVE-2018-1999002
 A arbitrary file read vulnerability exists in Jenkins 2.132 and earlier, 2.121.1 and earlier in the Stapler web framework's org/kohsuke/stapler/Stapler.java that allows attackers to send crafted HTTP requests returning the contents of any file on the Jenkins master file system that the Jenkins master has access to.

- [https://github.com/0xtavian/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins](https://github.com/0xtavian/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins) :  ![starts](https://img.shields.io/github/stars/0xtavian/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins.svg) ![forks](https://img.shields.io/github/forks/0xtavian/CVE-2019-1003000-and-CVE-2018-1999002-Pre-Auth-RCE-Jenkins.svg)


## CVE-2017-2606
 Jenkins before versions 2.44, 2.32.2 is vulnerable to an information exposure in the internal API that allows access to item names that should not be visible (SECURITY-380). This only affects anonymous users (other users legitimately have access) that were able to get a list of items via an UnprotectedRootAction.

- [https://github.com/Davi-afk/jenkins-cve-CVE-2017-2606](https://github.com/Davi-afk/jenkins-cve-CVE-2017-2606) :  ![starts](https://img.shields.io/github/stars/Davi-afk/jenkins-cve-CVE-2017-2606.svg) ![forks](https://img.shields.io/github/forks/Davi-afk/jenkins-cve-CVE-2017-2606.svg)

