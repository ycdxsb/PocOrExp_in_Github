# Update 2022-07-31
## CVE-2022-21449
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries). Supported versions that are affected are Oracle Java SE: 17.0.2 and 18; Oracle GraalVM Enterprise Edition: 21.3.1 and 22.0.0.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 7.5 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).

- [https://github.com/Skipper7718/CVE-2022-21449-showcase](https://github.com/Skipper7718/CVE-2022-21449-showcase) :  ![starts](https://img.shields.io/github/stars/Skipper7718/CVE-2022-21449-showcase.svg) ![forks](https://img.shields.io/github/forks/Skipper7718/CVE-2022-21449-showcase.svg)


## CVE-2022-2185
 A critical issue has been discovered in GitLab affecting all versions starting from 14.0 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 where an authenticated user authorized to import projects could import a maliciously crafted project leading to remote code execution.

- [https://github.com/ESUAdmin/CVE-2022-2185](https://github.com/ESUAdmin/CVE-2022-2185) :  ![starts](https://img.shields.io/github/stars/ESUAdmin/CVE-2022-2185.svg) ![forks](https://img.shields.io/github/forks/ESUAdmin/CVE-2022-2185.svg)


## CVE-2022-1119
 The Simple File List WordPress plugin is vulnerable to Arbitrary File Download via the eeFile parameter found in the ~/includes/ee-downloader.php file due to missing controls which makes it possible unauthenticated attackers to supply a path to a file that will subsequently be downloaded, in versions up to and including 3.2.7.

- [https://github.com/z92g/CVE-2022-1119](https://github.com/z92g/CVE-2022-1119) :  ![starts](https://img.shields.io/github/stars/z92g/CVE-2022-1119.svg) ![forks](https://img.shields.io/github/forks/z92g/CVE-2022-1119.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/cd80-ctf/CVE-2021-4034](https://github.com/cd80-ctf/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/cd80-ctf/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/cd80-ctf/CVE-2021-4034.svg)


## CVE-2021-0431
 In avrc_msg_cback of avrc_api.cc, there is a possible out of bounds read due to a missing bounds check. This could lead to remote information disclosure to a paired device with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-8.1 Android-9 Android-10Android ID: A-174149901

- [https://github.com/nanopathi/system_bt_AOSP10_r33_CVE-2021-0431](https://github.com/nanopathi/system_bt_AOSP10_r33_CVE-2021-0431) :  ![starts](https://img.shields.io/github/stars/nanopathi/system_bt_AOSP10_r33_CVE-2021-0431.svg) ![forks](https://img.shields.io/github/forks/nanopathi/system_bt_AOSP10_r33_CVE-2021-0431.svg)


## CVE-2019-7609
 Kibana versions before 5.6.15 and 6.6.1 contain an arbitrary code execution flaw in the Timelion visualizer. An attacker with access to the Timelion application could send a request that will attempt to execute javascript code. This could possibly lead to an attacker executing arbitrary commands with permissions of the Kibana process on the host system.

- [https://github.com/jas502n/kibana-RCE](https://github.com/jas502n/kibana-RCE) :  ![starts](https://img.shields.io/github/stars/jas502n/kibana-RCE.svg) ![forks](https://img.shields.io/github/forks/jas502n/kibana-RCE.svg)


## CVE-2016-10045
 The isMail transport in PHPMailer before 5.2.20 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code by leveraging improper interaction between the escapeshellarg function and internal escaping performed in the mail function in PHP. NOTE: this vulnerability exists because of an incorrect fix for CVE-2016-10033.

- [https://github.com/pedro823/cve-2016-10033-45](https://github.com/pedro823/cve-2016-10033-45) :  ![starts](https://img.shields.io/github/stars/pedro823/cve-2016-10033-45.svg) ![forks](https://img.shields.io/github/forks/pedro823/cve-2016-10033-45.svg)


## CVE-2004-2687
 distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.

- [https://github.com/angelpimentell/distcc_cve_2004-2687_exploit](https://github.com/angelpimentell/distcc_cve_2004-2687_exploit) :  ![starts](https://img.shields.io/github/stars/angelpimentell/distcc_cve_2004-2687_exploit.svg) ![forks](https://img.shields.io/github/forks/angelpimentell/distcc_cve_2004-2687_exploit.svg)

