# Update 2021-06-15
## CVE-2021-22201
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.9. A specially crafted import file could read files on the server.

- [https://github.com/exp1orer/CVE-2021-22201](https://github.com/exp1orer/CVE-2021-22201) :  ![starts](https://img.shields.io/github/stars/exp1orer/CVE-2021-22201.svg) ![forks](https://img.shields.io/github/forks/exp1orer/CVE-2021-22201.svg)


## CVE-2021-3560
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)
- [https://github.com/tyleraharrison/CVE-2021-3560_PoC](https://github.com/tyleraharrison/CVE-2021-3560_PoC) :  ![starts](https://img.shields.io/github/stars/tyleraharrison/CVE-2021-3560_PoC.svg) ![forks](https://img.shields.io/github/forks/tyleraharrison/CVE-2021-3560_PoC.svg)


## CVE-2020-24186
 A Remote Code Execution vulnerability exists in the gVectors wpDiscuz plugin 7.0 through 7.0.4 for WordPress, which allows unauthenticated users to upload any type of file, including PHP files via the wmuUploadFiles AJAX action.

- [https://github.com/hevox/CVE-2020-24186-wpDiscuz-7.0.4-RCE](https://github.com/hevox/CVE-2020-24186-wpDiscuz-7.0.4-RCE) :  ![starts](https://img.shields.io/github/stars/hevox/CVE-2020-24186-wpDiscuz-7.0.4-RCE.svg) ![forks](https://img.shields.io/github/forks/hevox/CVE-2020-24186-wpDiscuz-7.0.4-RCE.svg)


## CVE-2020-3187
 A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and obtain read and delete access to sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of the HTTP URL. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences. An exploit could allow the attacker to view or delete arbitrary files on the targeted system. When the device is reloaded after exploitation of this vulnerability, any files that were deleted are restored. The attacker can only view and delete files within the web services file system. This file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability can not be used to obtain access to ASA or FTD system files or underlying operating system (OS) files. Reloading the affected device will restore all files within the web services file system.

- [https://github.com/sujaygr8/CVE-2020-3187](https://github.com/sujaygr8/CVE-2020-3187) :  ![starts](https://img.shields.io/github/stars/sujaygr8/CVE-2020-3187.svg) ![forks](https://img.shields.io/github/forks/sujaygr8/CVE-2020-3187.svg)


## CVE-2020-1337
 An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system, aka 'Windows Print Spooler Elevation of Privilege Vulnerability'.

- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)


## CVE-2020-1313
 An elevation of privilege vulnerability exists when the Windows Update Orchestrator Service improperly handles file operations, aka 'Windows Update Orchestrator Service Elevation of Privilege Vulnerability'.

- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)


## CVE-2019-18634
 In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.

- [https://github.com/edsonjt81/sudo-cve-2019-18634](https://github.com/edsonjt81/sudo-cve-2019-18634) :  ![starts](https://img.shields.io/github/stars/edsonjt81/sudo-cve-2019-18634.svg) ![forks](https://img.shields.io/github/forks/edsonjt81/sudo-cve-2019-18634.svg)


## CVE-2019-14287
 In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a &quot;sudo -u \#$((0xffffffff))&quot; command.

- [https://github.com/edsonjt81/CVE-2019-14287-](https://github.com/edsonjt81/CVE-2019-14287-) :  ![starts](https://img.shields.io/github/stars/edsonjt81/CVE-2019-14287-.svg) ![forks](https://img.shields.io/github/forks/edsonjt81/CVE-2019-14287-.svg)


## CVE-2019-12725
 Zeroshell 3.9.0 is prone to a remote command execution vulnerability. Specifically, this issue occurs because the web application mishandles a few HTTP parameters. An unauthenticated attacker can exploit this issue by injecting OS commands inside the vulnerable parameters.

- [https://github.com/hevox/CVE-2019-12725-Command-Injection](https://github.com/hevox/CVE-2019-12725-Command-Injection) :  ![starts](https://img.shields.io/github/stars/hevox/CVE-2019-12725-Command-Injection.svg) ![forks](https://img.shields.io/github/forks/hevox/CVE-2019-12725-Command-Injection.svg)


## CVE-2019-10008
 Zoho ManageEngine ServiceDesk 9.3 allows session hijacking and privilege escalation because an established guest session is automatically converted into an established administrator session when the guest user enters the administrator username, with an arbitrary incorrect password, in an mc/ login attempt within a different browser tab.

- [https://github.com/ignis-sec/CVE-2019-10008](https://github.com/ignis-sec/CVE-2019-10008) :  ![starts](https://img.shields.io/github/stars/ignis-sec/CVE-2019-10008.svg) ![forks](https://img.shields.io/github/forks/ignis-sec/CVE-2019-10008.svg)


## CVE-2019-8979
 Kohana through 3.3.6 has SQL Injection when the order_by() parameter can be controlled.

- [https://github.com/elttam/ko7demo](https://github.com/elttam/ko7demo) :  ![starts](https://img.shields.io/github/stars/elttam/ko7demo.svg) ![forks](https://img.shields.io/github/forks/elttam/ko7demo.svg)


## CVE-2018-19422
 /panel/uploads in Subrion CMS 4.2.1 allows remote attackers to execute arbitrary PHP code via a .pht or .phar file, because the .htaccess file omits these.

- [https://github.com/hevox/CVE-2018-19422-SubrionCMS-RCE](https://github.com/hevox/CVE-2018-19422-SubrionCMS-RCE) :  ![starts](https://img.shields.io/github/stars/hevox/CVE-2018-19422-SubrionCMS-RCE.svg) ![forks](https://img.shields.io/github/forks/hevox/CVE-2018-19422-SubrionCMS-RCE.svg)


## CVE-2016-10555
 Since &quot;algorithm&quot; isn't enforced in jwt.decode()in jwt-simple 0.3.0 and earlier, a malicious user could choose what algorithm is sent sent to the server. If the server is expecting RSA but is sent HMAC-SHA with RSA's public key, the server will think the public key is actually an HMAC private key. This could be used to forge any data an attacker wants.

- [https://github.com/FroydCod3r/poc-cve-2016-10555](https://github.com/FroydCod3r/poc-cve-2016-10555) :  ![starts](https://img.shields.io/github/stars/FroydCod3r/poc-cve-2016-10555.svg) ![forks](https://img.shields.io/github/forks/FroydCod3r/poc-cve-2016-10555.svg)

