# Update 2025-10-15
## CVE-2025-61984
 ssh in OpenSSH before 10.1 allows control characters in usernames that originate from certain possibly untrusted sources, potentially leading to code execution when a ProxyCommand is used. The untrusted sources are the command line and %-sequence expansion of a configuration file. (A configuration file that provides a complete literal username is not categorized as an untrusted source.)

- [https://github.com/ThanhCT-CyX/Test-CVE-2025-61984](https://github.com/ThanhCT-CyX/Test-CVE-2025-61984) :  ![starts](https://img.shields.io/github/stars/ThanhCT-CyX/Test-CVE-2025-61984.svg) ![forks](https://img.shields.io/github/forks/ThanhCT-CyX/Test-CVE-2025-61984.svg)


## CVE-2025-61884
 Vulnerability in the Oracle Configurator product of Oracle E-Business Suite (component: Runtime UI).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Configurator.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle Configurator accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/rxerium/CVE-2025-61882-CVE-2025-61884](https://github.com/rxerium/CVE-2025-61882-CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-61882-CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-61882-CVE-2025-61884.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-61884](https://github.com/B1ack4sh/Blackash-CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-61884.svg)


## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/rxerium/CVE-2025-61882-CVE-2025-61884](https://github.com/rxerium/CVE-2025-61882-CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-61882-CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-61882-CVE-2025-61884.svg)


## CVE-2025-59489
 Unity Runtime before 2025-10-02 on Android, Windows, macOS, and Linux allows argument injection that can result in loading of library code from an unintended location. If an application was built with a version of Unity Editor that had the vulnerable Unity Runtime code, then an adversary may be able to execute code on, and exfiltrate confidential information from, the machine on which that application is running. NOTE: product status is provided for Unity Editor because that is the information available from the Supplier. However, updating Unity Editor typically does not address the effects of the vulnerability; instead, it is necessary to rebuild and redeploy all affected applications.

- [https://github.com/AdriianFdz/Exploit-CVE-2025-59489](https://github.com/AdriianFdz/Exploit-CVE-2025-59489) :  ![starts](https://img.shields.io/github/stars/AdriianFdz/Exploit-CVE-2025-59489.svg) ![forks](https://img.shields.io/github/forks/AdriianFdz/Exploit-CVE-2025-59489.svg)


## CVE-2025-59246
 Azure Entra ID Elevation of Privilege Vulnerability

- [https://github.com/callinston/CVE-2025-59246](https://github.com/callinston/CVE-2025-59246) :  ![starts](https://img.shields.io/github/stars/callinston/CVE-2025-59246.svg) ![forks](https://img.shields.io/github/forks/callinston/CVE-2025-59246.svg)


## CVE-2025-57203
 MagicProject AI version 9.1 is affected by a Cross-Site Scripting (XSS) vulnerability within the chatbot generation feature available to authenticated admin users. The vulnerability resides in the prompt parameter submitted to the /dashboard/user/generator/generate-stream endpoint via a multipart/form-data POST request. Due to insufficient input sanitization, attackers can inject HTML-based JavaScript payloads. This payload is stored and rendered unsanitized in subsequent views, leading to execution in other users' browsers when they access affected content. This issue allows an authenticated attacker to execute arbitrary JavaScript in the context of another user, potentially leading to session hijacking, privilege escalation, data exfiltration, or administrative account takeover. The application does not implement a Content Security Policy (CSP) or adequate input filtering to prevent such attacks. A fix should include proper sanitization, output encoding, and strong CSP enforcement to mitigate exploitation.

- [https://github.com/xchg-rax-rax/AvTech-PoCs](https://github.com/xchg-rax-rax/AvTech-PoCs) :  ![starts](https://img.shields.io/github/stars/xchg-rax-rax/AvTech-PoCs.svg) ![forks](https://img.shields.io/github/forks/xchg-rax-rax/AvTech-PoCs.svg)


## CVE-2025-39913
 /IRQ

- [https://github.com/byteReaper77/CVE-2025-39913](https://github.com/byteReaper77/CVE-2025-39913) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-39913.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-39913.svg)


## CVE-2025-27817
Since Apache Kafka 3.9.1/4.0.0, we have added a system property ("-Dorg.apache.kafka.sasl.oauthbearer.allowed.urls") to set the allowed urls in SASL JAAS configuration. In 3.9.1, it accepts all urls by default for backward compatibility. However in 4.0.0 and newer, the default value is empty list and users have to set the allowed urls explicitly.

- [https://github.com/oriolrius/kafka-keycloak-oauth](https://github.com/oriolrius/kafka-keycloak-oauth) :  ![starts](https://img.shields.io/github/stars/oriolrius/kafka-keycloak-oauth.svg) ![forks](https://img.shields.io/github/forks/oriolrius/kafka-keycloak-oauth.svg)


## CVE-2025-11171
 The Chartify – WordPress Chart Plugin for WordPress is vulnerable to Missing Authentication for Critical Function in all versions up to, and including, 3.5.9. This is due to the plugin registering an unauthenticated AJAX action that dispatches to admin-class methods based on a request parameter, without any nonce or capability checks. This makes it possible for unauthenticated attackers to execute administrative functions via the wp-admin/admin-ajax.php endpoint granted they can identify callable method names.

- [https://github.com/SnailSploit/CVE-2025-11171---GitHub-Security-Advisory](https://github.com/SnailSploit/CVE-2025-11171---GitHub-Security-Advisory) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2025-11171---GitHub-Security-Advisory.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2025-11171---GitHub-Security-Advisory.svg)


## CVE-2024-43425
 A flaw was found in Moodle. Additional restrictions are required to avoid a remote code execution risk in calculated question types. Note: This requires the capability to add/update questions.

- [https://github.com/Tnot123/cve-2024-43425](https://github.com/Tnot123/cve-2024-43425) :  ![starts](https://img.shields.io/github/stars/Tnot123/cve-2024-43425.svg) ![forks](https://img.shields.io/github/forks/Tnot123/cve-2024-43425.svg)


## CVE-2024-39930
 The built-in SSH server of Gogs through 0.13.0 allows argument injection in internal/ssh/ssh.go, leading to remote code execution. Authenticated attackers can exploit this by opening an SSH connection and sending a malicious --split-string env request if the built-in SSH server is activated. Windows installations are unaffected.

- [https://github.com/laachy/CVE-2024-39930-ptrace-detection-mitigation](https://github.com/laachy/CVE-2024-39930-ptrace-detection-mitigation) :  ![starts](https://img.shields.io/github/stars/laachy/CVE-2024-39930-ptrace-detection-mitigation.svg) ![forks](https://img.shields.io/github/forks/laachy/CVE-2024-39930-ptrace-detection-mitigation.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux](https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux) :  ![starts](https://img.shields.io/github/stars/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg) ![forks](https://img.shields.io/github/forks/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg)


## CVE-2017-12542
 A authentication bypass and execution of code vulnerability in HPE Integrated Lights-out 4 (iLO 4) version prior to 2.53 was found.

- [https://github.com/VijayShankar22/CVE-2017-12542](https://github.com/VijayShankar22/CVE-2017-12542) :  ![starts](https://img.shields.io/github/stars/VijayShankar22/CVE-2017-12542.svg) ![forks](https://img.shields.io/github/forks/VijayShankar22/CVE-2017-12542.svg)

