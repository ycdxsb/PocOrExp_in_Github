# Update 2022-10-24
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/jayaram-yalla/CVE-2022-42889-POC_TEXT4SHELL](https://github.com/jayaram-yalla/CVE-2022-42889-POC_TEXT4SHELL) :  ![starts](https://img.shields.io/github/stars/jayaram-yalla/CVE-2022-42889-POC_TEXT4SHELL.svg) ![forks](https://img.shields.io/github/forks/jayaram-yalla/CVE-2022-42889-POC_TEXT4SHELL.svg)
- [https://github.com/akshayithape-devops/CVE-2022-42889-POC](https://github.com/akshayithape-devops/CVE-2022-42889-POC) :  ![starts](https://img.shields.io/github/stars/akshayithape-devops/CVE-2022-42889-POC.svg) ![forks](https://img.shields.io/github/forks/akshayithape-devops/CVE-2022-42889-POC.svg)
- [https://github.com/galoget/CVE-2022-42889-Text4Shell-Docker](https://github.com/galoget/CVE-2022-42889-Text4Shell-Docker) :  ![starts](https://img.shields.io/github/stars/galoget/CVE-2022-42889-Text4Shell-Docker.svg) ![forks](https://img.shields.io/github/forks/galoget/CVE-2022-42889-Text4Shell-Docker.svg)
- [https://github.com/rhitikwadhvana/CVE-2022-42889-Text4Shell-Exploit-POC](https://github.com/rhitikwadhvana/CVE-2022-42889-Text4Shell-Exploit-POC) :  ![starts](https://img.shields.io/github/stars/rhitikwadhvana/CVE-2022-42889-Text4Shell-Exploit-POC.svg) ![forks](https://img.shields.io/github/forks/rhitikwadhvana/CVE-2022-42889-Text4Shell-Exploit-POC.svg)


## CVE-2022-41082
 Microsoft Exchange Server Remote Code Execution Vulnerability.

- [https://github.com/stat1st1c/CVE-2022-41082-RCE-POC](https://github.com/stat1st1c/CVE-2022-41082-RCE-POC) :  ![starts](https://img.shields.io/github/stars/stat1st1c/CVE-2022-41082-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/stat1st1c/CVE-2022-41082-RCE-POC.svg)


## CVE-2022-41040
 Microsoft Exchange Server Elevation of Privilege Vulnerability.

- [https://github.com/stat1st1c/CVE-2022-41082-RCE-POC](https://github.com/stat1st1c/CVE-2022-41082-RCE-POC) :  ![starts](https://img.shields.io/github/stars/stat1st1c/CVE-2022-41082-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/stat1st1c/CVE-2022-41082-RCE-POC.svg)


## CVE-2022-39197
 An XSS (Cross Site Scripting) vulnerability was found in HelpSystems Cobalt Strike through 4.7 that allowed a remote attacker to execute HTML on the Cobalt Strike teamserver. To exploit the vulnerability, one must first inspect a Cobalt Strike payload, and then modify the username field in the payload (or create a new payload with the extracted information and then modify that username field to be malformed).

- [https://github.com/TheCryingGame/CVE-2022-39197-RCE](https://github.com/TheCryingGame/CVE-2022-39197-RCE) :  ![starts](https://img.shields.io/github/stars/TheCryingGame/CVE-2022-39197-RCE.svg) ![forks](https://img.shields.io/github/forks/TheCryingGame/CVE-2022-39197-RCE.svg)


## CVE-2022-36663
 Gluu Oxauth before v4.4.1 allows attackers to execute blind SSRF (Server-Side Request Forgery) attacks via a crafted request_uri parameter.

- [https://github.com/Qeisi/CVE-2022-36663-PoC](https://github.com/Qeisi/CVE-2022-36663-PoC) :  ![starts](https://img.shields.io/github/stars/Qeisi/CVE-2022-36663-PoC.svg) ![forks](https://img.shields.io/github/forks/Qeisi/CVE-2022-36663-PoC.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/zhzyker/CVE-2021-4034](https://github.com/zhzyker/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/zhzyker/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/zhzyker/CVE-2021-4034.svg)
- [https://github.com/c3l3si4n/pwnkit](https://github.com/c3l3si4n/pwnkit) :  ![starts](https://img.shields.io/github/stars/c3l3si4n/pwnkit.svg) ![forks](https://img.shields.io/github/forks/c3l3si4n/pwnkit.svg)
- [https://github.com/dadvlingd/-CVE-2021-4034](https://github.com/dadvlingd/-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/dadvlingd/-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dadvlingd/-CVE-2021-4034.svg)
- [https://github.com/chenaotian/CVE-2021-4034](https://github.com/chenaotian/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2021-4034.svg)
- [https://github.com/FDlucifer/Pwnkit-go](https://github.com/FDlucifer/Pwnkit-go) :  ![starts](https://img.shields.io/github/stars/FDlucifer/Pwnkit-go.svg) ![forks](https://img.shields.io/github/forks/FDlucifer/Pwnkit-go.svg)
- [https://github.com/Kirill89/CVE-2021-4034](https://github.com/Kirill89/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Kirill89/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Kirill89/CVE-2021-4034.svg)
- [https://github.com/x04000/CVE-2021-4034](https://github.com/x04000/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/x04000/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/x04000/CVE-2021-4034.svg)
- [https://github.com/nel0x/pwnkit-vulnerability](https://github.com/nel0x/pwnkit-vulnerability) :  ![starts](https://img.shields.io/github/stars/nel0x/pwnkit-vulnerability.svg) ![forks](https://img.shields.io/github/forks/nel0x/pwnkit-vulnerability.svg)


## CVE-2020-36518
 jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.

- [https://github.com/ghillert/boot-jackson-cve](https://github.com/ghillert/boot-jackson-cve) :  ![starts](https://img.shields.io/github/stars/ghillert/boot-jackson-cve.svg) ![forks](https://img.shields.io/github/forks/ghillert/boot-jackson-cve.svg)


## CVE-2020-15568
 TerraMaster TOS before 4.1.29 has Invalid Parameter Checking that leads to code injection as root. This is a dynamic class method invocation vulnerability in include/exportUser.php, in which an attacker can trigger a call to the exec method with (for example) OS commands in the opt parameter.

- [https://github.com/n0bugz/CVE-2020-15568](https://github.com/n0bugz/CVE-2020-15568) :  ![starts](https://img.shields.io/github/stars/n0bugz/CVE-2020-15568.svg) ![forks](https://img.shields.io/github/forks/n0bugz/CVE-2020-15568.svg)


## CVE-2017-0785
 A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.

- [https://github.com/sh4rknado/BlueBorn](https://github.com/sh4rknado/BlueBorn) :  ![starts](https://img.shields.io/github/stars/sh4rknado/BlueBorn.svg) ![forks](https://img.shields.io/github/forks/sh4rknado/BlueBorn.svg)


## CVE-2014-8731
 PHPMemcachedAdmin 1.2.2 and earlier allows remote attackers to execute arbitrary PHP code via vectors related &quot;serialized data and the last part of the concatenated filename,&quot; which creates a file in webroot.

- [https://github.com/sbani/CVE-2014-8731-PoC](https://github.com/sbani/CVE-2014-8731-PoC) :  ![starts](https://img.shields.io/github/stars/sbani/CVE-2014-8731-PoC.svg) ![forks](https://img.shields.io/github/forks/sbani/CVE-2014-8731-PoC.svg)

