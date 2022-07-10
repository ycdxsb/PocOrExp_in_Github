# Update 2022-07-10
## CVE-2022-34963
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/bypazs/CVE-2022-34963](https://github.com/bypazs/CVE-2022-34963) :  ![starts](https://img.shields.io/github/stars/bypazs/CVE-2022-34963.svg) ![forks](https://img.shields.io/github/forks/bypazs/CVE-2022-34963.svg)


## CVE-2022-33980
 Apache Commons Configuration performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.configuration2.interpol.Lookup that performs the interpolation. Starting with version 2.4 and continuing through 2.7, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Configuration 2.8.0, which disables the problematic interpolators by default.

- [https://github.com/tangxiaofeng7/CVE-2022-33980-Apache-Commons-Configuration-RCE](https://github.com/tangxiaofeng7/CVE-2022-33980-Apache-Commons-Configuration-RCE) :  ![starts](https://img.shields.io/github/stars/tangxiaofeng7/CVE-2022-33980-Apache-Commons-Configuration-RCE.svg) ![forks](https://img.shields.io/github/forks/tangxiaofeng7/CVE-2022-33980-Apache-Commons-Configuration-RCE.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/coskper-papa/CVE-2022-26134](https://github.com/coskper-papa/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/coskper-papa/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/coskper-papa/CVE-2022-26134.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/An00bRektn/CVE-2021-4034](https://github.com/An00bRektn/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/An00bRektn/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/An00bRektn/CVE-2021-4034.svg)
- [https://github.com/sofire/polkit-0.96-CVE-2021-4034](https://github.com/sofire/polkit-0.96-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/sofire/polkit-0.96-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/sofire/polkit-0.96-CVE-2021-4034.svg)
- [https://github.com/Nosferatuvjr/PwnKit](https://github.com/Nosferatuvjr/PwnKit) :  ![starts](https://img.shields.io/github/stars/Nosferatuvjr/PwnKit.svg) ![forks](https://img.shields.io/github/forks/Nosferatuvjr/PwnKit.svg)
- [https://github.com/OxWeb4/CVE-2021-4034-](https://github.com/OxWeb4/CVE-2021-4034-) :  ![starts](https://img.shields.io/github/stars/OxWeb4/CVE-2021-4034-.svg) ![forks](https://img.shields.io/github/forks/OxWeb4/CVE-2021-4034-.svg)
- [https://github.com/puckiestyle/CVE-2021-4034](https://github.com/puckiestyle/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-4034.svg)
- [https://github.com/deoxykev/CVE-2021-4034-Rust](https://github.com/deoxykev/CVE-2021-4034-Rust) :  ![starts](https://img.shields.io/github/stars/deoxykev/CVE-2021-4034-Rust.svg) ![forks](https://img.shields.io/github/forks/deoxykev/CVE-2021-4034-Rust.svg)
- [https://github.com/scent2d/PoC-CVE-2021-4034](https://github.com/scent2d/PoC-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/scent2d/PoC-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/scent2d/PoC-CVE-2021-4034.svg)
- [https://github.com/0x4ndy/CVE-2021-4034-PoC](https://github.com/0x4ndy/CVE-2021-4034-PoC) :  ![starts](https://img.shields.io/github/stars/0x4ndy/CVE-2021-4034-PoC.svg) ![forks](https://img.shields.io/github/forks/0x4ndy/CVE-2021-4034-PoC.svg)
- [https://github.com/pyhrr0/pwnkit](https://github.com/pyhrr0/pwnkit) :  ![starts](https://img.shields.io/github/stars/pyhrr0/pwnkit.svg) ![forks](https://img.shields.io/github/forks/pyhrr0/pwnkit.svg)


## CVE-2020-13401
 An issue was discovered in Docker Engine before 19.03.11. An attacker in a container, with the CAP_NET_RAW capability, can craft IPv6 router advertisements, and consequently spoof external IPv6 hosts, obtain sensitive information, or cause a denial of service.

- [https://github.com/arax-zaeimi/Docker-Container-CVE-2020-13401](https://github.com/arax-zaeimi/Docker-Container-CVE-2020-13401) :  ![starts](https://img.shields.io/github/stars/arax-zaeimi/Docker-Container-CVE-2020-13401.svg) ![forks](https://img.shields.io/github/forks/arax-zaeimi/Docker-Container-CVE-2020-13401.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/Chethine/EsFileExplorer-CVE-2019-6447](https://github.com/Chethine/EsFileExplorer-CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/Chethine/EsFileExplorer-CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/Chethine/EsFileExplorer-CVE-2019-6447.svg)


## CVE-2019-1040
 A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection, aka 'Windows NTLM Tampering Vulnerability'.

- [https://github.com/fox-it/cve-2019-1040-scanner](https://github.com/fox-it/cve-2019-1040-scanner) :  ![starts](https://img.shields.io/github/stars/fox-it/cve-2019-1040-scanner.svg) ![forks](https://img.shields.io/github/forks/fox-it/cve-2019-1040-scanner.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/mmeza-developer/go--CVE-2018-6574](https://github.com/mmeza-developer/go--CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/mmeza-developer/go--CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/mmeza-developer/go--CVE-2018-6574.svg)


## CVE-2015-4024
 Algorithmic complexity vulnerability in the multipart_buffer_headers function in main/rfc1867.c in PHP before 5.4.41, 5.5.x before 5.5.25, and 5.6.x before 5.6.9 allows remote attackers to cause a denial of service (CPU consumption) via crafted form data that triggers an improper order-of-growth outcome.

- [https://github.com/typcn/php-load-test](https://github.com/typcn/php-load-test) :  ![starts](https://img.shields.io/github/stars/typcn/php-load-test.svg) ![forks](https://img.shields.io/github/forks/typcn/php-load-test.svg)

