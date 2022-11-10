# Update 2022-11-10
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/karthikuj/cve-2022-42889-text4shell-docker](https://github.com/karthikuj/cve-2022-42889-text4shell-docker) :  ![starts](https://img.shields.io/github/stars/karthikuj/cve-2022-42889-text4shell-docker.svg) ![forks](https://img.shields.io/github/forks/karthikuj/cve-2022-42889-text4shell-docker.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/iloveflag/Fast-CVE-2022-22965](https://github.com/iloveflag/Fast-CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/iloveflag/Fast-CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/iloveflag/Fast-CVE-2022-22965.svg)


## CVE-2022-20138
 In ACTION_MANAGED_PROFILE_PROVISIONED of DevicePolicyManagerService.java, there is a possible way for unprivileged app to send MANAGED_PROFILE_PROVISIONED intent due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-210469972

- [https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2022-20138](https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2022-20138) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_base_AOSP10_r33_CVE-2022-20138.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_base_AOSP10_r33_CVE-2022-20138.svg)


## CVE-2022-3602
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash (causing a denial of service) or potentially remote code execution. Many platforms implement stack overflow protections which would mitigate against the risk of remote code execution. The risk may be further mitigated based on stack layout for any given platform/compiler. Pre-announcements of CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6).

- [https://github.com/corelight/CVE-2022-3602](https://github.com/corelight/CVE-2022-3602) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2022-3602.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2022-3602.svg)


## CVE-2022-0829
 Improper Authorization in GitHub repository webmin/webmin prior to 1.990.

- [https://github.com/gokul-ramesh/WebminRCE-exploit](https://github.com/gokul-ramesh/WebminRCE-exploit) :  ![starts](https://img.shields.io/github/stars/gokul-ramesh/WebminRCE-exploit.svg) ![forks](https://img.shields.io/github/forks/gokul-ramesh/WebminRCE-exploit.svg)


## CVE-2022-0824
 Improper Access Control to Remote Code Execution in GitHub repository webmin/webmin prior to 1.990.

- [https://github.com/gokul-ramesh/WebminRCE-exploit](https://github.com/gokul-ramesh/WebminRCE-exploit) :  ![starts](https://img.shields.io/github/stars/gokul-ramesh/WebminRCE-exploit.svg) ![forks](https://img.shields.io/github/forks/gokul-ramesh/WebminRCE-exploit.svg)


## CVE-2021-38819
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/m4sk0ff/CVE-2021-38819](https://github.com/m4sk0ff/CVE-2021-38819) :  ![starts](https://img.shields.io/github/stars/m4sk0ff/CVE-2021-38819.svg) ![forks](https://img.shields.io/github/forks/m4sk0ff/CVE-2021-38819.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/sai-reddy2021/CVE-2021-1675-LPE](https://github.com/sai-reddy2021/CVE-2021-1675-LPE) :  ![starts](https://img.shields.io/github/stars/sai-reddy2021/CVE-2021-1675-LPE.svg) ![forks](https://img.shields.io/github/forks/sai-reddy2021/CVE-2021-1675-LPE.svg)


## CVE-2018-1000117
 Python Software Foundation CPython version From 3.2 until 3.6.4 on Windows contains a Buffer Overflow vulnerability in os.symlink() function on Windows that can result in Arbitrary code execution, likely escalation of privilege. This attack appears to be exploitable via a python script that creates a symlink with an attacker controlled name or location. This vulnerability appears to have been fixed in 3.7.0 and 3.6.5.

- [https://github.com/u0pattern/CVE-2018-1000117-Exploit](https://github.com/u0pattern/CVE-2018-1000117-Exploit) :  ![starts](https://img.shields.io/github/stars/u0pattern/CVE-2018-1000117-Exploit.svg) ![forks](https://img.shields.io/github/forks/u0pattern/CVE-2018-1000117-Exploit.svg)


## CVE-2018-13405
 The inode_init_owner function in fs/inode.c in the Linux kernel through 3.16 allows local users to create files with an unintended group ownership, in a scenario where a directory is SGID to a certain group and is writable by a user who is not a member of that group. Here, the non-member can trigger creation of a plain file whose group ownership is that group. The intended behavior was that the non-member can trigger creation of a directory (but not a plain file) whose group ownership is that group. The non-member can escalate privileges by making the plain file executable and SGID.

- [https://github.com/nidhi7598/linux-3.0.35_CVE-2018-13405](https://github.com/nidhi7598/linux-3.0.35_CVE-2018-13405) :  ![starts](https://img.shields.io/github/stars/nidhi7598/linux-3.0.35_CVE-2018-13405.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/linux-3.0.35_CVE-2018-13405.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/jeyaseelans86/CVE-2018-6574](https://github.com/jeyaseelans86/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/jeyaseelans86/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/jeyaseelans86/CVE-2018-6574.svg)
- [https://github.com/jeyaseelans86/new-CVE-2018-6574](https://github.com/jeyaseelans86/new-CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/jeyaseelans86/new-CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/jeyaseelans86/new-CVE-2018-6574.svg)
- [https://github.com/chr1sM/CVE-2018-6574](https://github.com/chr1sM/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/chr1sM/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/chr1sM/CVE-2018-6574.svg)

