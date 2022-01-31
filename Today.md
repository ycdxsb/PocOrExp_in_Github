# Update 2022-01-31
## CVE-2022-24032
 Adenza AxiomSL ControllerView through 10.8.1 is vulnerable to user enumeration. An attacker can identify valid usernames on the platform because a failed login attempt produces a different error message when the username is valid.

- [https://github.com/jdordonezn/CVE-2022-24032](https://github.com/jdordonezn/CVE-2022-24032) :  ![starts](https://img.shields.io/github/stars/jdordonezn/CVE-2022-24032.svg) ![forks](https://img.shields.io/github/forks/jdordonezn/CVE-2022-24032.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/RtlCyclone/CVE_2022_21907-poc](https://github.com/RtlCyclone/CVE_2022_21907-poc) :  ![starts](https://img.shields.io/github/stars/RtlCyclone/CVE_2022_21907-poc.svg) ![forks](https://img.shields.io/github/forks/RtlCyclone/CVE_2022_21907-poc.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/0xBruno/CVE-2021-22204](https://github.com/0xBruno/CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/0xBruno/CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/0xBruno/CVE-2021-22204.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/OxWeb4/CVE-2021-4034-](https://github.com/OxWeb4/CVE-2021-4034-) :  ![starts](https://img.shields.io/github/stars/OxWeb4/CVE-2021-4034-.svg) ![forks](https://img.shields.io/github/forks/OxWeb4/CVE-2021-4034-.svg)
- [https://github.com/navisec/CVE-2021-4034-PwnKit](https://github.com/navisec/CVE-2021-4034-PwnKit) :  ![starts](https://img.shields.io/github/stars/navisec/CVE-2021-4034-PwnKit.svg) ![forks](https://img.shields.io/github/forks/navisec/CVE-2021-4034-PwnKit.svg)
- [https://github.com/sofire/polkit-0.96-CVE-2021-4034](https://github.com/sofire/polkit-0.96-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/sofire/polkit-0.96-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/sofire/polkit-0.96-CVE-2021-4034.svg)
- [https://github.com/codiobert/pwnkit-scanner](https://github.com/codiobert/pwnkit-scanner) :  ![starts](https://img.shields.io/github/stars/codiobert/pwnkit-scanner.svg) ![forks](https://img.shields.io/github/forks/codiobert/pwnkit-scanner.svg)
- [https://github.com/v-rzh/CVE-2021-4034](https://github.com/v-rzh/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/v-rzh/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/v-rzh/CVE-2021-4034.svg)
- [https://github.com/TW-D/PwnKit-Vulnerability_CVE-2021-4034](https://github.com/TW-D/PwnKit-Vulnerability_CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/TW-D/PwnKit-Vulnerability_CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/TW-D/PwnKit-Vulnerability_CVE-2021-4034.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/jm33-m0/CVE-2021-3156](https://github.com/jm33-m0/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/jm33-m0/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/jm33-m0/CVE-2021-3156.svg)
- [https://github.com/freeFV/CVE-2021-3156](https://github.com/freeFV/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/freeFV/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/freeFV/CVE-2021-3156.svg)


## CVE-2021-0928
 In createFromParcel of OutputConfiguration.java, there is a possible parcel serialization/deserialization mismatch due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-9Android ID: A-188675581

- [https://github.com/michalbednarski/ReparcelBug2](https://github.com/michalbednarski/ReparcelBug2) :  ![starts](https://img.shields.io/github/stars/michalbednarski/ReparcelBug2.svg) ![forks](https://img.shields.io/github/forks/michalbednarski/ReparcelBug2.svg)


## CVE-2020-35476
 A remote code execution vulnerability occurs in OpenTSDB through 2.4.0 via command injection in the yrange parameter. The yrange value is written to a gnuplot file in the /tmp directory. This file is then executed via the mygnuplot.sh shell script. (tsd/GraphHandler.java attempted to prevent command injections by blocking backticks but this is insufficient.)

- [https://github.com/glowbase/CVE-2020-35476](https://github.com/glowbase/CVE-2020-35476) :  ![starts](https://img.shields.io/github/stars/glowbase/CVE-2020-35476.svg) ![forks](https://img.shields.io/github/forks/glowbase/CVE-2020-35476.svg)

