# Update 2021-05-15
## CVE-2021-32471
 Insufficient input validation in the Marvin Minsky 1967 implementation of the Universal Turing Machine allows program users to execute arbitrary code via crafted data. For example, a tape head may have an unexpected location after the processing of input composed of As and Bs (instead of 0s and 1s). NOTE: the discoverer states &quot;this vulnerability has no real-world implications.&quot;

- [https://github.com/intrinsic-propensity/turing-machine](https://github.com/intrinsic-propensity/turing-machine) :  ![starts](https://img.shields.io/github/stars/intrinsic-propensity/turing-machine.svg) ![forks](https://img.shields.io/github/forks/intrinsic-propensity/turing-machine.svg)


## CVE-2021-27342
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/guywhataguy/D-Link-CVE-2021-27342-exploit](https://github.com/guywhataguy/D-Link-CVE-2021-27342-exploit) :  ![starts](https://img.shields.io/github/stars/guywhataguy/D-Link-CVE-2021-27342-exploit.svg) ![forks](https://img.shields.io/github/forks/guywhataguy/D-Link-CVE-2021-27342-exploit.svg)


## CVE-2021-26295
 Apache OFBiz has unsafe deserialization prior to 17.12.06. An unauthenticated attacker can use this vulnerability to successfully take over Apache OFBiz.

- [https://github.com/yuaneuro/ofbiz-poc](https://github.com/yuaneuro/ofbiz-poc) :  ![starts](https://img.shields.io/github/stars/yuaneuro/ofbiz-poc.svg) ![forks](https://img.shields.io/github/forks/yuaneuro/ofbiz-poc.svg)


## CVE-2021-21551
 Dell dbutil_2_3.sys driver contains an insufficient access control vulnerability which may lead to escalation of privileges, denial of service, or information disclosure. Local authenticated user access is required.

- [https://github.com/waldo-irc/CVE-2021-21551](https://github.com/waldo-irc/CVE-2021-21551) :  ![starts](https://img.shields.io/github/stars/waldo-irc/CVE-2021-21551.svg) ![forks](https://img.shields.io/github/forks/waldo-irc/CVE-2021-21551.svg)


## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.

- [https://github.com/tao-sun2/CVE-2021-21300](https://github.com/tao-sun2/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/tao-sun2/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/tao-sun2/CVE-2021-21300.svg)


## CVE-2021-20202
 A flaw was found in keycloak. Directories can be created prior to the Java process creating them in the temporary directory, but with wider user permissions, allowing the attacker to have access to the contents that keycloak stores in this directory. The highest threat from this vulnerability is to data confidentiality and integrity.

- [https://github.com/Jarry1sec/CVE-2021-20202](https://github.com/Jarry1sec/CVE-2021-20202) :  ![starts](https://img.shields.io/github/stars/Jarry1sec/CVE-2021-20202.svg) ![forks](https://img.shields.io/github/forks/Jarry1sec/CVE-2021-20202.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/wuuconix/CVE-2021-3156-Dockerfile-not-succeed](https://github.com/wuuconix/CVE-2021-3156-Dockerfile-not-succeed) :  ![starts](https://img.shields.io/github/stars/wuuconix/CVE-2021-3156-Dockerfile-not-succeed.svg) ![forks](https://img.shields.io/github/forks/wuuconix/CVE-2021-3156-Dockerfile-not-succeed.svg)


## CVE-2021-2109
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/yuaneuro/CVE-2021-2109_poc](https://github.com/yuaneuro/CVE-2021-2109_poc) :  ![starts](https://img.shields.io/github/stars/yuaneuro/CVE-2021-2109_poc.svg) ![forks](https://img.shields.io/github/forks/yuaneuro/CVE-2021-2109_poc.svg)


## CVE-2021-2021
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/TheCryingGame/CVE-2021-2021good](https://github.com/TheCryingGame/CVE-2021-2021good) :  ![starts](https://img.shields.io/github/stars/TheCryingGame/CVE-2021-2021good.svg) ![forks](https://img.shields.io/github/forks/TheCryingGame/CVE-2021-2021good.svg)


## CVE-2021-1456
 Multiple vulnerabilities in the web-based management interface of Cisco Firepower Management Center (FMC) Software could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of the interface. These vulnerabilities are due to insufficient validation of user-supplied input by the web-based management interface. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or access sensitive, browser-based information.

- [https://github.com/Jarry1sec/CVE-2021-14562](https://github.com/Jarry1sec/CVE-2021-14562) :  ![starts](https://img.shields.io/github/stars/Jarry1sec/CVE-2021-14562.svg) ![forks](https://img.shields.io/github/forks/Jarry1sec/CVE-2021-14562.svg)


## CVE-2020-28018
 Exim 4 before 4.94.2 allows Use After Free in smtp_reset in certain situations that may be common for builds with OpenSSL.

- [https://github.com/lmol/CVE-2020-28018](https://github.com/lmol/CVE-2020-28018) :  ![starts](https://img.shields.io/github/stars/lmol/CVE-2020-28018.svg) ![forks](https://img.shields.io/github/forks/lmol/CVE-2020-28018.svg)


## CVE-2020-27955
 Git LFS 2.12.0 allows Remote Code Execution.

- [https://github.com/qzyqzynb/CVE-2020-27955](https://github.com/qzyqzynb/CVE-2020-27955) :  ![starts](https://img.shields.io/github/stars/qzyqzynb/CVE-2020-27955.svg) ![forks](https://img.shields.io/github/forks/qzyqzynb/CVE-2020-27955.svg)


## CVE-2020-9496
 XML-RPC request are vulnerable to unsafe deserialization and Cross-Site Scripting issues in Apache OFBiz 17.12.03

- [https://github.com/yuaneuro/ofbiz-poc](https://github.com/yuaneuro/ofbiz-poc) :  ![starts](https://img.shields.io/github/stars/yuaneuro/ofbiz-poc.svg) ![forks](https://img.shields.io/github/forks/yuaneuro/ofbiz-poc.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/SUNNYSAINI01001/46635.py_CVE-2019-9053](https://github.com/SUNNYSAINI01001/46635.py_CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/SUNNYSAINI01001/46635.py_CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/SUNNYSAINI01001/46635.py_CVE-2019-9053.svg)


## CVE-2016-2098
 Action Pack in Ruby on Rails before 3.2.22.2, 4.x before 4.1.14.2, and 4.2.x before 4.2.5.2 allows remote attackers to execute arbitrary Ruby code by leveraging an application's unrestricted use of the render method.

- [https://github.com/0x00-0x00/CVE-2016-2098](https://github.com/0x00-0x00/CVE-2016-2098) :  ![starts](https://img.shields.io/github/stars/0x00-0x00/CVE-2016-2098.svg) ![forks](https://img.shields.io/github/forks/0x00-0x00/CVE-2016-2098.svg)
- [https://github.com/Debalinax64/CVE-2016-2098](https://github.com/Debalinax64/CVE-2016-2098) :  ![starts](https://img.shields.io/github/stars/Debalinax64/CVE-2016-2098.svg) ![forks](https://img.shields.io/github/forks/Debalinax64/CVE-2016-2098.svg)

