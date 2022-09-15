# Update 2022-09-15
## CVE-2022-37703
 In Amanda 3.5.1, an information leak vulnerability was found in the calcsize SUID binary. An attacker can abuse this vulnerability to know if a directory exists or not anywhere in the fs. The binary will use `opendir()` as root directly without checking the path, letting the attacker provide an arbitrary path.

- [https://github.com/MaherAzzouzi/CVE-2022-37703](https://github.com/MaherAzzouzi/CVE-2022-37703) :  ![starts](https://img.shields.io/github/stars/MaherAzzouzi/CVE-2022-37703.svg) ![forks](https://img.shields.io/github/forks/MaherAzzouzi/CVE-2022-37703.svg)


## CVE-2022-35841
 Windows Enterprise App Management Service Remote Code Execution Vulnerability.

- [https://github.com/Wack0/CVE-2022-35841](https://github.com/Wack0/CVE-2022-35841) :  ![starts](https://img.shields.io/github/stars/Wack0/CVE-2022-35841.svg) ![forks](https://img.shields.io/github/forks/Wack0/CVE-2022-35841.svg)


## CVE-2022-34715
 Windows Network File System Remote Code Execution Vulnerability.

- [https://github.com/Starssgo/CVE-2022-34715-POC](https://github.com/Starssgo/CVE-2022-34715-POC) :  ![starts](https://img.shields.io/github/stars/Starssgo/CVE-2022-34715-POC.svg) ![forks](https://img.shields.io/github/forks/Starssgo/CVE-2022-34715-POC.svg)


## CVE-2022-20186
 In kbase_mem_alias of mali_kbase_mem_linux.c, there is a possible arbitrary code execution due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-215001024References: N/A

- [https://github.com/SmileTabLabo/CVE-2022-20186_CTXZ](https://github.com/SmileTabLabo/CVE-2022-20186_CTXZ) :  ![starts](https://img.shields.io/github/stars/SmileTabLabo/CVE-2022-20186_CTXZ.svg) ![forks](https://img.shields.io/github/forks/SmileTabLabo/CVE-2022-20186_CTXZ.svg)


## CVE-2022-1292
 The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n). Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd).

- [https://github.com/und3sc0n0c1d0/CVE-2022-1292](https://github.com/und3sc0n0c1d0/CVE-2022-1292) :  ![starts](https://img.shields.io/github/stars/und3sc0n0c1d0/CVE-2022-1292.svg) ![forks](https://img.shields.io/github/forks/und3sc0n0c1d0/CVE-2022-1292.svg)


## CVE-2020-8515
 DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta, and Vigor300B 1.3.3_Beta, 1.4.2.1_Beta, and 1.4.4_Beta devices allow remote code execution as root (without authentication) via shell metacharacters to the cgi-bin/mainfunction.cgi URI. This issue has been fixed in Vigor3900/2960/300B v1.5.1.

- [https://github.com/trhacknon/CVE-2020-8515](https://github.com/trhacknon/CVE-2020-8515) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2020-8515.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2020-8515.svg)
- [https://github.com/trhacknon/CVE-2020-8515-PoC](https://github.com/trhacknon/CVE-2020-8515-PoC) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2020-8515-PoC.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2020-8515-PoC.svg)


## CVE-2020-1947
 In Apache ShardingSphere(incubator) 4.0.0-RC3 and 4.0.0, the ShardingSphere's web console uses the SnakeYAML library for parsing YAML inputs to load datasource configuration. SnakeYAML allows to unmarshal data to a Java type By using the YAML tag. Unmarshalling untrusted data can lead to security flaws of RCE.

- [https://github.com/EdwardChristmas/CVE-2020-1947](https://github.com/EdwardChristmas/CVE-2020-1947) :  ![starts](https://img.shields.io/github/stars/EdwardChristmas/CVE-2020-1947.svg) ![forks](https://img.shields.io/github/forks/EdwardChristmas/CVE-2020-1947.svg)


## CVE-2019-9766
 Stack-based buffer overflow in Free MP3 CD Ripper 2.6, when converting a file, allows user-assisted remote attackers to execute arbitrary code via a crafted .mp3 file.

- [https://github.com/zeronohacker/CVE-2019-9766](https://github.com/zeronohacker/CVE-2019-9766) :  ![starts](https://img.shields.io/github/stars/zeronohacker/CVE-2019-9766.svg) ![forks](https://img.shields.io/github/forks/zeronohacker/CVE-2019-9766.svg)

