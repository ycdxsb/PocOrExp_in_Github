# Update 2025-07-18
## CVE-2025-52689
 Successful exploitation of the vulnerability could allow an unauthenticated attacker to obtain a valid session ID with administrator privileges by spoofing the login request, potentially allowing the attacker to modify the behaviour of the access point.

- [https://github.com/UltimateHG/CVE-2025-52689-PoC](https://github.com/UltimateHG/CVE-2025-52689-PoC) :  ![starts](https://img.shields.io/github/stars/UltimateHG/CVE-2025-52689-PoC.svg) ![forks](https://img.shields.io/github/forks/UltimateHG/CVE-2025-52689-PoC.svg)


## CVE-2025-52688
 Successful exploitation of the vulnerability could allow an attacker to inject commands with root privileges on the access point, potentially leading to the loss of confidentiality, integrity, availability, and full control of the access point.

- [https://github.com/joelczk/CVE-2025-52688](https://github.com/joelczk/CVE-2025-52688) :  ![starts](https://img.shields.io/github/stars/joelczk/CVE-2025-52688.svg) ![forks](https://img.shields.io/github/forks/joelczk/CVE-2025-52688.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/hackmelocal/HML-CVE-2025-49113-Round-Cube](https://github.com/hackmelocal/HML-CVE-2025-49113-Round-Cube) :  ![starts](https://img.shields.io/github/stars/hackmelocal/HML-CVE-2025-49113-Round-Cube.svg) ![forks](https://img.shields.io/github/forks/hackmelocal/HML-CVE-2025-49113-Round-Cube.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/nguyentranbaotran/cve-2025-48384-poc](https://github.com/nguyentranbaotran/cve-2025-48384-poc) :  ![starts](https://img.shields.io/github/stars/nguyentranbaotran/cve-2025-48384-poc.svg) ![forks](https://img.shields.io/github/forks/nguyentranbaotran/cve-2025-48384-poc.svg)
- [https://github.com/altm4n/cve-2025-48384](https://github.com/altm4n/cve-2025-48384) :  ![starts](https://img.shields.io/github/stars/altm4n/cve-2025-48384.svg) ![forks](https://img.shields.io/github/forks/altm4n/cve-2025-48384.svg)
- [https://github.com/altm4n/cve-2025-48384-hub](https://github.com/altm4n/cve-2025-48384-hub) :  ![starts](https://img.shields.io/github/stars/altm4n/cve-2025-48384-hub.svg) ![forks](https://img.shields.io/github/forks/altm4n/cve-2025-48384-hub.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/rxerium/CVE-2025-47812](https://github.com/rxerium/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-47812.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/Floodnut/CVE-2025-32463](https://github.com/Floodnut/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/Floodnut/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/Floodnut/CVE-2025-32463.svg)
- [https://github.com/92gmuz/CVE-2025-32463](https://github.com/92gmuz/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/92gmuz/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/92gmuz/CVE-2025-32463.svg)
- [https://github.com/krypton-0x00/CVE-2025-32463-Chwoot-POC](https://github.com/krypton-0x00/CVE-2025-32463-Chwoot-POC) :  ![starts](https://img.shields.io/github/stars/krypton-0x00/CVE-2025-32463-Chwoot-POC.svg) ![forks](https://img.shields.io/github/forks/krypton-0x00/CVE-2025-32463-Chwoot-POC.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-32432](https://github.com/B1ack4sh/Blackash-CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-32432.svg)


## CVE-2025-27521
Impact: Successful exploitation of this vulnerability may affect service confidentiality.

- [https://github.com/alialucas7/CVE-2025-27521_PoC](https://github.com/alialucas7/CVE-2025-27521_PoC) :  ![starts](https://img.shields.io/github/stars/alialucas7/CVE-2025-27521_PoC.svg) ![forks](https://img.shields.io/github/forks/alialucas7/CVE-2025-27521_PoC.svg)


## CVE-2025-22870
 Matching of hosts against proxy patterns can improperly treat an IPv6 zone ID as a hostname component. For example, when the NO_PROXY environment variable is set to "*.example.com", a request to "[::1%25.example.com]:80` will incorrectly match and not be proxied.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-22870](https://github.com/B1ack4sh/Blackash-CVE-2025-22870) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-22870.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-22870.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/B1ack4sh/Blackash-CVE-2025-5777](https://github.com/B1ack4sh/Blackash-CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-5777.svg)


## CVE-2025-2721
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: The code maintainer explains that "[the] call is invalid [as] the buffer pointed to by "data" must have "len" valid bytes." The documentation was fixed to make that clear.

- [https://github.com/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit](https://github.com/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2025-27210_NodeJS_Path_Traversal_Exploit.svg)


## CVE-2023-38408
 The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system. (Code in /usr/lib is not necessarily safe for loading into ssh-agent.) NOTE: this issue exists because of an incomplete fix for CVE-2016-10009.

- [https://github.com/Adel2411/cyber-combat](https://github.com/Adel2411/cyber-combat) :  ![starts](https://img.shields.io/github/stars/Adel2411/cyber-combat.svg) ![forks](https://img.shields.io/github/forks/Adel2411/cyber-combat.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/DanielFEXKEX/CVE-Scanner](https://github.com/DanielFEXKEX/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/DanielFEXKEX/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/DanielFEXKEX/CVE-Scanner.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/Kalidas-7/CVE-2019-9053](https://github.com/Kalidas-7/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/Kalidas-7/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/Kalidas-7/CVE-2019-9053.svg)


## CVE-2018-2628
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)
- [https://github.com/tdy218/ysoserial-cve-2018-2628](https://github.com/tdy218/ysoserial-cve-2018-2628) :  ![starts](https://img.shields.io/github/stars/tdy218/ysoserial-cve-2018-2628.svg) ![forks](https://img.shields.io/github/forks/tdy218/ysoserial-cve-2018-2628.svg)
- [https://github.com/jas502n/CVE-2018-2628](https://github.com/jas502n/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2018-2628.svg)
- [https://github.com/shengqi158/CVE-2018-2628](https://github.com/shengqi158/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/shengqi158/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/shengqi158/CVE-2018-2628.svg)
- [https://github.com/forlin/CVE-2018-2628](https://github.com/forlin/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/forlin/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/forlin/CVE-2018-2628.svg)
- [https://github.com/aedoo/CVE-2018-2628-MultiThreading](https://github.com/aedoo/CVE-2018-2628-MultiThreading) :  ![starts](https://img.shields.io/github/stars/aedoo/CVE-2018-2628-MultiThreading.svg) ![forks](https://img.shields.io/github/forks/aedoo/CVE-2018-2628-MultiThreading.svg)
- [https://github.com/jiansiting/weblogic-cve-2018-2628](https://github.com/jiansiting/weblogic-cve-2018-2628) :  ![starts](https://img.shields.io/github/stars/jiansiting/weblogic-cve-2018-2628.svg) ![forks](https://img.shields.io/github/forks/jiansiting/weblogic-cve-2018-2628.svg)
- [https://github.com/0xMJ/CVE-2018-2628](https://github.com/0xMJ/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/0xMJ/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/0xMJ/CVE-2018-2628.svg)
- [https://github.com/Lighird/CVE-2018-2628](https://github.com/Lighird/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/Lighird/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/Lighird/CVE-2018-2628.svg)
- [https://github.com/Nervous/WebLogic-RCE-exploit](https://github.com/Nervous/WebLogic-RCE-exploit) :  ![starts](https://img.shields.io/github/stars/Nervous/WebLogic-RCE-exploit.svg) ![forks](https://img.shields.io/github/forks/Nervous/WebLogic-RCE-exploit.svg)
- [https://github.com/likekabin/CVE-2018-2628](https://github.com/likekabin/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2018-2628.svg)
- [https://github.com/zjxzjx/CVE-2018-2628-detect](https://github.com/zjxzjx/CVE-2018-2628-detect) :  ![starts](https://img.shields.io/github/stars/zjxzjx/CVE-2018-2628-detect.svg) ![forks](https://img.shields.io/github/forks/zjxzjx/CVE-2018-2628-detect.svg)
- [https://github.com/Shadowshusky/CVE-2018-2628all](https://github.com/Shadowshusky/CVE-2018-2628all) :  ![starts](https://img.shields.io/github/stars/Shadowshusky/CVE-2018-2628all.svg) ![forks](https://img.shields.io/github/forks/Shadowshusky/CVE-2018-2628all.svg)
- [https://github.com/victor0013/CVE-2018-2628](https://github.com/victor0013/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/victor0013/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/victor0013/CVE-2018-2628.svg)
- [https://github.com/skydarker/CVE-2018-2628](https://github.com/skydarker/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/skydarker/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/skydarker/CVE-2018-2628.svg)
- [https://github.com/9uest/CVE-2018-2628](https://github.com/9uest/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/9uest/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/9uest/CVE-2018-2628.svg)
- [https://github.com/cscadoge/weblogic-cve-2018-2628](https://github.com/cscadoge/weblogic-cve-2018-2628) :  ![starts](https://img.shields.io/github/stars/cscadoge/weblogic-cve-2018-2628.svg) ![forks](https://img.shields.io/github/forks/cscadoge/weblogic-cve-2018-2628.svg)
- [https://github.com/wrysunny/cve-2018-2628](https://github.com/wrysunny/cve-2018-2628) :  ![starts](https://img.shields.io/github/stars/wrysunny/cve-2018-2628.svg) ![forks](https://img.shields.io/github/forks/wrysunny/cve-2018-2628.svg)
- [https://github.com/stevenlinfeng/CVE-2018-2628](https://github.com/stevenlinfeng/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/stevenlinfeng/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/stevenlinfeng/CVE-2018-2628.svg)
- [https://github.com/seethen/cve-2018-2628](https://github.com/seethen/cve-2018-2628) :  ![starts](https://img.shields.io/github/stars/seethen/cve-2018-2628.svg) ![forks](https://img.shields.io/github/forks/seethen/cve-2018-2628.svg)
- [https://github.com/shaoshore/CVE-2018-2628](https://github.com/shaoshore/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/shaoshore/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/shaoshore/CVE-2018-2628.svg)
- [https://github.com/BabyTeam1024/cve-2018-2628](https://github.com/BabyTeam1024/cve-2018-2628) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/cve-2018-2628.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/cve-2018-2628.svg)


## CVE-2016-6210
 sshd in OpenSSH before 7.3, when SHA256 or SHA512 are used for user password hashing, uses BLOWFISH hashing on a static password when the username does not exist, which allows remote attackers to enumerate users by leveraging the timing difference between responses when a large password is provided.

- [https://github.com/KiPhuong/cve-2016-6210](https://github.com/KiPhuong/cve-2016-6210) :  ![starts](https://img.shields.io/github/stars/KiPhuong/cve-2016-6210.svg) ![forks](https://img.shields.io/github/forks/KiPhuong/cve-2016-6210.svg)


## CVE-2016-3749
 server/LockSettingsService.java in LockSettingsService in Android 6.x before 2016-07-01 allows attackers to modify the screen-lock password or pattern via a crafted application, aka internal bug 28163930.

- [https://github.com/nirdev/CVE-2016-3749-PoC](https://github.com/nirdev/CVE-2016-3749-PoC) :  ![starts](https://img.shields.io/github/stars/nirdev/CVE-2016-3749-PoC.svg) ![forks](https://img.shields.io/github/forks/nirdev/CVE-2016-3749-PoC.svg)

