# Update 2024-06-20
## CVE-2024-31497
 In PuTTY 0.68 through 0.80 before 0.81, biased ECDSA nonce generation allows an attacker to recover a user's NIST P-521 secret key via a quick attack in approximately 60 signatures. This is especially important in a scenario where an adversary is able to read messages signed by PuTTY or Pageant. The required set of signed messages may be publicly readable because they are stored in a public Git service that supports use of SSH for commit signing, and the signatures were made by Pageant through an agent-forwarding mechanism. In other words, an adversary may already have enough signature information to compromise a victim's private key, even if there is no further use of vulnerable PuTTY versions. After a key compromise, an adversary may be able to conduct supply-chain attacks on software maintained in Git. A second, independent scenario is that the adversary is an operator of an SSH server to which the victim authenticates (for remote login or file copy), even though this server is not fully trusted by the victim, and the victim uses the same private key for SSH connections to other services operated by other entities. Here, the rogue server operator (who would otherwise have no way to determine the victim's private key) can derive the victim's private key, and then use it for unauthorized access to those other services. If the other services include Git services, then again it may be possible to conduct supply-chain attacks on software maintained in Git. This also affects, for example, FileZilla before 3.67.0, WinSCP before 6.3.3, TortoiseGit before 2.15.0.1, and TortoiseSVN through 1.14.6.

- [https://github.com/daedalus/BreakingECDSAwithLLL](https://github.com/daedalus/BreakingECDSAwithLLL) :  ![starts](https://img.shields.io/github/stars/daedalus/BreakingECDSAwithLLL.svg) ![forks](https://img.shields.io/github/forks/daedalus/BreakingECDSAwithLLL.svg)


## CVE-2024-30078
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/nkontopoul/checkwifivulnerability](https://github.com/nkontopoul/checkwifivulnerability) :  ![starts](https://img.shields.io/github/stars/nkontopoul/checkwifivulnerability.svg) ![forks](https://img.shields.io/github/forks/nkontopoul/checkwifivulnerability.svg)


## CVE-2024-29824
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/R4be1/CVE-2024-29824](https://github.com/R4be1/CVE-2024-29824) :  ![starts](https://img.shields.io/github/stars/R4be1/CVE-2024-29824.svg) ![forks](https://img.shields.io/github/forks/R4be1/CVE-2024-29824.svg)


## CVE-2024-28397
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape) :  ![starts](https://img.shields.io/github/stars/Marven11/CVE-2024-28397-js2py-Sandbox-Escape.svg) ![forks](https://img.shields.io/github/forks/Marven11/CVE-2024-28397-js2py-Sandbox-Escape.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/ShubhamKanhere307/CVE-2024-21413](https://github.com/ShubhamKanhere307/CVE-2024-21413) :  ![starts](https://img.shields.io/github/stars/ShubhamKanhere307/CVE-2024-21413.svg) ![forks](https://img.shields.io/github/forks/ShubhamKanhere307/CVE-2024-21413.svg)


## CVE-2024-4577
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/amandineVdw/CVE-2024-4577](https://github.com/amandineVdw/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/amandineVdw/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/amandineVdw/CVE-2024-4577.svg)
- [https://github.com/jakabakos/CVE-2024-4577-PHP-CGI-argument-injection-RCE](https://github.com/jakabakos/CVE-2024-4577-PHP-CGI-argument-injection-RCE) :  ![starts](https://img.shields.io/github/stars/jakabakos/CVE-2024-4577-PHP-CGI-argument-injection-RCE.svg) ![forks](https://img.shields.io/github/forks/jakabakos/CVE-2024-4577-PHP-CGI-argument-injection-RCE.svg)


## CVE-2024-4232
 This vulnerability exists in Digisol Router (DG-GR1321: Hardware version 3.7L; Firmware version : v3.2.02) due to presence of root terminal access on a serial interface without proper access control. An attacker with physical access could exploit this by identifying UART pins and accessing the root shell on the vulnerable system. Successful exploitation of this vulnerability could allow the attacker to access the sensitive information on the targeted system.This vulnerability exists in Digisol Router (DG-GR1321: Hardware version 3.7L; Firmware version : v3.2.02) due to lack of encryption or hashing in storing of passwords within the router's firmware/ database. An attacker with physical access could exploit this by extracting the firmware and reverse engineer the binary data to access the plaintext passwords on the vulnerable system. Successful exploitation of this vulnerability could allow the attacker to gain unauthorized access to the targeted system.

- [https://github.com/Redfox-Secuirty/Digisol-DG-GR1321-s-Password-Storage-in-Plaintext-CVE-2024-4232](https://github.com/Redfox-Secuirty/Digisol-DG-GR1321-s-Password-Storage-in-Plaintext-CVE-2024-4232) :  ![starts](https://img.shields.io/github/stars/Redfox-Secuirty/Digisol-DG-GR1321-s-Password-Storage-in-Plaintext-CVE-2024-4232.svg) ![forks](https://img.shields.io/github/forks/Redfox-Secuirty/Digisol-DG-GR1321-s-Password-Storage-in-Plaintext-CVE-2024-4232.svg)


## CVE-2024-4231
 This vulnerability exists in Digisol Router (DG-GR1321: Hardware version 3.7L; Firmware version : v3.2.02) due to presence of root terminal access on a serial interface without proper access control. An attacker with physical access could exploit this by identifying UART pins and accessing the root shell on the vulnerable system. Successful exploitation of this vulnerability could allow the attacker to access the sensitive information on the targeted system.

- [https://github.com/Redfox-Secuirty/Digisol-DG-GR1321-s-Improper-Access-Control-CVE-2024-4231](https://github.com/Redfox-Secuirty/Digisol-DG-GR1321-s-Improper-Access-Control-CVE-2024-4231) :  ![starts](https://img.shields.io/github/stars/Redfox-Secuirty/Digisol-DG-GR1321-s-Improper-Access-Control-CVE-2024-4231.svg) ![forks](https://img.shields.io/github/forks/Redfox-Secuirty/Digisol-DG-GR1321-s-Improper-Access-Control-CVE-2024-4231.svg)


## CVE-2024-3788
 Vulnerability in WBSAirback 21.02.04, which involves improper neutralisation of Server-Side Includes (SSI), through License (/admin/CDPUsers). Exploitation of this vulnerability could allow a remote user to execute arbitrary code.

- [https://github.com/7Ragnarok7/CVE-2024-37888](https://github.com/7Ragnarok7/CVE-2024-37888) :  ![starts](https://img.shields.io/github/stars/7Ragnarok7/CVE-2024-37888.svg) ![forks](https://img.shields.io/github/forks/7Ragnarok7/CVE-2024-37888.svg)


## CVE-2024-2257
 This vulnerability exists in Digisol Router (DG-GR1321: Hardware version 3.7L; Firmware version : v3.2.02) due to improper implementation of password policies. An attacker with physical access could exploit this by creating password that do not adhere to the defined security standards/policy on the vulnerable system. Successful exploitation of this vulnerability could allow the attacker to expose the router to potential security threats.

- [https://github.com/Redfox-Secuirty/Digisol-DG-GR1321-s-Password-Policy-Bypass-CVE-2024-2257](https://github.com/Redfox-Secuirty/Digisol-DG-GR1321-s-Password-Policy-Bypass-CVE-2024-2257) :  ![starts](https://img.shields.io/github/stars/Redfox-Secuirty/Digisol-DG-GR1321-s-Password-Policy-Bypass-CVE-2024-2257.svg) ![forks](https://img.shields.io/github/forks/Redfox-Secuirty/Digisol-DG-GR1321-s-Password-Policy-Bypass-CVE-2024-2257.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/scs-labrat/android_autorooter](https://github.com/scs-labrat/android_autorooter) :  ![starts](https://img.shields.io/github/stars/scs-labrat/android_autorooter.svg) ![forks](https://img.shields.io/github/forks/scs-labrat/android_autorooter.svg)
- [https://github.com/pl4int3xt/cve_2024_0044](https://github.com/pl4int3xt/cve_2024_0044) :  ![starts](https://img.shields.io/github/stars/pl4int3xt/cve_2024_0044.svg) ![forks](https://img.shields.io/github/forks/pl4int3xt/cve_2024_0044.svg)


## CVE-2023-22726
 act is a project which allows for local running of github actions. The artifact server that stores artifacts from Github Action runs does not sanitize path inputs. This allows an attacker to download and overwrite arbitrary files on the host from a Github Action. This issue may lead to privilege escalation. The /upload endpoint is vulnerable to path traversal as filepath is user controlled, and ultimately flows into os.Mkdir and os.Open. The /artifact endpoint is vulnerable to path traversal as the path is variable is user controlled, and the specified file is ultimately returned by the server. This has been addressed in version 0.2.40. Users are advised to upgrade. Users unable to upgrade may, during implementation of Open and OpenAtEnd for FS, ensure to use ValidPath() to check against path traversal or clean the user-provided paths manually.

- [https://github.com/ProxyPog/POC-CVE-2023-22726](https://github.com/ProxyPog/POC-CVE-2023-22726) :  ![starts](https://img.shields.io/github/stars/ProxyPog/POC-CVE-2023-22726.svg) ![forks](https://img.shields.io/github/forks/ProxyPog/POC-CVE-2023-22726.svg)


## CVE-2021-0466
 In startIpClient of ClientModeImpl.java, there is a possible identifier which could be used to track a device. This could lead to remote information disclosure to a proximal attacker, with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-154114734

- [https://github.com/uthrasri/frameworks_opt_net_CVE-2021-0466](https://github.com/uthrasri/frameworks_opt_net_CVE-2021-0466) :  ![starts](https://img.shields.io/github/stars/uthrasri/frameworks_opt_net_CVE-2021-0466.svg) ![forks](https://img.shields.io/github/forks/uthrasri/frameworks_opt_net_CVE-2021-0466.svg)


## CVE-2021-0390
 In various methods of WifiNetworkSuggestionsManager.java, there is a possible modification of suggested networks due to a missing permission check. This could lead to local escalation of privilege by a background user on the same device with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-8.1 Android-9 Android-10Android ID: A-174749461

- [https://github.com/uthrasri/frameworks_opt_net_CVE-2021-0390](https://github.com/uthrasri/frameworks_opt_net_CVE-2021-0390) :  ![starts](https://img.shields.io/github/stars/uthrasri/frameworks_opt_net_CVE-2021-0390.svg) ![forks](https://img.shields.io/github/forks/uthrasri/frameworks_opt_net_CVE-2021-0390.svg)


## CVE-2020-2969
 Vulnerability in the Data Pump component of Oracle Database Server. Supported versions that are affected are 11.2.0.4, 12.1.0.2, 12.2.0.1, 18c and 19c. Difficult to exploit vulnerability allows high privileged attacker having DBA role account privilege with network access via Oracle Net to compromise Data Pump. Successful attacks of this vulnerability can result in takeover of Data Pump. CVSS 3.1 Base Score 6.6 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/emad-almousa/CVE-2020-2969](https://github.com/emad-almousa/CVE-2020-2969) :  ![starts](https://img.shields.io/github/stars/emad-almousa/CVE-2020-2969.svg) ![forks](https://img.shields.io/github/forks/emad-almousa/CVE-2020-2969.svg)


## CVE-2019-17666
 rtl_p2p_noa_ie in drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux kernel through 5.3.6 lacks a certain upper-bound check, leading to a buffer overflow.

- [https://github.com/uthrasri/CVE-2019-17666](https://github.com/uthrasri/CVE-2019-17666) :  ![starts](https://img.shields.io/github/stars/uthrasri/CVE-2019-17666.svg) ![forks](https://img.shields.io/github/forks/uthrasri/CVE-2019-17666.svg)


## CVE-2019-16746
 An issue was discovered in net/wireless/nl80211.c in the Linux kernel through 5.2.17. It does not check the length of variable elements in a beacon head, leading to a buffer overflow.

- [https://github.com/uthrasri/CVE-2019-16746](https://github.com/uthrasri/CVE-2019-16746) :  ![starts](https://img.shields.io/github/stars/uthrasri/CVE-2019-16746.svg) ![forks](https://img.shields.io/github/forks/uthrasri/CVE-2019-16746.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/jobroche/libssh-scanner](https://github.com/jobroche/libssh-scanner) :  ![starts](https://img.shields.io/github/stars/jobroche/libssh-scanner.svg) ![forks](https://img.shields.io/github/forks/jobroche/libssh-scanner.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/bme2003/CVE-2018-6574](https://github.com/bme2003/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/bme2003/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/bme2003/CVE-2018-6574.svg)

