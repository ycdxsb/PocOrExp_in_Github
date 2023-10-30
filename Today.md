# Update 2023-10-30
## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/0xKayala/CVE-2023-33246](https://github.com/0xKayala/CVE-2023-33246) :  ![starts](https://img.shields.io/github/stars/0xKayala/CVE-2023-33246.svg) ![forks](https://img.shields.io/github/forks/0xKayala/CVE-2023-33246.svg)


## CVE-2023-29552
 The Service Location Protocol (SLP, RFC 2608) allows an unauthenticated, remote attacker to register arbitrary services. This could allow the attacker to use spoofed UDP traffic to conduct a denial-of-service attack with a significant amplification factor.

- [https://github.com/0xKayala/CVE-2023-29552](https://github.com/0xKayala/CVE-2023-29552) :  ![starts](https://img.shields.io/github/stars/0xKayala/CVE-2023-29552.svg) ![forks](https://img.shields.io/github/forks/0xKayala/CVE-2023-29552.svg)


## CVE-2023-4966
 Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server.

- [https://github.com/certat/citrix-logchecker](https://github.com/certat/citrix-logchecker) :  ![starts](https://img.shields.io/github/stars/certat/citrix-logchecker.svg) ![forks](https://img.shields.io/github/forks/certat/citrix-logchecker.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/Diego-AltF4/CVE-2023-4911](https://github.com/Diego-AltF4/CVE-2023-4911) :  ![starts](https://img.shields.io/github/stars/Diego-AltF4/CVE-2023-4911.svg) ![forks](https://img.shields.io/github/forks/Diego-AltF4/CVE-2023-4911.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/BearClaw96/CVE-2022-22963-Poc-Bearcules](https://github.com/BearClaw96/CVE-2022-22963-Poc-Bearcules) :  ![starts](https://img.shields.io/github/stars/BearClaw96/CVE-2022-22963-Poc-Bearcules.svg) ![forks](https://img.shields.io/github/forks/BearClaw96/CVE-2022-22963-Poc-Bearcules.svg)


## CVE-2022-1292
 The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n). Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd).

- [https://github.com/alcaparra/CVE-2022-1292](https://github.com/alcaparra/CVE-2022-1292) :  ![starts](https://img.shields.io/github/stars/alcaparra/CVE-2022-1292.svg) ![forks](https://img.shields.io/github/forks/alcaparra/CVE-2022-1292.svg)
- [https://github.com/greek0x0/CVE-2022-1292](https://github.com/greek0x0/CVE-2022-1292) :  ![starts](https://img.shields.io/github/stars/greek0x0/CVE-2022-1292.svg) ![forks](https://img.shields.io/github/forks/greek0x0/CVE-2022-1292.svg)
- [https://github.com/li8u99/CVE-2022-1292](https://github.com/li8u99/CVE-2022-1292) :  ![starts](https://img.shields.io/github/stars/li8u99/CVE-2022-1292.svg) ![forks](https://img.shields.io/github/forks/li8u99/CVE-2022-1292.svg)
- [https://github.com/rama291041610/CVE-2022-1292](https://github.com/rama291041610/CVE-2022-1292) :  ![starts](https://img.shields.io/github/stars/rama291041610/CVE-2022-1292.svg) ![forks](https://img.shields.io/github/forks/rama291041610/CVE-2022-1292.svg)
- [https://github.com/und3sc0n0c1d0/CVE-2022-1292](https://github.com/und3sc0n0c1d0/CVE-2022-1292) :  ![starts](https://img.shields.io/github/stars/und3sc0n0c1d0/CVE-2022-1292.svg) ![forks](https://img.shields.io/github/forks/und3sc0n0c1d0/CVE-2022-1292.svg)
- [https://github.com/nidhi7598/openssl-OpenSSL_1_1_1g_AOSP_10_r33_CVE-2022-1292](https://github.com/nidhi7598/openssl-OpenSSL_1_1_1g_AOSP_10_r33_CVE-2022-1292) :  ![starts](https://img.shields.io/github/stars/nidhi7598/openssl-OpenSSL_1_1_1g_AOSP_10_r33_CVE-2022-1292.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/openssl-OpenSSL_1_1_1g_AOSP_10_r33_CVE-2022-1292.svg)


## CVE-2021-42342
 An issue was discovered in GoAhead 4.x and 5.x before 5.1.5. In the file upload filter, user form variables can be passed to CGI scripts without being prefixed with the CGI prefix. This permits tunneling untrusted environment variables into vulnerable CGI scripts.

- [https://github.com/ijh4723/-zeroboo-Gohead-CVE-2021-42342-1](https://github.com/ijh4723/-zeroboo-Gohead-CVE-2021-42342-1) :  ![starts](https://img.shields.io/github/stars/ijh4723/-zeroboo-Gohead-CVE-2021-42342-1.svg) ![forks](https://img.shields.io/github/forks/ijh4723/-zeroboo-Gohead-CVE-2021-42342-1.svg)


## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.

- [https://github.com/Saboor-Hakimi-23/CVE-2021-21300](https://github.com/Saboor-Hakimi-23/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/Saboor-Hakimi-23/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/Saboor-Hakimi-23/CVE-2021-21300.svg)


## CVE-2009-3103
 Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2, Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a denial of service (system crash) via an &amp; (ampersand) character in a Process ID High header field in a NEGOTIATE PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location, aka &quot;SMBv2 Negotiation Vulnerability.&quot; NOTE: some of these details are obtained from third party information.

- [https://github.com/sec13b/ms09-050_CVE-2009-3103](https://github.com/sec13b/ms09-050_CVE-2009-3103) :  ![starts](https://img.shields.io/github/stars/sec13b/ms09-050_CVE-2009-3103.svg) ![forks](https://img.shields.io/github/forks/sec13b/ms09-050_CVE-2009-3103.svg)

