# Update 2022-07-04
## CVE-2022-26766
 A certificate parsing issue was addressed with improved checks. This issue is fixed in tvOS 15.5, iOS 15.5 and iPadOS 15.5, Security Update 2022-004 Catalina, watchOS 8.6, macOS Big Sur 11.6.6, macOS Monterey 12.4. A malicious app may be able to bypass signature validation.

- [https://github.com/zhuowei/CoreTrustDemo](https://github.com/zhuowei/CoreTrustDemo) :  ![starts](https://img.shields.io/github/stars/zhuowei/CoreTrustDemo.svg) ![forks](https://img.shields.io/github/forks/zhuowei/CoreTrustDemo.svg)


## CVE-2022-26763
 An out-of-bounds access issue was addressed with improved bounds checking. This issue is fixed in tvOS 15.5, iOS 15.5 and iPadOS 15.5, Security Update 2022-004 Catalina, watchOS 8.6, macOS Big Sur 11.6.6, macOS Monterey 12.4. A malicious application may be able to execute arbitrary code with system privileges.

- [https://github.com/zhuowei/PCICrash](https://github.com/zhuowei/PCICrash) :  ![starts](https://img.shields.io/github/stars/zhuowei/PCICrash.svg) ![forks](https://img.shields.io/github/forks/zhuowei/PCICrash.svg)


## CVE-2022-24342
 In JetBrains TeamCity before 2021.2.1, URL injection leading to CSRF was possible.

- [https://github.com/yuriisanin/CVE-2022-24342](https://github.com/yuriisanin/CVE-2022-24342) :  ![starts](https://img.shields.io/github/stars/yuriisanin/CVE-2022-24342.svg) ![forks](https://img.shields.io/github/forks/yuriisanin/CVE-2022-24342.svg)


## CVE-2022-2185
 A critical issue has been discovered in GitLab affecting all versions starting from 14.0 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 where it was possible for an unauthorised user to execute arbitrary code on the server using the project import feature.

- [https://github.com/safe3s/CVE-2022-2185-poc](https://github.com/safe3s/CVE-2022-2185-poc) :  ![starts](https://img.shields.io/github/stars/safe3s/CVE-2022-2185-poc.svg) ![forks](https://img.shields.io/github/forks/safe3s/CVE-2022-2185-poc.svg)


## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.

- [https://github.com/macilin/CVE-2021-21300](https://github.com/macilin/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/macilin/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/macilin/CVE-2021-21300.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/Osuni-99/CVE-2019-6447](https://github.com/Osuni-99/CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/Osuni-99/CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/Osuni-99/CVE-2019-6447.svg)


## CVE-2019-5420
 A remote code execution vulnerability in development mode Rails &lt;5.2.2.1, &lt;6.0.0.beta3 can allow an attacker to guess the automatically generated development mode secret token. This secret token can be used in combination with other Rails internals to escalate to a remote code execution exploit.

- [https://github.com/laffray/ruby-RCE-CVE-2019-5420-](https://github.com/laffray/ruby-RCE-CVE-2019-5420-) :  ![starts](https://img.shields.io/github/stars/laffray/ruby-RCE-CVE-2019-5420-.svg) ![forks](https://img.shields.io/github/forks/laffray/ruby-RCE-CVE-2019-5420-.svg)


## CVE-2018-13797
 The macaddress module before 0.2.9 for Node.js is prone to an arbitrary command injection flaw, due to allowing unsanitized input to an exec (rather than execFile) call.

- [https://github.com/dsp-testing/CVE-2018-13797](https://github.com/dsp-testing/CVE-2018-13797) :  ![starts](https://img.shields.io/github/stars/dsp-testing/CVE-2018-13797.svg) ![forks](https://img.shields.io/github/forks/dsp-testing/CVE-2018-13797.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/JBince/ShellShock](https://github.com/JBince/ShellShock) :  ![starts](https://img.shields.io/github/stars/JBince/ShellShock.svg) ![forks](https://img.shields.io/github/forks/JBince/ShellShock.svg)

