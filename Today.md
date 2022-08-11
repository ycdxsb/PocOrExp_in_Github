# Update 2022-08-11
## CVE-2022-33980
 Apache Commons Configuration performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.configuration2.interpol.Lookup that performs the interpolation. Starting with version 2.4 and continuing through 2.7, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Configuration 2.8.0, which disables the problematic interpolators by default.

- [https://github.com/HKirito/CVE-2022-33980](https://github.com/HKirito/CVE-2022-33980) :  ![starts](https://img.shields.io/github/stars/HKirito/CVE-2022-33980.svg) ![forks](https://img.shields.io/github/forks/HKirito/CVE-2022-33980.svg)


## CVE-2022-31101
 prestashop/blockwishlist is a prestashop extension which adds a block containing the customer's wishlists. In affected versions an authenticated customer can perform SQL injection. This issue is fixed in version 2.1.1. Users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/karthikuj/CVE-2022-31101](https://github.com/karthikuj/CVE-2022-31101) :  ![starts](https://img.shields.io/github/stars/karthikuj/CVE-2022-31101.svg) ![forks](https://img.shields.io/github/forks/karthikuj/CVE-2022-31101.svg)


## CVE-2022-30216
 Windows Server Service Tampering Vulnerability.

- [https://github.com/corelight/CVE-2022-30216](https://github.com/corelight/CVE-2022-30216) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2022-30216.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2022-30216.svg)


## CVE-2022-29968
 An issue was discovered in the Linux kernel through 5.17.5. io_rw_init_file in fs/io_uring.c lacks initialization of kiocb-&gt;private.

- [https://github.com/jprx/CVE-2022-29968](https://github.com/jprx/CVE-2022-29968) :  ![starts](https://img.shields.io/github/stars/jprx/CVE-2022-29968.svg) ![forks](https://img.shields.io/github/forks/jprx/CVE-2022-29968.svg)


## CVE-2022-24087
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/seymanurmutlu/CVE-2022-24086-CVE-2022-24087](https://github.com/seymanurmutlu/CVE-2022-24086-CVE-2022-24087) :  ![starts](https://img.shields.io/github/stars/seymanurmutlu/CVE-2022-24086-CVE-2022-24087.svg) ![forks](https://img.shields.io/github/forks/seymanurmutlu/CVE-2022-24086-CVE-2022-24087.svg)


## CVE-2022-23131
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).

- [https://github.com/SCAMagic/CVE-2022-23131poc-exp-zabbix-](https://github.com/SCAMagic/CVE-2022-23131poc-exp-zabbix-) :  ![starts](https://img.shields.io/github/stars/SCAMagic/CVE-2022-23131poc-exp-zabbix-.svg) ![forks](https://img.shields.io/github/forks/SCAMagic/CVE-2022-23131poc-exp-zabbix-.svg)


## CVE-2022-21881
 Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21879.

- [https://github.com/theabysslabs/CVE-2022-21881](https://github.com/theabysslabs/CVE-2022-21881) :  ![starts](https://img.shields.io/github/stars/theabysslabs/CVE-2022-21881.svg) ![forks](https://img.shields.io/github/forks/theabysslabs/CVE-2022-21881.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/UNICORDev/exploit-CVE-2021-3560](https://github.com/UNICORDev/exploit-CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/UNICORDev/exploit-CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/UNICORDev/exploit-CVE-2021-3560.svg)


## CVE-2019-17621
 The UPnP endpoint URL /gena.cgi in the D-Link DIR-859 Wi-Fi router 1.05 and 1.06B01 Beta01 allows an Unauthenticated remote attacker to execute system commands as root, by sending a specially crafted HTTP SUBSCRIBE request to the UPnP service when connecting to the local network.

- [https://github.com/Squirre17/CVE-2019-17621](https://github.com/Squirre17/CVE-2019-17621) :  ![starts](https://img.shields.io/github/stars/Squirre17/CVE-2019-17621.svg) ![forks](https://img.shields.io/github/forks/Squirre17/CVE-2019-17621.svg)


## CVE-2019-8985
 On Netis WF2411 with firmware 2.1.36123 and other Netis WF2xxx devices (possibly WF2411 through WF2880), there is a stack-based buffer overflow that does not require authentication. This can cause denial of service (device restart) or remote code execution. This vulnerability can be triggered by a GET request with a long HTTP &quot;Authorization: Basic&quot; header that is mishandled by user_auth-&gt;user_ok in /bin/boa.

- [https://github.com/Squirre17/CVE-2019-8985](https://github.com/Squirre17/CVE-2019-8985) :  ![starts](https://img.shields.io/github/stars/Squirre17/CVE-2019-8985.svg) ![forks](https://img.shields.io/github/forks/Squirre17/CVE-2019-8985.svg)


## CVE-2019-8591
 A type confusion issue was addressed with improved memory handling. This issue is fixed in iOS 12.3, macOS Mojave 10.14.5, tvOS 12.3, watchOS 5.2.1. An application may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/jsherman212/used_sock](https://github.com/jsherman212/used_sock) :  ![starts](https://img.shields.io/github/stars/jsherman212/used_sock.svg) ![forks](https://img.shields.io/github/forks/jsherman212/used_sock.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/markisback/CVE-2018-6574](https://github.com/markisback/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/markisback/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/markisback/CVE-2018-6574.svg)

