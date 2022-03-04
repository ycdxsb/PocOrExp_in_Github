# Update 2022-03-04
## CVE-2022-25090
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ComparedArray/printix-CVE-2022-25090](https://github.com/ComparedArray/printix-CVE-2022-25090) :  ![starts](https://img.shields.io/github/stars/ComparedArray/printix-CVE-2022-25090.svg) ![forks](https://img.shields.io/github/forks/ComparedArray/printix-CVE-2022-25090.svg)


## CVE-2022-23131
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)


## CVE-2022-22947
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/lucksec/Spring-Cloud-Gateway-CVE-2022-22947](https://github.com/lucksec/Spring-Cloud-Gateway-CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/lucksec/Spring-Cloud-Gateway-CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/lucksec/Spring-Cloud-Gateway-CVE-2022-22947.svg)


## CVE-2021-3007
 ** DISPUTED ** Laminas Project laminas-http before 2.14.2, and Zend Framework 3.0.0, has a deserialization vulnerability that can lead to remote code execution if the content is controllable, related to the __destruct method of the Zend\Http\Response\Stream class in Stream.php. NOTE: Zend Framework is no longer supported by the maintainer. NOTE: the laminas-http vendor considers this a &quot;vulnerability in the PHP language itself&quot; but has added certain type checking as a way to prevent exploitation in (unrecommended) use cases where attacker-supplied data can be deserialized.

- [https://github.com/Vulnmachines/ZF3_CVE-2021-3007](https://github.com/Vulnmachines/ZF3_CVE-2021-3007) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/ZF3_CVE-2021-3007.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/ZF3_CVE-2021-3007.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/Anonymous-Family/CVE-2020-1472](https://github.com/Anonymous-Family/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/CVE-2020-1472.svg)
- [https://github.com/Anonymous-Family/Zero-day-scanning](https://github.com/Anonymous-Family/Zero-day-scanning) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/Zero-day-scanning.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/Zero-day-scanning.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/takumak/cve-2019-5736-reproducer](https://github.com/takumak/cve-2019-5736-reproducer) :  ![starts](https://img.shields.io/github/stars/takumak/cve-2019-5736-reproducer.svg) ![forks](https://img.shields.io/github/forks/takumak/cve-2019-5736-reproducer.svg)


## CVE-2019-2022
 In rw_t3t_act_handle_fmt_rsp and rw_t3t_act_handle_sro_rsp of rw_t3t.cc, there is a possible out-of-bound read due to a missing bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9Android ID: A-120506143

- [https://github.com/AhnSungHoon/Kali_CVE](https://github.com/AhnSungHoon/Kali_CVE) :  ![starts](https://img.shields.io/github/stars/AhnSungHoon/Kali_CVE.svg) ![forks](https://img.shields.io/github/forks/AhnSungHoon/Kali_CVE.svg)


## CVE-2018-11235
 In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs &quot;git clone --recurse-submodules&quot; because submodule &quot;names&quot; are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with &quot;../&quot; in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.

- [https://github.com/twseptian/CVE-2018-11235-Git-Submodule-CE-and-Docker-Ngrok-Configuration](https://github.com/twseptian/CVE-2018-11235-Git-Submodule-CE-and-Docker-Ngrok-Configuration) :  ![starts](https://img.shields.io/github/stars/twseptian/CVE-2018-11235-Git-Submodule-CE-and-Docker-Ngrok-Configuration.svg) ![forks](https://img.shields.io/github/forks/twseptian/CVE-2018-11235-Git-Submodule-CE-and-Docker-Ngrok-Configuration.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/twseptian/CVE-2018-6574](https://github.com/twseptian/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/twseptian/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/twseptian/CVE-2018-6574.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/ellietoulabi/Dirty-Cow](https://github.com/ellietoulabi/Dirty-Cow) :  ![starts](https://img.shields.io/github/stars/ellietoulabi/Dirty-Cow.svg) ![forks](https://img.shields.io/github/forks/ellietoulabi/Dirty-Cow.svg)


## CVE-2016-4437
 Apache Shiro before 1.2.5, when a cipher key has not been configured for the &quot;remember me&quot; feature, allows remote attackers to execute arbitrary code or bypass intended access restrictions via an unspecified request parameter.

- [https://github.com/XuCcc/VulEnv](https://github.com/XuCcc/VulEnv) :  ![starts](https://img.shields.io/github/stars/XuCcc/VulEnv.svg) ![forks](https://img.shields.io/github/forks/XuCcc/VulEnv.svg)

