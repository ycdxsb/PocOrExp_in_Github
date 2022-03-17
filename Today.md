# Update 2022-03-17
## CVE-2022-24086
 Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier) are affected by an improper input validation vulnerability during the checkout process. Exploitation of this issue does not require user interaction and could result in arbitrary code execution.

- [https://github.com/k0zulzr/CVE-2022-24086-RCE](https://github.com/k0zulzr/CVE-2022-24086-RCE) :  ![starts](https://img.shields.io/github/stars/k0zulzr/CVE-2022-24086-RCE.svg) ![forks](https://img.shields.io/github/forks/k0zulzr/CVE-2022-24086-RCE.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/bysinks/CVE-2022-22947](https://github.com/bysinks/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/bysinks/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/bysinks/CVE-2022-22947.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/MrP1xel/CVE-2022-0847-dirty-pipe-kernel-checker](https://github.com/MrP1xel/CVE-2022-0847-dirty-pipe-kernel-checker) :  ![starts](https://img.shields.io/github/stars/MrP1xel/CVE-2022-0847-dirty-pipe-kernel-checker.svg) ![forks](https://img.shields.io/github/forks/MrP1xel/CVE-2022-0847-dirty-pipe-kernel-checker.svg)
- [https://github.com/githublihaha/DirtyPIPE-CVE-2022-0847](https://github.com/githublihaha/DirtyPIPE-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/githublihaha/DirtyPIPE-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/githublihaha/DirtyPIPE-CVE-2022-0847.svg)
- [https://github.com/phuonguno98/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/phuonguno98/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/phuonguno98/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/phuonguno98/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2022-0778
 The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Internally this function is used when parsing certificates that contain elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has invalid explicit curve parameters. Since certificate parsing happens prior to verification of the certificate signature, any process that parses an externally supplied certificate may thus be subject to a denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients consuming server certificates - TLS servers consuming client certificates - Hosting providers taking certificates or private keys from customers - Certificate authorities parsing certification requests from subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate which makes it slightly harder to trigger the infinite loop. However any operation which requires the public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-signed certificate to trigger the loop during verification of the certificate signature. This issue affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the 15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected 1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc).

- [https://github.com/drago-96/CVE-2022-0778](https://github.com/drago-96/CVE-2022-0778) :  ![starts](https://img.shields.io/github/stars/drago-96/CVE-2022-0778.svg) ![forks](https://img.shields.io/github/forks/drago-96/CVE-2022-0778.svg)


## CVE-2021-39165
 Cachet is an open source status page. With Cachet prior to and including 2.3.18, there is a SQL injection which is in the `SearchableTrait#scopeSearch()`. Attackers without authentication can utilize this vulnerability to exfiltrate sensitive data from the database such as administrator's password and session. The original repository of Cachet &lt;https://github.com/CachetHQ/Cachet&gt; is not active, the stable version 2.3.18 and it's developing 2.4 branch is affected.

- [https://github.com/W0rty/CVE-2021-39165](https://github.com/W0rty/CVE-2021-39165) :  ![starts](https://img.shields.io/github/stars/W0rty/CVE-2021-39165.svg) ![forks](https://img.shields.io/github/forks/W0rty/CVE-2021-39165.svg)


## CVE-2021-30955
 A race condition was addressed with improved state handling. This issue is fixed in macOS Monterey 12.1, watchOS 8.3, iOS 15.2 and iPadOS 15.2, tvOS 15.2. A malicious application may be able to execute arbitrary code with kernel privileges.

- [https://github.com/Dylbin/desc_race](https://github.com/Dylbin/desc_race) :  ![starts](https://img.shields.io/github/stars/Dylbin/desc_race.svg) ![forks](https://img.shields.io/github/forks/Dylbin/desc_race.svg)


## CVE-2021-29441
 Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, when configured to use authentication (-Dnacos.core.auth.enabled=true) Nacos uses the AuthFilter servlet filter to enforce authentication. This filter has a backdoor that enables Nacos servers to bypass this filter and therefore skip authentication checks. This mechanism relies on the user-agent HTTP header so it can be easily spoofed. This issue may allow any user to carry out any administrative tasks on the Nacos server.

- [https://github.com/bysinks/CVE-2021-29441](https://github.com/bysinks/CVE-2021-29441) :  ![starts](https://img.shields.io/github/stars/bysinks/CVE-2021-29441.svg) ![forks](https://img.shields.io/github/forks/bysinks/CVE-2021-29441.svg)


## CVE-2021-21341
 XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16, there is vulnerability which may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU type or parallel execution of such a payload resulting in a denial of service only by manipulating the processed input stream. No user is affected who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.

- [https://github.com/Mani1325/ka-cve-2021-21341](https://github.com/Mani1325/ka-cve-2021-21341) :  ![starts](https://img.shields.io/github/stars/Mani1325/ka-cve-2021-21341.svg) ![forks](https://img.shields.io/github/forks/Mani1325/ka-cve-2021-21341.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Ankit-Ojha16/CVE-2021-4034](https://github.com/Ankit-Ojha16/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Ankit-Ojha16/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Ankit-Ojha16/CVE-2021-4034.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/si1ent-le/CVE-2019-5736](https://github.com/si1ent-le/CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/si1ent-le/CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/si1ent-le/CVE-2019-5736.svg)


## CVE-2019-1653
 A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated, remote attacker to retrieve sensitive information. The vulnerability is due to improper access controls for URLs. An attacker could exploit this vulnerability by connecting to an affected device via HTTP or HTTPS and requesting specific URLs. A successful exploit could allow the attacker to download the router configuration or detailed diagnostic information. Cisco has released firmware updates that address this vulnerability.

- [https://github.com/0x27/CiscoRV320Dump](https://github.com/0x27/CiscoRV320Dump) :  ![starts](https://img.shields.io/github/stars/0x27/CiscoRV320Dump.svg) ![forks](https://img.shields.io/github/forks/0x27/CiscoRV320Dump.svg)


## CVE-2019-1458
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'.

- [https://github.com/DreamoneOnly/CVE-2019-1458-malware](https://github.com/DreamoneOnly/CVE-2019-1458-malware) :  ![starts](https://img.shields.io/github/stars/DreamoneOnly/CVE-2019-1458-malware.svg) ![forks](https://img.shields.io/github/forks/DreamoneOnly/CVE-2019-1458-malware.svg)


## CVE-2019-0193
 In Apache Solr, the DataImportHandler, an optional but popular module to pull in data from databases and other sources, has a feature in which the whole DIH configuration can come from a request's &quot;dataConfig&quot; parameter. The debug mode of the DIH admin screen uses this to allow convenient debugging / development of a DIH config. Since a DIH config can contain scripts, this parameter is a security risk. Starting with version 8.2.0 of Solr, use of this parameter requires setting the Java System property &quot;enable.dih.dataConfigParam&quot; to true.

- [https://github.com/Bin4xin/bigger-than-bigger](https://github.com/Bin4xin/bigger-than-bigger) :  ![starts](https://img.shields.io/github/stars/Bin4xin/bigger-than-bigger.svg) ![forks](https://img.shields.io/github/forks/Bin4xin/bigger-than-bigger.svg)


## CVE-2018-11235
 In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs &quot;git clone --recurse-submodules&quot; because submodule &quot;names&quot; are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with &quot;../&quot; in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.

- [https://github.com/SenSecurity/exploit](https://github.com/SenSecurity/exploit) :  ![starts](https://img.shields.io/github/stars/SenSecurity/exploit.svg) ![forks](https://img.shields.io/github/forks/SenSecurity/exploit.svg)


## CVE-2018-6242
 Some NVIDIA Tegra mobile processors released prior to 2016 contain a buffer overflow vulnerability in BootROM Recovery Mode (RCM). An attacker with physical access to the device's USB and the ability to force the device to reboot into RCM could exploit the vulnerability to execute unverified code.

- [https://github.com/DavidBuchanan314/NXLoader](https://github.com/DavidBuchanan314/NXLoader) :  ![starts](https://img.shields.io/github/stars/DavidBuchanan314/NXLoader.svg) ![forks](https://img.shields.io/github/forks/DavidBuchanan314/NXLoader.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a &quot;&lt;?php &quot; substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/rodnt/laravel-phpunit-rce-masscaner](https://github.com/rodnt/laravel-phpunit-rce-masscaner) :  ![starts](https://img.shields.io/github/stars/rodnt/laravel-phpunit-rce-masscaner.svg) ![forks](https://img.shields.io/github/forks/rodnt/laravel-phpunit-rce-masscaner.svg)

