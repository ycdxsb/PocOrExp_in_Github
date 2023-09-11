# Update 2023-09-11
## CVE-2023-23333
 There is a command injection vulnerability in SolarView Compact through 6.00, attackers can execute commands by bypassing internal restrictions through downloader.php.

- [https://github.com/getdrive/PoC](https://github.com/getdrive/PoC) :  ![starts](https://img.shields.io/github/stars/getdrive/PoC.svg) ![forks](https://img.shields.io/github/forks/getdrive/PoC.svg)


## CVE-2023-1698
 In multiple products of WAGO a vulnerability allows an unauthenticated, remote attacker to create new users and change the device configuration which can result in unintended behaviour, Denial of Service and full system compromise.

- [https://github.com/codeb0ss/CVE-2023-1698-PoC](https://github.com/codeb0ss/CVE-2023-1698-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-1698-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-1698-PoC.svg)


## CVE-2023-1389
 TP-Link Archer AX21 (AX1800) firmware versions before 1.1.4 Build 20230219 contained a command injection vulnerability in the country form of the /cgi-bin/luci;stok=/locale endpoint on the web management interface. Specifically, the country parameter of the write operation was not sanitized before being used in a call to popen(), allowing an unauthenticated attacker to inject commands, which would be run as root, with a simple POST request.

- [https://github.com/Terminal1337/CVE-2023-1389](https://github.com/Terminal1337/CVE-2023-1389) :  ![starts](https://img.shields.io/github/stars/Terminal1337/CVE-2023-1389.svg) ![forks](https://img.shields.io/github/forks/Terminal1337/CVE-2023-1389.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/0xZon/CVE-2022-46169-Exploit](https://github.com/0xZon/CVE-2022-46169-Exploit) :  ![starts](https://img.shields.io/github/stars/0xZon/CVE-2022-46169-Exploit.svg) ![forks](https://img.shields.io/github/forks/0xZon/CVE-2022-46169-Exploit.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/34006133/CVE-2022-42889](https://github.com/34006133/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/34006133/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/34006133/CVE-2022-42889.svg)


## CVE-2022-23808
 An issue was discovered in phpMyAdmin 5.1 before 5.1.2. An attacker can inject malicious code into aspects of the setup script, which can allow XSS or HTML injection.

- [https://github.com/dipakpanchal05/CVE-2022-23808](https://github.com/dipakpanchal05/CVE-2022-23808) :  ![starts](https://img.shields.io/github/stars/dipakpanchal05/CVE-2022-23808.svg) ![forks](https://img.shields.io/github/forks/dipakpanchal05/CVE-2022-23808.svg)


## CVE-2021-40404
 An authentication bypass vulnerability exists in the cgiserver.cgi Login functionality of reolink RLC-410W v3.0.0.136_20121102. A specially-crafted HTTP request can lead to authentication bypass. An attacker can send an HTTP request to trigger this vulnerability.

- [https://github.com/aredspy/ReoLink-Reboot](https://github.com/aredspy/ReoLink-Reboot) :  ![starts](https://img.shields.io/github/stars/aredspy/ReoLink-Reboot.svg) ![forks](https://img.shields.io/github/forks/aredspy/ReoLink-Reboot.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Naughty-SEC/pkexec-shell-executor](https://github.com/Naughty-SEC/pkexec-shell-executor) :  ![starts](https://img.shields.io/github/stars/Naughty-SEC/pkexec-shell-executor.svg) ![forks](https://img.shields.io/github/forks/Naughty-SEC/pkexec-shell-executor.svg)


## CVE-2021-2075
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Samples). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)


## CVE-2020-0601
 A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates.An attacker could exploit the vulnerability by using a spoofed code-signing certificate to sign a malicious executable, making it appear the file was from a trusted, legitimate source, aka 'Windows CryptoAPI Spoofing Vulnerability'.

- [https://github.com/tyj956413282/curveball-plus](https://github.com/tyj956413282/curveball-plus) :  ![starts](https://img.shields.io/github/stars/tyj956413282/curveball-plus.svg) ![forks](https://img.shields.io/github/forks/tyj956413282/curveball-plus.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/hadrian3689/webmin_1.920](https://github.com/hadrian3689/webmin_1.920) :  ![starts](https://img.shields.io/github/stars/hadrian3689/webmin_1.920.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/webmin_1.920.svg)


## CVE-2019-1253
 An elevation of privilege vulnerability exists when the Windows AppX Deployment Server improperly handles junctions.To exploit this vulnerability, an attacker would first have to gain execution on the victim system, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1215, CVE-2019-1278, CVE-2019-1303.

- [https://github.com/offsec-ttps/CVE2019-1253-Compiled](https://github.com/offsec-ttps/CVE2019-1253-Compiled) :  ![starts](https://img.shields.io/github/stars/offsec-ttps/CVE2019-1253-Compiled.svg) ![forks](https://img.shields.io/github/forks/offsec-ttps/CVE2019-1253-Compiled.svg)


## CVE-2019-0803
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0685, CVE-2019-0859.

- [https://github.com/Iamgublin/CVE-2019-0803](https://github.com/Iamgublin/CVE-2019-0803) :  ![starts](https://img.shields.io/github/stars/Iamgublin/CVE-2019-0803.svg) ![forks](https://img.shields.io/github/forks/Iamgublin/CVE-2019-0803.svg)


## CVE-2019-0683
 An elevation of privilege vulnerability exists in Active Directory Forest trusts due to a default setting that lets an attacker in the trusting forest request delegation of a TGT for an identity from the trusted forest, aka 'Active Directory Elevation of Privilege Vulnerability'.

- [https://github.com/offsec-ttps/CVE2019-0683](https://github.com/offsec-ttps/CVE2019-0683) :  ![starts](https://img.shields.io/github/stars/offsec-ttps/CVE2019-0683.svg) ![forks](https://img.shields.io/github/forks/offsec-ttps/CVE2019-0683.svg)


## CVE-2018-15133
 In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.

- [https://github.com/kozmic/laravel-poc-CVE-2018-15133](https://github.com/kozmic/laravel-poc-CVE-2018-15133) :  ![starts](https://img.shields.io/github/stars/kozmic/laravel-poc-CVE-2018-15133.svg) ![forks](https://img.shields.io/github/forks/kozmic/laravel-poc-CVE-2018-15133.svg)
- [https://github.com/AlienX2001/better-poc-for-CVE-2018-15133](https://github.com/AlienX2001/better-poc-for-CVE-2018-15133) :  ![starts](https://img.shields.io/github/stars/AlienX2001/better-poc-for-CVE-2018-15133.svg) ![forks](https://img.shields.io/github/forks/AlienX2001/better-poc-for-CVE-2018-15133.svg)


## CVE-2018-1270
 Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket endpoints with a simple, in-memory STOMP broker through the spring-messaging module. A malicious user (or attacker) can craft a message to the broker that can lead to a remote code execution attack.

- [https://github.com/tafamace/CVE-2018-1270](https://github.com/tafamace/CVE-2018-1270) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1270.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1270.svg)


## CVE-2015-9235
 In jsonwebtoken node module before 4.2.2 it is possible for an attacker to bypass verification when a token digitally signed with an asymmetric key (RS/ES family) of algorithms but instead the attacker send a token digitally signed with a symmetric algorithm (HS* family).

- [https://github.com/WinDyAlphA/CVE-2015-9235_JWT_key_confusion](https://github.com/WinDyAlphA/CVE-2015-9235_JWT_key_confusion) :  ![starts](https://img.shields.io/github/stars/WinDyAlphA/CVE-2015-9235_JWT_key_confusion.svg) ![forks](https://img.shields.io/github/forks/WinDyAlphA/CVE-2015-9235_JWT_key_confusion.svg)


## CVE-2012-5221
 Directory traversal vulnerability in the PostScript Interpreter, as used on the HP LaserJet 4xxx, 5200, 90xx, M30xx, M4345, M50xx, M90xx, P3005, and P4xxx; LaserJet Enterprise P3015; Color LaserJet 3xxx, 47xx, 5550, 9500, CM60xx, CP35xx, CP4005, and CP6015; Color LaserJet Enterprise CP4xxx; and 9250c Digital Sender with model-dependent firmware through 52.x allows remote attackers to read arbitrary files via unknown vectors.

- [https://github.com/aredspy/HPCredDumper](https://github.com/aredspy/HPCredDumper) :  ![starts](https://img.shields.io/github/stars/aredspy/HPCredDumper.svg) ![forks](https://img.shields.io/github/forks/aredspy/HPCredDumper.svg)


## CVE-2007-4559
 Directory traversal vulnerability in the (1) extract and (2) extractall functions in the tarfile module in Python allows user-assisted remote attackers to overwrite arbitrary files via a .. (dot dot) sequence in filenames in a TAR archive, a related issue to CVE-2001-1267.

- [https://github.com/davidholiday/CVE-2007-4559](https://github.com/davidholiday/CVE-2007-4559) :  ![starts](https://img.shields.io/github/stars/davidholiday/CVE-2007-4559.svg) ![forks](https://img.shields.io/github/forks/davidholiday/CVE-2007-4559.svg)

