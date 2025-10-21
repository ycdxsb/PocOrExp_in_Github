# Update 2025-10-21
## CVE-2025-59295
 Heap-based buffer overflow in Internet Explorer allows an unauthorized attacker to execute code over a network.

- [https://github.com/usjnx72726w/CVE-2025-59295](https://github.com/usjnx72726w/CVE-2025-59295) :  ![starts](https://img.shields.io/github/stars/usjnx72726w/CVE-2025-59295.svg) ![forks](https://img.shields.io/github/forks/usjnx72726w/CVE-2025-59295.svg)


## CVE-2025-59285
 Deserialization of untrusted data in Azure Monitor Agent allows an authorized attacker to elevate privileges locally.

- [https://github.com/allinsthon/CVE-2025-59285](https://github.com/allinsthon/CVE-2025-59285) :  ![starts](https://img.shields.io/github/stars/allinsthon/CVE-2025-59285.svg) ![forks](https://img.shields.io/github/forks/allinsthon/CVE-2025-59285.svg)


## CVE-2025-55315
 Inconsistent interpretation of http requests ('http request/response smuggling') in ASP.NET Core allows an authorized attacker to bypass a security feature over a network.

- [https://github.com/7huukdlnkjkjba/CVE-2025-55315-](https://github.com/7huukdlnkjkjba/CVE-2025-55315-) :  ![starts](https://img.shields.io/github/stars/7huukdlnkjkjba/CVE-2025-55315-.svg) ![forks](https://img.shields.io/github/forks/7huukdlnkjkjba/CVE-2025-55315-.svg)


## CVE-2025-54874
 OpenJPEG is an open-source JPEG 2000 codec. In OpenJPEG from 2.5.1 through 2.5.3, a call to opj_jp2_read_header may lead to OOB heap memory write when the data stream p_stream is too short and p_image is not initialized.

- [https://github.com/cyhe50/cve-2025-54874-poc](https://github.com/cyhe50/cve-2025-54874-poc) :  ![starts](https://img.shields.io/github/stars/cyhe50/cve-2025-54874-poc.svg) ![forks](https://img.shields.io/github/forks/cyhe50/cve-2025-54874-poc.svg)


## CVE-2025-54236
 Adobe Commerce versions 2.4.9-alpha2, 2.4.8-p2, 2.4.7-p7, 2.4.6-p12, 2.4.5-p14, 2.4.4-p15 and earlier are affected by an Improper Input Validation vulnerability. A successful attacker can abuse this to achieve session takeover, increasing the confidentiality, and integrity impact to high. Exploitation of this issue does not require user interaction.

- [https://github.com/wubinworks/magento2-session-reaper-patch](https://github.com/wubinworks/magento2-session-reaper-patch) :  ![starts](https://img.shields.io/github/stars/wubinworks/magento2-session-reaper-patch.svg) ![forks](https://img.shields.io/github/forks/wubinworks/magento2-session-reaper-patch.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/MiclelsonCN/CVE-2025-49844_POC](https://github.com/MiclelsonCN/CVE-2025-49844_POC) :  ![starts](https://img.shields.io/github/stars/MiclelsonCN/CVE-2025-49844_POC.svg) ![forks](https://img.shields.io/github/forks/MiclelsonCN/CVE-2025-49844_POC.svg)


## CVE-2025-39965
time we go through the byspi list.

- [https://github.com/Shreyas-Penkar/CVE-2025-39965](https://github.com/Shreyas-Penkar/CVE-2025-39965) :  ![starts](https://img.shields.io/github/stars/Shreyas-Penkar/CVE-2025-39965.svg) ![forks](https://img.shields.io/github/forks/Shreyas-Penkar/CVE-2025-39965.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/robbin0919/CVE-2025-32463](https://github.com/robbin0919/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/robbin0919/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/robbin0919/CVE-2025-32463.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/Batman529/PoC-CVE-2025-32433](https://github.com/Batman529/PoC-CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/Batman529/PoC-CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/Batman529/PoC-CVE-2025-32433.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/MiclelsonCN/CVE-2025-30208_POC](https://github.com/MiclelsonCN/CVE-2025-30208_POC) :  ![starts](https://img.shields.io/github/stars/MiclelsonCN/CVE-2025-30208_POC.svg) ![forks](https://img.shields.io/github/forks/MiclelsonCN/CVE-2025-30208_POC.svg)


## CVE-2025-11579
 github.com/nwaples/rardecode versions =2.1.1 fail to restrict the dictionary size when reading large RAR dictionary sizes, which allows an attacker to provide a specially crafted RAR file and cause Denial of Service via an Out Of Memory Crash.

- [https://github.com/shinigami-777/PoC_CVE-2025-11579](https://github.com/shinigami-777/PoC_CVE-2025-11579) :  ![starts](https://img.shields.io/github/stars/shinigami-777/PoC_CVE-2025-11579.svg) ![forks](https://img.shields.io/github/forks/shinigami-777/PoC_CVE-2025-11579.svg)


## CVE-2025-10294
 The OwnID Passwordless Login plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 1.3.4. This is due to the plugin not properly checking if the ownid_shared_secret value is empty prior to authenticating a user via JWT. This makes it possible for unauthenticated attackers to log in as other users, including administrators, on instances where the plugin has not been fully configured yet.

- [https://github.com/RedFoxNxploits/CVE-2025-10294-Poc](https://github.com/RedFoxNxploits/CVE-2025-10294-Poc) :  ![starts](https://img.shields.io/github/stars/RedFoxNxploits/CVE-2025-10294-Poc.svg) ![forks](https://img.shields.io/github/forks/RedFoxNxploits/CVE-2025-10294-Poc.svg)


## CVE-2025-1094
 Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.

- [https://github.com/PinkArmor/CVE-2025-1094-Lab-Setup](https://github.com/PinkArmor/CVE-2025-1094-Lab-Setup) :  ![starts](https://img.shields.io/github/stars/PinkArmor/CVE-2025-1094-Lab-Setup.svg) ![forks](https://img.shields.io/github/forks/PinkArmor/CVE-2025-1094-Lab-Setup.svg)


## CVE-2025-1087
 Kong Insomnia Desktop Application before 11.0.2 contains a template injection vulnerability that allows attackers to execute arbitrary code. The vulnerability exists due to insufficient validation of user-supplied input when processing template strings, which can lead to arbitrary JavaScript execution in the context of the application.

- [https://github.com/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874](https://github.com/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874) :  ![starts](https://img.shields.io/github/stars/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874.svg) ![forks](https://img.shields.io/github/forks/ryanmroth/Orbit-Fox_SSRF_CVE-2025-10874.svg)


## CVE-2025-1023
 A vulnerability exists in ChurchCRM 5.13.0 and prior that allows an attacker to execute arbitrary SQL queries by exploiting a time-based blind SQL Injection vulnerability in the EditEventTypes functionality. The newCountName parameter is directly concatenated into an SQL query without proper sanitization, allowing an attacker to manipulate database queries and execute arbitrary commands, potentially leading to data exfiltration, modification, or deletion.

- [https://github.com/dptsec/CVE-2025-10230](https://github.com/dptsec/CVE-2025-10230) :  ![starts](https://img.shields.io/github/stars/dptsec/CVE-2025-10230.svg) ![forks](https://img.shields.io/github/forks/dptsec/CVE-2025-10230.svg)


## CVE-2024-20405
 This vulnerability is due to insufficient validation of user-supplied input for specific HTTP requests that are sent to an affected device. An attacker could exploit this vulnerability by persuading a user to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the affected interface or access sensitive information on the affected device.

- [https://github.com/3zz4t/CVE-2024-20405](https://github.com/3zz4t/CVE-2024-20405) :  ![starts](https://img.shields.io/github/stars/3zz4t/CVE-2024-20405.svg) ![forks](https://img.shields.io/github/forks/3zz4t/CVE-2024-20405.svg)


## CVE-2024-20404
 This vulnerability is due to insufficient validation of user-supplied input for specific HTTP requests that are sent to an affected system. An attacker could exploit this vulnerability by sending a crafted HTTP request to the affected device. A successful exploit could allow the attacker to obtain limited sensitive information for services that are associated to the affected device.

- [https://github.com/3zz4t/CVE-2024-20404](https://github.com/3zz4t/CVE-2024-20404) :  ![starts](https://img.shields.io/github/stars/3zz4t/CVE-2024-20404.svg) ![forks](https://img.shields.io/github/forks/3zz4t/CVE-2024-20404.svg)


## CVE-2023-28121
 An issue in WooCommerce Payments plugin for WordPress (versions 5.6.1 and lower) allows an unauthenticated attacker to send requests on behalf of an elevated user, like administrator. This allows a remote, unauthenticated attacker to gain admin access on a site that has the affected version of the plugin activated.

- [https://github.com/0axz-tools/CVE-2023-28121](https://github.com/0axz-tools/CVE-2023-28121) :  ![starts](https://img.shields.io/github/stars/0axz-tools/CVE-2023-28121.svg) ![forks](https://img.shields.io/github/forks/0axz-tools/CVE-2023-28121.svg)


## CVE-2022-24348
 Argo CD before 2.1.9 and 2.2.x before 2.2.4 allows directory traversal related to Helm charts because of an error in helmTemplate in repository.go. For example, an attacker may be able to discover credentials stored in a YAML file.

- [https://github.com/DeveloperOl/CVE-2022-24348-2](https://github.com/DeveloperOl/CVE-2022-24348-2) :  ![starts](https://img.shields.io/github/stars/DeveloperOl/CVE-2022-24348-2.svg) ![forks](https://img.shields.io/github/forks/DeveloperOl/CVE-2022-24348-2.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/NickoPS87/Spring4Shell-Python-Firewall-POC](https://github.com/NickoPS87/Spring4Shell-Python-Firewall-POC) :  ![starts](https://img.shields.io/github/stars/NickoPS87/Spring4Shell-Python-Firewall-POC.svg) ![forks](https://img.shields.io/github/forks/NickoPS87/Spring4Shell-Python-Firewall-POC.svg)


## CVE-2017-1000353
 Jenkins versions 2.56 and earlier as well as 2.46.1 LTS and earlier are vulnerable to an unauthenticated remote code execution. An unauthenticated remote code execution vulnerability allowed attackers to transfer a serialized Java `SignedObject` object to the Jenkins CLI, that would be deserialized using a new `ObjectInputStream`, bypassing the existing blacklist-based protection mechanism. We're fixing this issue by adding `SignedObject` to the blacklist. We're also backporting the new HTTP CLI protocol from Jenkins 2.54 to LTS 2.46.2, and deprecating the remoting-based (i.e. Java serialization) CLI protocol, disabling it by default.

- [https://github.com/Jelc0Doesbruf/CVE-2017-1000353](https://github.com/Jelc0Doesbruf/CVE-2017-1000353) :  ![starts](https://img.shields.io/github/stars/Jelc0Doesbruf/CVE-2017-1000353.svg) ![forks](https://img.shields.io/github/forks/Jelc0Doesbruf/CVE-2017-1000353.svg)


## CVE-2015-1635
 HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka "HTTP.sys Remote Code Execution Vulnerability."

- [https://github.com/moeinmiadi/CVE-2015-1635_PoC](https://github.com/moeinmiadi/CVE-2015-1635_PoC) :  ![starts](https://img.shields.io/github/stars/moeinmiadi/CVE-2015-1635_PoC.svg) ![forks](https://img.shields.io/github/forks/moeinmiadi/CVE-2015-1635_PoC.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/0xinf0/bleeding_onions](https://github.com/0xinf0/bleeding_onions) :  ![starts](https://img.shields.io/github/stars/0xinf0/bleeding_onions.svg) ![forks](https://img.shields.io/github/forks/0xinf0/bleeding_onions.svg)

