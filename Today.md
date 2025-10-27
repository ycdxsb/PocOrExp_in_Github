# Update 2025-10-27
## CVE-2025-61884
 Vulnerability in the Oracle Configurator product of Oracle E-Business Suite (component: Runtime UI).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Configurator.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle Configurator accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/siddu7575/CVE-2025-61882-CVE-2025-61884](https://github.com/siddu7575/CVE-2025-61882-CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/siddu7575/CVE-2025-61882-CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/siddu7575/CVE-2025-61882-CVE-2025-61884.svg)


## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/siddu7575/CVE-2025-61882-CVE-2025-61884](https://github.com/siddu7575/CVE-2025-61882-CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/siddu7575/CVE-2025-61882-CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/siddu7575/CVE-2025-61882-CVE-2025-61884.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/jiansiting/CVE-2025-59287](https://github.com/jiansiting/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/jiansiting/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/jiansiting/CVE-2025-59287.svg)
- [https://github.com/garvitv14/CVE-2025-59287](https://github.com/garvitv14/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/garvitv14/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/garvitv14/CVE-2025-59287.svg)


## CVE-2025-48385
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When cloning a repository Git knows to optionally fetch a bundle advertised by the remote server, which allows the server-side to offload parts of the clone to a CDN. The Git client does not perform sufficient validation of the advertised bundles, which allows the remote side to perform protocol injection. This protocol injection can cause the client to write the fetched bundle to a location controlled by the adversary. The fetched content is fully controlled by the server, which can in the worst case lead to arbitrary code execution. The use of bundle URIs is not enabled by default and can be controlled by the bundle.heuristic config option. Some cases of the vulnerability require that the adversary is in control of where a repository will be cloned to. This either requires social engineering or a recursive clone with submodules. These cases can thus be avoided by disabling recursive clones. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/Mitchellzhou1/CVE-2025-48385-PoC](https://github.com/Mitchellzhou1/CVE-2025-48385-PoC) :  ![starts](https://img.shields.io/github/stars/Mitchellzhou1/CVE-2025-48385-PoC.svg) ![forks](https://img.shields.io/github/forks/Mitchellzhou1/CVE-2025-48385-PoC.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/DensuLabs/CVE-2025-32463](https://github.com/DensuLabs/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/DensuLabs/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/DensuLabs/CVE-2025-32463.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/rvizx/CVE-2025-24893](https://github.com/rvizx/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2025-24893.svg)


## CVE-2025-9983
The vendor did not respond in any way. Only version 11.100001.01.28 was tested, other versions might also be vulnerable.

- [https://github.com/sohaibeb/CVE-2025-9983](https://github.com/sohaibeb/CVE-2025-9983) :  ![starts](https://img.shields.io/github/stars/sohaibeb/CVE-2025-9983.svg) ![forks](https://img.shields.io/github/forks/sohaibeb/CVE-2025-9983.svg)


## CVE-2025-6130
 A vulnerability, which was classified as critical, has been found in TOTOLINK EX1200T 4.1.2cu.5232_B20210713. This issue affects some unknown processing of the file /boafrm/formStats of the component HTTP POST Request Handler. The manipulation leads to buffer overflow. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/pentastic-be/CVE-2025-61304](https://github.com/pentastic-be/CVE-2025-61304) :  ![starts](https://img.shields.io/github/stars/pentastic-be/CVE-2025-61304.svg) ![forks](https://img.shields.io/github/forks/pentastic-be/CVE-2025-61304.svg)


## CVE-2025-4796
 The Eventin plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 4.0.34. This is due to the plugin not properly validating a user's identity or capability prior to updating their details like email in the 'Eventin\Speaker\Api\SpeakerController::update_item' function. This makes it possible for unauthenticated attackers with contributor-level and above permissions to change arbitrary user's email addresses, including administrators, and leverage that to reset the user's password and gain access to their account.

- [https://github.com/Nxploited/CVE-2025-4796](https://github.com/Nxploited/CVE-2025-4796) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-4796.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-4796.svg)


## CVE-2025-4334
 The Simple User Registration plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 6.3. This is due to insufficient restrictions on user meta values that can be supplied during registration. This makes it possible for unauthenticated attackers to register as an administrator.

- [https://github.com/vinodwick/CVE-2025-4334](https://github.com/vinodwick/CVE-2025-4334) :  ![starts](https://img.shields.io/github/stars/vinodwick/CVE-2025-4334.svg) ![forks](https://img.shields.io/github/forks/vinodwick/CVE-2025-4334.svg)


## CVE-2024-41570
 An Unauthenticated Server-Side Request Forgery (SSRF) in demon callback handling in Havoc 2 0.7 allows attackers to send arbitrary network traffic originating from the team server.

- [https://github.com/diemoeve/CVE-2024-41570](https://github.com/diemoeve/CVE-2024-41570) :  ![starts](https://img.shields.io/github/stars/diemoeve/CVE-2024-41570.svg) ![forks](https://img.shields.io/github/forks/diemoeve/CVE-2024-41570.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/r0xDB/CVE-2024-23897](https://github.com/r0xDB/CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/r0xDB/CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/r0xDB/CVE-2024-23897.svg)


## CVE-2024-12084
 A heap-based buffer overflow flaw was found in the rsync daemon. This issue is due to improper handling of attacker-controlled checksum lengths (s2length) in the code. When MAX_DIGEST_LEN exceeds the fixed SUM_LENGTH (16 bytes), an attacker can write out of bounds in the sum2 buffer.

- [https://github.com/0xSigSegv0x00/cve-2024-12084](https://github.com/0xSigSegv0x00/cve-2024-12084) :  ![starts](https://img.shields.io/github/stars/0xSigSegv0x00/cve-2024-12084.svg) ![forks](https://img.shields.io/github/forks/0xSigSegv0x00/cve-2024-12084.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/davidrxchester/Grafana-8.3-Directory-Traversal](https://github.com/davidrxchester/Grafana-8.3-Directory-Traversal) :  ![starts](https://img.shields.io/github/stars/davidrxchester/Grafana-8.3-Directory-Traversal.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/Grafana-8.3-Directory-Traversal.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)
- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)

