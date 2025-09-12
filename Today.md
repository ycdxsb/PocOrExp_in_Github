# Update 2025-09-12
## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819](https://github.com/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819.svg)


## CVE-2025-57520
 A Cross Site Scripting (XSS) vulnerability exists in Decap CMS thru 3.8.3. Input fields such as body, tags, title, and description are not properly sanitized before being rendered in the content preview pane. This enables an attacker to inject arbitrary JavaScript which executes whenever a user views the preview panel. The vulnerability affects multiple input vectors and does not require user interaction beyond viewing the affected content.

- [https://github.com/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-](https://github.com/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-) :  ![starts](https://img.shields.io/github/stars/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-.svg) ![forks](https://img.shields.io/github/forks/onurcangnc/CVE-2025-57520-Stored-XSS-in-Decap-CMS-3.8.3-.svg)


## CVE-2025-57392
 BenimPOS Masaustu 3.0.x is affected by insecure file permissions. The application installation directory grants Everyone and BUILTIN\Users groups FILE_ALL_ACCESS, allowing local users to replace or modify .exe and .dll files. This may lead to privilege escalation or arbitrary code execution upon launch by another user or elevated context.

- [https://github.com/meisterlos/CVE-2025-57392](https://github.com/meisterlos/CVE-2025-57392) :  ![starts](https://img.shields.io/github/stars/meisterlos/CVE-2025-57392.svg) ![forks](https://img.shields.io/github/forks/meisterlos/CVE-2025-57392.svg)


## CVE-2025-55232
 Deserialization of untrusted data in Microsoft High Performance Compute Pack (HPC) allows an unauthorized attacker to execute code over a network.

- [https://github.com/h4xnz/CVE-2025-55232-Exploit](https://github.com/h4xnz/CVE-2025-55232-Exploit) :  ![starts](https://img.shields.io/github/stars/h4xnz/CVE-2025-55232-Exploit.svg) ![forks](https://img.shields.io/github/forks/h4xnz/CVE-2025-55232-Exploit.svg)


## CVE-2025-54236
 Adobe Commerce versions 2.4.9-alpha2, 2.4.8-p2, 2.4.7-p7, 2.4.6-p12, 2.4.5-p14, 2.4.4-p15 and earlier are affected by an Improper Input Validation vulnerability. A successful attacker can abuse this to achieve session takeover, increasing the confidentiality, and integrity impact to high. Exploitation of this issue does not require user interaction.

- [https://github.com/amalpvatayam67/day01-sessionreaper-lab](https://github.com/amalpvatayam67/day01-sessionreaper-lab) :  ![starts](https://img.shields.io/github/stars/amalpvatayam67/day01-sessionreaper-lab.svg) ![forks](https://img.shields.io/github/forks/amalpvatayam67/day01-sessionreaper-lab.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/Zuack55/Roundcube-1.6.10-Post-Auth-RCE-CVE-2025-49113-](https://github.com/Zuack55/Roundcube-1.6.10-Post-Auth-RCE-CVE-2025-49113-) :  ![starts](https://img.shields.io/github/stars/Zuack55/Roundcube-1.6.10-Post-Auth-RCE-CVE-2025-49113-.svg) ![forks](https://img.shields.io/github/forks/Zuack55/Roundcube-1.6.10-Post-Auth-RCE-CVE-2025-49113-.svg)


## CVE-2025-42957
 SAP S/4HANA allows an attacker with user privileges to exploit a vulnerability in the function module exposed via RFC. This flaw enables the injection of arbitrary ABAP code into the system, bypassing essential authorization checks. This vulnerability effectively functions as a backdoor, creating the risk of full system compromise, undermining the confidentiality, integrity and availability of the system.

- [https://github.com/mrk336/CVE-2025-42957-SAP-S-4HANA-Under-Siege](https://github.com/mrk336/CVE-2025-42957-SAP-S-4HANA-Under-Siege) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2025-42957-SAP-S-4HANA-Under-Siege.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2025-42957-SAP-S-4HANA-Under-Siege.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/scandijamjam1/CVE-2025-32433](https://github.com/scandijamjam1/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/scandijamjam1/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/scandijamjam1/CVE-2025-32433.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/f4dee-backup/CVE-2025-31161](https://github.com/f4dee-backup/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/f4dee-backup/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/f4dee-backup/CVE-2025-31161.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/Bishben/xwiki-15.10.8-reverse-shell-cve-2025-24893](https://github.com/Bishben/xwiki-15.10.8-reverse-shell-cve-2025-24893) :  ![starts](https://img.shields.io/github/stars/Bishben/xwiki-15.10.8-reverse-shell-cve-2025-24893.svg) ![forks](https://img.shields.io/github/forks/Bishben/xwiki-15.10.8-reverse-shell-cve-2025-24893.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/yum1ra/CVE-2025-24054_CVE-2025-24071-PoC](https://github.com/yum1ra/CVE-2025-24054_CVE-2025-24071-PoC) :  ![starts](https://img.shields.io/github/stars/yum1ra/CVE-2025-24054_CVE-2025-24071-PoC.svg) ![forks](https://img.shields.io/github/forks/yum1ra/CVE-2025-24054_CVE-2025-24071-PoC.svg)


## CVE-2025-24054
 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/yum1ra/CVE-2025-24054_CVE-2025-24071-PoC](https://github.com/yum1ra/CVE-2025-24054_CVE-2025-24071-PoC) :  ![starts](https://img.shields.io/github/stars/yum1ra/CVE-2025-24054_CVE-2025-24071-PoC.svg) ![forks](https://img.shields.io/github/forks/yum1ra/CVE-2025-24054_CVE-2025-24071-PoC.svg)


## CVE-2025-10142
 The PagBank / PagSeguro Connect para WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'status' parameter in all versions up to, and including, 4.44.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with Shop Manager-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/MooseLoveti/PagSeguro-Connect-Para-WooCommerce-CVE-Report](https://github.com/MooseLoveti/PagSeguro-Connect-Para-WooCommerce-CVE-Report) :  ![starts](https://img.shields.io/github/stars/MooseLoveti/PagSeguro-Connect-Para-WooCommerce-CVE-Report.svg) ![forks](https://img.shields.io/github/forks/MooseLoveti/PagSeguro-Connect-Para-WooCommerce-CVE-Report.svg)


## CVE-2025-5660
 A vulnerability, which was classified as critical, has been found in PHPGurukul Complaint Management System 2.0. Affected by this issue is some unknown functionality of the file /user/register-complaint.php. The manipulation of the argument noc leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Userr404/CVE-2025-56605](https://github.com/Userr404/CVE-2025-56605) :  ![starts](https://img.shields.io/github/stars/Userr404/CVE-2025-56605.svg) ![forks](https://img.shields.io/github/forks/Userr404/CVE-2025-56605.svg)


## CVE-2024-32019
 Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC](https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC) :  ![starts](https://img.shields.io/github/stars/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC.svg) ![forks](https://img.shields.io/github/forks/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/P4x1s/CVE-2024-23897](https://github.com/P4x1s/CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2024-23897.svg)
- [https://github.com/amalpvatayam67/day03-jenkins-23897](https://github.com/amalpvatayam67/day03-jenkins-23897) :  ![starts](https://img.shields.io/github/stars/amalpvatayam67/day03-jenkins-23897.svg) ![forks](https://img.shields.io/github/forks/amalpvatayam67/day03-jenkins-23897.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/P4x1s/CVE-2024-6387](https://github.com/P4x1s/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2024-6387.svg)


## CVE-2024-4956
 Path Traversal in Sonatype Nexus Repository 3 allows an unauthenticated attacker to read system files. Fixed in version 3.68.1.

- [https://github.com/amalpvatayam67/day04-nexus-4956](https://github.com/amalpvatayam67/day04-nexus-4956) :  ![starts](https://img.shields.io/github/stars/amalpvatayam67/day04-nexus-4956.svg) ![forks](https://img.shields.io/github/forks/amalpvatayam67/day04-nexus-4956.svg)


## CVE-2023-23638
This issue affects Apache Dubbo 2.7.x version 2.7.21 and prior versions; Apache Dubbo 3.0.x version 3.0.13 and prior versions; Apache Dubbo 3.1.x version 3.1.5 and prior versions. 

- [https://github.com/P4x1s/CVE-2023-23638-Tools](https://github.com/P4x1s/CVE-2023-23638-Tools) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2023-23638-Tools.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2023-23638-Tools.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/P4x1s/CVE-2023-23397-POC](https://github.com/P4x1s/CVE-2023-23397-POC) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2023-23397-POC.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2023-23397-POC.svg)


## CVE-2023-1454
 A vulnerability classified as critical has been found in jeecg-boot 3.5.0. This affects an unknown part of the file jmreport/qurestSql. The manipulation of the argument apiSelectId leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-223299.

- [https://github.com/P4x1s/CVE-2023-1454-EXP](https://github.com/P4x1s/CVE-2023-1454-EXP) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2023-1454-EXP.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2023-1454-EXP.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel’s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/P4x1s/CVE-2023-0386](https://github.com/P4x1s/CVE-2023-0386) :  ![starts](https://img.shields.io/github/stars/P4x1s/CVE-2023-0386.svg) ![forks](https://img.shields.io/github/forks/P4x1s/CVE-2023-0386.svg)


## CVE-2022-22972
 VMware Workspace ONE Access, Identity Manager and vRealize Automation contain an authentication bypass vulnerability affecting local domain users. A malicious actor with network access to the UI may be able to obtain administrative access without the need to authenticate.

- [https://github.com/xk4ng/CVE-2022-22972](https://github.com/xk4ng/CVE-2022-22972) :  ![starts](https://img.shields.io/github/stars/xk4ng/CVE-2022-22972.svg) ![forks](https://img.shields.io/github/forks/xk4ng/CVE-2022-22972.svg)


## CVE-2022-20699
 Multiple vulnerabilities in Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers could allow an attacker to do any of the following: Execute arbitrary code Elevate privileges Execute arbitrary commands Bypass authentication and authorization protections Fetch and run unsigned software Cause denial of service (DoS) For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/Rohan-flutterint/CVE-2022-20699](https://github.com/Rohan-flutterint/CVE-2022-20699) :  ![starts](https://img.shields.io/github/stars/Rohan-flutterint/CVE-2022-20699.svg) ![forks](https://img.shields.io/github/forks/Rohan-flutterint/CVE-2022-20699.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/muhammad1596/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-21239
 PySAML2 is a pure python implementation of SAML Version 2 Standard. PySAML2 before 6.5.0 has an improper verification of cryptographic signature vulnerability. Users of pysaml2 that use the default CryptoBackendXmlSec1 backend and need to verify signed SAML documents are impacted. PySAML2 does not ensure that a signed SAML document is correctly signed. The default CryptoBackendXmlSec1 backend is using the xmlsec1 binary to verify the signature of signed SAML documents, but by default xmlsec1 accepts any type of key found within the given document. xmlsec1 needs to be configured explicitly to only use only _x509 certificates_ for the verification process of the SAML document signature. This is fixed in PySAML2 6.5.0.

- [https://github.com/illera88/CVE-2021-21239](https://github.com/illera88/CVE-2021-21239) :  ![starts](https://img.shields.io/github/stars/illera88/CVE-2021-21239.svg) ![forks](https://img.shields.io/github/forks/illera88/CVE-2021-21239.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/anonymous121029034720384234234/py-network-scanner](https://github.com/anonymous121029034720384234234/py-network-scanner) :  ![starts](https://img.shields.io/github/stars/anonymous121029034720384234234/py-network-scanner.svg) ![forks](https://img.shields.io/github/forks/anonymous121029034720384234234/py-network-scanner.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow "go get" remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/currently-unkwn/CVE-2018-6574](https://github.com/currently-unkwn/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/currently-unkwn/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/currently-unkwn/CVE-2018-6574.svg)
- [https://github.com/adendarys/CVE-2018-6574](https://github.com/adendarys/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/adendarys/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/adendarys/CVE-2018-6574.svg)


## CVE-2017-12865
 Stack-based buffer overflow in "dnsproxy.c" in connman 1.34 and earlier allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted response query string passed to the "name" variable.

- [https://github.com/ManaswiJaiswal/Reproducing-ConnMan-1.34](https://github.com/ManaswiJaiswal/Reproducing-ConnMan-1.34) :  ![starts](https://img.shields.io/github/stars/ManaswiJaiswal/Reproducing-ConnMan-1.34.svg) ![forks](https://img.shields.io/github/forks/ManaswiJaiswal/Reproducing-ConnMan-1.34.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/insecrez/Remote-Integer-Overflow-Vulnerability](https://github.com/insecrez/Remote-Integer-Overflow-Vulnerability) :  ![starts](https://img.shields.io/github/stars/insecrez/Remote-Integer-Overflow-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/insecrez/Remote-Integer-Overflow-Vulnerability.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/kaylertee/Computer-Security-Equifax-2017](https://github.com/kaylertee/Computer-Security-Equifax-2017) :  ![starts](https://img.shields.io/github/stars/kaylertee/Computer-Security-Equifax-2017.svg) ![forks](https://img.shields.io/github/forks/kaylertee/Computer-Security-Equifax-2017.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/pardhu045/linux-privilege-escalation](https://github.com/pardhu045/linux-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/pardhu045/linux-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/pardhu045/linux-privilege-escalation.svg)


## CVE-2014-0160
 The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.

- [https://github.com/tomdevman/heartbleed-bug](https://github.com/tomdevman/heartbleed-bug) :  ![starts](https://img.shields.io/github/stars/tomdevman/heartbleed-bug.svg) ![forks](https://img.shields.io/github/forks/tomdevman/heartbleed-bug.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/boriitoo/CVE-2012-2982](https://github.com/boriitoo/CVE-2012-2982) :  ![starts](https://img.shields.io/github/stars/boriitoo/CVE-2012-2982.svg) ![forks](https://img.shields.io/github/forks/boriitoo/CVE-2012-2982.svg)

