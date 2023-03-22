# Update 2023-03-22
## CVE-2023-27326
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Impalabs/CVE-2023-27326](https://github.com/Impalabs/CVE-2023-27326) :  ![starts](https://img.shields.io/github/stars/Impalabs/CVE-2023-27326.svg) ![forks](https://img.shields.io/github/forks/Impalabs/CVE-2023-27326.svg)


## CVE-2023-23416
 Windows Cryptographic Services Remote Code Execution Vulnerability

- [https://github.com/amitdubey1921/CVE-2023-23416](https://github.com/amitdubey1921/CVE-2023-23416) :  ![starts](https://img.shields.io/github/stars/amitdubey1921/CVE-2023-23416.svg) ![forks](https://img.shields.io/github/forks/amitdubey1921/CVE-2023-23416.svg)


## CVE-2023-23415
 Internet Control Message Protocol (ICMP) Remote Code Execution Vulnerability

- [https://github.com/amitdubey1921/CVE-2023-23416](https://github.com/amitdubey1921/CVE-2023-23416) :  ![starts](https://img.shields.io/github/stars/amitdubey1921/CVE-2023-23416.svg) ![forks](https://img.shields.io/github/forks/amitdubey1921/CVE-2023-23416.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/Trackflaw/CVE-2023-23397](https://github.com/Trackflaw/CVE-2023-23397) :  ![starts](https://img.shields.io/github/stars/Trackflaw/CVE-2023-23397.svg) ![forks](https://img.shields.io/github/forks/Trackflaw/CVE-2023-23397.svg)
- [https://github.com/SecCTechs/CVE-2023-23397](https://github.com/SecCTechs/CVE-2023-23397) :  ![starts](https://img.shields.io/github/stars/SecCTechs/CVE-2023-23397.svg) ![forks](https://img.shields.io/github/forks/SecCTechs/CVE-2023-23397.svg)


## CVE-2023-23192
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/pinarsadioglu/CVE-2023-23192](https://github.com/pinarsadioglu/CVE-2023-23192) :  ![starts](https://img.shields.io/github/stars/pinarsadioglu/CVE-2023-23192.svg) ![forks](https://img.shields.io/github/forks/pinarsadioglu/CVE-2023-23192.svg)
- [https://github.com/Penkyzduyi/CVE-2023-23192](https://github.com/Penkyzduyi/CVE-2023-23192) :  ![starts](https://img.shields.io/github/stars/Penkyzduyi/CVE-2023-23192.svg) ![forks](https://img.shields.io/github/forks/Penkyzduyi/CVE-2023-23192.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability.

- [https://github.com/HKxiaoli/Windows_AFD_LPE_CVE-2023-21768](https://github.com/HKxiaoli/Windows_AFD_LPE_CVE-2023-21768) :  ![starts](https://img.shields.io/github/stars/HKxiaoli/Windows_AFD_LPE_CVE-2023-21768.svg) ![forks](https://img.shields.io/github/forks/HKxiaoli/Windows_AFD_LPE_CVE-2023-21768.svg)


## CVE-2023-1337
 The RapidLoad Power-Up for Autoptimize plugin for WordPress is vulnerable to unauthorized data loss due to a missing capability check on the clear_uucss_logs function in versions up to, and including, 1.7.1. This makes it possible for authenticated attackers with subscriber-level access to delete plugin log files.

- [https://github.com/Penkyzduyi/CVE-2023-1337](https://github.com/Penkyzduyi/CVE-2023-1337) :  ![starts](https://img.shields.io/github/stars/Penkyzduyi/CVE-2023-1337.svg) ![forks](https://img.shields.io/github/forks/Penkyzduyi/CVE-2023-1337.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/doosec101/CVE-2022-46169](https://github.com/doosec101/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/doosec101/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/doosec101/CVE-2022-46169.svg)


## CVE-2022-35649
 The vulnerability was found in Moodle, occurs due to improper input validation when parsing PostScript code. An omitted execution parameter results in a remote code execution risk for sites running GhostScript versions older than 9.50. Successful exploitation of this vulnerability may result in complete compromise of vulnerable system.

- [https://github.com/antoinenguyen-09/CVE-2022-35649](https://github.com/antoinenguyen-09/CVE-2022-35649) :  ![starts](https://img.shields.io/github/stars/antoinenguyen-09/CVE-2022-35649.svg) ![forks](https://img.shields.io/github/forks/antoinenguyen-09/CVE-2022-35649.svg)


## CVE-2022-24715
 Icinga Web 2 is an open source monitoring web interface, framework and command-line interface. Authenticated users, with access to the configuration, can create SSH resource files in unintended directories, leading to the execution of arbitrary code. This issue has been resolved in versions 2.8.6, 2.9.6 and 2.10 of Icinga Web 2. Users unable to upgrade should limit access to the Icinga Web 2 configuration.

- [https://github.com/JacobEbben/CVE-2022-24715](https://github.com/JacobEbben/CVE-2022-24715) :  ![starts](https://img.shields.io/github/stars/JacobEbben/CVE-2022-24715.svg) ![forks](https://img.shields.io/github/forks/JacobEbben/CVE-2022-24715.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Hattan515/POC-CVE-2021-41773](https://github.com/Hattan515/POC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Hattan515/POC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Hattan515/POC-CVE-2021-41773.svg)
- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-30632
 Out of bounds write in V8 in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/maldev866/ChExp_CVE-2021-30632](https://github.com/maldev866/ChExp_CVE-2021-30632) :  ![starts](https://img.shields.io/github/stars/maldev866/ChExp_CVE-2021-30632.svg) ![forks](https://img.shields.io/github/forks/maldev866/ChExp_CVE-2021-30632.svg)


## CVE-2021-27065
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27078.

- [https://github.com/Nick-Yin12/106362522](https://github.com/Nick-Yin12/106362522) :  ![starts](https://img.shields.io/github/stars/Nick-Yin12/106362522.svg) ![forks](https://img.shields.io/github/forks/Nick-Yin12/106362522.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.

- [https://github.com/Nick-Yin12/106362522](https://github.com/Nick-Yin12/106362522) :  ![starts](https://img.shields.io/github/stars/Nick-Yin12/106362522.svg) ![forks](https://img.shields.io/github/forks/Nick-Yin12/106362522.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/ch4rum/CVE-2021-4034](https://github.com/ch4rum/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ch4rum/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ch4rum/CVE-2021-4034.svg)


## CVE-2021-3656
 A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested guest (L2). Due to improper validation of the &quot;virt_ext&quot; field, this issue could allow a malicious L1 to disable both VMLOAD/VMSAVE intercepts and VLS (Virtual VMLOAD/VMSAVE) for the L2 guest. As a result, the L2 guest would be allowed to read/write physical pages of the host, resulting in a crash of the entire system, leak of sensitive data or potential guest-to-host escape.

- [https://github.com/rami08448/CVE-2021-3656-Demo](https://github.com/rami08448/CVE-2021-3656-Demo) :  ![starts](https://img.shields.io/github/stars/rami08448/CVE-2021-3656-Demo.svg) ![forks](https://img.shields.io/github/forks/rami08448/CVE-2021-3656-Demo.svg)


## CVE-2020-26256
 Fast-csv is an npm package for parsing and formatting CSVs or any other delimited value file in node. In fast-cvs before version 4.3.6 there is a possible ReDoS vulnerability (Regular Expression Denial of Service) when using ignoreEmpty option when parsing. This has been patched in `v4.3.6` You will only be affected by this if you use the `ignoreEmpty` parsing option. If you do use this option it is recommended that you upgrade to the latest version `v4.3.6` This vulnerability was found using a CodeQL query which identified `EMPTY_ROW_REGEXP` regular expression as vulnerable.

- [https://github.com/ossf-cve-benchmark/CVE-2020-26256](https://github.com/ossf-cve-benchmark/CVE-2020-26256) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2020-26256.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2020-26256.svg)


## CVE-2020-1971
 The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the &quot;-crl_download&quot; option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).

- [https://github.com/nidhi7598/OPENSSL_1.1.11g_G3_CVE-2020-1971](https://github.com/nidhi7598/OPENSSL_1.1.11g_G3_CVE-2020-1971) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.11g_G3_CVE-2020-1971.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.11g_G3_CVE-2020-1971.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/heeloo123/CVE-2020-0796](https://github.com/heeloo123/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/heeloo123/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/heeloo123/CVE-2020-0796.svg)


## CVE-2018-6341
 React applications which rendered to HTML using the ReactDOMServer API were not escaping user-supplied attribute names at render-time. That lack of escaping could lead to a cross-site scripting vulnerability. This issue affected minor releases 16.0.x, 16.1.x, 16.2.x, 16.3.x, and 16.4.x. It was fixed in 16.0.1, 16.1.2, 16.2.1, 16.3.3, and 16.4.2.

- [https://github.com/diwangs/react16-ssr](https://github.com/diwangs/react16-ssr) :  ![starts](https://img.shields.io/github/stars/diwangs/react16-ssr.svg) ![forks](https://img.shields.io/github/forks/diwangs/react16-ssr.svg)

