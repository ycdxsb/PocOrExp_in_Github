# Update 2026-07-11
## CVE-2026-61343
 LibreBooking's email template editor save action passes the submitted template name directly into the destination file path, allowing a remote attacker with administrator credentials to write an arbitrary file outside the template directory and execute code. Fixed in 5.1.0.

- [https://github.com/nmagill123/CVE-2026-61343-poc-librebooking-rce](https://github.com/nmagill123/CVE-2026-61343-poc-librebooking-rce) :  ![starts](https://img.shields.io/github/stars/nmagill123/CVE-2026-61343-poc-librebooking-rce.svg) ![forks](https://img.shields.io/github/forks/nmagill123/CVE-2026-61343-poc-librebooking-rce.svg)


## CVE-2026-57517
 Control Web Panel before 0.9.8.1225 contains a blind SQL injection vulnerability that allows unauthenticated remote attackers to execute arbitrary SQL queries by submitting unsanitized input through the userRes POST parameter at the user endpoint. Attackers can exploit MySQL root privileges obtained via the injection to write arbitrary files using INTO DUMPFILE, enabling deployment of a PHP webshell to the web-accessible roundcube logs directory and achieving remote code execution as the cwpsvc account.

- [https://github.com/gagaltotal/CVE-2026-57517-CWP](https://github.com/gagaltotal/CVE-2026-57517-CWP) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-57517-CWP.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-57517-CWP.svg)


## CVE-2026-56876
 extract-zip does not validate symlink targets when extracting zip archives. When processing a malicious zip file containing a symlink with a relative path like '../../../../etc/passwd', extract-zip will extract the symlink without validation, allowing it to point outside the extraction directory. Depending on how extract-zip is used, an attacker could read or write to arbitrary files.

- [https://github.com/ziad626/CVE-2026-56876-POC](https://github.com/ziad626/CVE-2026-56876-POC) :  ![starts](https://img.shields.io/github/stars/ziad626/CVE-2026-56876-POC.svg) ![forks](https://img.shields.io/github/forks/ziad626/CVE-2026-56876-POC.svg)


## CVE-2026-56129
 Generic IO & Memory Access driver for PCs provided by TOSHIBA CORPORATION and Dynabook Inc. exposes its IOCTL with insufficient access control. A logged-in user with no administrative privilege may access physical memory.

- [https://github.com/valium007/qiomem](https://github.com/valium007/qiomem) :  ![starts](https://img.shields.io/github/stars/valium007/qiomem.svg) ![forks](https://img.shields.io/github/forks/valium007/qiomem.svg)


## CVE-2026-53571
 Vite is a frontend tooling framework for JavaScript. Prior to 8.0.16, 7.3.5, and 6.4.3, the contents of files that are specified by server.fs.deny can be returned to the browser on Windows. Vite’s dev server denies direct access to sensitive files through server.fs.deny, including entries such as .env, .env.*, and *.{crt,pem}. However, on Windows, the deny logic does not correctly normalize NTFS ADS path forms before access checks are applied. Because of this, requests such as /.env::$DATA?raw are treated as allowed paths, while Windows resolves them to the original file's default data stream. Similar to that, Windows allows accessing a file using a different name with the 8.3 short name compatibility feature. Vite did not reject accessing files via them. This vulnerability is fixed in 8.0.16, 7.3.5, and 6.4.3.

- [https://github.com/TazmiDev/CVE-2026-53571](https://github.com/TazmiDev/CVE-2026-53571) :  ![starts](https://img.shields.io/github/stars/TazmiDev/CVE-2026-53571.svg) ![forks](https://img.shields.io/github/forks/TazmiDev/CVE-2026-53571.svg)


## CVE-2026-53359
use-after-free.

- [https://github.com/xj2268-TA/KVM-Januscape](https://github.com/xj2268-TA/KVM-Januscape) :  ![starts](https://img.shields.io/github/stars/xj2268-TA/KVM-Januscape.svg) ![forks](https://img.shields.io/github/forks/xj2268-TA/KVM-Januscape.svg)


## CVE-2026-50656
 Microsoft is aware of an elevation of privilege in the Microsoft Malware Protection Engine in Microsoft Defender publicly referred to as &quot;RoguePlanet &quot;.

- [https://github.com/g0thamRabb1t/CVE-2026-50656-rogueplanet-validation](https://github.com/g0thamRabb1t/CVE-2026-50656-rogueplanet-validation) :  ![starts](https://img.shields.io/github/stars/g0thamRabb1t/CVE-2026-50656-rogueplanet-validation.svg) ![forks](https://img.shields.io/github/forks/g0thamRabb1t/CVE-2026-50656-rogueplanet-validation.svg)


## CVE-2026-49230
Users are recommended to upgrade to version 3.17.0, which fixes the issue.

- [https://github.com/BiiTts/CVE-2026-49230-APISIX-jwe-decrypt-Auth-Bypass](https://github.com/BiiTts/CVE-2026-49230-APISIX-jwe-decrypt-Auth-Bypass) :  ![starts](https://img.shields.io/github/stars/BiiTts/CVE-2026-49230-APISIX-jwe-decrypt-Auth-Bypass.svg) ![forks](https://img.shields.io/github/forks/BiiTts/CVE-2026-49230-APISIX-jwe-decrypt-Auth-Bypass.svg)


## CVE-2026-48908
 A vulnerability in SP Page Builder for Joomla allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.

- [https://github.com/cazzysoci/cve-2026-48908](https://github.com/cazzysoci/cve-2026-48908) :  ![starts](https://img.shields.io/github/stars/cazzysoci/cve-2026-48908.svg) ![forks](https://img.shields.io/github/forks/cazzysoci/cve-2026-48908.svg)
- [https://github.com/g0thamRabb1t/CVE-2026-48908-joomla-sp-page-builder-detection](https://github.com/g0thamRabb1t/CVE-2026-48908-joomla-sp-page-builder-detection) :  ![starts](https://img.shields.io/github/stars/g0thamRabb1t/CVE-2026-48908-joomla-sp-page-builder-detection.svg) ![forks](https://img.shields.io/github/forks/g0thamRabb1t/CVE-2026-48908-joomla-sp-page-builder-detection.svg)


## CVE-2026-48907
 A vulnerability in the JCE editor extension for Joomla allows the creation of new editor profiles for unauthenticated users, ultimately resulting in PHP code upload and execution.

- [https://github.com/g0thamRabb1t/CVE-2026-48907-Joomla-JCE-detection](https://github.com/g0thamRabb1t/CVE-2026-48907-Joomla-JCE-detection) :  ![starts](https://img.shields.io/github/stars/g0thamRabb1t/CVE-2026-48907-Joomla-JCE-detection.svg) ![forks](https://img.shields.io/github/forks/g0thamRabb1t/CVE-2026-48907-Joomla-JCE-detection.svg)


## CVE-2026-48282
 ColdFusion versions 2025.9, 2023.20 and earlier are affected by an Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability that could lead to arbitrary code execution in the context of the current user. Exploitation of this issue does not require user interaction. Scope is changed.

- [https://github.com/g0thamRabb1t/CVE-2026-48282-coldfusion-rds-detection](https://github.com/g0thamRabb1t/CVE-2026-48282-coldfusion-rds-detection) :  ![starts](https://img.shields.io/github/stars/g0thamRabb1t/CVE-2026-48282-coldfusion-rds-detection.svg) ![forks](https://img.shields.io/github/forks/g0thamRabb1t/CVE-2026-48282-coldfusion-rds-detection.svg)


## CVE-2026-46331
offset_valid() against INT_MIN, where negation is undefined.

- [https://github.com/g0thamRabb1t/CVE-2026-46331-pedit-COW-detection](https://github.com/g0thamRabb1t/CVE-2026-46331-pedit-COW-detection) :  ![starts](https://img.shields.io/github/stars/g0thamRabb1t/CVE-2026-46331-pedit-COW-detection.svg) ![forks](https://img.shields.io/github/forks/g0thamRabb1t/CVE-2026-46331-pedit-COW-detection.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/yellow-key/yellowkey-bitlocker](https://github.com/yellow-key/yellowkey-bitlocker) :  ![starts](https://img.shields.io/github/stars/yellow-key/yellowkey-bitlocker.svg) ![forks](https://img.shields.io/github/forks/yellow-key/yellowkey-bitlocker.svg)


## CVE-2026-43503
so segments drawing frags from frag_list members carry the marker.

- [https://github.com/lieehrdiansyah12/CVE-2026-43503](https://github.com/lieehrdiansyah12/CVE-2026-43503) :  ![starts](https://img.shields.io/github/stars/lieehrdiansyah12/CVE-2026-43503.svg) ![forks](https://img.shields.io/github/forks/lieehrdiansyah12/CVE-2026-43503.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/pubglite55/oppo-ghostlock](https://github.com/pubglite55/oppo-ghostlock) :  ![starts](https://img.shields.io/github/stars/pubglite55/oppo-ghostlock.svg) ![forks](https://img.shields.io/github/forks/pubglite55/oppo-ghostlock.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/g0thamRabb1t/CVE-2026-43284-dirtyfrag-detection](https://github.com/g0thamRabb1t/CVE-2026-43284-dirtyfrag-detection) :  ![starts](https://img.shields.io/github/stars/g0thamRabb1t/CVE-2026-43284-dirtyfrag-detection.svg) ![forks](https://img.shields.io/github/forks/g0thamRabb1t/CVE-2026-43284-dirtyfrag-detection.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/phil-dirt/CVE-2026-41089-LongLogon](https://github.com/phil-dirt/CVE-2026-41089-LongLogon) :  ![starts](https://img.shields.io/github/stars/phil-dirt/CVE-2026-41089-LongLogon.svg) ![forks](https://img.shields.io/github/forks/phil-dirt/CVE-2026-41089-LongLogon.svg)


## CVE-2026-40473
Users are recommended to upgrade to version 4.20.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.6. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.2.

- [https://github.com/oscerd/CVE-2026-40473](https://github.com/oscerd/CVE-2026-40473) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-40473.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-40473.svg)


## CVE-2026-8037
 OS Command Injection Remote Code Execution Vulnerability in API in Progress ADC Products allows an un-authenticated attacker to execute arbitrary commands on the LoadMaster appliance by exploiting unsanitized input in multiple command endpoints

- [https://github.com/Caster-chen/CVE-2026-8037-POC](https://github.com/Caster-chen/CVE-2026-8037-POC) :  ![starts](https://img.shields.io/github/stars/Caster-chen/CVE-2026-8037-POC.svg) ![forks](https://img.shields.io/github/forks/Caster-chen/CVE-2026-8037-POC.svg)


## CVE-2026-4257
 The Contact Form by Supsystic plugin for WordPress is vulnerable to Server-Side Template Injection (SSTI) leading to Remote Code Execution (RCE) in all versions up to, and including, 1.7.36. This is due to the plugin using the Twig `Twig_Loader_String` template engine without sandboxing, combined with the `cfsPreFill` prefill functionality that allows unauthenticated users to inject arbitrary Twig expressions into form field values via GET parameters. This makes it possible for unauthenticated attackers to execute arbitrary PHP functions and OS commands on the server by leveraging Twig's `registerUndefinedFilterCallback()` method to register arbitrary PHP callbacks.

- [https://github.com/dann3xplo1t/CVE-2026-4257](https://github.com/dann3xplo1t/CVE-2026-4257) :  ![starts](https://img.shields.io/github/stars/dann3xplo1t/CVE-2026-4257.svg) ![forks](https://img.shields.io/github/forks/dann3xplo1t/CVE-2026-4257.svg)


## CVE-2026-0776
The specific flaw exists within the discord_rpc module. The product loads a file from an unsecured location. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of a target user. Was ZDI-CAN-27057.

- [https://github.com/zerkl/CVE-2026-0776](https://github.com/zerkl/CVE-2026-0776) :  ![starts](https://img.shields.io/github/stars/zerkl/CVE-2026-0776.svg) ![forks](https://img.shields.io/github/forks/zerkl/CVE-2026-0776.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-63579
 Unauthorized use of Kyocera printers, allows all information stored in the Kyocera address book to be exported. The security measure that encrypts incoming data ian be bypassed with this vulnerability, allowing encrypted data to be decrypted. Passwords and other sensitive information can be obtained. This affects Kyocera Command Center RX TASKalfa 2552ci, TASKalfa 3252ci, TASKalfa 2553ci, TASKalfa 3253ci, TASKalfa 3554ci, TASKalfa 4052ci, TASKalfa 5052ci, TASKalfa 6052ci, TASKalfa 7052ci, TASKalfa 8052ci, TASKalfa 7353ci, TASKalfa 8353ci, TASKalfa 2554ci, TASKalfa 3254ci, TASKalfa 505.

- [https://github.com/barisbaydur/CVE-2025-63579](https://github.com/barisbaydur/CVE-2025-63579) :  ![starts](https://img.shields.io/github/stars/barisbaydur/CVE-2025-63579.svg) ![forks](https://img.shields.io/github/forks/barisbaydur/CVE-2025-63579.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/Adel-hx0d/cve-2025-59287](https://github.com/Adel-hx0d/cve-2025-59287) :  ![starts](https://img.shields.io/github/stars/Adel-hx0d/cve-2025-59287.svg) ![forks](https://img.shields.io/github/forks/Adel-hx0d/cve-2025-59287.svg)


## CVE-2025-45422
 Incorrect access control in Proximus b-box v8c.725A allows authenticated attackers to bypass normal restrictions and make arbitrary changes to port forwarding rules.

- [https://github.com/Cedrico03/CVE-2025-45422---Bbox](https://github.com/Cedrico03/CVE-2025-45422---Bbox) :  ![starts](https://img.shields.io/github/stars/Cedrico03/CVE-2025-45422---Bbox.svg) ![forks](https://img.shields.io/github/forks/Cedrico03/CVE-2025-45422---Bbox.svg)


## CVE-2025-32375
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. Prior to 1.4.8, there was an insecure deserialization in BentoML's runner server. By setting specific headers and parameters in the POST request, it is possible to execute any unauthorized arbitrary code on the server, which will grant the attackers to have the initial access and information disclosure on the server. This vulnerability is fixed in 1.4.8.

- [https://github.com/surajpandeyp/CVE-2025-32375](https://github.com/surajpandeyp/CVE-2025-32375) :  ![starts](https://img.shields.io/github/stars/surajpandeyp/CVE-2025-32375.svg) ![forks](https://img.shields.io/github/forks/surajpandeyp/CVE-2025-32375.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/endusdksla/xwiki-cve-2025-24893](https://github.com/endusdksla/xwiki-cve-2025-24893) :  ![starts](https://img.shields.io/github/stars/endusdksla/xwiki-cve-2025-24893.svg) ![forks](https://img.shields.io/github/forks/endusdksla/xwiki-cve-2025-24893.svg)


## CVE-2025-22457
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.6, Ivanti Policy Secure before version 22.7R1.4, and Ivanti ZTA Gateways before version 22.8R2.2 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/benmevic/cve-2025-22457](https://github.com/benmevic/cve-2025-22457) :  ![starts](https://img.shields.io/github/stars/benmevic/cve-2025-22457.svg) ![forks](https://img.shields.io/github/forks/benmevic/cve-2025-22457.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/amnsecurity/ghostlink-writeup](https://github.com/amnsecurity/ghostlink-writeup) :  ![starts](https://img.shields.io/github/stars/amnsecurity/ghostlink-writeup.svg) ![forks](https://img.shields.io/github/forks/amnsecurity/ghostlink-writeup.svg)


## CVE-2022-46152
 OP-TEE Trusted OS is the secure side implementation of OP-TEE project, a Trusted Execution Environment. Versions prior to 3.19.0, contain an Improper Validation of Array Index vulnerability. The function `cleanup_shm_refs()` is called by both `entry_invoke_command()` and `entry_open_session()`. The commands `OPTEE_MSG_CMD_OPEN_SESSION` and `OPTEE_MSG_CMD_INVOKE_COMMAND` can be executed from the normal world via an OP-TEE SMC. This function is not validating the `num_params` argument, which is only limited to `OPTEE_MSG_MAX_NUM_PARAMS` (127) in the function `get_cmd_buffer()`. Therefore, an attacker in the normal world can craft an SMC call that will cause out-of-bounds reading in `cleanup_shm_refs` and potentially freeing of fake-objects in the function `mobj_put()`. A normal-world attacker with permission to execute SMC instructions may exploit this flaw. Maintainers believe this problem permits local privilege escalation from the normal world to the secure world. Version 3.19.0 contains a fix for this issue. There are no known workarounds.

- [https://github.com/0xbbdd/CVE-2022-46152](https://github.com/0xbbdd/CVE-2022-46152) :  ![starts](https://img.shields.io/github/stars/0xbbdd/CVE-2022-46152.svg) ![forks](https://img.shields.io/github/forks/0xbbdd/CVE-2022-46152.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/RootEvil333/CVE-2022-26134](https://github.com/RootEvil333/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/RootEvil333/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/RootEvil333/CVE-2022-26134.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/johnwickakash12/CVE-2021-41773](https://github.com/johnwickakash12/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/johnwickakash12/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/johnwickakash12/CVE-2021-41773.svg)


## CVE-2021-40346
 An integer overflow exists in HAProxy 2.0 through 2.5 in htx_add_header that can be exploited to perform an HTTP request smuggling attack, allowing an attacker to bypass all configured http-request HAProxy ACLs and possibly other ACLs.

- [https://github.com/jmg0929/CVE-2021-40346](https://github.com/jmg0929/CVE-2021-40346) :  ![starts](https://img.shields.io/github/stars/jmg0929/CVE-2021-40346.svg) ![forks](https://img.shields.io/github/forks/jmg0929/CVE-2021-40346.svg)


## CVE-2021-35448
 Emote Interactive Remote Mouse 3.008 on Windows allows attackers to execute arbitrary programs as Administrator by using the Image Transfer Folder feature to navigate to cmd.exe. It binds to local ports to listen for incoming connections.

- [https://github.com/Goultarde/CVE-2021-35448_RemoteMouse-3.008-RCE](https://github.com/Goultarde/CVE-2021-35448_RemoteMouse-3.008-RCE) :  ![starts](https://img.shields.io/github/stars/Goultarde/CVE-2021-35448_RemoteMouse-3.008-RCE.svg) ![forks](https://img.shields.io/github/forks/Goultarde/CVE-2021-35448_RemoteMouse-3.008-RCE.svg)


## CVE-2021-26832
 Cross Site Scripting (XSS) in the "Reset Password" page form of Priority Enterprise Management System v8.00 allows attackers to execute javascript on behalf of the victim by sending a malicious URL or directing the victim to a malicious site.

- [https://github.com/gal-nagli/CVE-2021-26832](https://github.com/gal-nagli/CVE-2021-26832) :  ![starts](https://img.shields.io/github/stars/gal-nagli/CVE-2021-26832.svg) ![forks](https://img.shields.io/github/forks/gal-nagli/CVE-2021-26832.svg)


## CVE-2021-3712
 ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING structure which contains a buffer holding the string data and a field holding the buffer length. This contrasts with normal C strings which are repesented as a buffer for the string data which is terminated with a NUL (0) byte. Although not a strict requirement, ASN.1 strings that are parsed using OpenSSL's own "d2i" functions (and other similar parsing functions) as well as any string whose value has been set with the ASN1_STRING_set() function will additionally NUL terminate the byte array in the ASN1_STRING structure. However, it is possible for applications to directly construct valid ASN1_STRING structures which do not NUL terminate the byte array by directly setting the "data" and "length" fields in the ASN1_STRING array. This can also happen by using the ASN1_STRING_set0() function. Numerous OpenSSL functions that print ASN.1 data have been found to assume that the ASN1_STRING byte array will be NUL terminated, even though this is not guaranteed for strings that have been directly constructed. Where an application requests an ASN.1 structure to be printed, and where that ASN.1 structure contains ASN1_STRINGs that have been directly constructed by the application without NUL terminating the "data" field, then a read buffer overrun can occur. The same thing can also occur during name constraints processing of certificates (for example if a certificate has been directly constructed by the application instead of loading it via the OpenSSL parsing functions, and the certificate contains non NUL terminated ASN1_STRING structures). It can also occur in the X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() functions. If a malicious actor can cause an application to directly construct an ASN1_STRING and then process it through one of the affected OpenSSL functions then this issue could be hit. This might result in a crash (causing a Denial of Service attack). It could also result in the disclosure of private memory contents (such as private keys, or sensitive plaintext). Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). Fixed in OpenSSL 1.0.2za (Affected 1.0.2-1.0.2y).

- [https://github.com/code-with-amitk/CentOS7_CVE-2021-3712_Remediation](https://github.com/code-with-amitk/CentOS7_CVE-2021-3712_Remediation) :  ![starts](https://img.shields.io/github/stars/code-with-amitk/CentOS7_CVE-2021-3712_Remediation.svg) ![forks](https://img.shields.io/github/forks/code-with-amitk/CentOS7_CVE-2021-3712_Remediation.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/iTzR1g/CVE-2019-9053](https://github.com/iTzR1g/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/iTzR1g/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/iTzR1g/CVE-2019-9053.svg)


## CVE-2017-15715
 In Apache httpd 2.4.0 to 2.4.29, the expression specified in FilesMatch could match '$' to a newline character in a malicious filename, rather than matching only the end of the filename. This could be exploited in environments where uploads of some files are are externally blocked, but only by matching the trailing portion of the filename.

- [https://github.com/ehsehs5652/CVE-2017-15715-httpd](https://github.com/ehsehs5652/CVE-2017-15715-httpd) :  ![starts](https://img.shields.io/github/stars/ehsehs5652/CVE-2017-15715-httpd.svg) ![forks](https://img.shields.io/github/forks/ehsehs5652/CVE-2017-15715-httpd.svg)


## CVE-2017-5123
 Insufficient data validation in waitid allowed an user to escape sandboxes on Linux.

- [https://github.com/h1bAna/CVE-2017-5123](https://github.com/h1bAna/CVE-2017-5123) :  ![starts](https://img.shields.io/github/stars/h1bAna/CVE-2017-5123.svg) ![forks](https://img.shields.io/github/forks/h1bAna/CVE-2017-5123.svg)

