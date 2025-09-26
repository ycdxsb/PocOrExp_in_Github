# Update 2025-09-26
## CVE-2025-57176
 The rfpiped service on TCP port 555 in Ceragon Networks / Siklu Communication EtherHaul series (8010TX and 1200FX tested) Firmware 7.4.0 through 10.7.3 allows unauthenticated file uploads to any writable location on the device. File upload packets use weak encryption (metadata only) with file contents transmitted in cleartext. No authentication or path validation is performed.

- [https://github.com/semaja22/CVE-2025-57176](https://github.com/semaja22/CVE-2025-57176) :  ![starts](https://img.shields.io/github/stars/semaja22/CVE-2025-57176.svg) ![forks](https://img.shields.io/github/forks/semaja22/CVE-2025-57176.svg)


## CVE-2025-57174
 An issue was discovered in Siklu Communications Etherhaul 8010TX and 1200FX devices, Firmware 7.4.0 through 10.7.3 and possibly other previous versions. The rfpiped service listening on TCP port 555 which uses static AES encryption keys hardcoded in the binary. These keys are identical across all devices, allowing attackers to craft encrypted packets that execute arbitrary commands without authentication. This is a failed patch for CVE-2017-7318. This issue may affect other Etherhaul series devices with shared firmware.

- [https://github.com/semaja22/CVE-2025-57174](https://github.com/semaja22/CVE-2025-57174) :  ![starts](https://img.shields.io/github/stars/semaja22/CVE-2025-57174.svg) ![forks](https://img.shields.io/github/forks/semaja22/CVE-2025-57174.svg)


## CVE-2025-56819
 An issue in Datart v.1.0.0-rc.3 allows a remote attacker to execute arbitrary code via the INIT connection parameter.

- [https://github.com/xyyzxc/CVE-2025-56819](https://github.com/xyyzxc/CVE-2025-56819) :  ![starts](https://img.shields.io/github/stars/xyyzxc/CVE-2025-56819.svg) ![forks](https://img.shields.io/github/forks/xyyzxc/CVE-2025-56819.svg)


## CVE-2025-56815
 Datart 1.0.0-rc.3 is vulnerable to Directory Traversal in the POST /viz/image interface, since the server directly uses MultipartFile.transferTo() to save the uploaded file to a path controllable by the user, and lacks strict verification of the file name.

- [https://github.com/xiaoxiaoranxxx/CVE-2025-56815](https://github.com/xiaoxiaoranxxx/CVE-2025-56815) :  ![starts](https://img.shields.io/github/stars/xiaoxiaoranxxx/CVE-2025-56815.svg) ![forks](https://img.shields.io/github/forks/xiaoxiaoranxxx/CVE-2025-56815.svg)


## CVE-2025-55780
 A null pointer dereference occurs in the function break_word_for_overflow_wrap() in MuPDF 1.26.4 when rendering a malformed EPUB document. Specifically, the function calls fz_html_split_flow() to split a FLOW_WORD node, but does not check if node-next is valid before accessing node-next-overflow_wrap, resulting in a crash if the split fails or returns a partial node chain.

- [https://github.com/ISH2YU/CVE-2025-55780](https://github.com/ISH2YU/CVE-2025-55780) :  ![starts](https://img.shields.io/github/stars/ISH2YU/CVE-2025-55780.svg) ![forks](https://img.shields.io/github/forks/ISH2YU/CVE-2025-55780.svg)


## CVE-2025-55188
 7-Zip before 25.01 does not always properly handle symbolic links during extraction.

- [https://github.com/Sh3ruman/CVE-2025-55188-7z-exploit](https://github.com/Sh3ruman/CVE-2025-55188-7z-exploit) :  ![starts](https://img.shields.io/github/stars/Sh3ruman/CVE-2025-55188-7z-exploit.svg) ![forks](https://img.shields.io/github/forks/Sh3ruman/CVE-2025-55188-7z-exploit.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/0xh3g4z1/CVE-2025-53770-SharePoint-RCE](https://github.com/0xh3g4z1/CVE-2025-53770-SharePoint-RCE) :  ![starts](https://img.shields.io/github/stars/0xh3g4z1/CVE-2025-53770-SharePoint-RCE.svg) ![forks](https://img.shields.io/github/forks/0xh3g4z1/CVE-2025-53770-SharePoint-RCE.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/nelissandro/CVE-2025-32463-Sudo-Chroot-Escape](https://github.com/nelissandro/CVE-2025-32463-Sudo-Chroot-Escape) :  ![starts](https://img.shields.io/github/stars/nelissandro/CVE-2025-32463-Sudo-Chroot-Escape.svg) ![forks](https://img.shields.io/github/forks/nelissandro/CVE-2025-32463-Sudo-Chroot-Escape.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/mirmeweu/cve-2025-32433](https://github.com/mirmeweu/cve-2025-32433) :  ![starts](https://img.shields.io/github/stars/mirmeweu/cve-2025-32433.svg) ![forks](https://img.shields.io/github/forks/mirmeweu/cve-2025-32433.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/0xh3g4z1/CVE-2025-29927-Next.js-Middleware-Authorization-Bypass](https://github.com/0xh3g4z1/CVE-2025-29927-Next.js-Middleware-Authorization-Bypass) :  ![starts](https://img.shields.io/github/stars/0xh3g4z1/CVE-2025-29927-Next.js-Middleware-Authorization-Bypass.svg) ![forks](https://img.shields.io/github/forks/0xh3g4z1/CVE-2025-29927-Next.js-Middleware-Authorization-Bypass.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/AliAmouz/CVE2025-24893](https://github.com/AliAmouz/CVE2025-24893) :  ![starts](https://img.shields.io/github/stars/AliAmouz/CVE2025-24893.svg) ![forks](https://img.shields.io/github/forks/AliAmouz/CVE2025-24893.svg)


## CVE-2025-10585
 Type confusion in V8 in Google Chrome prior to 140.0.7339.185 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/AdityaBhatt3010/CVE-2025-10585-The-Chrome-V8-Zero-Day](https://github.com/AdityaBhatt3010/CVE-2025-10585-The-Chrome-V8-Zero-Day) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2025-10585-The-Chrome-V8-Zero-Day.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2025-10585-The-Chrome-V8-Zero-Day.svg)
- [https://github.com/callinston/CVE-2025-10585](https://github.com/callinston/CVE-2025-10585) :  ![starts](https://img.shields.io/github/stars/callinston/CVE-2025-10585.svg) ![forks](https://img.shields.io/github/forks/callinston/CVE-2025-10585.svg)


## CVE-2025-10184
The root cause is a combination of missing permissions for write operations in several content providers (com.android.providers.telephony.PushMessageProvider, com.android.providers.telephony.PushShopProvider, com.android.providers.telephony.ServiceNumberProvider), and a blind SQL injection in the update method of those providers.

- [https://github.com/yuuouu/ColorOS-CVE-2025-10184](https://github.com/yuuouu/ColorOS-CVE-2025-10184) :  ![starts](https://img.shields.io/github/stars/yuuouu/ColorOS-CVE-2025-10184.svg) ![forks](https://img.shields.io/github/forks/yuuouu/ColorOS-CVE-2025-10184.svg)
- [https://github.com/People-11/CVE-2025-10184_PoC](https://github.com/People-11/CVE-2025-10184_PoC) :  ![starts](https://img.shields.io/github/stars/People-11/CVE-2025-10184_PoC.svg) ![forks](https://img.shields.io/github/forks/People-11/CVE-2025-10184_PoC.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/pablo388/WinRAR-CVE-2025-8088-PoC-RAR](https://github.com/pablo388/WinRAR-CVE-2025-8088-PoC-RAR) :  ![starts](https://img.shields.io/github/stars/pablo388/WinRAR-CVE-2025-8088-PoC-RAR.svg) ![forks](https://img.shields.io/github/forks/pablo388/WinRAR-CVE-2025-8088-PoC-RAR.svg)


## CVE-2025-2294
 The Kubio AI Page Builder plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.5.1 via thekubio_hybrid_theme_load_template function. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.

- [https://github.com/iteride/CVE-2025-2294](https://github.com/iteride/CVE-2025-2294) :  ![starts](https://img.shields.io/github/stars/iteride/CVE-2025-2294.svg) ![forks](https://img.shields.io/github/forks/iteride/CVE-2025-2294.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/JoaoLeonello/cve-2024-32002-poc](https://github.com/JoaoLeonello/cve-2024-32002-poc) :  ![starts](https://img.shields.io/github/stars/JoaoLeonello/cve-2024-32002-poc.svg) ![forks](https://img.shields.io/github/forks/JoaoLeonello/cve-2024-32002-poc.svg)


## CVE-2023-34233
 The Snowflake Connector for Python provides an interface for developing Python applications that can connect to Snowflake and perform all standard operations. Versions prior to 3.0.2 are vulnerable to command injection via single sign-on(SSO) browser URL authentication. In order to exploit the potential for command injection, an attacker would need to be successful in (1) establishing a malicious resource and (2) redirecting users to utilize the resource. The attacker could set up a malicious, publicly accessible server which responds to the SSO URL with an attack payload. If the attacker then tricked a user into visiting the maliciously crafted connection URL, the user’s local machine would render the malicious payload, leading to a remote code execution. This attack scenario can be mitigated through URL whitelisting as well as common anti-phishing resources. Version 3.0.2 contains a patch for this issue.

- [https://github.com/nayankadamm/CVE-2023-34233_Proof_OF_Concept](https://github.com/nayankadamm/CVE-2023-34233_Proof_OF_Concept) :  ![starts](https://img.shields.io/github/stars/nayankadamm/CVE-2023-34233_Proof_OF_Concept.svg) ![forks](https://img.shields.io/github/forks/nayankadamm/CVE-2023-34233_Proof_OF_Concept.svg)


## CVE-2022-35583
 wkhtmlTOpdf 0.12.6 is vulnerable to SSRF which allows an attacker to get initial access into the target's system by injecting iframe tag with initial asset IP address on it's source. This allows the attacker to takeover the whole infrastructure by accessing their internal assets.

- [https://github.com/Malayke/CVE-2022-35583-Pandoc-SSRF-POC](https://github.com/Malayke/CVE-2022-35583-Pandoc-SSRF-POC) :  ![starts](https://img.shields.io/github/stars/Malayke/CVE-2022-35583-Pandoc-SSRF-POC.svg) ![forks](https://img.shields.io/github/forks/Malayke/CVE-2022-35583-Pandoc-SSRF-POC.svg)


## CVE-2022-24434
 This affects all versions of package dicer. A malicious attacker can send a modified form to server, and crash the nodejs service. An attacker could sent the payload again and again so that the service continuously crashes.

- [https://github.com/nayankadamm/CVE-2022-24434_POC](https://github.com/nayankadamm/CVE-2022-24434_POC) :  ![starts](https://img.shields.io/github/stars/nayankadamm/CVE-2022-24434_POC.svg) ![forks](https://img.shields.io/github/forks/nayankadamm/CVE-2022-24434_POC.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/tea-celikik/Drupal-Exploit-Lab](https://github.com/tea-celikik/Drupal-Exploit-Lab) :  ![starts](https://img.shields.io/github/stars/tea-celikik/Drupal-Exploit-Lab.svg) ![forks](https://img.shields.io/github/forks/tea-celikik/Drupal-Exploit-Lab.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/FozilCV/Apache-Struts2-CVE-2017-5638](https://github.com/FozilCV/Apache-Struts2-CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/FozilCV/Apache-Struts2-CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/FozilCV/Apache-Struts2-CVE-2017-5638.svg)


## CVE-2008-0166
 OpenSSL 0.9.8c-1 up to versions before 0.9.8g-9 on Debian-based operating systems uses a random number generator that generates predictable numbers, which makes it easier for remote attackers to conduct brute force guessing attacks against cryptographic keys.

- [https://github.com/AhegaoPsyops/sslWeakness](https://github.com/AhegaoPsyops/sslWeakness) :  ![starts](https://img.shields.io/github/stars/AhegaoPsyops/sslWeakness.svg) ![forks](https://img.shields.io/github/forks/AhegaoPsyops/sslWeakness.svg)

