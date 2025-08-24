# Update 2025-08-24
## CVE-2025-55230
 Untrusted pointer dereference in Windows MBT Transport driver allows an authorized attacker to elevate privileges locally.

- [https://github.com/barbaraeivyu/CVE-2025-55230-Exploit](https://github.com/barbaraeivyu/CVE-2025-55230-Exploit) :  ![starts](https://img.shields.io/github/stars/barbaraeivyu/CVE-2025-55230-Exploit.svg) ![forks](https://img.shields.io/github/forks/barbaraeivyu/CVE-2025-55230-Exploit.svg)


## CVE-2025-53632
 Chall-Manager is a platform-agnostic system able to start Challenges on Demand of a player. When decoding a scenario (i.e. a zip archive), the path of the file to write is not checked, potentially leading to zip slips. Exploitation does not require authentication nor authorization, so anyone can exploit it. It should nonetheless not be exploitable as it is highly recommended to bury Chall-Manager deep within the infrastructure due to its large capabilities, so no users could reach the system. Patch has been implemented by commit 47d188f and shipped in v0.1.4.

- [https://github.com/pandatix/CVE-2025-53632](https://github.com/pandatix/CVE-2025-53632) :  ![starts](https://img.shields.io/github/stars/pandatix/CVE-2025-53632.svg) ![forks](https://img.shields.io/github/forks/pandatix/CVE-2025-53632.svg)


## CVE-2025-43300
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in macOS Sonoma 14.7.8, macOS Ventura 13.7.8, iPadOS 17.7.10, macOS Sequoia 15.6.1, iOS 18.6.2 and iPadOS 18.6.2. Processing a malicious image file may result in memory corruption. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.

- [https://github.com/h4xnz/CVE-2025-43300-Exploit](https://github.com/h4xnz/CVE-2025-43300-Exploit) :  ![starts](https://img.shields.io/github/stars/h4xnz/CVE-2025-43300-Exploit.svg) ![forks](https://img.shields.io/github/forks/h4xnz/CVE-2025-43300-Exploit.svg)
- [https://github.com/XiaomingX/CVE-2025-43300-exp](https://github.com/XiaomingX/CVE-2025-43300-exp) :  ![starts](https://img.shields.io/github/stars/XiaomingX/CVE-2025-43300-exp.svg) ![forks](https://img.shields.io/github/forks/XiaomingX/CVE-2025-43300-exp.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Haruaventure/CVE-2025-29927-Research](https://github.com/Haruaventure/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/Haruaventure/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/Haruaventure/CVE-2025-29927-Research.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/Diabl0xE/CVE-2025-27519](https://github.com/Diabl0xE/CVE-2025-27519) :  ![starts](https://img.shields.io/github/stars/Diabl0xE/CVE-2025-27519.svg) ![forks](https://img.shields.io/github/forks/Diabl0xE/CVE-2025-27519.svg)


## CVE-2025-27519
 Cognita is a RAG (Retrieval Augmented Generation) Framework for building modular, open source applications for production by TrueFoundry. A path traversal issue exists at /v1/internal/upload-to-local-directory which is enabled when the Local env variable is set to true, such as when Cognita is setup using Docker. Because the docker environment sets up the backend uvicorn server with auto reload enabled, when an attacker overwrites the /app/backend/__init__.py file, the file will automatically be reloaded and executed. This allows an attacker to get remote code execution in the context of the Docker container. This vulnerability is fixed in commit a78bd065e05a1b30a53a3386cc02e08c317d2243.

- [https://github.com/Diabl0xE/CVE-2025-27519](https://github.com/Diabl0xE/CVE-2025-27519) :  ![starts](https://img.shields.io/github/stars/Diabl0xE/CVE-2025-27519.svg) ![forks](https://img.shields.io/github/forks/Diabl0xE/CVE-2025-27519.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/x0da6h/POC-for-CVE-2025-24893](https://github.com/x0da6h/POC-for-CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/x0da6h/POC-for-CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/x0da6h/POC-for-CVE-2025-24893.svg)


## CVE-2025-8418
 The B Slider- Gutenberg Slider Block for WP plugin for WordPress is vulnerable to Arbitrary Plugin Installation in all versions up to, and including, 1.1.30. This is due to missing capability checks on the activated_plugin function. This makes it possible for authenticated attackers, with subscriber-level access and above, to install arbitrary plugins on the server which can make remote code execution possible.

- [https://github.com/LitBot123/CVE.py](https://github.com/LitBot123/CVE.py) :  ![starts](https://img.shields.io/github/stars/LitBot123/CVE.py.svg) ![forks](https://img.shields.io/github/forks/LitBot123/CVE.py.svg)


## CVE-2025-7431
 The Knowledge Base plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin slug setting in all versions up to, and including, 2.3.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level access, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/NagisaYumaa/CVE-2025-7431](https://github.com/NagisaYumaa/CVE-2025-7431) :  ![starts](https://img.shields.io/github/stars/NagisaYumaa/CVE-2025-7431.svg) ![forks](https://img.shields.io/github/forks/NagisaYumaa/CVE-2025-7431.svg)


## CVE-2025-5557
 A vulnerability has been found in PHPGurukul Teacher Subject Allocation Management System 1.0 and classified as critical. This vulnerability affects unknown code of the file /admin/edit-course.php. The manipulation of the argument editid leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Aether-0/CVE-2025-55575](https://github.com/Aether-0/CVE-2025-55575) :  ![starts](https://img.shields.io/github/stars/Aether-0/CVE-2025-55575.svg) ![forks](https://img.shields.io/github/forks/Aether-0/CVE-2025-55575.svg)


## CVE-2025-1337
 A vulnerability was found in Eastnets PaymentSafe 2.5.26.0. It has been classified as problematic. This affects an unknown part of the component BIC Search. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely. Upgrading to version 2.5.27.0 is able to address this issue.

- [https://github.com/ada-z3r0/CVE-2025-1337-PoC](https://github.com/ada-z3r0/CVE-2025-1337-PoC) :  ![starts](https://img.shields.io/github/stars/ada-z3r0/CVE-2025-1337-PoC.svg) ![forks](https://img.shields.io/github/forks/ada-z3r0/CVE-2025-1337-PoC.svg)


## CVE-2024-37054
 Deserialization of untrusted data can occur in versions of the MLflow platform running version 0.9.0 or newer, enabling a maliciously uploaded PyFunc model to run arbitrary code on an end user’s system when interacted with.

- [https://github.com/NiteeshPujari/CVE-2024-37054-MLflow-RCE](https://github.com/NiteeshPujari/CVE-2024-37054-MLflow-RCE) :  ![starts](https://img.shields.io/github/stars/NiteeshPujari/CVE-2024-37054-MLflow-RCE.svg) ![forks](https://img.shields.io/github/forks/NiteeshPujari/CVE-2024-37054-MLflow-RCE.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/0xr2r/CVE-2024-4367](https://github.com/0xr2r/CVE-2024-4367) :  ![starts](https://img.shields.io/github/stars/0xr2r/CVE-2024-4367.svg) ![forks](https://img.shields.io/github/forks/0xr2r/CVE-2024-4367.svg)


## CVE-2022-43110
 Voltronic Power ViewPower through 1.04-21353 and PowerShield Netguard before 1.04-23292 allows a remote attacker to configure the system via an unspecified web interface. An unauthenticated remote attacker can make changes to the system including: changing the web interface admin password, view/change system configuration, enumerate connected UPS devices and shut down connected UPS devices. This extends to being able to configure operating system commands that should run if the system detects a connected UPS shutting down.

- [https://github.com/ready2disclose/CVE-2022-43110](https://github.com/ready2disclose/CVE-2022-43110) :  ![starts](https://img.shields.io/github/stars/ready2disclose/CVE-2022-43110.svg) ![forks](https://img.shields.io/github/forks/ready2disclose/CVE-2022-43110.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/Haruaventure/CVE-2022-39299-Research](https://github.com/Haruaventure/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/Haruaventure/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/Haruaventure/CVE-2022-39299-Research.svg)


## CVE-2022-31491
 Voltronic Power ViewPower through 1.04-24215, ViewPower Pro through 2.0-22165, and PowerShield Netguard before 1.04-23292 allows a remote attacker to run arbitrary code via an unspecified web interface related to detection of a managed UPS shutting down. An unauthenticated attacker can use this to run arbitrary code immediately regardless of any managed UPS state or presence.

- [https://github.com/ready2disclose/CVE-2022-31491](https://github.com/ready2disclose/CVE-2022-31491) :  ![starts](https://img.shields.io/github/stars/ready2disclose/CVE-2022-31491.svg) ![forks](https://img.shields.io/github/forks/ready2disclose/CVE-2022-31491.svg)


## CVE-2022-31160
 jQuery UI is a curated set of user interface interactions, effects, widgets, and themes built on top of jQuery. Versions prior to 1.13.2 are potentially vulnerable to cross-site scripting. Initializing a checkboxradio widget on an input enclosed within a label makes that parent label contents considered as the input label. Calling `.checkboxradio( "refresh" )` on such a widget and the initial HTML contained encoded HTML entities will make them erroneously get decoded. This can lead to potentially executing JavaScript code. The bug has been patched in jQuery UI 1.13.2. To remediate the issue, someone who can change the initial HTML can wrap all the non-input contents of the `label` in a `span`.

- [https://github.com/CyberOne-TeamARES/jquery-cve-2022-31160](https://github.com/CyberOne-TeamARES/jquery-cve-2022-31160) :  ![starts](https://img.shields.io/github/stars/CyberOne-TeamARES/jquery-cve-2022-31160.svg) ![forks](https://img.shields.io/github/forks/CyberOne-TeamARES/jquery-cve-2022-31160.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/charanvoonna/CVE-2021-41773](https://github.com/charanvoonna/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/charanvoonna/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/charanvoonna/CVE-2021-41773.svg)
- [https://github.com/RizqiSec/CVE-2021-41773](https://github.com/RizqiSec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RizqiSec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RizqiSec/CVE-2021-41773.svg)


## CVE-2020-36847
 The Simple-File-List Plugin for WordPress is vulnerable to Remote Code Execution in versions up to, and including, 4.2.2 via the rename function which can be used to rename uploaded PHP code with a png extension to use a php extension. This allows unauthenticated attackers to execute code on the server.

- [https://github.com/137f/PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE](https://github.com/137f/PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE) :  ![starts](https://img.shields.io/github/stars/137f/PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE.svg) ![forks](https://img.shields.io/github/forks/137f/PoC-CVE-2020-36847-WordPress-Plugin-4.2.2-RCE.svg)


## CVE-2019-18935
 Progress Telerik UI for ASP.NET AJAX through 2019.3.1023 contains a .NET deserialization vulnerability in the RadAsyncUpload function. This is exploitable when the encryption keys are known due to the presence of CVE-2017-11317 or CVE-2017-11357, or other means. Exploitation can result in remote code execution. (As of 2020.1.114, a default setting prevents the exploit. In 2019.3.1023, but not earlier versions, a non-default setting can prevent exploitation.)

- [https://github.com/0xsharz/telerik-scanner-CVE-2019-18935](https://github.com/0xsharz/telerik-scanner-CVE-2019-18935) :  ![starts](https://img.shields.io/github/stars/0xsharz/telerik-scanner-CVE-2019-18935.svg) ![forks](https://img.shields.io/github/forks/0xsharz/telerik-scanner-CVE-2019-18935.svg)


## CVE-2015-3306
 The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.

- [https://github.com/donmedfor/CVE-2015-3306](https://github.com/donmedfor/CVE-2015-3306) :  ![starts](https://img.shields.io/github/stars/donmedfor/CVE-2015-3306.svg) ![forks](https://img.shields.io/github/forks/donmedfor/CVE-2015-3306.svg)

