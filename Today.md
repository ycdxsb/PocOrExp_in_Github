# Update 2026-07-05
## CVE-2026-56290
 The Joomla extension Page Builder CK is vulnerable to an unauthenticated arbitrary file upload that allows uploading executable files and leads to full RCE.

- [https://github.com/shinthink/pbck-exploit](https://github.com/shinthink/pbck-exploit) :  ![starts](https://img.shields.io/github/stars/shinthink/pbck-exploit.svg) ![forks](https://img.shields.io/github/forks/shinthink/pbck-exploit.svg)


## CVE-2026-55726
 The Azure Blob Storage container used for Gardyn device logs is publicly listable without authentication. A malicious user would be able to access any device log file available in the blob storage container.

- [https://github.com/MichaelAdamGroberman/CVE-2026-55726](https://github.com/MichaelAdamGroberman/CVE-2026-55726) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2026-55726.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2026-55726.svg)


## CVE-2026-54477
 The admin panel lacks standard security headers, enabling clickjacking and cross-site scripting attacks.

- [https://github.com/MichaelAdamGroberman/CVE-2026-54477](https://github.com/MichaelAdamGroberman/CVE-2026-54477) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2026-54477.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2026-54477.svg)


## CVE-2026-53753
 Crawl4AI is an open-source LLM friendly web crawler & scraper. Prior to 0.8.7, the _safe_eval_expression() function in the computed fields feature uses an AST validator that only blocks attributes starting with underscore. Python generator and frame object attributes (gi_frame, f_back, f_builtins) do NOT start with underscore, enabling a complete sandbox escape to achieve arbitrary code execution. The attack requires no authentication (JWT disabled by default) and is triggered via POST /crawl with a crafted extraction schema. This vulnerability is fixed in 0.8.7.

- [https://github.com/thecodeb0ss/Advanced-CVE-2026-53753](https://github.com/thecodeb0ss/Advanced-CVE-2026-53753) :  ![starts](https://img.shields.io/github/stars/thecodeb0ss/Advanced-CVE-2026-53753.svg) ![forks](https://img.shields.io/github/forks/thecodeb0ss/Advanced-CVE-2026-53753.svg)


## CVE-2026-49975
This issue affects Apache HTTP Server: from 2.4.17 through 2.4.67.

- [https://github.com/mindcodings/http2-bomb-detector](https://github.com/mindcodings/http2-bomb-detector) :  ![starts](https://img.shields.io/github/stars/mindcodings/http2-bomb-detector.svg) ![forks](https://img.shields.io/github/forks/mindcodings/http2-bomb-detector.svg)


## CVE-2026-49468
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. Prior to 1.84.0,  This vulnerability is fixed in 1.84.0.

- [https://github.com/BiiTts/CVE-2026-49468-LiteLLM-Auth-Bypass](https://github.com/BiiTts/CVE-2026-49468-LiteLLM-Auth-Bypass) :  ![starts](https://img.shields.io/github/stars/BiiTts/CVE-2026-49468-LiteLLM-Auth-Bypass.svg) ![forks](https://img.shields.io/github/forks/BiiTts/CVE-2026-49468-LiteLLM-Auth-Bypass.svg)


## CVE-2026-44963
 A vulnerability allowing remote code execution (RCE) on the Backup Server by an authenticated domain user.

- [https://github.com/suce0155/CVE_2026_44963](https://github.com/suce0155/CVE_2026_44963) :  ![starts](https://img.shields.io/github/stars/suce0155/CVE_2026_44963.svg) ![forks](https://img.shields.io/github/forks/suce0155/CVE_2026_44963.svg)


## CVE-2026-44825
  *  Clusters where template users have been assigned strong passwords after bootstrap

- [https://github.com/shinthink/solrradar](https://github.com/shinthink/solrradar) :  ![starts](https://img.shields.io/github/stars/shinthink/solrradar.svg) ![forks](https://img.shields.io/github/forks/shinthink/solrradar.svg)


## CVE-2026-35570
 OpenClaude is an open-source coding-agent command line interface for cloud and local model providers. Versions prior to 0.5.1 have a logic flaw in `bashToolHasPermission()` inside `src/tools/BashTool/bashPermissions.ts`. When the sandbox auto-allow feature is active and no explicit deny rule is configured, the function returns an `allow` result immediately — before the path constraint filter (`checkPathConstraints`) is ever evaluated. This allows commands containing path traversal sequences (e.g., `../../../../../etc/passwd`) to bypass directory restrictions entirely. Version 0.5.1 contains a patch for the issue.

- [https://github.com/Rickidevs/CVE-2026-35570](https://github.com/Rickidevs/CVE-2026-35570) :  ![starts](https://img.shields.io/github/stars/Rickidevs/CVE-2026-35570.svg) ![forks](https://img.shields.io/github/forks/Rickidevs/CVE-2026-35570.svg)


## CVE-2026-34835
 Rack is a modular Ruby web server interface. From versions 3.0.0.beta1 to before 3.1.21, and 3.2.0 to before 3.2.6, Rack::Request parses the Host header using an AUTHORITY regular expression that accepts characters not permitted in RFC-compliant hostnames, including /, ?, #, and @. Because req.host returns the full parsed value, applications that validate hosts using naive prefix or suffix checks can be bypassed. This can lead to host header poisoning in applications that use req.host, req.url, or req.base_url for link generation, redirects, or origin validation. This issue has been patched in versions 3.1.21 and 3.2.6.

- [https://github.com/Cyber-note/CVE-2026-34835-Black-box-Analysis](https://github.com/Cyber-note/CVE-2026-34835-Black-box-Analysis) :  ![starts](https://img.shields.io/github/stars/Cyber-note/CVE-2026-34835-Black-box-Analysis.svg) ![forks](https://img.shields.io/github/forks/Cyber-note/CVE-2026-34835-Black-box-Analysis.svg)


## CVE-2026-34070
 LangChain is a framework for building agents and LLM-powered applications. Prior to version 1.2.22, multiple functions in langchain_core.prompts.loading read files from paths embedded in deserialized config dicts without validating against directory traversal or absolute path injection. When an application passes user-influenced prompt configurations to load_prompt() or load_prompt_from_config(), an attacker can read arbitrary files on the host filesystem, constrained only by file-extension checks (.txt for templates, .json/.yaml for examples). This issue has been patched in version 1.2.22.

- [https://github.com/Rickidevs/CVE-2026-34070](https://github.com/Rickidevs/CVE-2026-34070) :  ![starts](https://img.shields.io/github/stars/Rickidevs/CVE-2026-34070.svg) ![forks](https://img.shields.io/github/forks/Rickidevs/CVE-2026-34070.svg)


## CVE-2026-32913
 OpenClaw before 2026.3.7 contains an improper header validation vulnerability in fetchWithSsrFGuard that forwards custom authorization headers across cross-origin redirects. Attackers can trigger redirects to different origins to intercept sensitive headers like X-Api-Key and Private-Token intended for the original destination.

- [https://github.com/Rickidevs/CVE-2026-32913](https://github.com/Rickidevs/CVE-2026-32913) :  ![starts](https://img.shields.io/github/stars/Rickidevs/CVE-2026-32913.svg) ![forks](https://img.shields.io/github/forks/Rickidevs/CVE-2026-32913.svg)


## CVE-2026-28995
 A logic issue was addressed with improved restrictions. This issue is fixed in iOS 18.7.9 and iPadOS 18.7.9, iOS 26.5 and iPadOS 26.5, macOS Tahoe 26.5, tvOS 26.5, visionOS 26.5, watchOS 26.5. A malicious app may be able to break out of its sandbox.

- [https://github.com/Robertmak2014-sudow/CVE-2026-28995](https://github.com/Robertmak2014-sudow/CVE-2026-28995) :  ![starts](https://img.shields.io/github/stars/Robertmak2014-sudow/CVE-2026-28995.svg) ![forks](https://img.shields.io/github/forks/Robertmak2014-sudow/CVE-2026-28995.svg)


## CVE-2026-28699
 Gitea versions up to and including 1.26.1 allow OAuth2 access token scope enforcement to be bypassed through HTTP Basic authentication.

- [https://github.com/Alardiians/gitea-CVE-2026-28699](https://github.com/Alardiians/gitea-CVE-2026-28699) :  ![starts](https://img.shields.io/github/stars/Alardiians/gitea-CVE-2026-28699.svg) ![forks](https://img.shields.io/github/forks/Alardiians/gitea-CVE-2026-28699.svg)


## CVE-2026-27771
 Gitea versions up to and including 1.26.1 have insufficient permission checks for Composer package source links, which can expose private or internal package source information.

- [https://github.com/portbuster1337/CVE-2026-27771](https://github.com/portbuster1337/CVE-2026-27771) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-27771.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-27771.svg)
- [https://github.com/HORKimhab/CVE-2026-27771](https://github.com/HORKimhab/CVE-2026-27771) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-27771.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-27771.svg)


## CVE-2026-26717
 An issue in OpenFUN Richie (LMS) in src/richie/apps/courses/api.py. The application used the non-constant time == operator for HMAC signature verification in the sync_course_run_from_request function. This allows remote attackers to forge valid signatures and bypass authentication by measuring response time discrepancies

- [https://github.com/Rickidevs/CVE-2026-26717](https://github.com/Rickidevs/CVE-2026-26717) :  ![starts](https://img.shields.io/github/stars/Rickidevs/CVE-2026-26717.svg) ![forks](https://img.shields.io/github/forks/Rickidevs/CVE-2026-26717.svg)


## CVE-2026-26114
 Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a network.

- [https://github.com/huynambka/cve-2026-26114-poc](https://github.com/huynambka/cve-2026-26114-poc) :  ![starts](https://img.shields.io/github/stars/huynambka/cve-2026-26114-poc.svg) ![forks](https://img.shields.io/github/forks/huynambka/cve-2026-26114-poc.svg)


## CVE-2026-20896
 Gitea Docker image versions up to and including 1.26.2 use REVERSE_PROXY_TRUSTED_PROXIES=* by default, allowing any source IP to impersonate a user when reverse-proxy authentication headers such as X-WEBAUTH-USER are enabled.

- [https://github.com/kaleth4/CVE-2026-20896](https://github.com/kaleth4/CVE-2026-20896) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-20896.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-20896.svg)


## CVE-2026-14459
This issue affects pardus-software: from = 1.0.4 before 1.0.5.

- [https://github.com/dasokkk/CVE-2026-14459-14460-pardus-software](https://github.com/dasokkk/CVE-2026-14459-14460-pardus-software) :  ![starts](https://img.shields.io/github/stars/dasokkk/CVE-2026-14459-14460-pardus-software.svg) ![forks](https://img.shields.io/github/forks/dasokkk/CVE-2026-14459-14460-pardus-software.svg)


## CVE-2026-11387
 The SMS Alert – SMS & OTP for WooCommerce, Order Notifications & Abandoned Cart Recovery plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 3.9.5. This is due to the plugin not properly validating a user's identity prior to updating their details like reset the password of any user account, including administrators, and gain full access to those accounts. This makes it possible for unauthenticated attackers to change arbitrary user's email addresses, including administrators, and leverage that to reset the user's password and gain access to their account. This is only vulnerable on sites with OTP verification for password resets enabled, and where the administrator (or other user) has set a phone number for OTP verification.

- [https://github.com/1beelze/CVE-2026-11387](https://github.com/1beelze/CVE-2026-11387) :  ![starts](https://img.shields.io/github/stars/1beelze/CVE-2026-11387.svg) ![forks](https://img.shields.io/github/forks/1beelze/CVE-2026-11387.svg)


## CVE-2026-8932
the private key.

- [https://github.com/0xBlackash/CVE-2026-8932](https://github.com/0xBlackash/CVE-2026-8932) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-8932.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-8932.svg)


## CVE-2026-8451
 Insufficient input validation in NetScaler ADC and NetScaler Gateway leading to memory overread if NetScaler ADC or NetScaler Gateway is configured as a SAML IDP

- [https://github.com/0xBlackash/CVE-2026-8451](https://github.com/0xBlackash/CVE-2026-8451) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-8451.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-8451.svg)


## CVE-2026-5524
 The Divi Form Builder plugin for WordPress is vulnerable to Arbitrary File Upload leading to Remote Code Execution in all versions up to and including 5.1.8. This is due to insufficient file extension validation in the do_image_upload() function where user-supplied input from the acceptFileTypes POST parameter is directly interpolated into a regular expression used to validate uploaded files. Attackers can specify PHP-executable extensions such as .phtml, .phar, .php5, or .php7 to bypass the plugin's .htaccess protection which only blocks .php files specifically. Additionally, on Nginx-based servers, the .htaccess protection is completely ineffective as Nginx does not process .htaccess files. This makes it possible for unauthenticated attackers (who can obtain a nonce from any public page containing a form) to upload executable PHP files to the publicly accessible /wp-content/uploads/de_fb_uploads/ directory and achieve Remote Code Execution by accessing the uploaded file via HTTP. The vulnerability was partially patched in version 5.1.3.

- [https://github.com/caterscam/CVE-2026-5524-PoC](https://github.com/caterscam/CVE-2026-5524-PoC) :  ![starts](https://img.shields.io/github/stars/caterscam/CVE-2026-5524-PoC.svg) ![forks](https://img.shields.io/github/forks/caterscam/CVE-2026-5524-PoC.svg)


## CVE-2026-5220
This issue affects DivvyDrive: from 4.8.2.23 before v.4.8.3.1.

- [https://github.com/lamaper/CVE-2026-52200](https://github.com/lamaper/CVE-2026-52200) :  ![starts](https://img.shields.io/github/stars/lamaper/CVE-2026-52200.svg) ![forks](https://img.shields.io/github/forks/lamaper/CVE-2026-52200.svg)


## CVE-2026-3927
 Incorrect security UI in PictureInPicture in Google Chrome prior to 146.0.7680.71 allowed a remote attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/Securify-AI/CVE-2026-39275](https://github.com/Securify-AI/CVE-2026-39275) :  ![starts](https://img.shields.io/github/stars/Securify-AI/CVE-2026-39275.svg) ![forks](https://img.shields.io/github/forks/Securify-AI/CVE-2026-39275.svg)


## CVE-2025-69212
 OpenSTAManager is an open source management software for technical assistance and invoicing. In 2.9.8 and earlier, a critical OS Command Injection vulnerability exists in the P7M (signed XML) file decoding functionality. An authenticated attacker can upload a ZIP file containing a .p7m file with a malicious filename to execute arbitrary system commands on the server.

- [https://github.com/0Zetrium0/CVE-2025-69212_PoC](https://github.com/0Zetrium0/CVE-2025-69212_PoC) :  ![starts](https://img.shields.io/github/stars/0Zetrium0/CVE-2025-69212_PoC.svg) ![forks](https://img.shields.io/github/forks/0Zetrium0/CVE-2025-69212_PoC.svg)


## CVE-2025-54309
 CrushFTP 10 before 10.8.5 and 11 before 11.3.4_23, when the DMZ proxy feature is not used, mishandles AS2 validation and consequently allows remote attackers to obtain admin access via HTTPS, as exploited in the wild in July 2025.

- [https://github.com/Smileyface101/CrushFTP-AS2-Bypass-Research-CVE-2025-54309](https://github.com/Smileyface101/CrushFTP-AS2-Bypass-Research-CVE-2025-54309) :  ![starts](https://img.shields.io/github/stars/Smileyface101/CrushFTP-AS2-Bypass-Research-CVE-2025-54309.svg) ![forks](https://img.shields.io/github/forks/Smileyface101/CrushFTP-AS2-Bypass-Research-CVE-2025-54309.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/1w4y/IngressNightmare-RCE-POC](https://github.com/1w4y/IngressNightmare-RCE-POC) :  ![starts](https://img.shields.io/github/stars/1w4y/IngressNightmare-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/1w4y/IngressNightmare-RCE-POC.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/YoguiCR/CVE-2024-21413-Outlook-Assessment](https://github.com/YoguiCR/CVE-2024-21413-Outlook-Assessment) :  ![starts](https://img.shields.io/github/stars/YoguiCR/CVE-2024-21413-Outlook-Assessment.svg) ![forks](https://img.shields.io/github/forks/YoguiCR/CVE-2024-21413-Outlook-Assessment.svg)


## CVE-2024-1561
 An issue was discovered in gradio-app/gradio, where the `/component_server` endpoint improperly allows the invocation of any method on a `Component` class with attacker-controlled arguments. Specifically, by exploiting the `move_resource_to_block_cache()` method of the `Block` class, an attacker can copy any file on the filesystem to a temporary directory and subsequently retrieve it. This vulnerability enables unauthorized local file read access, posing a significant risk especially when the application is exposed to the internet via `launch(share=True)`, thereby allowing remote attackers to read files on the host machine. Furthermore, gradio apps hosted on `huggingface.co` are also affected, potentially leading to the exposure of sensitive information such as API keys and credentials stored in environment variables.

- [https://github.com/K3ysTr0K3R/CVE-2024-1561](https://github.com/K3ysTr0K3R/CVE-2024-1561) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2024-1561.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2024-1561.svg)


## CVE-2023-5968
 Mattermost fails to properly sanitize the user object when updating the username, resulting in the password hash being included in the response body. 

- [https://github.com/Curtail-Inc/hello-ReGrade-security](https://github.com/Curtail-Inc/hello-ReGrade-security) :  ![starts](https://img.shields.io/github/stars/Curtail-Inc/hello-ReGrade-security.svg) ![forks](https://img.shields.io/github/forks/Curtail-Inc/hello-ReGrade-security.svg)


## CVE-2022-36446
 software/apt-lib.pl in Webmin before 1.997 lacks HTML escaping for a UI command.

- [https://github.com/darnabin/CVE-2022-36446-Webmin-RCE](https://github.com/darnabin/CVE-2022-36446-Webmin-RCE) :  ![starts](https://img.shields.io/github/stars/darnabin/CVE-2022-36446-Webmin-RCE.svg) ![forks](https://img.shields.io/github/forks/darnabin/CVE-2022-36446-Webmin-RCE.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/v-rzh/CVE-2021-4034](https://github.com/v-rzh/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/v-rzh/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/v-rzh/CVE-2021-4034.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/K3ysTr0K3R/CVE-2017-12615](https://github.com/K3ysTr0K3R/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-12615.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/kn9annihilator/CVE-2011-2523-vsFTPd-2.3.4-Writeup](https://github.com/kn9annihilator/CVE-2011-2523-vsFTPd-2.3.4-Writeup) :  ![starts](https://img.shields.io/github/stars/kn9annihilator/CVE-2011-2523-vsFTPd-2.3.4-Writeup.svg) ![forks](https://img.shields.io/github/forks/kn9annihilator/CVE-2011-2523-vsFTPd-2.3.4-Writeup.svg)

