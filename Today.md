# Update 2026-05-28
## CVE-2026-45401
 Open WebUI is a self-hosted artificial intelligence platform designed to operate entirely offline. Prior to 0.9.5, the validate_url() function in backend/open_webui/retrieval/web/utils.py only validates the initial URL submitted by the caller. The HTTP clients used downstream (sync requests, async aiohttp, langchain's WebBaseLoader) follow HTTP 3xx redirects by default and do not re-validate the redirect target against the private-IP / metadata-IP block list. Any authenticated user can therefore submit a public URL that 302-redirects to an internal address (e.g. 127.0.0.1, 169.254.169.254, RFC1918) and read the internal response body via the /api/v1/retrieval/process/web endpoint, the /api/v1/images/... endpoints, the /api/chat/completions endpoint with an image_url content part, and any other route that calls these helpers. This vulnerability is fixed in 0.9.5.

- [https://github.com/nayakchinmohan/CVE-2026-45401](https://github.com/nayakchinmohan/CVE-2026-45401) :  ![starts](https://img.shields.io/github/stars/nayakchinmohan/CVE-2026-45401.svg) ![forks](https://img.shields.io/github/forks/nayakchinmohan/CVE-2026-45401.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/jayhutajulu1/CVE-2026-43284-DirtyFrag-PoC](https://github.com/jayhutajulu1/CVE-2026-43284-DirtyFrag-PoC) :  ![starts](https://img.shields.io/github/stars/jayhutajulu1/CVE-2026-43284-DirtyFrag-PoC.svg) ![forks](https://img.shields.io/github/forks/jayhutajulu1/CVE-2026-43284-DirtyFrag-PoC.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/niekaicheng/CVE-2026-42945_NGINX_Rift](https://github.com/niekaicheng/CVE-2026-42945_NGINX_Rift) :  ![starts](https://img.shields.io/github/stars/niekaicheng/CVE-2026-42945_NGINX_Rift.svg) ![forks](https://img.shields.io/github/forks/niekaicheng/CVE-2026-42945_NGINX_Rift.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/willygailo/CVE-2026-41940-Linux](https://github.com/willygailo/CVE-2026-41940-Linux) :  ![starts](https://img.shields.io/github/stars/willygailo/CVE-2026-41940-Linux.svg) ![forks](https://img.shields.io/github/forks/willygailo/CVE-2026-41940-Linux.svg)


## CVE-2026-36239
 PbootCMS v.3.2.11 contains a code injection vulnerability in its site configuration functionality

- [https://github.com/TazmiDev/CVE-2026-36239](https://github.com/TazmiDev/CVE-2026-36239) :  ![starts](https://img.shields.io/github/stars/TazmiDev/CVE-2026-36239.svg) ![forks](https://img.shields.io/github/forks/TazmiDev/CVE-2026-36239.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/novysodope/copy-fail-CVE-2026-31431-C](https://github.com/novysodope/copy-fail-CVE-2026-31431-C) :  ![starts](https://img.shields.io/github/stars/novysodope/copy-fail-CVE-2026-31431-C.svg) ![forks](https://img.shields.io/github/forks/novysodope/copy-fail-CVE-2026-31431-C.svg)


## CVE-2026-27384
 Improper Validation of Specified Quantity in Input vulnerability in BoldGrid W3 Total Cache w3-total-cache allows Accessing Functionality Not Properly Constrained by ACLs.This issue affects W3 Total Cache: from n/a through = 2.9.1.

- [https://github.com/xxconi/CVE-2026-27384](https://github.com/xxconi/CVE-2026-27384) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-27384.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-27384.svg)


## CVE-2026-23520
 Arcane provides modern docker management. Prior to 1.13.0, Arcane has a command injection in the updater service. Arcane’s updater service supported lifecycle labels com.getarcaneapp.arcane.lifecycle.pre-update and com.getarcaneapp.arcane.lifecycle.post-update that allowed defining a command to run before or after a container update. The label value is passed directly to /bin/sh -c without sanitization or validation. Because any authenticated user (not limited to administrators) can create projects through the API, an attacker can create a project that specifies one of these lifecycle labels with a malicious command. When an administrator later triggers a container update (either manually or via scheduled update checks), Arcane reads the lifecycle label and executes its value as a shell command inside the container. This vulnerability is fixed in 1.13.0.

- [https://github.com/kikechans/-Educational-PoC-CVE-2026-23520](https://github.com/kikechans/-Educational-PoC-CVE-2026-23520) :  ![starts](https://img.shields.io/github/stars/kikechans/-Educational-PoC-CVE-2026-23520.svg) ![forks](https://img.shields.io/github/forks/kikechans/-Educational-PoC-CVE-2026-23520.svg)


## CVE-2026-20182
This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to the affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.

- [https://github.com/Nxploited/CVE-2026-20182](https://github.com/Nxploited/CVE-2026-20182) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-20182.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-20182.svg)


## CVE-2026-6741
 The LatePoint – Calendar Booking Plugin for Appointments and Events plugin for WordPress is vulnerable to Privilege Escalation in versions up to and including 5.4.1. This is due to a missing authorization check in the execute() method of the connect-customer-to-wp-user ability, which only requires the customer__edit capability granted to the latepoint_agent role by default, without verifying whether the target WordPress user ID belongs to a privileged account. This makes it possible for authenticated attackers with the latepoint_agent role to link any LatePoint customer record to an administrator's WordPress account and subsequently reset the administrator's password via the normal customer password-reset flow, resulting in full site takeover.

- [https://github.com/xxconi/CVE-2026-6741](https://github.com/xxconi/CVE-2026-6741) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-6741.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-6741.svg)


## CVE-2026-6271
 The Career Section plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 1.7 via the CV upload handler. This is due to missing file type validation. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.

- [https://github.com/xxconi/CVE-2026-6271](https://github.com/xxconi/CVE-2026-6271) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-6271.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-6271.svg)


## CVE-2026-5760
 SGLang's reranking endpoint (/v1/rerank) achieves Remote Code Execution (RCE) when a model file containing a malcious tokenizer.chat_template is loaded, as the Jinja2 chat templates are rendered using an unsandboxed jinja2.Environment().

- [https://github.com/glenfmessenger/sglang-lens](https://github.com/glenfmessenger/sglang-lens) :  ![starts](https://img.shields.io/github/stars/glenfmessenger/sglang-lens.svg) ![forks](https://img.shields.io/github/forks/glenfmessenger/sglang-lens.svg)


## CVE-2026-5718
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file upload in versions up to, and including, 1.3.9.6. This is due to insufficient file type validation that occurs when custom blacklist types are configured, which replaces the default dangerous extension denylist instead of merging with it, and the wpcf7_antiscript_file_name() sanitization function being bypassed for filenames containing non-ASCII characters. This makes it possible for unauthenticated attackers to upload arbitrary files, such as PHP files, to the server, which can be leveraged to achieve remote code execution.

- [https://github.com/xxconi/CVE-2026-5718](https://github.com/xxconi/CVE-2026-5718) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-5718.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-5718.svg)


## CVE-2026-5426
 Hard-coded ASP.NET/IIS machineKey value in Digital Knowledge KnowledgeDeliver deployments prior to February 24, 2026 allows adversaries to circumvent ViewState validation mechanisms and achieve remote code execution via malicious ViewState deserialization attacks

- [https://github.com/HORKimhab/CVE-2026-5426](https://github.com/HORKimhab/CVE-2026-5426) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-5426.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-5426.svg)


## CVE-2026-5364
 The Drag and Drop File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file upload in versions up to, and including, 1.1.3. This is due to the plugin extracting the file extension before sanitization occurs and allowing the file type parameter to be controlled by the attacker rather than being restricted to administrator-configured values, which when combined with the fact that validation occurs on the unsanitized extension while the file is saved with a sanitized extension, allows special characters like '$' to be stripped during the save process. This makes it possible for unauthenticated attackers to upload arbitrary PHP files and potentially achieve remote code execution, however, an .htaccess file and name randomization is in place which restricts real-world exploitability.

- [https://github.com/xxconi/CVE-2026-5364](https://github.com/xxconi/CVE-2026-5364) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-5364.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-5364.svg)


## CVE-2026-5229
 The Form Notify plugin for WordPress is vulnerable to Authentication Bypass in versions up to and including 1.1.10. This is due to the plugin trusting user-controlled cookie data to determine which WordPress account to authenticate after a LINE OAuth login. When LINE doesn't provide an email address (which is common), the plugin falls back to reading the 'form_notify_line_email' cookie value without verifying that the LINE account is associated with that email address. This makes it possible for unauthenticated attackers to gain access to any user account on the site, including administrator accounts, by completing a LINE OAuth flow with their own LINE account while injecting a malicious cookie containing the target victim's email address.

- [https://github.com/xxconi/CVE-2026-5229](https://github.com/xxconi/CVE-2026-5229) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-5229.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-5229.svg)


## CVE-2026-4809
 plank/laravel-mediable through version 6.4.0 can allow upload of a dangerous file type when an application using the package accepts or prefers a client-supplied MIME type during file upload handling. In that configuration, a remote attacker can submit a file containing executable PHP code while declaring a benign image MIME type, resulting in arbitrary file upload. If the uploaded file is stored in a web-accessible and executable location, this may lead to remote code execution. At the time of publication, no patch was available and the vendor had not responded to coordinated disclosure attempts.

- [https://github.com/HORKimhab/CVE-2026-48095](https://github.com/HORKimhab/CVE-2026-48095) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-48095.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-48095.svg)


## CVE-2026-4766
 The Easy Image Gallery plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the Gallery shortcode post meta field in all versions up to, and including, 1.5.3. This is due to insufficient input sanitization and output escaping on user-supplied gallery shortcode values. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Nxploited/CVE-2026-47668](https://github.com/Nxploited/CVE-2026-47668) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-47668.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-47668.svg)


## CVE-2026-4627
 A vulnerability was found in D-Link DIR-825 and DIR-825R 1.0.5/4.5.1. Affected is the function handler_update_system_time of the file libdeuteron_modules.so of the component NTP Service. The manipulation results in os command injection. The attack may be launched remotely. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/xxconi/CVE-2026-46275](https://github.com/xxconi/CVE-2026-46275) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-46275.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-46275.svg)


## CVE-2026-3296
 The Everest Forms plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.4.3 via deserialization of untrusted input from form entry metadata. This is due to the html-admin-page-entries-view.php file calling PHP's native unserialize() on stored entry meta values without passing the allowed_classes parameter. This makes it possible for unauthenticated attackers to inject a serialized PHP object payload through any public Everest Forms form field. The payload survives sanitize_text_field() sanitization (serialization control characters are not stripped) and is stored in the wp_evf_entrymeta database table. When an administrator views entries or views an individual entry, the unsafe unserialize() call processes the stored data without class restrictions.

- [https://github.com/xxconi/CVE-2026-3296](https://github.com/xxconi/CVE-2026-3296) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-3296.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-3296.svg)


## CVE-2026-3060
 SGLang' encoder parallel disaggregation system is vulnerable to unauthenticated remote code execution through the disaggregation module, which deserializes untrusted data using pickle.loads() without authentication.

- [https://github.com/glenfmessenger/sglang-lens](https://github.com/glenfmessenger/sglang-lens) :  ![starts](https://img.shields.io/github/stars/glenfmessenger/sglang-lens.svg) ![forks](https://img.shields.io/github/forks/glenfmessenger/sglang-lens.svg)


## CVE-2026-3059
 SGLang's multimodal generation module is vulnerable to unauthenticated remote code execution through the ZMQ broker, which deserializes untrusted data using pickle.loads() without authentication.

- [https://github.com/glenfmessenger/sglang-lens](https://github.com/glenfmessenger/sglang-lens) :  ![starts](https://img.shields.io/github/stars/glenfmessenger/sglang-lens.svg) ![forks](https://img.shields.io/github/forks/glenfmessenger/sglang-lens.svg)


## CVE-2026-2942
 The ProSolution WP Client plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'proSol_fileUploadProcess' function in all versions up to, and including, 1.9.9. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/xxconi/CVE-2026-2942](https://github.com/xxconi/CVE-2026-2942) :  ![starts](https://img.shields.io/github/stars/xxconi/CVE-2026-2942.svg) ![forks](https://img.shields.io/github/forks/xxconi/CVE-2026-2942.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2025-50946
 OS Command Injection in Olivetin 2025.4.22 Custom Themes via the ParseRequestURI function in service/internal/executor/arguments.go.

- [https://github.com/runt1me/cve-2025-50946](https://github.com/runt1me/cve-2025-50946) :  ![starts](https://img.shields.io/github/stars/runt1me/cve-2025-50946.svg) ![forks](https://img.shields.io/github/forks/runt1me/cve-2025-50946.svg)


## CVE-2025-21082
 in OpenHarmony v5.0.3 and prior versions allow a local attacker cause apps crash through type confusion.

- [https://github.com/kkaanozturk/HyperOS-Directory-Traversal-Analysis](https://github.com/kkaanozturk/HyperOS-Directory-Traversal-Analysis) :  ![starts](https://img.shields.io/github/stars/kkaanozturk/HyperOS-Directory-Traversal-Analysis.svg) ![forks](https://img.shields.io/github/forks/kkaanozturk/HyperOS-Directory-Traversal-Analysis.svg)


## CVE-2024-48990
 Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.

- [https://github.com/kikechans/-Linux-PrivEsc-CVE-2024-48990](https://github.com/kikechans/-Linux-PrivEsc-CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/kikechans/-Linux-PrivEsc-CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/kikechans/-Linux-PrivEsc-CVE-2024-48990.svg)


## CVE-2024-32019
 Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/kikechans/-Netdata-PrivEsc-CVE-2024-32019](https://github.com/kikechans/-Netdata-PrivEsc-CVE-2024-32019) :  ![starts](https://img.shields.io/github/stars/kikechans/-Netdata-PrivEsc-CVE-2024-32019.svg) ![forks](https://img.shields.io/github/forks/kikechans/-Netdata-PrivEsc-CVE-2024-32019.svg)


## CVE-2024-6783
 A vulnerability has been discovered in Vue, that allows an attacker to perform XSS via prototype pollution. The attacker could change the prototype chain of some properties such as `Object.prototype.staticClass` or `Object.prototype.staticStyle` to execute arbitrary JavaScript code.

- [https://github.com/HORKimhab/CVE-2024-6783](https://github.com/HORKimhab/CVE-2024-6783) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2024-6783.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2024-6783.svg)


## CVE-2023-50564
 An arbitrary file upload vulnerability in the component /inc/modules_install.php of Pluck-CMS v4.7.18 allows attackers to execute arbitrary code via uploading a crafted ZIP file.

- [https://github.com/kikechans/-Pluck-CMS-RCE-CVE-2023-50564](https://github.com/kikechans/-Pluck-CMS-RCE-CVE-2023-50564) :  ![starts](https://img.shields.io/github/stars/kikechans/-Pluck-CMS-RCE-CVE-2023-50564.svg) ![forks](https://img.shields.io/github/forks/kikechans/-Pluck-CMS-RCE-CVE-2023-50564.svg)


## CVE-2021-44967
 A Remote Code Execution (RCE) vulnerabilty exists in LimeSurvey 5.2.4 via the upload and install plugins function, which could let a remote malicious user upload an arbitrary PHP code file. NOTE: the Supplier's position is that plugins intentionally can contain arbitrary PHP code, and can only be installed by a superadmin, and therefore the security model is not violated by this finding.

- [https://github.com/kikechans/-Limesurvey-RCE-CVE-2021-44967](https://github.com/kikechans/-Limesurvey-RCE-CVE-2021-44967) :  ![starts](https://img.shields.io/github/stars/kikechans/-Limesurvey-RCE-CVE-2021-44967.svg) ![forks](https://img.shields.io/github/forks/kikechans/-Limesurvey-RCE-CVE-2021-44967.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/kikechans/-Grafana-LFI-CVE-2021-43798](https://github.com/kikechans/-Grafana-LFI-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/kikechans/-Grafana-LFI-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/kikechans/-Grafana-LFI-CVE-2021-43798.svg)


## CVE-2021-34527
pNote that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as “PrintNightmare”, documented in CVE-2021-34527./p

- [https://github.com/AlDawli/CVE-2021-34527-](https://github.com/AlDawli/CVE-2021-34527-) :  ![starts](https://img.shields.io/github/stars/AlDawli/CVE-2021-34527-.svg) ![forks](https://img.shields.io/github/forks/AlDawli/CVE-2021-34527-.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/Jeanback1/CVE-2021-3560-exploit](https://github.com/Jeanback1/CVE-2021-3560-exploit) :  ![starts](https://img.shields.io/github/stars/Jeanback1/CVE-2021-3560-exploit.svg) ![forks](https://img.shields.io/github/forks/Jeanback1/CVE-2021-3560-exploit.svg)


## CVE-2019-6340
 Some field types do not properly sanitize data from non-form sources in Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. This can lead to arbitrary PHP code execution in some cases. A site is only affected by this if one of the following conditions is met: The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests, or the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services in Drupal 7. (Note: The Drupal 7 Services module itself does not require an update at this time, but you should apply other contributed updates associated with this advisory if Services is in use.)

- [https://github.com/joaoaugustom/Drupal_REST-RCE_Unauthenticated](https://github.com/joaoaugustom/Drupal_REST-RCE_Unauthenticated) :  ![starts](https://img.shields.io/github/stars/joaoaugustom/Drupal_REST-RCE_Unauthenticated.svg) ![forks](https://img.shields.io/github/forks/joaoaugustom/Drupal_REST-RCE_Unauthenticated.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/kikechans/-SSH-Enum-CVE-2018-15473](https://github.com/kikechans/-SSH-Enum-CVE-2018-15473) :  ![starts](https://img.shields.io/github/stars/kikechans/-SSH-Enum-CVE-2018-15473.svg) ![forks](https://img.shields.io/github/forks/kikechans/-SSH-Enum-CVE-2018-15473.svg)


## CVE-2017-10271
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/Dungsocool/CVE-2017-10271](https://github.com/Dungsocool/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2017-10271.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/jaden-mas1010/Metasploitable2-Vulnerability-Assessment](https://github.com/jaden-mas1010/Metasploitable2-Vulnerability-Assessment) :  ![starts](https://img.shields.io/github/stars/jaden-mas1010/Metasploitable2-Vulnerability-Assessment.svg) ![forks](https://img.shields.io/github/forks/jaden-mas1010/Metasploitable2-Vulnerability-Assessment.svg)

