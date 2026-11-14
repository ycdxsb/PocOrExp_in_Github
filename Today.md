# Update 2026-11-14
## CVE-2026-127016
 The MISP Modules website component exposes external tool management endpoints (add, delete, change status, and change configuration) that did not enforce the optional administrator authentication policy. When ADMIN_PASSWORD was configured in the application environment, the module configuration endpoints correctly required an authenticated administrator session, but the external tools management handlers processed requests from anonymous users without any authorization check. An unauthenticated attacker with network access to the website could add arbitrary external tools, delete existing tools, toggle their active status, and modify their configurations including API keys and ingestion URLs. This inconsistency allowed bypass of the intended access control for the external tools management functionality. The vulnerability is conditional on ADMIN_PASSWORD being set; installations without an admin password intentionally permit open management access by design. The affected component is the external_tools Flask blueprint within the MISP Modules website application.

- [https://github.com/fumioryoto/CVE-2026-127016](https://github.com/fumioryoto/CVE-2026-127016) :  ![starts](https://img.shields.io/github/stars/fumioryoto/CVE-2026-127016.svg) ![forks](https://img.shields.io/github/forks/fumioryoto/CVE-2026-127016.svg)


## CVE-2026-126537
 The Ninja Forms - File Uploads add-on for WordPress is vulnerable to Arbitrary File Deletion (and arbitrary file read via S3/Dropbox/Google Drive exfiltration) in versions up to, and including, 3.3.36. The flaw spans NF_FU_Fields_Upload::process() in includes/fields/upload.php — which returns early (leaving the client-supplied files[] intact) whenever a public submission carries a nonempty extra.saveProgress — and NF_FU_External_Abstracts_Service::process_upload() in includes/external/abstracts/service.php, whose authoritative-path reload only fires when the client sends upload_id. By omitting upload_id, an attacker's data[file_path] survives into the Background Upload queue and is used by both upload_file_to_s3() (as SourceFile) and the maybe_delete_server_file() unlink() call in includes/external/abstracts/backgroundupload.php, with no canonicalization or upload-directory containment check (the plugin's own is_path_within_upload_dir() helper is only applied on admin paths). This makes it possible for unauthenticated attackers to delete arbitrary files on the affected site's server which may make remote code execution possible — specifically, deleting wp-config.php forces WordPress into its setup screen, enabling full site takeover.

- [https://github.com/im0xfay/CVE-2026-126537](https://github.com/im0xfay/CVE-2026-126537) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-126537.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-126537.svg)


## CVE-2026-126187
 React is a JavaScript library for building user interfaces. From 19.0.0 until 19.0.9, 19.1.10, 19.2.9, and 19.3.1, the react-server-dom-webpack, react-server-dom-parcel, and react-server-dom-turbopack packages are vulnerable to unauthenticated remote code execution through crafted payloads targeting frameworks that support React Server Components. The vulnerability only affects extremely rare cases where responses transport multiple typed arrays and an attacker-controlled value. Applications whose React code does not use a server are not affected. Applications that do not use a framework, bundler, or bundler plugin that supports React Server Components are not affected. This issue is fixed in versions 19.0.9, 19.1.10, 19.2.9, and 19.3.1.

- [https://github.com/TahuCryptsi/poc-cve-2026-126187-rsc-usecache-rce](https://github.com/TahuCryptsi/poc-cve-2026-126187-rsc-usecache-rce) :  ![starts](https://img.shields.io/github/stars/TahuCryptsi/poc-cve-2026-126187-rsc-usecache-rce.svg) ![forks](https://img.shields.io/github/forks/TahuCryptsi/poc-cve-2026-126187-rsc-usecache-rce.svg)


## CVE-2026-126170
 A improper encoding or escaping of output vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.2, FortiAnalyzer 7.6.0 through 7.6.7, FortiAnalyzer Cloud 8.0.1 through 8.0.2, FortiAnalyzer Cloud 7.6.0 through 7.6.7, FortiAnalyzer-BigData 7.6.0 through 7.6.2, FortiManager 8.0.0 through 8.0.2, FortiManager 7.6.0 through 7.6.7, FortiManager Cloud 8.0.1 through 8.0.2, FortiManager Cloud 7.6.0 through 7.6.7 may allow an unauthenticated attacker to execute unauthorized code or commands via a specially crafted HTTP request

- [https://github.com/googlesky/CVE-2026-126170](https://github.com/googlesky/CVE-2026-126170) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126170.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126170.svg)


## CVE-2026-126148
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6 may allow an unauthenticated attacker to execute unauthorized code or commands via crafted HA join-request packets.

- [https://github.com/googlesky/CVE-2026-126148](https://github.com/googlesky/CVE-2026-126148) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126148.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126148.svg)


## CVE-2026-126147
 A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiMail 7.4.0 through 7.4.8, FortiMail 7.2 all versions may allow an unauthenticated attacker to execute unauthorized code or commands via crafted requests.

- [https://github.com/googlesky/CVE-2026-126147](https://github.com/googlesky/CVE-2026-126147) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-126147.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-126147.svg)


## CVE-2026-125350
 Use after free in XML in Google Chrome prior to 157.0.8103.50 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2026-125350-poc](https://github.com/dexteon/cve-2026-125350-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2026-125350-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2026-125350-poc.svg)


## CVE-2026-123807
 Signal K Server is a server application that runs on a central hub in a boat. From 2.0.0 until 2.34.0 for Signal K Server and from 1.0.0 until 1.5.3 for @signalk/resources-provider, the v2 REST route GET /signalk/v2/api/resources/:resourceType/:resourceId accepts an unsafe resourceId that can escape the intended resource directory. The route passes the attacker-controlled resourceId through src/api/resources/index.ts to FileStore.getResource() in packages/resources-provider-plugin/src/filestorage.ts without adequate path containment, allowing arbitrary JSON files reachable by the server to be read. Related PUT and DELETE resource operations can write or delete files outside the storage root. Deployments with allow_readonly enabled permit anonymous reads, while other deployments require a readonly user token. Reading security.json exposes the HS256 JWT signing secret and password hashes, allowing an attacker to forge an administrator token. Administrative access to POST /skServer/providers can then create an Execute provider that runs commands with the server process privileges and persists its configuration across restarts. This issue is fixed in Signal K Server 2.34.0 and @signalk/resources-provider 1.5.3.

- [https://github.com/qianlijaingshan/signalk-audit](https://github.com/qianlijaingshan/signalk-audit) :  ![starts](https://img.shields.io/github/stars/qianlijaingshan/signalk-audit.svg) ![forks](https://img.shields.io/github/forks/qianlijaingshan/signalk-audit.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/kaiqui/cve-2026-123158-lab](https://github.com/kaiqui/cve-2026-123158-lab) :  ![starts](https://img.shields.io/github/stars/kaiqui/cve-2026-123158-lab.svg) ![forks](https://img.shields.io/github/forks/kaiqui/cve-2026-123158-lab.svg)
- [https://github.com/garvthakkar17/sshole-alpine-cve-2026-123158](https://github.com/garvthakkar17/sshole-alpine-cve-2026-123158) :  ![starts](https://img.shields.io/github/stars/garvthakkar17/sshole-alpine-cve-2026-123158.svg) ![forks](https://img.shields.io/github/forks/garvthakkar17/sshole-alpine-cve-2026-123158.svg)
- [https://github.com/zanarelkov/CVE-2026-123158_SSHole_PoC](https://github.com/zanarelkov/CVE-2026-123158_SSHole_PoC) :  ![starts](https://img.shields.io/github/stars/zanarelkov/CVE-2026-123158_SSHole_PoC.svg) ![forks](https://img.shields.io/github/forks/zanarelkov/CVE-2026-123158_SSHole_PoC.svg)


## CVE-2026-121653
 SQL injection in the Core of Ivanti Endpoint Manager before version 2024 SU8 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/googlesky/CVE-2026-121653](https://github.com/googlesky/CVE-2026-121653) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-121653.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-121653.svg)


## CVE-2026-120868
 Memory overflow in Packet Processing can lead to unpredictable or erroneous behavior or Denial of Service in NetScaler ADC and NetScaler Gateway.

- [https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) :  ![starts](https://img.shields.io/github/stars/ThomasPoppelgaard/netscaler-ctx697096-checker.svg) ![forks](https://img.shields.io/github/forks/ThomasPoppelgaard/netscaler-ctx697096-checker.svg)


## CVE-2026-119987
 Untrusted search path in Microsoft Windows App Store allows an authorized attacker to elevate privileges locally.

- [https://github.com/karollooool/CVE-2026-119987-writeup](https://github.com/karollooool/CVE-2026-119987-writeup) :  ![starts](https://img.shields.io/github/stars/karollooool/CVE-2026-119987-writeup.svg) ![forks](https://img.shields.io/github/forks/karollooool/CVE-2026-119987-writeup.svg)


## CVE-2026-119958
 Out-of-bounds write in Windows LDAP - Lightweight Directory Access Protocol allows an unauthorized attacker to execute code over a network.

- [https://github.com/googlesky/CVE-2026-119958](https://github.com/googlesky/CVE-2026-119958) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-119958.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-119958.svg)


## CVE-2026-119618
Affected releases of mod_h2 from GitHub: from 2.0.8 through 2.0.42.

- [https://github.com/googlesky/CVE-2026-119618](https://github.com/googlesky/CVE-2026-119618) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-119618.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-119618.svg)
- [https://github.com/geovanidps/cve-2026-119618-Apache](https://github.com/geovanidps/cve-2026-119618-Apache) :  ![starts](https://img.shields.io/github/stars/geovanidps/cve-2026-119618-Apache.svg) ![forks](https://img.shields.io/github/forks/geovanidps/cve-2026-119618-Apache.svg)
- [https://github.com/suominen/CVE-2026-119618](https://github.com/suominen/CVE-2026-119618) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-119618.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-119618.svg)
- [https://github.com/LLCForge/CVE-2026-119618](https://github.com/LLCForge/CVE-2026-119618) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-119618.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-119618.svg)
- [https://github.com/jeffschafer/Bigfix-Apache-HTTP2-Vulnerability-Scanner-CVE-2026-119618](https://github.com/jeffschafer/Bigfix-Apache-HTTP2-Vulnerability-Scanner-CVE-2026-119618) :  ![starts](https://img.shields.io/github/stars/jeffschafer/Bigfix-Apache-HTTP2-Vulnerability-Scanner-CVE-2026-119618.svg) ![forks](https://img.shields.io/github/forks/jeffschafer/Bigfix-Apache-HTTP2-Vulnerability-Scanner-CVE-2026-119618.svg)
- [https://github.com/jeffschafer/Apache-HTTP2-RCE-HEAP-CORRUPTION-CVE-2026-119618-STAND-ALONE-SCANNER](https://github.com/jeffschafer/Apache-HTTP2-RCE-HEAP-CORRUPTION-CVE-2026-119618-STAND-ALONE-SCANNER) :  ![starts](https://img.shields.io/github/stars/jeffschafer/Apache-HTTP2-RCE-HEAP-CORRUPTION-CVE-2026-119618-STAND-ALONE-SCANNER.svg) ![forks](https://img.shields.io/github/forks/jeffschafer/Apache-HTTP2-RCE-HEAP-CORRUPTION-CVE-2026-119618-STAND-ALONE-SCANNER.svg)
- [https://github.com/foxcornlab/apache-httpd-scanner](https://github.com/foxcornlab/apache-httpd-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/apache-httpd-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/apache-httpd-scanner.svg)


## CVE-2026-111190
 The ARForms plugin for WordPress is vulnerable to arbitrary file upload in all versions up to, and including, 7.2.4 via its form file-upload handler. The name of the stored file is taken from an attacker-controlled request header and is not adequately restricted to safe file types, and the plugin's file-type and content-safety checks can be evaded, allowing files that contain executable PHP code to be written to a publicly accessible directory. This makes it possible for unauthenticated attackers to upload malicious files to the affected site's server, which may make remote code execution possible. Exploitation requires a published form containing a File field to be publicly accessible on the site.

- [https://github.com/im0xfay/CVE-ARFORMS](https://github.com/im0xfay/CVE-ARFORMS) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-ARFORMS.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-ARFORMS.svg)


## CVE-2026-110264
 An issue has been discovered in GitLab CE/EE affecting all versions from 7.0 before 18.11.13, 19.0 before 19.0.10, 19.1 before 19.1.9, 19.2 before 19.2.9, 19.3 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server due to integer overflow when compiling a specially crafted regular expression.

- [https://github.com/mohammadzarnian1357/Exploit-CVE-2026-110264-GitLab-CE-EE-RCE](https://github.com/mohammadzarnian1357/Exploit-CVE-2026-110264-GitLab-CE-EE-RCE) :  ![starts](https://img.shields.io/github/stars/mohammadzarnian1357/Exploit-CVE-2026-110264-GitLab-CE-EE-RCE.svg) ![forks](https://img.shields.io/github/forks/mohammadzarnian1357/Exploit-CVE-2026-110264-GitLab-CE-EE-RCE.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/toxy4ny/php2shell-checker](https://github.com/toxy4ny/php2shell-checker) :  ![starts](https://img.shields.io/github/stars/toxy4ny/php2shell-checker.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/php2shell-checker.svg)
- [https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619](https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/seppegadeyne/php2shell-runcloud-builds](https://github.com/seppegadeyne/php2shell-runcloud-builds) :  ![starts](https://img.shields.io/github/stars/seppegadeyne/php2shell-runcloud-builds.svg) ![forks](https://img.shields.io/github/forks/seppegadeyne/php2shell-runcloud-builds.svg)
- [https://github.com/Galeax/PHP2Shell-Mitigations](https://github.com/Galeax/PHP2Shell-Mitigations) :  ![starts](https://img.shields.io/github/stars/Galeax/PHP2Shell-Mitigations.svg) ![forks](https://img.shields.io/github/forks/Galeax/PHP2Shell-Mitigations.svg)


## CVE-2026-109163
This issue affects Apache HTTP Server: 2.4.69.

- [https://github.com/foxcornlab/apache-httpd-scanner](https://github.com/foxcornlab/apache-httpd-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/apache-httpd-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/apache-httpd-scanner.svg)


## CVE-2026-106023
This issue affects Apache HTTP Server: from 2.4.30 through 2.4.69.

- [https://github.com/foxcornlab/apache-httpd-scanner](https://github.com/foxcornlab/apache-httpd-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/apache-httpd-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/apache-httpd-scanner.svg)


## CVE-2026-105440
Extreme Networks would like to thank Toàn Lê (GitHub: https://github.com/toanln-cov) for responsibly disclosing this vulnerability and for working with our PSIRT team through coordinated disclosure.

- [https://github.com/toanln-cov/CVE-2026-105440](https://github.com/toanln-cov/CVE-2026-105440) :  ![starts](https://img.shields.io/github/stars/toanln-cov/CVE-2026-105440.svg) ![forks](https://img.shields.io/github/forks/toanln-cov/CVE-2026-105440.svg)


## CVE-2026-104246
 The Contact Form 7 Signature Addon WordPress plugin through 4.2.2 does not sanitize a signature field value before building an email attachment path from it, allowing unauthenticated users to attach arbitrary files (bounded to wp-content on current Contact Form 7) to a form's outgoing email via path traversal; when a form is configured to email a copy to a submitter-controlled address, the attacker can read the targeted file.

- [https://github.com/currenge/cf7-signature-addon-security-patch](https://github.com/currenge/cf7-signature-addon-security-patch) :  ![starts](https://img.shields.io/github/stars/currenge/cf7-signature-addon-security-patch.svg) ![forks](https://img.shields.io/github/forks/currenge/cf7-signature-addon-security-patch.svg)


## CVE-2026-99999
A more complete validation at input is forthcoming, but needs more work.

- [https://github.com/debuman/cve-2026-99999-scanner](https://github.com/debuman/cve-2026-99999-scanner) :  ![starts](https://img.shields.io/github/stars/debuman/cve-2026-99999-scanner.svg) ![forks](https://img.shields.io/github/forks/debuman/cve-2026-99999-scanner.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/mumaosong/CVE-2026-98260-Drive](https://github.com/mumaosong/CVE-2026-98260-Drive) :  ![starts](https://img.shields.io/github/stars/mumaosong/CVE-2026-98260-Drive.svg) ![forks](https://img.shields.io/github/forks/mumaosong/CVE-2026-98260-Drive.svg)
- [https://github.com/osamaassolimany-ui/TimerRoot](https://github.com/osamaassolimany-ui/TimerRoot) :  ![starts](https://img.shields.io/github/stars/osamaassolimany-ui/TimerRoot.svg) ![forks](https://img.shields.io/github/forks/osamaassolimany-ui/TimerRoot.svg)


## CVE-2026-97793
 Missing authentication for critical function in Windows Setup and Deployment allows an authorized attacker to elevate privileges locally.

- [https://github.com/yo-yo-yo-jbo/intro_to_com](https://github.com/yo-yo-yo-jbo/intro_to_com) :  ![starts](https://img.shields.io/github/stars/yo-yo-yo-jbo/intro_to_com.svg) ![forks](https://img.shields.io/github/forks/yo-yo-yo-jbo/intro_to_com.svg)


## CVE-2026-96054
 Heap-based buffer overflow in Microsoft Color Management allows an unauthorized attacker to execute code locally.

- [https://github.com/kagancapar/CVE-2026-96054](https://github.com/kagancapar/CVE-2026-96054) :  ![starts](https://img.shields.io/github/stars/kagancapar/CVE-2026-96054.svg) ![forks](https://img.shields.io/github/forks/kagancapar/CVE-2026-96054.svg)


## CVE-2026-88235
 Unintended proxy or intermediary ('confused deputy') in Servicing Stack Updates allows an authorized attacker to elevate privileges locally.

- [https://github.com/crisprss/CVE-2026-88235](https://github.com/crisprss/CVE-2026-88235) :  ![starts](https://img.shields.io/github/stars/crisprss/CVE-2026-88235.svg) ![forks](https://img.shields.io/github/forks/crisprss/CVE-2026-88235.svg)


## CVE-2026-87772
This issue affects Pardus About: before 1.2.5.

- [https://github.com/jankesec/CVE-2026-87772-pardus-about-lpe](https://github.com/jankesec/CVE-2026-87772-pardus-about-lpe) :  ![starts](https://img.shields.io/github/stars/jankesec/CVE-2026-87772-pardus-about-lpe.svg) ![forks](https://img.shields.io/github/forks/jankesec/CVE-2026-87772-pardus-about-lpe.svg)


## CVE-2026-87491
 Out of bounds write in V8 in Google Chrome prior to 153.0.8010.36 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/dexteon/cve-2026-87491-poc](https://github.com/dexteon/cve-2026-87491-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2026-87491-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2026-87491-poc.svg)


## CVE-2026-85046
 Type confusion in V8 in Google Chrome prior to 152.0.7977.82 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2026-85046-poc](https://github.com/dexteon/cve-2026-85046-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2026-85046-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2026-85046-poc.svg)


## CVE-2026-83844
 Out-of-bounds read in Windows Paint allows an unauthorized attacker to execute code locally.

- [https://github.com/zake1god/CVE-2026-83844](https://github.com/zake1god/CVE-2026-83844) :  ![starts](https://img.shields.io/github/stars/zake1god/CVE-2026-83844.svg) ![forks](https://img.shields.io/github/forks/zake1god/CVE-2026-83844.svg)


## CVE-2026-79707
 A Path Traversal vulnerability in the builder endpoint in Google Cloud Agent Development Kit (ADK) versions 1.9.0 through 1.21.0 on Python allows an unauthenticated remote attacker to read arbitrary files using a crafted file_path query parameter.

- [https://github.com/xqi1337/CVE-2026-79707-Exploitation](https://github.com/xqi1337/CVE-2026-79707-Exploitation) :  ![starts](https://img.shields.io/github/stars/xqi1337/CVE-2026-79707-Exploitation.svg) ![forks](https://img.shields.io/github/forks/xqi1337/CVE-2026-79707-Exploitation.svg)


## CVE-2026-78287
 Improper Control of Generation of Code ('Code Injection') vulnerability in Staggs STAGGS staggs allows Remote Code Inclusion.This issue affects STAGGS: from n/a through 3.3.0.

- [https://github.com/evenomn/CVE-2026-78287](https://github.com/evenomn/CVE-2026-78287) :  ![starts](https://img.shields.io/github/stars/evenomn/CVE-2026-78287.svg) ![forks](https://img.shields.io/github/forks/evenomn/CVE-2026-78287.svg)


## CVE-2026-76954
 An improper neutralization of special elements used in an SQL command vulnerability in the Auth API in Synology DiskStation Manager (DSM) before 7.2.1-69057-13, 7.2.2-72806-10, 7.3.2-86009-5, and 7.4.1-90080-1 allows remote attackers to read or write arbitrary files and conduct denial-of-service attacks.

- [https://github.com/ansonhsu-ai/synology-dsm-cve-2026-76954-ste](https://github.com/ansonhsu-ai/synology-dsm-cve-2026-76954-ste) :  ![starts](https://img.shields.io/github/stars/ansonhsu-ai/synology-dsm-cve-2026-76954-ste.svg) ![forks](https://img.shields.io/github/forks/ansonhsu-ai/synology-dsm-cve-2026-76954-ste.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/Jenderal92/metapwn-mass](https://github.com/Jenderal92/metapwn-mass) :  ![starts](https://img.shields.io/github/stars/Jenderal92/metapwn-mass.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/metapwn-mass.svg)


## CVE-2026-56290
 Joomla Extension - joomlack.fr - Unauthenticated file upload in Page Builder CK extension  3.6.0 - The Joomla extension Page Builder CK is vulnerable to an unauthenticated arbitrary file upload that allows uploading executable files and leads to full RCE.

- [https://github.com/Mushr00w/CVE-2026-56290](https://github.com/Mushr00w/CVE-2026-56290) :  ![starts](https://img.shields.io/github/stars/Mushr00w/CVE-2026-56290.svg) ![forks](https://img.shields.io/github/forks/Mushr00w/CVE-2026-56290.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/username-enzo/Fold7-Canada-TempRoot-Lock](https://github.com/username-enzo/Fold7-Canada-TempRoot-Lock) :  ![starts](https://img.shields.io/github/stars/username-enzo/Fold7-Canada-TempRoot-Lock.svg) ![forks](https://img.shields.io/github/forks/username-enzo/Fold7-Canada-TempRoot-Lock.svg)


## CVE-2026-34621
 Acrobat Reader versions 24.001.30356, 26.001.21367 and earlier are affected by an Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/dexteon/cve-2026-34621-poc](https://github.com/dexteon/cve-2026-34621-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2026-34621-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2026-34621-poc.svg)


## CVE-2026-12413
 An invalidly formatted IKEv2 fragment causes the Libreswan pluto daemon to crash and restart. Continued exploitation would cause a denial of service. The function reassemble_v2_incoming_fragments() would ignore unknown outer payloads but still store these in a fixed size array msg_digest.digest[PAYLIMIT]. An off-by-one error in the assertion PASSERT(logger, md-digest_roof  elemsof(md-digest)) causes the daemon to abort. No remote code execution is possible. Any configuration that allows IKEv2 connections that do not set fragmentation=no are vulnerable. IKEv1 is not affected.

- [https://github.com/Mohammad-Jafar-Shabib/CVE-2026-12413-libreswan-poc](https://github.com/Mohammad-Jafar-Shabib/CVE-2026-12413-libreswan-poc) :  ![starts](https://img.shields.io/github/stars/Mohammad-Jafar-Shabib/CVE-2026-12413-libreswan-poc.svg) ![forks](https://img.shields.io/github/forks/Mohammad-Jafar-Shabib/CVE-2026-12413-libreswan-poc.svg)


## CVE-2026-11702
Secrets generated in multiprocess applications are predictable across processes.

- [https://github.com/Lariinz/CVE-2026-117025](https://github.com/Lariinz/CVE-2026-117025) :  ![starts](https://img.shields.io/github/stars/Lariinz/CVE-2026-117025.svg) ![forks](https://img.shields.io/github/forks/Lariinz/CVE-2026-117025.svg)


## CVE-2026-11645
 Out of bounds read and write in V8 in Google Chrome prior to 149.0.7827.103 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2026-11645-poc](https://github.com/dexteon/cve-2026-11645-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2026-11645-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2026-11645-poc.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/cyberkiddle/CVE-2026-109618](https://github.com/cyberkiddle/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/cyberkiddle/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cyberkiddle/CVE-2026-109618.svg)


## CVE-2026-9198
 IBM Langflow OSS 1.0.0 through 1.10.0 allows unauthenticated attackers to chain /api/v1/auto_login (mints SUPERUSER tokens to any network caller) with /api/v1/validate/code (executes user code via exec()) to achieve full RCE on default Langflow deployments

- [https://github.com/Edward-w-Jack/CVE-2026-9198](https://github.com/Edward-w-Jack/CVE-2026-9198) :  ![starts](https://img.shields.io/github/stars/Edward-w-Jack/CVE-2026-9198.svg) ![forks](https://img.shields.io/github/forks/Edward-w-Jack/CVE-2026-9198.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Repobor/ghostlock-cve-2026-43499-4.19-thyme](https://github.com/Repobor/ghostlock-cve-2026-43499-4.19-thyme) :  ![starts](https://img.shields.io/github/stars/Repobor/ghostlock-cve-2026-43499-4.19-thyme.svg) ![forks](https://img.shields.io/github/forks/Repobor/ghostlock-cve-2026-43499-4.19-thyme.svg)


## CVE-2026-3910
 Inappropriate implementation in V8 in Google Chrome prior to 146.0.7680.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2026-3910-poc](https://github.com/dexteon/cve-2026-3910-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2026-3910-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2026-3910-poc.svg)


## CVE-2026-2441
 Use after free in CSS in Google Chrome prior to 145.0.7632.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2026-2441-poc](https://github.com/dexteon/cve-2026-2441-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2026-2441-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2026-2441-poc.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/TheMursalin/CVE-2026-109618](https://github.com/TheMursalin/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/TheMursalin/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/TheMursalin/CVE-2026-109618.svg)


## CVE-2026-0101
 Improper validation of specified quantities in input within AMD Power Management Firmware (PMFW) could allow a local attacker to pass unsanitized input, potentially resulting in a system crash or denial of service.

- [https://github.com/George0Papasotiriou/CVE-2026-0101-BLE-Address-Spoofing-via-Weak-Resolvable-Private-Address](https://github.com/George0Papasotiriou/CVE-2026-0101-BLE-Address-Spoofing-via-Weak-Resolvable-Private-Address) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-0101-BLE-Address-Spoofing-via-Weak-Resolvable-Private-Address.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-0101-BLE-Address-Spoofing-via-Weak-Resolvable-Private-Address.svg)


## CVE-2025-55177
 Incomplete authorization of linked device synchronization messages in WhatsApp for iOS prior to v2.25.21.73, WhatsApp Business for iOS v2.25.21.78, and WhatsApp for Mac v2.25.21.78 could have allowed an unrelated user to trigger processing of content from an arbitrary URL on a target’s device. We assess that this vulnerability, in combination with an OS-level vulnerability on Apple platforms (CVE-2025-43300), may have been exploited in a sophisticated attack against specific targeted users.

- [https://github.com/giannicabrera90-design/iOS-WhatsApp-Zero-Click-Forensic-Scanner](https://github.com/giannicabrera90-design/iOS-WhatsApp-Zero-Click-Forensic-Scanner) :  ![starts](https://img.shields.io/github/stars/giannicabrera90-design/iOS-WhatsApp-Zero-Click-Forensic-Scanner.svg) ![forks](https://img.shields.io/github/forks/giannicabrera90-design/iOS-WhatsApp-Zero-Click-Forensic-Scanner.svg)


## CVE-2025-43300
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 15.8.5 and iPadOS 15.8.5, iOS 16.7.12 and iPadOS 16.7.12, iOS 18.6.2 and iPadOS 18.6.2, iPadOS 17.7.10, macOS Sequoia 15.6.1, macOS Sonoma 14.7.8, macOS Ventura 13.7.8. Processing a malicious image file may result in memory corruption. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.

- [https://github.com/giannicabrera90-design/iOS-WhatsApp-Zero-Click-Forensic-Scanner](https://github.com/giannicabrera90-design/iOS-WhatsApp-Zero-Click-Forensic-Scanner) :  ![starts](https://img.shields.io/github/stars/giannicabrera90-design/iOS-WhatsApp-Zero-Click-Forensic-Scanner.svg) ![forks](https://img.shields.io/github/forks/giannicabrera90-design/iOS-WhatsApp-Zero-Click-Forensic-Scanner.svg)


## CVE-2025-22226
 VMware ESXi, Workstation, and Fusion contain an information disclosure vulnerability due to an out-of-bounds read in HGFS. A malicious actor with administrative privileges to a virtual machine may be able to exploit this issue to leak memory from the vmx process.

- [https://github.com/dexteon/cve-2025-22226-poc](https://github.com/dexteon/cve-2025-22226-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2025-22226-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2025-22226-poc.svg)


## CVE-2025-22224
 VMware ESXi, and Workstation contain a TOCTOU (Time-of-Check Time-of-Use) vulnerability that leads to an out-of-bounds write. A malicious actor with local administrative privileges on a virtual machine may exploit this issue to execute code as the virtual machine's VMX process running on the host.

- [https://github.com/dexteon/cve-2025-22224-poc](https://github.com/dexteon/cve-2025-22224-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2025-22224-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2025-22224-poc.svg)


## CVE-2025-15556
 Notepad++ versions prior to 8.8.9, when using the WinGUp updater, contain an update integrity verification vulnerability where downloaded update metadata and installers are not cryptographically verified. An attacker able to intercept or redirect update traffic can cause the updater to download and execute an attacker-controlled installer, resulting in arbitrary code execution with the privileges of the user.

- [https://github.com/dexteon/cve-2025-15556-poc](https://github.com/dexteon/cve-2025-15556-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2025-15556-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2025-15556-poc.svg)


## CVE-2025-14174
 Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 143.0.7499.110 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2025-14174-poc](https://github.com/dexteon/cve-2025-14174-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2025-14174-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2025-14174-poc.svg)


## CVE-2025-13223
 Type Confusion in V8 in Google Chrome prior to 142.0.7444.175 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2025-13223-poc](https://github.com/dexteon/cve-2025-13223-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2025-13223-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2025-13223-poc.svg)


## CVE-2025-10585
 Type confusion in V8 in Google Chrome prior to 140.0.7339.185 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2025-10585-poc](https://github.com/dexteon/cve-2025-10585-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2025-10585-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2025-10585-poc.svg)


## CVE-2025-6558
 Insufficient validation of untrusted input in ANGLE and GPU in Google Chrome prior to 138.0.7204.157 allowed a remote attacker to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2025-6558-poc](https://github.com/dexteon/cve-2025-6558-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2025-6558-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2025-6558-poc.svg)


## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2025-6554-poc](https://github.com/dexteon/cve-2025-6554-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2025-6554-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2025-6554-poc.svg)


## CVE-2025-5419
 Out of bounds read and write in V8 in Google Chrome prior to 137.0.7151.68 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2025-5419-poc](https://github.com/dexteon/cve-2025-5419-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2025-5419-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2025-5419-poc.svg)


## CVE-2025-4609
 Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 136.0.7103.113 allowed a remote attacker to potentially perform a sandbox escape via a malicious file. (Chromium security severity: High)

- [https://github.com/vobando007/cve-2025-4609-mojo-poc](https://github.com/vobando007/cve-2025-4609-mojo-poc) :  ![starts](https://img.shields.io/github/stars/vobando007/cve-2025-4609-mojo-poc.svg) ![forks](https://img.shields.io/github/forks/vobando007/cve-2025-4609-mojo-poc.svg)
- [https://github.com/vobando0077/cve-2025-4609-mojo-poc](https://github.com/vobando0077/cve-2025-4609-mojo-poc) :  ![starts](https://img.shields.io/github/stars/vobando0077/cve-2025-4609-mojo-poc.svg) ![forks](https://img.shields.io/github/forks/vobando0077/cve-2025-4609-mojo-poc.svg)
- [https://github.com/santiagovillalobos6900-commits/cve-2025-4609-mojo-poc](https://github.com/santiagovillalobos6900-commits/cve-2025-4609-mojo-poc) :  ![starts](https://img.shields.io/github/stars/santiagovillalobos6900-commits/cve-2025-4609-mojo-poc.svg) ![forks](https://img.shields.io/github/forks/santiagovillalobos6900-commits/cve-2025-4609-mojo-poc.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/dexteon/nextjs-middleware-auth-bypass-cve-2025-29927](https://github.com/dexteon/nextjs-middleware-auth-bypass-cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/dexteon/nextjs-middleware-auth-bypass-cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/dexteon/nextjs-middleware-auth-bypass-cve-2025-29927.svg)


## CVE-2025-2783
 Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 134.0.6998.177 allowed a remote attacker to perform a sandbox escape via a malicious file. (Chromium security severity: High)

- [https://github.com/dexteon/cve-2025-2783-poc](https://github.com/dexteon/cve-2025-2783-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2025-2783-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2025-2783-poc.svg)


## CVE-2025-1094
 Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.

- [https://github.com/dexteon/cve-2025-1094-poc](https://github.com/dexteon/cve-2025-1094-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2025-1094-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2025-1094-poc.svg)


## CVE-2024-37032
 Ollama before 0.1.34 does not validate the format of the digest (sha256 with 64 hex digits) when getting the model path, and thus mishandles the TestGetBlobsPath test cases such as fewer than 64 hex digits, more than 64 hex digits, or an initial ../ substring.

- [https://github.com/dexteon/probllama-ollama-rce-cve-2024-37032](https://github.com/dexteon/probllama-ollama-rce-cve-2024-37032) :  ![starts](https://img.shields.io/github/stars/dexteon/probllama-ollama-rce-cve-2024-37032.svg) ![forks](https://img.shields.io/github/forks/dexteon/probllama-ollama-rce-cve-2024-37032.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/d4ytox/CVE-2024-23897](https://github.com/d4ytox/CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/d4ytox/CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/d4ytox/CVE-2024-23897.svg)


## CVE-2024-8859
 A path traversal vulnerability exists in mlflow/mlflow version 2.15.1. When users configure and use the dbfs service, concatenating the URL directly into the file protocol results in an arbitrary file read vulnerability. This issue occurs because only the path part of the URL is checked, while parts such as query and parameters are not handled. The vulnerability is triggered if the user has configured the dbfs service, and during usage, the service is mounted to a local directory.

- [https://github.com/dexteon/mlflow-dbfs-path-traversal-cve-2024-8859](https://github.com/dexteon/mlflow-dbfs-path-traversal-cve-2024-8859) :  ![starts](https://img.shields.io/github/stars/dexteon/mlflow-dbfs-path-traversal-cve-2024-8859.svg) ![forks](https://img.shields.io/github/forks/dexteon/mlflow-dbfs-path-traversal-cve-2024-8859.svg)


## CVE-2024-5932
 The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code remotely, and to delete arbitrary files.

- [https://github.com/0o176/CVE-2024-5932_PoC](https://github.com/0o176/CVE-2024-5932_PoC) :  ![starts](https://img.shields.io/github/stars/0o176/CVE-2024-5932_PoC.svg) ![forks](https://img.shields.io/github/forks/0o176/CVE-2024-5932_PoC.svg)


## CVE-2024-3095
 A Server-Side Request Forgery (SSRF) vulnerability exists in the Web Research Retriever component of langchain-ai/langchain version 0.1.5. The vulnerability arises because the Web Research Retriever does not restrict requests to remote internet addresses, allowing it to reach local addresses. This flaw enables attackers to execute port scans, access local services, and in some scenarios, read instance metadata from cloud environments. The vulnerability is particularly concerning as it can be exploited to abuse the Web Explorer server as a proxy for web attacks on third parties and interact with servers in the local network, including reading their response data. This could potentially lead to arbitrary code execution, depending on the nature of the local services. The vulnerability is limited to GET requests, as POST requests are not possible, but the impact on confidentiality, integrity, and availability is significant due to the potential for stolen credentials and state-changing interactions with internal APIs.

- [https://github.com/dexteon/langchain-webresearch-ssrf-cve-2024-3095](https://github.com/dexteon/langchain-webresearch-ssrf-cve-2024-3095) :  ![starts](https://img.shields.io/github/stars/dexteon/langchain-webresearch-ssrf-cve-2024-3095.svg) ![forks](https://img.shields.io/github/forks/dexteon/langchain-webresearch-ssrf-cve-2024-3095.svg)


## CVE-2024-2057
 A vulnerability was found in LangChain langchain_community 0.0.26. It has been classified as critical. Affected is the function load_local in the library libs/community/langchain_community/retrievers/tfidf.py of the component TFIDFRetriever. The manipulation leads to server-side request forgery. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 0.0.27 is able to address this issue. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-255372.

- [https://github.com/dexteon/langchain-tfidf-pickle-rce-cve-2024-2057](https://github.com/dexteon/langchain-tfidf-pickle-rce-cve-2024-2057) :  ![starts](https://img.shields.io/github/stars/dexteon/langchain-tfidf-pickle-rce-cve-2024-2057.svg) ![forks](https://img.shields.io/github/forks/dexteon/langchain-tfidf-pickle-rce-cve-2024-2057.svg)


## CVE-2023-46229
 LangChain before 0.0.317 allows SSRF via document_loaders/recursive_url_loader.py because crawling can proceed from an external server to an internal server.

- [https://github.com/dexteon/langchain-sitemap-ssrf-cve-2023-46229](https://github.com/dexteon/langchain-sitemap-ssrf-cve-2023-46229) :  ![starts](https://img.shields.io/github/stars/dexteon/langchain-sitemap-ssrf-cve-2023-46229.svg) ![forks](https://img.shields.io/github/forks/dexteon/langchain-sitemap-ssrf-cve-2023-46229.svg)


## CVE-2023-36845
  *  23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/cxb2523/ccfb-pointwise-20261109-010-cve-2023-36845-scanner](https://github.com/cxb2523/ccfb-pointwise-20261109-010-cve-2023-36845-scanner) :  ![starts](https://img.shields.io/github/stars/cxb2523/ccfb-pointwise-20261109-010-cve-2023-36845-scanner.svg) ![forks](https://img.shields.io/github/forks/cxb2523/ccfb-pointwise-20261109-010-cve-2023-36845-scanner.svg)
- [https://github.com/cxb2523/ccfb-pointwise-20261111-claude-uid831-867-017-cve-2023-36845-scanner](https://github.com/cxb2523/ccfb-pointwise-20261111-claude-uid831-867-017-cve-2023-36845-scanner) :  ![starts](https://img.shields.io/github/stars/cxb2523/ccfb-pointwise-20261111-claude-uid831-867-017-cve-2023-36845-scanner.svg) ![forks](https://img.shields.io/github/forks/cxb2523/ccfb-pointwise-20261111-claude-uid831-867-017-cve-2023-36845-scanner.svg)


## CVE-2023-28252
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/Joe1sn/CVE_2023_28252](https://github.com/Joe1sn/CVE_2023_28252) :  ![starts](https://img.shields.io/github/stars/Joe1sn/CVE_2023_28252.svg) ![forks](https://img.shields.io/github/forks/Joe1sn/CVE_2023_28252.svg)


## CVE-2023-26369
 Acrobat Reader versions 23.003.20284 (and earlier), 20.005.30516 (and earlier) and 20.005.30514 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/dexteon/cve-2023-26369-poc](https://github.com/dexteon/cve-2023-26369-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2023-26369-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2023-26369-poc.svg)


## CVE-2023-21608
 Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/dexteon/cve-2023-21608-poc](https://github.com/dexteon/cve-2023-21608-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2023-21608-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2023-21608-poc.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage](https://github.com/MingqiZhang7710/cve-2022-0847-poc-dockerimage) :  ![starts](https://img.shields.io/github/stars/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg) ![forks](https://img.shields.io/github/forks/MingqiZhang7710/cve-2022-0847-poc-dockerimage.svg)


## CVE-2021-28550
 Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by a Use After Free vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/dexteon/cve-2021-28550-poc](https://github.com/dexteon/cve-2021-28550-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2021-28550-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2021-28550-poc.svg)


## CVE-2021-23337
 Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.

- [https://github.com/mcpmark-eval-liuhezi/ghsa-lodash-ci-7f3c9a](https://github.com/mcpmark-eval-liuhezi/ghsa-lodash-ci-7f3c9a) :  ![starts](https://img.shields.io/github/stars/mcpmark-eval-liuhezi/ghsa-lodash-ci-7f3c9a.svg) ![forks](https://img.shields.io/github/forks/mcpmark-eval-liuhezi/ghsa-lodash-ci-7f3c9a.svg)


## CVE-2021-22986
 On BIG-IP versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x before 14.1.4, 13.1.x before 13.1.3.6, and 12.1.x before 12.1.5.3 amd BIG-IQ 7.1.0.x before 7.1.0.3 and 7.0.0.x before 7.0.0.2, the iControl REST interface has an unauthenticated remote command execution vulnerability. Note: Software versions which have reached End of Software Development (EoSD) are not evaluated.

- [https://github.com/qdtad/CVE-2021-22986](https://github.com/qdtad/CVE-2021-22986) :  ![starts](https://img.shields.io/github/stars/qdtad/CVE-2021-22986.svg) ![forks](https://img.shields.io/github/forks/qdtad/CVE-2021-22986.svg)


## CVE-2021-21017
 Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and 2017.011.30188 (and earlier) are affected by a heap-based buffer overflow vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/dexteon/cve-2021-21017-poc](https://github.com/dexteon/cve-2021-21017-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2021-21017-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2021-21017-poc.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2020-11651
 An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods without authentication. These methods can be used to retrieve user tokens from the salt master and/or run arbitrary commands on salt minions.

- [https://github.com/datefer1989/datefer-offsec](https://github.com/datefer1989/datefer-offsec) :  ![starts](https://img.shields.io/github/stars/datefer1989/datefer-offsec.svg) ![forks](https://img.shields.io/github/forks/datefer1989/datefer-offsec.svg)


## CVE-2020-9715
 Adobe Acrobat and Reader versions 2020.009.20074 and earlier, 2020.001.30002, 2017.011.30171 and earlier, and 2015.006.30523 and earlier have an use-after-free vulnerability. Successful exploitation could lead to arbitrary code execution .

- [https://github.com/dexteon/cve-2020-9715-poc](https://github.com/dexteon/cve-2020-9715-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2020-9715-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2020-9715-poc.svg)


## CVE-2020-0041
 In binder_transaction of binder.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-145988638References: Upstream kernel

- [https://github.com/ankitpipalia/rmx1901-research](https://github.com/ankitpipalia/rmx1901-research) :  ![starts](https://img.shields.io/github/stars/ankitpipalia/rmx1901-research.svg) ![forks](https://img.shields.io/github/forks/ankitpipalia/rmx1901-research.svg)


## CVE-2019-25677
 WinRAR 5.61 contains a denial of service vulnerability that allows local attackers to crash the application by placing a malformed winrar.lng language file in the installation directory. Attackers can trigger the crash by opening an archive and pressing the test button, causing an access violation at memory address 004F1DB8 when the application attempts to read invalid data.

- [https://github.com/kagancapar/CVE-2019-25677](https://github.com/kagancapar/CVE-2019-25677) :  ![starts](https://img.shields.io/github/stars/kagancapar/CVE-2019-25677.svg) ![forks](https://img.shields.io/github/forks/kagancapar/CVE-2019-25677.svg)


## CVE-2018-4990
 Adobe Acrobat and Reader versions 2018.011.20038 and earlier, 2017.011.30079 and earlier, and 2015.006.30417 and earlier have a Double Free vulnerability. Successful exploitation could lead to arbitrary code execution in the context of the current user.

- [https://github.com/dexteon/cve-2018-4990-poc](https://github.com/dexteon/cve-2018-4990-poc) :  ![starts](https://img.shields.io/github/stars/dexteon/cve-2018-4990-poc.svg) ![forks](https://img.shields.io/github/forks/dexteon/cve-2018-4990-poc.svg)


## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.

- [https://github.com/HarshithM834/CYSE425-Lab1-Samba-Security-Assessment](https://github.com/HarshithM834/CYSE425-Lab1-Samba-Security-Assessment) :  ![starts](https://img.shields.io/github/stars/HarshithM834/CYSE425-Lab1-Samba-Security-Assessment.svg) ![forks](https://img.shields.io/github/forks/HarshithM834/CYSE425-Lab1-Samba-Security-Assessment.svg)

