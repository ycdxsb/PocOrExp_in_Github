# Update 2026-10-26
## CVE-2026-116012
 Ghidra before 12.2 contains a numeric truncation vulnerability in PackedDecode::skipAttribute and skipAttributeRemaining in marshal.cc that stores 64-bit string lengths in 32-bit variables. Attackers can supply a crafted packed stream, such as a malicious .sla file, to inject attributes into the decompiler's input or crash the decompiler process.

- [https://github.com/D7EAD/CVE-2026-116012](https://github.com/D7EAD/CVE-2026-116012) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-116012.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-116012.svg)


## CVE-2026-116011
 Crow before 1.3.4 contains an uncontrolled recursion vulnerability in crow::json::load() that allows remote unauthenticated attackers to crash the server by sending deeply nested JSON. Attackers can send a request body with thousands of nested objects to exhaust the worker thread stack, terminating the process and dropping all connections.

- [https://github.com/D7EAD/CVE-2026-116011](https://github.com/D7EAD/CVE-2026-116011) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-116011.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-116011.svg)


## CVE-2026-114820
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 8u511-b32, 8u511-perf-b32, 11.0.33.0.2, 17.0.21.0.2, 21.0.13.0.2, 25.0.5.0.2, 27.0.1.0.2; Oracle GraalVM for JDK: 17.0.21.0.2 and  21.0.13.0.2; Oracle GraalVM Enterprise Edition: 21.3.20.0.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 9.1 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).

- [https://github.com/joedayz/cve-2026-114820-java-scan](https://github.com/joedayz/cve-2026-114820-java-scan) :  ![starts](https://img.shields.io/github/stars/joedayz/cve-2026-114820-java-scan.svg) ![forks](https://img.shields.io/github/forks/joedayz/cve-2026-114820-java-scan.svg)


## CVE-2026-114612
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From 1.87.0 until 1.100.4, 1.101.3, 1.102.2, 1.103.1, and 1.104.0-rc.2, the proxy reuses one cryptographic context for at-rest secrets and session tokens, allowing an authenticated internal user to have crafted metadata containing a forged administrator credential encrypted and returned by the API-key flow. Replaying that ciphertext as a bearer token causes the proxy to trust the forged proxy administrator identity, permitting administrative access and arbitrary commands through the MCP stdio endpoint. Versions 1.87.0 through 1.90.x require EXPERIMENTAL_UI_LOGIN to be enabled, while versions after 1.91.0 are exploitable in the default configuration. This issue was fixed in LiteLLM 1.100.4, 1.101.3, 1.102.2, 1.103.1, and 1.104.0-rc.2.

- [https://github.com/Hunt-Benito/one-salt-to-forge-them-all-cve-2026-114612-forged-admin-session-in-litellm](https://github.com/Hunt-Benito/one-salt-to-forge-them-all-cve-2026-114612-forged-admin-session-in-litellm) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/one-salt-to-forge-them-all-cve-2026-114612-forged-admin-session-in-litellm.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/one-salt-to-forge-them-all-cve-2026-114612-forged-admin-session-in-litellm.svg)


## CVE-2026-114509
 Laravel is a web application framework. Prior to 12.68.0 and 13.29.0, TokenGuard configured as a standard token-based API guard does not reject a crafted non-string credential. Under affected MySQL or MariaDB configurations, the authentication lookup can match an unintended existing user, allowing an unauthenticated attacker to bypass authentication and take over an account on routes protected by TokenGuard. This issue is fixed in versions 12.68.0 and 13.29.0.

- [https://github.com/emirwtz/CVE-2026-114509](https://github.com/emirwtz/CVE-2026-114509) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-114509.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-114509.svg)
- [https://github.com/dimasma0305/CVE-2026-114509](https://github.com/dimasma0305/CVE-2026-114509) :  ![starts](https://img.shields.io/github/stars/dimasma0305/CVE-2026-114509.svg) ![forks](https://img.shields.io/github/forks/dimasma0305/CVE-2026-114509.svg)
- [https://github.com/ArioVeisa/cve-2026-114509-laravel-tokenguard](https://github.com/ArioVeisa/cve-2026-114509-laravel-tokenguard) :  ![starts](https://img.shields.io/github/stars/ArioVeisa/cve-2026-114509-laravel-tokenguard.svg) ![forks](https://img.shields.io/github/forks/ArioVeisa/cve-2026-114509-laravel-tokenguard.svg)


## CVE-2026-114102
 adm-zip before 0.6.1 contains a denial of service vulnerability that allows unauthenticated attackers to crash the Node.js process via a malformed ZIP file, because inflateAsync in methods/inflater.js lacks a zlib stream error listener. Attackers can supply a ZIP with corrupted DEFLATE data processed by readFileAsync, readAsTextAsync, extractAllToAsync, or getDataAsync, triggering an uncatchable exception that terminates all in-flight requests.

- [https://github.com/anywaye/nilepatch-admzip-dos](https://github.com/anywaye/nilepatch-admzip-dos) :  ![starts](https://img.shields.io/github/stars/anywaye/nilepatch-admzip-dos.svg) ![forks](https://img.shields.io/github/forks/anywaye/nilepatch-admzip-dos.svg)


## CVE-2026-114101
 Coraza before 3.8.1 extracts multipart upload filenames with Go's mime.ParseMediaType, which silently ignores RFC 5987 filename* parameters whose charset is not utf-8 or us-ascii. Unauthenticated attackers can send a decoy filename with filename*=iso-8859-1''shell.php, or filename* alone, so FILES-based rules never see the real name, letting dangerous uploads reach backends that honor filename*.

- [https://github.com/anywaye/nilepatch-coraza-bypass](https://github.com/anywaye/nilepatch-coraza-bypass) :  ![starts](https://img.shields.io/github/stars/anywaye/nilepatch-coraza-bypass.svg) ![forks](https://img.shields.io/github/forks/anywaye/nilepatch-coraza-bypass.svg)


## CVE-2026-112900
 Pillow is a Python imaging library. From 2.6.0 until 13.0.0, Pillow is vulnerable to argument injection when invoking Ghostscript for EPS input. EpsImagePlugin.Ghostscript passes a caller-controlled input filename after -f without converting it to a safe absolute path, so a name beginning with a hyphen can be interpreted as a Ghostscript option. An attacker who controls the filename can inject Ghostscript arguments. Arbitrary command execution specifically requires a leading @ argument-file filename and control of the referenced text file containing additional Ghostscript arguments; the reported chain reproduces with the default -dSAFER invocation. This issue is fixed in version 13.0.0.

- [https://github.com/moprius/CVE-2026-112900-Pillow-PoC](https://github.com/moprius/CVE-2026-112900-Pillow-PoC) :  ![starts](https://img.shields.io/github/stars/moprius/CVE-2026-112900-Pillow-PoC.svg) ![forks](https://img.shields.io/github/forks/moprius/CVE-2026-112900-Pillow-PoC.svg)


## CVE-2026-111943
 On most platforms, Go uses the given system root certificates. However, in some narrower cases, the system trust stores may not be updated without further action. To defend against the narrower set of cases that may remain affected, a denylist was added in crypto/x509 to return an error when calling Verify with any of the known intermediate certificates that are no longer considered to be trustworthy.

- [https://github.com/NiBi8z/BadTrust](https://github.com/NiBi8z/BadTrust) :  ![starts](https://img.shields.io/github/stars/NiBi8z/BadTrust.svg) ![forks](https://img.shields.io/github/forks/NiBi8z/BadTrust.svg)
- [https://github.com/Ishanoshada/Emudhra-Ca-Compromise-Lab](https://github.com/Ishanoshada/Emudhra-Ca-Compromise-Lab) :  ![starts](https://img.shields.io/github/stars/Ishanoshada/Emudhra-Ca-Compromise-Lab.svg) ![forks](https://img.shields.io/github/forks/Ishanoshada/Emudhra-Ca-Compromise-Lab.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/tc4dy/CVE-2026-111497-Toolkit](https://github.com/tc4dy/CVE-2026-111497-Toolkit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-111497-Toolkit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-111497-Toolkit.svg)
- [https://github.com/CompleTetech-Security/node2shell-check](https://github.com/CompleTetech-Security/node2shell-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node2shell-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node2shell-check.svg)
- [https://github.com/googlesky/CVE-2026-111497](https://github.com/googlesky/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-111497.svg)
- [https://github.com/mahumadad/CVE-2026-111497-assessment](https://github.com/mahumadad/CVE-2026-111497-assessment) :  ![starts](https://img.shields.io/github/stars/mahumadad/CVE-2026-111497-assessment.svg) ![forks](https://img.shields.io/github/forks/mahumadad/CVE-2026-111497-assessment.svg)
- [https://github.com/s1ko/poc-cve-2026-111497](https://github.com/s1ko/poc-cve-2026-111497) :  ![starts](https://img.shields.io/github/stars/s1ko/poc-cve-2026-111497.svg) ![forks](https://img.shields.io/github/forks/s1ko/poc-cve-2026-111497.svg)
- [https://github.com/mnk-works/cve-2026-111497-rce-checker](https://github.com/mnk-works/cve-2026-111497-rce-checker) :  ![starts](https://img.shields.io/github/stars/mnk-works/cve-2026-111497-rce-checker.svg) ![forks](https://img.shields.io/github/forks/mnk-works/cve-2026-111497-rce-checker.svg)
- [https://github.com/utkarsssh17/cve-2026-111497-brotli-poc](https://github.com/utkarsssh17/cve-2026-111497-brotli-poc) :  ![starts](https://img.shields.io/github/stars/utkarsssh17/cve-2026-111497-brotli-poc.svg) ![forks](https://img.shields.io/github/forks/utkarsssh17/cve-2026-111497-brotli-poc.svg)
- [https://github.com/syrex1013/CVE-2026-111497-node2shell](https://github.com/syrex1013/CVE-2026-111497-node2shell) :  ![starts](https://img.shields.io/github/stars/syrex1013/CVE-2026-111497-node2shell.svg) ![forks](https://img.shields.io/github/forks/syrex1013/CVE-2026-111497-node2shell.svg)
- [https://github.com/pt-act/node2shell-cve-2026-111497](https://github.com/pt-act/node2shell-cve-2026-111497) :  ![starts](https://img.shields.io/github/stars/pt-act/node2shell-cve-2026-111497.svg) ![forks](https://img.shields.io/github/forks/pt-act/node2shell-cve-2026-111497.svg)
- [https://github.com/Secragon/node2shell-radar](https://github.com/Secragon/node2shell-radar) :  ![starts](https://img.shields.io/github/stars/Secragon/node2shell-radar.svg) ![forks](https://img.shields.io/github/forks/Secragon/node2shell-radar.svg)
- [https://github.com/ks-labs/brotli-patch](https://github.com/ks-labs/brotli-patch) :  ![starts](https://img.shields.io/github/stars/ks-labs/brotli-patch.svg) ![forks](https://img.shields.io/github/forks/ks-labs/brotli-patch.svg)
- [https://github.com/datmt/emudhra-fix](https://github.com/datmt/emudhra-fix) :  ![starts](https://img.shields.io/github/stars/datmt/emudhra-fix.svg) ![forks](https://img.shields.io/github/forks/datmt/emudhra-fix.svg)
- [https://github.com/yavuzsemih/brotli-secfix](https://github.com/yavuzsemih/brotli-secfix) :  ![starts](https://img.shields.io/github/stars/yavuzsemih/brotli-secfix.svg) ![forks](https://img.shields.io/github/forks/yavuzsemih/brotli-secfix.svg)
- [https://github.com/Blackman99/lotstamp](https://github.com/Blackman99/lotstamp) :  ![starts](https://img.shields.io/github/stars/Blackman99/lotstamp.svg) ![forks](https://img.shields.io/github/forks/Blackman99/lotstamp.svg)
- [https://github.com/lesterlam/node2shell](https://github.com/lesterlam/node2shell) :  ![starts](https://img.shields.io/github/stars/lesterlam/node2shell.svg) ![forks](https://img.shields.io/github/forks/lesterlam/node2shell.svg)
- [https://github.com/hadayalab-web/pandemic-fortress-advisories](https://github.com/hadayalab-web/pandemic-fortress-advisories) :  ![starts](https://img.shields.io/github/stars/hadayalab-web/pandemic-fortress-advisories.svg) ![forks](https://img.shields.io/github/forks/hadayalab-web/pandemic-fortress-advisories.svg)


## CVE-2026-110922
 Use after free in Prerender in Google Chrome prior to 155.0.8059.84 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/VABISMO/chrome2shell](https://github.com/VABISMO/chrome2shell) :  ![starts](https://img.shields.io/github/stars/VABISMO/chrome2shell.svg) ![forks](https://img.shields.io/github/forks/VABISMO/chrome2shell.svg)


## CVE-2026-110264
 An issue has been discovered in GitLab CE/EE affecting all versions from 7.0 before 18.11.13, 19.0 before 19.0.10, 19.1 before 19.1.9, 19.2 before 19.2.9, 19.3 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server due to integer overflow when compiling a specially crafted regular expression.

- [https://github.com/emirwtz/CVE-2026-110264](https://github.com/emirwtz/CVE-2026-110264) :  ![starts](https://img.shields.io/github/stars/emirwtz/CVE-2026-110264.svg) ![forks](https://img.shields.io/github/forks/emirwtz/CVE-2026-110264.svg)
- [https://github.com/googlesky/CVE-2026-110264](https://github.com/googlesky/CVE-2026-110264) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-110264.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-110264.svg)
- [https://github.com/Masriyan/Exploit-CVE-2026-110264-GitLab-CE-EE-RCE](https://github.com/Masriyan/Exploit-CVE-2026-110264-GitLab-CE-EE-RCE) :  ![starts](https://img.shields.io/github/stars/Masriyan/Exploit-CVE-2026-110264-GitLab-CE-EE-RCE.svg) ![forks](https://img.shields.io/github/forks/Masriyan/Exploit-CVE-2026-110264-GitLab-CE-EE-RCE.svg)
- [https://github.com/FranklinF25/regex2shell](https://github.com/FranklinF25/regex2shell) :  ![starts](https://img.shields.io/github/stars/FranklinF25/regex2shell.svg) ![forks](https://img.shields.io/github/forks/FranklinF25/regex2shell.svg)


## CVE-2026-110152
 Buffer overflow in ANGLE in Google Chrome on on Android prior to 155.0.8059.79 allowed a remote attacker to potentially execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/utkarsssh17/cve-2026-110152-chrome-ngle-rce-poc](https://github.com/utkarsssh17/cve-2026-110152-chrome-ngle-rce-poc) :  ![starts](https://img.shields.io/github/stars/utkarsssh17/cve-2026-110152-chrome-ngle-rce-poc.svg) ![forks](https://img.shields.io/github/forks/utkarsssh17/cve-2026-110152-chrome-ngle-rce-poc.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/zr0n/php2shell](https://github.com/zr0n/php2shell) :  ![starts](https://img.shields.io/github/stars/zr0n/php2shell.svg) ![forks](https://img.shields.io/github/forks/zr0n/php2shell.svg)
- [https://github.com/mefulton/CVE-2026-109618-analysis](https://github.com/mefulton/CVE-2026-109618-analysis) :  ![starts](https://img.shields.io/github/stars/mefulton/CVE-2026-109618-analysis.svg) ![forks](https://img.shields.io/github/forks/mefulton/CVE-2026-109618-analysis.svg)
- [https://github.com/agrresore/php2shell](https://github.com/agrresore/php2shell) :  ![starts](https://img.shields.io/github/stars/agrresore/php2shell.svg) ![forks](https://img.shields.io/github/forks/agrresore/php2shell.svg)
- [https://github.com/CompleTetech-Security/php2shell-check](https://github.com/CompleTetech-Security/php2shell-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/php2shell-check.svg)
- [https://github.com/VABISMO/php2shell-nginx-fpm-full-rce](https://github.com/VABISMO/php2shell-nginx-fpm-full-rce) :  ![starts](https://img.shields.io/github/stars/VABISMO/php2shell-nginx-fpm-full-rce.svg) ![forks](https://img.shields.io/github/forks/VABISMO/php2shell-nginx-fpm-full-rce.svg)
- [https://github.com/Noshadi-sec/cve-2026-109618-109619-poc](https://github.com/Noshadi-sec/cve-2026-109618-109619-poc) :  ![starts](https://img.shields.io/github/stars/Noshadi-sec/cve-2026-109618-109619-poc.svg) ![forks](https://img.shields.io/github/forks/Noshadi-sec/cve-2026-109618-109619-poc.svg)
- [https://github.com/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC](https://github.com/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC) :  ![starts](https://img.shields.io/github/stars/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg) ![forks](https://img.shields.io/github/forks/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg)
- [https://github.com/ihsansencan/Php2Shell-Lab](https://github.com/ihsansencan/Php2Shell-Lab) :  ![starts](https://img.shields.io/github/stars/ihsansencan/Php2Shell-Lab.svg) ![forks](https://img.shields.io/github/forks/ihsansencan/Php2Shell-Lab.svg)
- [https://github.com/softjapan/php74-cve-patched](https://github.com/softjapan/php74-cve-patched) :  ![starts](https://img.shields.io/github/stars/softjapan/php74-cve-patched.svg) ![forks](https://img.shields.io/github/forks/softjapan/php74-cve-patched.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/zr0n/php2shell](https://github.com/zr0n/php2shell) :  ![starts](https://img.shields.io/github/stars/zr0n/php2shell.svg) ![forks](https://img.shields.io/github/forks/zr0n/php2shell.svg)
- [https://github.com/mefulton/CVE-2026-109618-analysis](https://github.com/mefulton/CVE-2026-109618-analysis) :  ![starts](https://img.shields.io/github/stars/mefulton/CVE-2026-109618-analysis.svg) ![forks](https://img.shields.io/github/forks/mefulton/CVE-2026-109618-analysis.svg)
- [https://github.com/agrresore/php2shell](https://github.com/agrresore/php2shell) :  ![starts](https://img.shields.io/github/stars/agrresore/php2shell.svg) ![forks](https://img.shields.io/github/forks/agrresore/php2shell.svg)
- [https://github.com/Noshadi-sec/cve-2026-109618-109619-poc](https://github.com/Noshadi-sec/cve-2026-109618-109619-poc) :  ![starts](https://img.shields.io/github/stars/Noshadi-sec/cve-2026-109618-109619-poc.svg) ![forks](https://img.shields.io/github/forks/Noshadi-sec/cve-2026-109618-109619-poc.svg)
- [https://github.com/CompleTetech-Security/php2shell-check](https://github.com/CompleTetech-Security/php2shell-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/php2shell-check.svg)
- [https://github.com/VABISMO/php2shell-nginx-fpm-full-rce](https://github.com/VABISMO/php2shell-nginx-fpm-full-rce) :  ![starts](https://img.shields.io/github/stars/VABISMO/php2shell-nginx-fpm-full-rce.svg) ![forks](https://img.shields.io/github/forks/VABISMO/php2shell-nginx-fpm-full-rce.svg)
- [https://github.com/memuratozturk/php2shell-poc](https://github.com/memuratozturk/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/memuratozturk/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/memuratozturk/php2shell-poc.svg)
- [https://github.com/EXT-IT/php2shell-check](https://github.com/EXT-IT/php2shell-check) :  ![starts](https://img.shields.io/github/stars/EXT-IT/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/EXT-IT/php2shell-check.svg)
- [https://github.com/Chr1s-T/php2shell-cve-2026-109618](https://github.com/Chr1s-T/php2shell-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/Chr1s-T/php2shell-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/Chr1s-T/php2shell-cve-2026-109618.svg)


## CVE-2026-106074
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-106074-check](https://github.com/CompleTetech-Security/node-cve-2026-106074-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-106074-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-106074-check.svg)


## CVE-2026-106073
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-106073-check](https://github.com/CompleTetech-Security/node-cve-2026-106073-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-106073-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-106073-check.svg)


## CVE-2026-106072
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-106072-check](https://github.com/CompleTetech-Security/node-cve-2026-106072-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-106072-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-106072-check.svg)


## CVE-2026-106071
This vulnerability affects Node.js **26.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-106071-check](https://github.com/CompleTetech-Security/node-cve-2026-106071-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-106071-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-106071-check.svg)


## CVE-2026-106070
This vulnerability affects Node.js **26.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-106070-check](https://github.com/CompleTetech-Security/node-cve-2026-106070-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-106070-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-106070-check.svg)


## CVE-2026-106069
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-106069-check](https://github.com/CompleTetech-Security/node-cve-2026-106069-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-106069-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-106069-check.svg)


## CVE-2026-105483
This vulnerability affects Node.js **26.x** and **24.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-105483-check](https://github.com/CompleTetech-Security/node-cve-2026-105483-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-105483-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-105483-check.svg)


## CVE-2026-105482
This vulnerability affects Node.js 26.x, 24.x, and 22.x.

- [https://github.com/CompleTetech-Security/node-cve-2026-105482-check](https://github.com/CompleTetech-Security/node-cve-2026-105482-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-105482-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-105482-check.svg)


## CVE-2026-105481
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-105481-check](https://github.com/CompleTetech-Security/node-cve-2026-105481-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-105481-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-105481-check.svg)


## CVE-2026-105445
 An Incorrect Privilege Assignment vulnerability in Docker Hub's account-to-organization conversion feature allowed an authenticated attacker to reassign a personal access token (PAT) they controlled to another Docker Hub user without rotating or revoking the token secret. The unchanged PAT then authenticated to the registry as the recipient and could pull, push, or delete images, within its scopes, in repositories accessible to that user, including organization repositories.

- [https://github.com/CompleTetech-Security/docker-hub-pat-check](https://github.com/CompleTetech-Security/docker-hub-pat-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/docker-hub-pat-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/docker-hub-pat-check.svg)


## CVE-2026-104935
 Authentication bypass by spoofing in ICS before version 25.1.3.0 allows a remote unauthenticated attacker to execute arbitrary commands. This does not impact ICS version 22.7R2.14 or prior.

- [https://github.com/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check](https://github.com/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check.svg)


## CVE-2026-104849
 Tinypool is a minimal Node.js worker thread pool implementation. Prior to 2.1.2, Tinypool reads filename from a caller-supplied options object in pool.run(task, options) without requiring an own property, so a polluted Object.prototype.filename can replace the intended worker module. Applications are affected only when they pass their own second-argument options object to pool.run(); calls without that argument use the trusted default options object. An attacker who can first pollute the prototype can cause the worker pool to load attacker-selected JavaScript and can read or modify task data with the host process's privileges. This issue is fixed in version 2.1.2.

- [https://github.com/CompleTetech-Security/tinypool-options-rce-check](https://github.com/CompleTetech-Security/tinypool-options-rce-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/tinypool-options-rce-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/tinypool-options-rce-check.svg)


## CVE-2026-104286
 An improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiMail 7.4.0 through 7.4.8, FortiMail 7.2.0 through 7.2.9 may allow an unauthenticated attacker to write arbitrary files on the underlying system via crafted HTTP or HTTPS requests.

- [https://github.com/CompleTetech-Security/fortimail-cve-2026-104286-check](https://github.com/CompleTetech-Security/fortimail-cve-2026-104286-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/fortimail-cve-2026-104286-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/fortimail-cve-2026-104286-check.svg)


## CVE-2026-102826
 simple-git, an interface for running git commands in any node.js application, enables applications to execute Git operations from JavaScript. Prior to 4.0.0, the default blockUnsafeOperationsPlugin does not completely reject configuration includes supplied through customArgs to git.clone(). The missing include.path classification permits Git to load an attacker-controlled configuration file, and the initial remediation does not cover includeIf.condition.path, allowing the same file-loading primitive through a conditional include. A loaded configuration can set an executable Git option such as core.sshCommand, which Git invokes during the clone operation with the privileges of the Node.js process. Exploitation requires the application to pass attacker-influenced custom arguments and requires an attacker-controlled file that the process can read. This issue is fixed in 4.0.0.

- [https://github.com/CompleTetech-Security/simplegit-rce-check](https://github.com/CompleTetech-Security/simplegit-rce-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/simplegit-rce-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/simplegit-rce-check.svg)


## CVE-2026-102785
 Joomla Extension - yootheme.com - Unauthenticated remote code execution in YOOtheme Pro 5.0.0-5.0.52 - YOOtheme Pro’s publicly accessible image transformation handler incompletely binds normalized image operations and the output destination to its request signature. An unauthenticated remote attacker can reuse a signature disclosed in a legitimate public image URL, inject additional image operations, traverse out of the intended cache directory, and write an attacker-controlled PNG/PHP polyglot to an executable public media directory.

- [https://github.com/antid00t/CVE-2026-102785](https://github.com/antid00t/CVE-2026-102785) :  ![starts](https://img.shields.io/github/stars/antid00t/CVE-2026-102785.svg) ![forks](https://img.shields.io/github/forks/antid00t/CVE-2026-102785.svg)


## CVE-2026-102764
 The vulnerability exists within internal components of BeyondTrust’s Remote Support product. The components did not adequately validate the origin of the messages it received. Under the right conditions, this could allow an attacker to perform file operations on the appliance.

- [https://github.com/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check](https://github.com/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check.svg)


## CVE-2026-102258
 Post-authentication Stored Cross-Site Scripting (XSS) vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a remote authenticated attacker as administrator to store and potentially execute arbitrary JavaScript code in the Appliance Management Console (AMC).

- [https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check.svg)


## CVE-2026-102257
 A Zip Slip vulnerability in the in the SMA1000 Appliance Management Console (AMC) interface allows an attacker to extract files outside the intended destination directory using a specially crafted archive, resulting in remote code execution.

- [https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check.svg)


## CVE-2026-102256
 Post-authentication Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability has been identified in the SMA1000 appliance which in specific conditions could potentially enable a remote authenticated attacker as administrator to execute arbitrary OS commands, resulting in remote code execution.

- [https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check.svg)


## CVE-2026-102255
 A Pre-authentication SSRF vulnerability exists in the SMA1000 Appliance Work Place interface due to an unintended alternate access path. By abusing this path, a remote unauthenticated attacker could potentially exploit this vulnerability to direct the appliance to issue requests on their behalf and reach internal functionality and perform unauthorized operations.

- [https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/sganggs/CVE-2026-98260-BRM-AN00](https://github.com/sganggs/CVE-2026-98260-BRM-AN00) :  ![starts](https://img.shields.io/github/stars/sganggs/CVE-2026-98260-BRM-AN00.svg) ![forks](https://img.shields.io/github/forks/sganggs/CVE-2026-98260-BRM-AN00.svg)


## CVE-2026-96889
 A flaw was found in librsvg. When processing an SVG document containing nested XML inclusions (Xincludes) with duplicate entity declarations, a use-after-free error can occur. This vulnerability arises because the library incorrectly frees an XML entity that is still in use by the parser. An attacker could potentially exploit this to cause a denial of service or execute arbitrary code.

- [https://github.com/CompleTetech-Security/sharp-rsvg-rce-check](https://github.com/CompleTetech-Security/sharp-rsvg-rce-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/sharp-rsvg-rce-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/sharp-rsvg-rce-check.svg)


## CVE-2026-96652
 Plex Media Server before 1.43.3.10861 allows SSRF via '/player/timeline'. An attacker using any X-Plex-Token value can include a full URL in the 'protocol' parameter and force the Plex server to POST to the attacker's chosen destination.

- [https://github.com/TheGlitchFixer/plex2shell-check](https://github.com/TheGlitchFixer/plex2shell-check) :  ![starts](https://img.shields.io/github/stars/TheGlitchFixer/plex2shell-check.svg) ![forks](https://img.shields.io/github/forks/TheGlitchFixer/plex2shell-check.svg)


## CVE-2026-92935
 vm2 is a sandbox for running untrusted Node.js code. In versions = 3.11.4 and = 3.11.6, the NodeVM constructor computes `hasRealRequireConfig` with `typeof requireOpts === 'object' && requireOpts !== null`, so an array-shaped `require` value (for example `require: []`) satisfies the guard that is meant to reject nesting without an explicit require configuration. `makeResolverFromLegacyOptions()` then destructures the array into undefined option fields and returns a resolver containing only `NESTING_OVERRIDE.vm2`. As a result, an attacker who can supply JavaScript executed by a NodeVM configured with truthy `nesting` and an array-shaped `require` (e.g. `new NodeVM({nesting: true, require: []})`) can require the host `vm2` module, create an inner NodeVM with an attacker-chosen builtin allowlist (such as `child_process`), and execute arbitrary commands with the privileges of the host Node.js process, escaping the sandbox. Outer builtin restrictions do not constrain the attacker-created inner NodeVM. This issue is fixed in vm2 3.11.7.

- [https://github.com/CompleTetech-Security/vm2-nesting-check](https://github.com/CompleTetech-Security/vm2-nesting-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/vm2-nesting-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/vm2-nesting-check.svg)


## CVE-2026-88778
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23.

- [https://github.com/CompleTetech-Security/netscaler-cve-2026-88778-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88778-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/netscaler-cve-2026-88778-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/netscaler-cve-2026-88778-check.svg)


## CVE-2026-88777
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23  leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleTetech-Security/netscaler-cve-2026-88777-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88777-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/netscaler-cve-2026-88777-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/netscaler-cve-2026-88777-check.svg)


## CVE-2026-88776
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23  leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleTetech-Security/netscaler-cve-2026-88776-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88776-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/netscaler-cve-2026-88776-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/netscaler-cve-2026-88776-check.svg)


## CVE-2026-88775
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading Memory overflow vulnerability leading to unpredictable or erroneous behavior or Denial of Service

- [https://github.com/CompleTetech-Security/netscaler-cve-2026-88775-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88775-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/netscaler-cve-2026-88775-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/netscaler-cve-2026-88775-check.svg)


## CVE-2026-88774
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to a feature policy bypass due to improper HTTP URL based expression usage.

- [https://github.com/CompleTetech-Security/netscaler-cve-2026-88774-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88774-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/netscaler-cve-2026-88774-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/netscaler-cve-2026-88774-check.svg)


## CVE-2026-88773
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1-37.279 and NDcPP; Gateway: before 14.1-73.37 FIPS and before 13.1-64.23.

- [https://github.com/CompleTetech-Security/netscaler-cve-2026-88773-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88773-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/netscaler-cve-2026-88773-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/netscaler-cve-2026-88773-check.svg)


## CVE-2026-88772
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to Remote Code Execution or Denial of Service

- [https://github.com/CompleTetech-Security/netscaler-cve-2026-88772-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88772-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/netscaler-cve-2026-88772-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/netscaler-cve-2026-88772-check.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/CompleTetech-Security/netscaler-cve-2026-88771-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88771-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/netscaler-cve-2026-88771-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/netscaler-cve-2026-88771-check.svg)


## CVE-2026-88009
 Traefik is an open source HTTP reverse proxy and load balancer. Prior to 2.11.57, and 3.7.13, Traefik accepts a rootless HTTP/1 request target that Go stores in URL.Opaque while leaving URL.Path empty. The rewriteRequestBuilder path evaluates routing, path sanitization, forwardAuth, encodedCharacters, and access logging against a path normalized to / but forwards URL.Opaque verbatim to the backend, allowing cross-vhost routing bypass, path-scoped authorization bypass, and access-log evasion when the backend interprets the opaque target as a path. This issue is fixed in 2.11.57 and 3.7.13.

- [https://github.com/Boreas37/CVE-2026-88009-PoC](https://github.com/Boreas37/CVE-2026-88009-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-88009-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-88009-PoC.svg)


## CVE-2026-86076
 n8n is an open source workflow automation platform. Prior to 1.123.76, 2.37.7, and 2.38.2, the expression compiler sanitizer resolved through dynamically scoped this and did not reject reserved class member names. A class field named __sanitize could rebind the sanitizer and reach the Function constructor, enabling backend code execution and editor-preview JavaScript execution. The affected AST hook is PrototypeSanitizer in packages/workflow/src/expression-sandboxing.ts. This issue is fixed in versions 1.123.76, 2.37.7 and 2.38.2.

- [https://github.com/Boreas37/CVE-2026-86076-PoC](https://github.com/Boreas37/CVE-2026-86076-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-86076-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-86076-PoC.svg)


## CVE-2026-85595
 Traefik versions before v2.11.55 and versions v3.0.0 through v3.7.10 contain an authentication bypass vulnerability in the digestAuth middleware where unknown usernames receive an empty secret instead of rejection. Attackers can compute a valid digest response using the empty secret and arbitrary credentials to bypass authentication on any digestAuth-protected route without a valid username or password.

- [https://github.com/Boreas37/CVE-2026-85595-PoC](https://github.com/Boreas37/CVE-2026-85595-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-85595-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-85595-PoC.svg)


## CVE-2026-85168
 n8n versions before 1.123.73, 2.35.4, and 2.36.2 contain a remote code execution vulnerability in the Git node. The node reset a fixed list of command-bearing configuration keys before each operation, but that list did not cover the content-filter and merge-driver key families. A repository with local configuration setting one of those keys together with a matching attribute pattern causes git to execute the configured command during an ordinary Add, Commit, Checkout, or Pull operation. The command runs as the n8n process user.

- [https://github.com/Boreas37/CVE-2026-85168-PoC](https://github.com/Boreas37/CVE-2026-85168-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-85168-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-85168-PoC.svg)


## CVE-2026-69254
 Flowise is a drag & drop user interface to build a customized large language model flow. Prior to 3.1.3, executeJavaScriptCode() accepted caller-provided nodeVMOptions and merged them over the default NodeVM security settings in packages/components/src/utils.ts. An authenticated attacker reaching packages/server/src/routes/node-custom-functions/index.ts could run a custom function that imported flowise-components/dist/src/utils.js, called executeJavaScriptCode() again with nodeVMOptions.require.builtin set to allow all built-in modules, and then required child_process to execute arbitrary system commands as root on the Flowise server. This issue is fixed in version 3.1.3.

- [https://github.com/CompleTetech-Security/flowise-cve-2026-69254-check](https://github.com/CompleTetech-Security/flowise-cve-2026-69254-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/flowise-cve-2026-69254-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/flowise-cve-2026-69254-check.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/No-World/rootkit](https://github.com/No-World/rootkit) :  ![starts](https://img.shields.io/github/stars/No-World/rootkit.svg) ![forks](https://img.shields.io/github/forks/No-World/rootkit.svg)


## CVE-2026-59774
 Gitea's Org-mode markup renderer processes INCLUDE directives supplied to the repository markup endpoint without preventing access to server-side files. An unauthenticated attacker can use a suitable public repository to read files accessible to the Gitea service account. If the disclosed files include app.ini and its INTERNAL_TOKEN, the attacker can chain the disclosure with internal logger access to modify a Git hook and execute commands as the Gitea service account.

- [https://github.com/Ly0kha/CVE-2026-59774](https://github.com/Ly0kha/CVE-2026-59774) :  ![starts](https://img.shields.io/github/stars/Ly0kha/CVE-2026-59774.svg) ![forks](https://img.shields.io/github/forks/Ly0kha/CVE-2026-59774.svg)


## CVE-2026-58045
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-58045-check](https://github.com/CompleTetech-Security/node-cve-2026-58045-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-58045-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-58045-check.svg)


## CVE-2026-58044
This vulnerability affects all supported release lines: **Node.js 22**, **Node.js 24**, and **Node.js 26**.

- [https://github.com/CompleTetech-Security/node-cve-2026-58044-check](https://github.com/CompleTetech-Security/node-cve-2026-58044-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-58044-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-58044-check.svg)


## CVE-2026-58043
This vulnerability affects Node.js **main**, **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-58043-check](https://github.com/CompleTetech-Security/node-cve-2026-58043-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-58043-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-58043-check.svg)


## CVE-2026-58042
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-58042-check](https://github.com/CompleTetech-Security/node-cve-2026-58042-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-58042-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-58042-check.svg)


## CVE-2026-58041
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-58041-check](https://github.com/CompleTetech-Security/node-cve-2026-58041-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-58041-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-58041-check.svg)


## CVE-2026-58040
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-58040-check](https://github.com/CompleTetech-Security/node-cve-2026-58040-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-58040-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-58040-check.svg)


## CVE-2026-58039
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-58039-check](https://github.com/CompleTetech-Security/node-cve-2026-58039-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-58039-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-58039-check.svg)


## CVE-2026-56850
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-56850-check](https://github.com/CompleTetech-Security/node-cve-2026-56850-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-56850-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-56850-check.svg)


## CVE-2026-56848
This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-56848-check](https://github.com/CompleTetech-Security/node-cve-2026-56848-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-56848-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-56848-check.svg)


## CVE-2026-56847
This vulnerability affects Node.js **22.x**, **24.x**, and **26.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-56847-check](https://github.com/CompleTetech-Security/node-cve-2026-56847-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-56847-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-56847-check.svg)


## CVE-2026-56846
This vulnerability affects Node.js **24.x** and **22.x**.

- [https://github.com/CompleTetech-Security/node-cve-2026-56846-check](https://github.com/CompleTetech-Security/node-cve-2026-56846-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/node-cve-2026-56846-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/node-cve-2026-56846-check.svg)


## CVE-2026-56190
 Use of uninitialized resource in Windows RDP allows an unauthorized attacker to execute code over a network.

- [https://github.com/danarhirany300-ctrl/CVE-2026-56190-Windows-Server-2022-RDP](https://github.com/danarhirany300-ctrl/CVE-2026-56190-Windows-Server-2022-RDP) :  ![starts](https://img.shields.io/github/stars/danarhirany300-ctrl/CVE-2026-56190-Windows-Server-2022-RDP.svg) ![forks](https://img.shields.io/github/forks/danarhirany300-ctrl/CVE-2026-56190-Windows-Server-2022-RDP.svg)


## CVE-2026-44848
 Portainer Community Edition is a lightweight service delivery platform for containerized applications that can be used to manage Docker, Swarm, Kubernetes and ACI environments. From 2.33.0 to before 2.33.8, 2.39.2, and 2.41.0, The Docker plugin management endpoints (/plugins/*) were not registered with a handler, so standard users with endpoint access could call privileged plugin operations — including installing and enabling plugins — directly against the underlying Docker daemon. The vulnerability is exposed when a non-admin Portainer user (Standard User role, or any role granted endpoint-level access) has been given access to a Docker endpoint via Portainer RBAC. This vulnerability is fixed in 2.33.8, 2.39.2, and 2.41.0.

- [https://github.com/mnk-works/portainer-cve-2026-44848-checker](https://github.com/mnk-works/portainer-cve-2026-44848-checker) :  ![starts](https://img.shields.io/github/stars/mnk-works/portainer-cve-2026-44848-checker.svg) ![forks](https://img.shields.io/github/forks/mnk-works/portainer-cve-2026-44848-checker.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC](https://github.com/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC) :  ![starts](https://img.shields.io/github/stars/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC.svg) ![forks](https://img.shields.io/github/forks/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/lunacysoft/CVE-2026-39987-POC-Marimo](https://github.com/lunacysoft/CVE-2026-39987-POC-Marimo) :  ![starts](https://img.shields.io/github/stars/lunacysoft/CVE-2026-39987-POC-Marimo.svg) ![forks](https://img.shields.io/github/forks/lunacysoft/CVE-2026-39987-POC-Marimo.svg)


## CVE-2026-38526
 An authenticated arbitrary file upload vulnerability in the /admin/tinymce/upload endpoint of Webkul Krayin CRM v2.2.x allows attackers to execute arbitrary code via uploading a crafted PHP file.

- [https://github.com/sh3llc0d3-0x15/CVE-2026-38526-Exploit](https://github.com/sh3llc0d3-0x15/CVE-2026-38526-Exploit) :  ![starts](https://img.shields.io/github/stars/sh3llc0d3-0x15/CVE-2026-38526-Exploit.svg) ![forks](https://img.shields.io/github/forks/sh3llc0d3-0x15/CVE-2026-38526-Exploit.svg)


## CVE-2026-21589
 This is a vulnerability in Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center. Crowd Data Center, Crucible and Fisheye. This Arbitrary File Access vulnerability allows an unauthenticated attacker to access specific files within the web application root directory in affected versions. Exploitation requires prior knowledge of the target file's exact name and path; this vulnerability does not allow attackers to enumerate or list directory contents. In some configurations, there may be some sensitive files that make this highly severe. This vulnerability allows an unauthenticated remote attacker to access specific files within the web application root directory in affected versions. The vulnerability must be addressed for affected versions of: -- Bitbucket Data Center, introduced in version = 4.6.0, fix versions: 9.4.26, 10.2.8, 10.5.1 -- Confluence Data Center, introduced in version = 5.10.0, fix versions 9.2.26, 10.2.19 -- Crowd Data Center, introduced in version = 2.11.0, fix versions 6.3.7, 7.0.3, 7.1.7, 7.2.4 -- Jira Software Data Center, introduced in version = 7.1.0, fix versions 9.12.40, 10.3.26, 11.3.12 -- Jira Service Management Data Center, introduced in version = 3.1.0, fix versions 5.12.40, 10.3.26, 11.3.12 -- Bamboo Data Center = 7.0.1, fix versions 10.2.24, 12.1.12 -- Crucible, fix versions 4.9.15 -- Fisheye, fix version 4.9.15 -- Exploitation requires prior knowledge of the target file's exact name and path. The vulnerability does not include the capability to enumerate or list directory contents.

- [https://github.com/CompleTetech-Security/atlassian-cve-2026-21589-check](https://github.com/CompleTetech-Security/atlassian-cve-2026-21589-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/atlassian-cve-2026-21589-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/atlassian-cve-2026-21589-check.svg)


## CVE-2026-19490
This issue affects ADC: from 14.1 through 73.32 and from 13.1 through 63.21; Gateway: from 14.1 through 73.32 and from 13.1 through 63.21.

- [https://github.com/CompleTetech-Security/netscaler-cve-2026-19490-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-19490-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/netscaler-cve-2026-19490-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/netscaler-cve-2026-19490-check.svg)


## CVE-2026-19489
This issue affects ADC: from 14.1 through 73.32 and from 13.1 through 63.21; Gateway: from 14.1 through 73.32 and from 13.1 through 63.21.

- [https://github.com/CompleTetech-Security/netscaler-cve-2026-19489-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-19489-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/netscaler-cve-2026-19489-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/netscaler-cve-2026-19489-check.svg)


## CVE-2026-17106
 The tar extraction routines in moby/go-archive (Unpack, UnpackLayer, Untar/UntarUncompressed, and the ApplyLayer helpers) do not confine filesystem operations to the destination directory. The extractor decides where each archive entry lands using lexical string checks and then performs the filesystem operation on a path that is resolved by the OS, so links introduced by the archive can be followed out of the destination directory. An attacker who controls the contents of an archive can create or overwrite files at arbitrary paths writable by the extracting process.

- [https://github.com/CompleTetech-Security/copyescape-check](https://github.com/CompleTetech-Security/copyescape-check) :  ![starts](https://img.shields.io/github/stars/CompleTetech-Security/copyescape-check.svg) ![forks](https://img.shields.io/github/forks/CompleTetech-Security/copyescape-check.svg)


## CVE-2026-11556
 A security flaw has been discovered in Tenda F451 1.0.0.7/1.0.0.9. Impacted is the function formWriteFacMac of the file /goform/WriteFacMac of the component Web Management Interface. Performing a manipulation of the argument mac results in os command injection. Remote exploitation of the attack is possible. The exploit has been released to the public and may be used for attacks.

- [https://github.com/slabbdev/php-cve-2026-115560-kit](https://github.com/slabbdev/php-cve-2026-115560-kit) :  ![starts](https://img.shields.io/github/stars/slabbdev/php-cve-2026-115560-kit.svg) ![forks](https://img.shields.io/github/forks/slabbdev/php-cve-2026-115560-kit.svg)
- [https://github.com/googlesky/CVE-2026-115560](https://github.com/googlesky/CVE-2026-115560) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-115560.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-115560.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/baimaobg/php-cve-2026-109619-lab](https://github.com/baimaobg/php-cve-2026-109619-lab) :  ![starts](https://img.shields.io/github/stars/baimaobg/php-cve-2026-109619-lab.svg) ![forks](https://img.shields.io/github/forks/baimaobg/php-cve-2026-109619-lab.svg)
- [https://github.com/leonlai-tw/php-eol-cve-2026-109618-109619](https://github.com/leonlai-tw/php-eol-cve-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/leonlai-tw/php-eol-cve-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/leonlai-tw/php-eol-cve-2026-109618-109619.svg)
- [https://github.com/mostofajr7-sudo/CVE-2026-109618-CVE-2026-109619-php2shell-](https://github.com/mostofajr7-sudo/CVE-2026-109618-CVE-2026-109619-php2shell-) :  ![starts](https://img.shields.io/github/stars/mostofajr7-sudo/CVE-2026-109618-CVE-2026-109619-php2shell-.svg) ![forks](https://img.shields.io/github/forks/mostofajr7-sudo/CVE-2026-109618-CVE-2026-109619-php2shell-.svg)
- [https://github.com/vintage-alt/CVE-2026-109618-and-CVE-2026-109619-php2shell-burpproxy](https://github.com/vintage-alt/CVE-2026-109618-and-CVE-2026-109619-php2shell-burpproxy) :  ![starts](https://img.shields.io/github/stars/vintage-alt/CVE-2026-109618-and-CVE-2026-109619-php2shell-burpproxy.svg) ![forks](https://img.shields.io/github/forks/vintage-alt/CVE-2026-109618-and-CVE-2026-109619-php2shell-burpproxy.svg)
- [https://github.com/Taz1920/cve-2026-109619](https://github.com/Taz1920/cve-2026-109619) :  ![starts](https://img.shields.io/github/stars/Taz1920/cve-2026-109619.svg) ![forks](https://img.shields.io/github/forks/Taz1920/cve-2026-109619.svg)
- [https://github.com/devzyai/CVE-2026-109618-POC](https://github.com/devzyai/CVE-2026-109618-POC) :  ![starts](https://img.shields.io/github/stars/devzyai/CVE-2026-109618-POC.svg) ![forks](https://img.shields.io/github/forks/devzyai/CVE-2026-109618-POC.svg)


## CVE-2026-10709
 A maliciously crafted FBX file, when parsed through Autodesk FBX SDK, can trigger a stack-based buffer overflow vulnerability in fbxsdk::FbxIO::BinaryReadSectionHeader. A malicious actor can leverage this vulnerability to execute arbitrary code in the context of the current process.

- [https://github.com/raivenLockdown/CVE-2026-107092](https://github.com/raivenLockdown/CVE-2026-107092) :  ![starts](https://img.shields.io/github/stars/raivenLockdown/CVE-2026-107092.svg) ![forks](https://img.shields.io/github/forks/raivenLockdown/CVE-2026-107092.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/RuanSerraAzul/CVE-2026-109619-POC](https://github.com/RuanSerraAzul/CVE-2026-109619-POC) :  ![starts](https://img.shields.io/github/stars/RuanSerraAzul/CVE-2026-109619-POC.svg) ![forks](https://img.shields.io/github/forks/RuanSerraAzul/CVE-2026-109619-POC.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/jigrit/CVE-2025-32463](https://github.com/jigrit/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/jigrit/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/jigrit/CVE-2025-32463.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/hujiaozhuzhu/CVE-2025-29927__Next.js](https://github.com/hujiaozhuzhu/CVE-2025-29927__Next.js) :  ![starts](https://img.shields.io/github/stars/hujiaozhuzhu/CVE-2025-29927__Next.js.svg) ![forks](https://img.shields.io/github/forks/hujiaozhuzhu/CVE-2025-29927__Next.js.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2025-5548
 A vulnerability, which was classified as critical, was found in FreeFloat FTP Server 1.0. Affected is an unknown function of the component NOOP Command Handler. The manipulation leads to buffer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/pedrose-99/CVE-2025-5548](https://github.com/pedrose-99/CVE-2025-5548) :  ![starts](https://img.shields.io/github/stars/pedrose-99/CVE-2025-5548.svg) ![forks](https://img.shields.io/github/forks/pedrose-99/CVE-2025-5548.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/ayato-shitomi/WebLab_CVE-2025-29927](https://github.com/ayato-shitomi/WebLab_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ayato-shitomi/WebLab_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ayato-shitomi/WebLab_CVE-2025-29927.svg)


## CVE-2024-48990
 Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.

- [https://github.com/endermixxer/CVE-2024-48990_needrestart](https://github.com/endermixxer/CVE-2024-48990_needrestart) :  ![starts](https://img.shields.io/github/stars/endermixxer/CVE-2024-48990_needrestart.svg) ![forks](https://img.shields.io/github/forks/endermixxer/CVE-2024-48990_needrestart.svg)


## CVE-2024-45490
 An issue was discovered in libexpat before 2.6.3. xmlparse.c does not reject a negative length for XML_ParseBuffer.

- [https://github.com/jstjep00/CVE-2024-45490-libexpat-poc](https://github.com/jstjep00/CVE-2024-45490-libexpat-poc) :  ![starts](https://img.shields.io/github/stars/jstjep00/CVE-2024-45490-libexpat-poc.svg) ![forks](https://img.shields.io/github/forks/jstjep00/CVE-2024-45490-libexpat-poc.svg)


## CVE-2024-10441
 Improper encoding or escaping of output vulnerability in the system plugin daemon in Synology BeeStation OS (BSM) before 1.1-65374 and Synology DiskStation Manager (DSM) before 7.2-64570-4, 7.2.1-69057-6 and 7.2.2-72806-1 allows remote attackers to execute arbitrary code via unspecified vectors.

- [https://github.com/Ntn10/cve-2024-10441-synology-rce](https://github.com/Ntn10/cve-2024-10441-synology-rce) :  ![starts](https://img.shields.io/github/stars/Ntn10/cve-2024-10441-synology-rce.svg) ![forks](https://img.shields.io/github/forks/Ntn10/cve-2024-10441-synology-rce.svg)


## CVE-2023-41991
 A certificate validation issue was addressed. This issue is fixed in macOS Ventura 13.6, iOS 16.7 and iPadOS 16.7. A malicious app may be able to bypass signature validation. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 16.7.

- [https://github.com/lambertse/CoreTrust-bypass](https://github.com/lambertse/CoreTrust-bypass) :  ![starts](https://img.shields.io/github/stars/lambertse/CoreTrust-bypass.svg) ![forks](https://img.shields.io/github/forks/lambertse/CoreTrust-bypass.svg)


## CVE-2021-31166
 HTTP Protocol Stack Remote Code Execution Vulnerability

- [https://github.com/testerxma/cve-2021-31166-poc](https://github.com/testerxma/cve-2021-31166-poc) :  ![starts](https://img.shields.io/github/stars/testerxma/cve-2021-31166-poc.svg) ![forks](https://img.shields.io/github/forks/testerxma/cve-2021-31166-poc.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)

