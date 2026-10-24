# Update 2026-10-24
## CVE-2026-114509
 Laravel is a web application framework. Prior to 12.68.0 and 13.29.0, TokenGuard configured as a standard token-based API guard does not reject a crafted non-string credential. Under affected MySQL or MariaDB configurations, the authentication lookup can match an unintended existing user, allowing an unauthenticated attacker to bypass authentication and take over an account on routes protected by TokenGuard. This issue is fixed in versions 12.68.0 and 13.29.0.

- [https://github.com/tajulasri/-CVE-2026-114509-POC](https://github.com/tajulasri/-CVE-2026-114509-POC) :  ![starts](https://img.shields.io/github/stars/tajulasri/-CVE-2026-114509-POC.svg) ![forks](https://img.shields.io/github/forks/tajulasri/-CVE-2026-114509-POC.svg)


## CVE-2026-114406
Due to inability to only distrust specific intermediate certificates in all clients using the system CA store, root CA certificates of authorities that signed weak intermediate CA certificates are being removed.

- [https://github.com/andersundsehr/ca-trust-audit](https://github.com/andersundsehr/ca-trust-audit) :  ![starts](https://img.shields.io/github/stars/andersundsehr/ca-trust-audit.svg) ![forks](https://img.shields.io/github/forks/andersundsehr/ca-trust-audit.svg)


## CVE-2026-114102
 adm-zip before 0.6.1 contains a denial of service vulnerability that allows unauthenticated attackers to crash the Node.js process via a malformed ZIP file, because inflateAsync in methods/inflater.js lacks a zlib stream error listener. Attackers can supply a ZIP with corrupted DEFLATE data processed by readFileAsync, readAsTextAsync, extractAllToAsync, or getDataAsync, triggering an uncatchable exception that terminates all in-flight requests.

- [https://github.com/cafaye/nilepatch-admzip-dos](https://github.com/cafaye/nilepatch-admzip-dos) :  ![starts](https://img.shields.io/github/stars/cafaye/nilepatch-admzip-dos.svg) ![forks](https://img.shields.io/github/forks/cafaye/nilepatch-admzip-dos.svg)


## CVE-2026-114101
 Coraza before 3.8.1 extracts multipart upload filenames with Go's mime.ParseMediaType, which silently ignores RFC 5987 filename* parameters whose charset is not utf-8 or us-ascii. Unauthenticated attackers can send a decoy filename with filename*=iso-8859-1''shell.php, or filename* alone, so FILES-based rules never see the real name, letting dangerous uploads reach backends that honor filename*.

- [https://github.com/cafaye/nilepatch-coraza-bypass](https://github.com/cafaye/nilepatch-coraza-bypass) :  ![starts](https://img.shields.io/github/stars/cafaye/nilepatch-coraza-bypass.svg) ![forks](https://img.shields.io/github/forks/cafaye/nilepatch-coraza-bypass.svg)


## CVE-2026-113812
Configuration and environment variables can override this selection. Users should check which CA store their client uses. If it uses the system store, check for and install the operating system vendor's updates for this incident.

- [https://github.com/andersundsehr/ca-trust-audit](https://github.com/andersundsehr/ca-trust-audit) :  ![starts](https://img.shields.io/github/stars/andersundsehr/ca-trust-audit.svg) ![forks](https://img.shields.io/github/forks/andersundsehr/ca-trust-audit.svg)


## CVE-2026-111943
 On most platforms, Go uses the given system root certificates. However, in some narrower cases, the system trust stores may not be updated without further action. To defend against the narrower set of cases that may remain affected, a denylist was added in crypto/x509 to return an error when calling Verify with any of the known intermediate certificates that are no longer considered to be trustworthy.

- [https://github.com/andersundsehr/ca-trust-audit](https://github.com/andersundsehr/ca-trust-audit) :  ![starts](https://img.shields.io/github/stars/andersundsehr/ca-trust-audit.svg) ![forks](https://img.shields.io/github/forks/andersundsehr/ca-trust-audit.svg)
- [https://github.com/BlackthornYugen/tiny-key-s-server](https://github.com/BlackthornYugen/tiny-key-s-server) :  ![starts](https://img.shields.io/github/stars/BlackthornYugen/tiny-key-s-server.svg) ![forks](https://img.shields.io/github/forks/BlackthornYugen/tiny-key-s-server.svg)
- [https://github.com/majiayu000/trustsweep](https://github.com/majiayu000/trustsweep) :  ![starts](https://img.shields.io/github/stars/majiayu000/trustsweep.svg) ![forks](https://img.shields.io/github/forks/majiayu000/trustsweep.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/CaterMaoZi/CVE-2026-111497-POC](https://github.com/CaterMaoZi/CVE-2026-111497-POC) :  ![starts](https://img.shields.io/github/stars/CaterMaoZi/CVE-2026-111497-POC.svg) ![forks](https://img.shields.io/github/forks/CaterMaoZi/CVE-2026-111497-POC.svg)
- [https://github.com/dimasma0305/CVE-2026-111497-POC](https://github.com/dimasma0305/CVE-2026-111497-POC) :  ![starts](https://img.shields.io/github/stars/dimasma0305/CVE-2026-111497-POC.svg) ![forks](https://img.shields.io/github/forks/dimasma0305/CVE-2026-111497-POC.svg)
- [https://github.com/TheFool-TAROT/CVE-2026-111497-brotli-pwn](https://github.com/TheFool-TAROT/CVE-2026-111497-brotli-pwn) :  ![starts](https://img.shields.io/github/stars/TheFool-TAROT/CVE-2026-111497-brotli-pwn.svg) ![forks](https://img.shields.io/github/forks/TheFool-TAROT/CVE-2026-111497-brotli-pwn.svg)
- [https://github.com/Sami-AlEsh/nodejs-security-check](https://github.com/Sami-AlEsh/nodejs-security-check) :  ![starts](https://img.shields.io/github/stars/Sami-AlEsh/nodejs-security-check.svg) ![forks](https://img.shields.io/github/forks/Sami-AlEsh/nodejs-security-check.svg)
- [https://github.com/hypnguyen1209/CVE-2026-111497](https://github.com/hypnguyen1209/CVE-2026-111497) :  ![starts](https://img.shields.io/github/stars/hypnguyen1209/CVE-2026-111497.svg) ![forks](https://img.shields.io/github/forks/hypnguyen1209/CVE-2026-111497.svg)
- [https://github.com/AdapptOnAzure/cve-2026-111497-mitigation](https://github.com/AdapptOnAzure/cve-2026-111497-mitigation) :  ![starts](https://img.shields.io/github/stars/AdapptOnAzure/cve-2026-111497-mitigation.svg) ![forks](https://img.shields.io/github/forks/AdapptOnAzure/cve-2026-111497-mitigation.svg)
- [https://github.com/ikow/brotli2crash](https://github.com/ikow/brotli2crash) :  ![starts](https://img.shields.io/github/stars/ikow/brotli2crash.svg) ![forks](https://img.shields.io/github/forks/ikow/brotli2crash.svg)
- [https://github.com/TahuCryptsi/node-brotli-check](https://github.com/TahuCryptsi/node-brotli-check) :  ![starts](https://img.shields.io/github/stars/TahuCryptsi/node-brotli-check.svg) ![forks](https://img.shields.io/github/forks/TahuCryptsi/node-brotli-check.svg)
- [https://github.com/incu-tech/october-cyber-family](https://github.com/incu-tech/october-cyber-family) :  ![starts](https://img.shields.io/github/stars/incu-tech/october-cyber-family.svg) ![forks](https://img.shields.io/github/forks/incu-tech/october-cyber-family.svg)
- [https://github.com/The-DevOps-Daily/node-runtime-audit](https://github.com/The-DevOps-Daily/node-runtime-audit) :  ![starts](https://img.shields.io/github/stars/The-DevOps-Daily/node-runtime-audit.svg) ![forks](https://img.shields.io/github/forks/The-DevOps-Daily/node-runtime-audit.svg)
- [https://github.com/WASD258-jpg/dsh-hardening](https://github.com/WASD258-jpg/dsh-hardening) :  ![starts](https://img.shields.io/github/stars/WASD258-jpg/dsh-hardening.svg) ![forks](https://img.shields.io/github/forks/WASD258-jpg/dsh-hardening.svg)


## CVE-2026-110264
 An issue has been discovered in GitLab CE/EE affecting all versions from 7.0 before 18.11.13, 19.0 before 19.0.10, 19.1 before 19.1.9, 19.2 before 19.2.9, 19.3 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server due to integer overflow when compiling a specially crafted regular expression.

- [https://github.com/nh4ttruong/cve-2026-110264-poc](https://github.com/nh4ttruong/cve-2026-110264-poc) :  ![starts](https://img.shields.io/github/stars/nh4ttruong/cve-2026-110264-poc.svg) ![forks](https://img.shields.io/github/forks/nh4ttruong/cve-2026-110264-poc.svg)
- [https://github.com/xaviware/go-gitlab-cve-2026-110264-scanner](https://github.com/xaviware/go-gitlab-cve-2026-110264-scanner) :  ![starts](https://img.shields.io/github/stars/xaviware/go-gitlab-cve-2026-110264-scanner.svg) ![forks](https://img.shields.io/github/forks/xaviware/go-gitlab-cve-2026-110264-scanner.svg)
- [https://github.com/TahuCryptsi/poc-gitlab-onigmo-cve-2026-110264](https://github.com/TahuCryptsi/poc-gitlab-onigmo-cve-2026-110264) :  ![starts](https://img.shields.io/github/stars/TahuCryptsi/poc-gitlab-onigmo-cve-2026-110264.svg) ![forks](https://img.shields.io/github/forks/TahuCryptsi/poc-gitlab-onigmo-cve-2026-110264.svg)
- [https://github.com/TahuCryptsi/gitlab-onigmo-check](https://github.com/TahuCryptsi/gitlab-onigmo-check) :  ![starts](https://img.shields.io/github/stars/TahuCryptsi/gitlab-onigmo-check.svg) ![forks](https://img.shields.io/github/forks/TahuCryptsi/gitlab-onigmo-check.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/ikow/php2shell-poc](https://github.com/ikow/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/ikow/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/ikow/php2shell-poc.svg)
- [https://github.com/assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/assetnote/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/assetnote/php2shell-scanner.svg)
- [https://github.com/devploit/php2shell](https://github.com/devploit/php2shell) :  ![starts](https://img.shields.io/github/stars/devploit/php2shell.svg) ![forks](https://img.shields.io/github/forks/devploit/php2shell.svg)
- [https://github.com/Qsnh/php2shell-fixed](https://github.com/Qsnh/php2shell-fixed) :  ![starts](https://img.shields.io/github/stars/Qsnh/php2shell-fixed.svg) ![forks](https://img.shields.io/github/forks/Qsnh/php2shell-fixed.svg)
- [https://github.com/vperetti/php-cve-2026-109618-109619-backports](https://github.com/vperetti/php-cve-2026-109618-109619-backports) :  ![starts](https://img.shields.io/github/stars/vperetti/php-cve-2026-109618-109619-backports.svg) ![forks](https://img.shields.io/github/forks/vperetti/php-cve-2026-109618-109619-backports.svg)
- [https://github.com/Stonlifer/php2shell](https://github.com/Stonlifer/php2shell) :  ![starts](https://img.shields.io/github/stars/Stonlifer/php2shell.svg) ![forks](https://img.shields.io/github/forks/Stonlifer/php2shell.svg)
- [https://github.com/exception0x876/php74-el7-patched](https://github.com/exception0x876/php74-el7-patched) :  ![starts](https://img.shields.io/github/stars/exception0x876/php74-el7-patched.svg) ![forks](https://img.shields.io/github/forks/exception0x876/php74-el7-patched.svg)
- [https://github.com/getastra/php2shell-triage](https://github.com/getastra/php2shell-triage) :  ![starts](https://img.shields.io/github/stars/getastra/php2shell-triage.svg) ![forks](https://img.shields.io/github/forks/getastra/php2shell-triage.svg)
- [https://github.com/waksboy/fixed-fpm-cve-2026-109618-and-109619-images](https://github.com/waksboy/fixed-fpm-cve-2026-109618-and-109619-images) :  ![starts](https://img.shields.io/github/stars/waksboy/fixed-fpm-cve-2026-109618-and-109619-images.svg) ![forks](https://img.shields.io/github/forks/waksboy/fixed-fpm-cve-2026-109618-and-109619-images.svg)
- [https://github.com/ericmann/php2shell-ioc](https://github.com/ericmann/php2shell-ioc) :  ![starts](https://img.shields.io/github/stars/ericmann/php2shell-ioc.svg) ![forks](https://img.shields.io/github/forks/ericmann/php2shell-ioc.svg)
- [https://github.com/adityaaravind/php2shell-check](https://github.com/adityaaravind/php2shell-check) :  ![starts](https://img.shields.io/github/stars/adityaaravind/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/adityaaravind/php2shell-check.svg)
- [https://github.com/GlobalsecureAcademy/php2shell-scanner-CVE-2026-109618-CVE-2026-109619](https://github.com/GlobalsecureAcademy/php2shell-scanner-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/GlobalsecureAcademy/php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/GlobalsecureAcademy/php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/ZeroHackOrg/php2shell-poc](https://github.com/ZeroHackOrg/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/ZeroHackOrg/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/ZeroHackOrg/php2shell-poc.svg)
- [https://github.com/alham-rizvi/php2shell-scanner](https://github.com/alham-rizvi/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/alham-rizvi/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/alham-rizvi/php2shell-scanner.svg)
- [https://github.com/mirrored-projects/PHP74-Windows-CVE2026](https://github.com/mirrored-projects/PHP74-Windows-CVE2026) :  ![starts](https://img.shields.io/github/stars/mirrored-projects/PHP74-Windows-CVE2026.svg) ![forks](https://img.shields.io/github/forks/mirrored-projects/PHP74-Windows-CVE2026.svg)
- [https://github.com/ginoa79/php56-php2shell-backport](https://github.com/ginoa79/php56-php2shell-backport) :  ![starts](https://img.shields.io/github/stars/ginoa79/php56-php2shell-backport.svg) ![forks](https://img.shields.io/github/forks/ginoa79/php56-php2shell-backport.svg)
- [https://github.com/gputier/php-rfc1867-guard](https://github.com/gputier/php-rfc1867-guard) :  ![starts](https://img.shields.io/github/stars/gputier/php-rfc1867-guard.svg) ![forks](https://img.shields.io/github/forks/gputier/php-rfc1867-guard.svg)
- [https://github.com/l3tchupkt/php2shell](https://github.com/l3tchupkt/php2shell) :  ![starts](https://img.shields.io/github/stars/l3tchupkt/php2shell.svg) ![forks](https://img.shields.io/github/forks/l3tchupkt/php2shell.svg)
- [https://github.com/covertswarmlabs/PHP2Shell-Check](https://github.com/covertswarmlabs/PHP2Shell-Check) :  ![starts](https://img.shields.io/github/stars/covertswarmlabs/PHP2Shell-Check.svg) ![forks](https://img.shields.io/github/forks/covertswarmlabs/PHP2Shell-Check.svg)
- [https://github.com/zhqagp/php-7.2](https://github.com/zhqagp/php-7.2) :  ![starts](https://img.shields.io/github/stars/zhqagp/php-7.2.svg) ![forks](https://img.shields.io/github/forks/zhqagp/php-7.2.svg)
- [https://github.com/open0x01/php2shell](https://github.com/open0x01/php2shell) :  ![starts](https://img.shields.io/github/stars/open0x01/php2shell.svg) ![forks](https://img.shields.io/github/forks/open0x01/php2shell.svg)
- [https://github.com/ivanscm/php80-cve-2026-109618](https://github.com/ivanscm/php80-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/ivanscm/php80-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/ivanscm/php80-cve-2026-109618.svg)
- [https://github.com/rodrigocolozio/php2shell-check](https://github.com/rodrigocolozio/php2shell-check) :  ![starts](https://img.shields.io/github/stars/rodrigocolozio/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/rodrigocolozio/php2shell-check.svg)
- [https://github.com/Swordsec/php2shell-guard](https://github.com/Swordsec/php2shell-guard) :  ![starts](https://img.shields.io/github/stars/Swordsec/php2shell-guard.svg) ![forks](https://img.shields.io/github/forks/Swordsec/php2shell-guard.svg)
- [https://github.com/frnmrls/php70-cve-2026-backport](https://github.com/frnmrls/php70-cve-2026-backport) :  ![starts](https://img.shields.io/github/stars/frnmrls/php70-cve-2026-backport.svg) ![forks](https://img.shields.io/github/forks/frnmrls/php70-cve-2026-backport.svg)
- [https://github.com/meuhland/php-legacy-windows-builds](https://github.com/meuhland/php-legacy-windows-builds) :  ![starts](https://img.shields.io/github/stars/meuhland/php-legacy-windows-builds.svg) ![forks](https://img.shields.io/github/forks/meuhland/php-legacy-windows-builds.svg)
- [https://github.com/MakFly/php2shell-check](https://github.com/MakFly/php2shell-check) :  ![starts](https://img.shields.io/github/stars/MakFly/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/MakFly/php2shell-check.svg)
- [https://github.com/mspiq/php2shell-scanner](https://github.com/mspiq/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/mspiq/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/mspiq/php2shell-scanner.svg)
- [https://github.com/stufently/php-patched-images](https://github.com/stufently/php-patched-images) :  ![starts](https://img.shields.io/github/stars/stufently/php-patched-images.svg) ![forks](https://img.shields.io/github/forks/stufently/php-patched-images.svg)
- [https://github.com/xbuddhi/php2shell-fix](https://github.com/xbuddhi/php2shell-fix) :  ![starts](https://img.shields.io/github/stars/xbuddhi/php2shell-fix.svg) ![forks](https://img.shields.io/github/forks/xbuddhi/php2shell-fix.svg)
- [https://github.com/thegillion/uisp-php2shell-guard](https://github.com/thegillion/uisp-php2shell-guard) :  ![starts](https://img.shields.io/github/stars/thegillion/uisp-php2shell-guard.svg) ![forks](https://img.shields.io/github/forks/thegillion/uisp-php2shell-guard.svg)
- [https://github.com/pattingbabies/php2shell-CVE-2026-109618-109619](https://github.com/pattingbabies/php2shell-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/pattingbabies/php2shell-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/pattingbabies/php2shell-CVE-2026-109618-109619.svg)
- [https://github.com/KyleClouthier/php2shell-check](https://github.com/KyleClouthier/php2shell-check) :  ![starts](https://img.shields.io/github/stars/KyleClouthier/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/KyleClouthier/php2shell-check.svg)
- [https://github.com/pax-k/Php2Shell-POC](https://github.com/pax-k/Php2Shell-POC) :  ![starts](https://img.shields.io/github/stars/pax-k/Php2Shell-POC.svg) ![forks](https://img.shields.io/github/forks/pax-k/Php2Shell-POC.svg)
- [https://github.com/baimaobg/php-cve-2026-109619-lab](https://github.com/baimaobg/php-cve-2026-109619-lab) :  ![starts](https://img.shields.io/github/stars/baimaobg/php-cve-2026-109619-lab.svg) ![forks](https://img.shields.io/github/forks/baimaobg/php-cve-2026-109619-lab.svg)
- [https://github.com/SanWRoot/php2shell-LAB-POC-](https://github.com/SanWRoot/php2shell-LAB-POC-) :  ![starts](https://img.shields.io/github/stars/SanWRoot/php2shell-LAB-POC-.svg) ![forks](https://img.shields.io/github/forks/SanWRoot/php2shell-LAB-POC-.svg)
- [https://github.com/aduli198/CVE-2026-109618_CVE-2026-109619](https://github.com/aduli198/CVE-2026-109618_CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/aduli198/CVE-2026-109618_CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/aduli198/CVE-2026-109618_CVE-2026-109619.svg)
- [https://github.com/kishwordulal2005/CVE-2026-109618-and-CVE-2026-109619-Exploit](https://github.com/kishwordulal2005/CVE-2026-109618-and-CVE-2026-109619-Exploit) :  ![starts](https://img.shields.io/github/stars/kishwordulal2005/CVE-2026-109618-and-CVE-2026-109619-Exploit.svg) ![forks](https://img.shields.io/github/forks/kishwordulal2005/CVE-2026-109618-and-CVE-2026-109619-Exploit.svg)
- [https://github.com/neelsomani/benevolent-php](https://github.com/neelsomani/benevolent-php) :  ![starts](https://img.shields.io/github/stars/neelsomani/benevolent-php.svg) ![forks](https://img.shields.io/github/forks/neelsomani/benevolent-php.svg)
- [https://github.com/absholi7ly/Deep-Technical-Report-CVE-2026-109618-CVE-2026-109619-PHP2Shell](https://github.com/absholi7ly/Deep-Technical-Report-CVE-2026-109618-CVE-2026-109619-PHP2Shell) :  ![starts](https://img.shields.io/github/stars/absholi7ly/Deep-Technical-Report-CVE-2026-109618-CVE-2026-109619-PHP2Shell.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/Deep-Technical-Report-CVE-2026-109618-CVE-2026-109619-PHP2Shell.svg)
- [https://github.com/LeminEly/CVE-2026-109618-109619](https://github.com/LeminEly/CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/LeminEly/CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/LeminEly/CVE-2026-109618-109619.svg)
- [https://github.com/aledus10/PHP2Shell-Lab](https://github.com/aledus10/PHP2Shell-Lab) :  ![starts](https://img.shields.io/github/stars/aledus10/PHP2Shell-Lab.svg) ![forks](https://img.shields.io/github/forks/aledus10/PHP2Shell-Lab.svg)
- [https://github.com/mefulton/CVE-2026-109618-analysis](https://github.com/mefulton/CVE-2026-109618-analysis) :  ![starts](https://img.shields.io/github/stars/mefulton/CVE-2026-109618-analysis.svg) ![forks](https://img.shields.io/github/forks/mefulton/CVE-2026-109618-analysis.svg)
- [https://github.com/Lexsah/php2shell-detection](https://github.com/Lexsah/php2shell-detection) :  ![starts](https://img.shields.io/github/stars/Lexsah/php2shell-detection.svg) ![forks](https://img.shields.io/github/forks/Lexsah/php2shell-detection.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/assetnote/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/assetnote/php2shell-scanner.svg)
- [https://github.com/devploit/php2shell](https://github.com/devploit/php2shell) :  ![starts](https://img.shields.io/github/stars/devploit/php2shell.svg) ![forks](https://img.shields.io/github/forks/devploit/php2shell.svg)
- [https://github.com/Qsnh/php2shell-fixed](https://github.com/Qsnh/php2shell-fixed) :  ![starts](https://img.shields.io/github/stars/Qsnh/php2shell-fixed.svg) ![forks](https://img.shields.io/github/forks/Qsnh/php2shell-fixed.svg)
- [https://github.com/vperetti/php-cve-2026-109618-109619-backports](https://github.com/vperetti/php-cve-2026-109618-109619-backports) :  ![starts](https://img.shields.io/github/stars/vperetti/php-cve-2026-109618-109619-backports.svg) ![forks](https://img.shields.io/github/forks/vperetti/php-cve-2026-109618-109619-backports.svg)
- [https://github.com/aancw/php2shell-scanner](https://github.com/aancw/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/aancw/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/aancw/php2shell-scanner.svg)
- [https://github.com/JoasASantos/php2shell-exploit](https://github.com/JoasASantos/php2shell-exploit) :  ![starts](https://img.shields.io/github/stars/JoasASantos/php2shell-exploit.svg) ![forks](https://img.shields.io/github/forks/JoasASantos/php2shell-exploit.svg)
- [https://github.com/Stonlifer/php2shell](https://github.com/Stonlifer/php2shell) :  ![starts](https://img.shields.io/github/stars/Stonlifer/php2shell.svg) ![forks](https://img.shields.io/github/forks/Stonlifer/php2shell.svg)
- [https://github.com/exception0x876/php74-el7-patched](https://github.com/exception0x876/php74-el7-patched) :  ![starts](https://img.shields.io/github/stars/exception0x876/php74-el7-patched.svg) ![forks](https://img.shields.io/github/forks/exception0x876/php74-el7-patched.svg)
- [https://github.com/getastra/php2shell-triage](https://github.com/getastra/php2shell-triage) :  ![starts](https://img.shields.io/github/stars/getastra/php2shell-triage.svg) ![forks](https://img.shields.io/github/forks/getastra/php2shell-triage.svg)
- [https://github.com/waksboy/fixed-fpm-cve-2026-109618-and-109619-images](https://github.com/waksboy/fixed-fpm-cve-2026-109618-and-109619-images) :  ![starts](https://img.shields.io/github/stars/waksboy/fixed-fpm-cve-2026-109618-and-109619-images.svg) ![forks](https://img.shields.io/github/forks/waksboy/fixed-fpm-cve-2026-109618-and-109619-images.svg)
- [https://github.com/ericmann/php2shell-ioc](https://github.com/ericmann/php2shell-ioc) :  ![starts](https://img.shields.io/github/stars/ericmann/php2shell-ioc.svg) ![forks](https://img.shields.io/github/forks/ericmann/php2shell-ioc.svg)
- [https://github.com/Sol0-dev/php2shell](https://github.com/Sol0-dev/php2shell) :  ![starts](https://img.shields.io/github/stars/Sol0-dev/php2shell.svg) ![forks](https://img.shields.io/github/forks/Sol0-dev/php2shell.svg)
- [https://github.com/adityaaravind/php2shell-check](https://github.com/adityaaravind/php2shell-check) :  ![starts](https://img.shields.io/github/stars/adityaaravind/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/adityaaravind/php2shell-check.svg)
- [https://github.com/GlobalsecureAcademy/php2shell-scanner-CVE-2026-109618-CVE-2026-109619](https://github.com/GlobalsecureAcademy/php2shell-scanner-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/GlobalsecureAcademy/php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/GlobalsecureAcademy/php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/ZeroHackOrg/php2shell-poc](https://github.com/ZeroHackOrg/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/ZeroHackOrg/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/ZeroHackOrg/php2shell-poc.svg)
- [https://github.com/alham-rizvi/php2shell-scanner](https://github.com/alham-rizvi/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/alham-rizvi/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/alham-rizvi/php2shell-scanner.svg)
- [https://github.com/mirrored-projects/PHP74-Windows-CVE2026](https://github.com/mirrored-projects/PHP74-Windows-CVE2026) :  ![starts](https://img.shields.io/github/stars/mirrored-projects/PHP74-Windows-CVE2026.svg) ![forks](https://img.shields.io/github/forks/mirrored-projects/PHP74-Windows-CVE2026.svg)
- [https://github.com/Bulletdev/php2shell-poc](https://github.com/Bulletdev/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/Bulletdev/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/Bulletdev/php2shell-poc.svg)
- [https://github.com/ginoa79/php56-php2shell-backport](https://github.com/ginoa79/php56-php2shell-backport) :  ![starts](https://img.shields.io/github/stars/ginoa79/php56-php2shell-backport.svg) ![forks](https://img.shields.io/github/forks/ginoa79/php56-php2shell-backport.svg)
- [https://github.com/gputier/php-rfc1867-guard](https://github.com/gputier/php-rfc1867-guard) :  ![starts](https://img.shields.io/github/stars/gputier/php-rfc1867-guard.svg) ![forks](https://img.shields.io/github/forks/gputier/php-rfc1867-guard.svg)
- [https://github.com/l3tchupkt/php2shell](https://github.com/l3tchupkt/php2shell) :  ![starts](https://img.shields.io/github/stars/l3tchupkt/php2shell.svg) ![forks](https://img.shields.io/github/forks/l3tchupkt/php2shell.svg)
- [https://github.com/pruiz/php-CVE-2026-109618](https://github.com/pruiz/php-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/pruiz/php-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/pruiz/php-CVE-2026-109618.svg)
- [https://github.com/ivanscm/php80-cve-2026-109618](https://github.com/ivanscm/php80-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/ivanscm/php80-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/ivanscm/php80-cve-2026-109618.svg)
- [https://github.com/pattingbabies/php2shell-CVE-2026-109618-109619](https://github.com/pattingbabies/php2shell-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/pattingbabies/php2shell-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/pattingbabies/php2shell-CVE-2026-109618-109619.svg)
- [https://github.com/covertswarmlabs/PHP2Shell-Check](https://github.com/covertswarmlabs/PHP2Shell-Check) :  ![starts](https://img.shields.io/github/stars/covertswarmlabs/PHP2Shell-Check.svg) ![forks](https://img.shields.io/github/forks/covertswarmlabs/PHP2Shell-Check.svg)
- [https://github.com/zhqagp/php-7.2](https://github.com/zhqagp/php-7.2) :  ![starts](https://img.shields.io/github/stars/zhqagp/php-7.2.svg) ![forks](https://img.shields.io/github/forks/zhqagp/php-7.2.svg)
- [https://github.com/open0x01/php2shell](https://github.com/open0x01/php2shell) :  ![starts](https://img.shields.io/github/stars/open0x01/php2shell.svg) ![forks](https://img.shields.io/github/forks/open0x01/php2shell.svg)
- [https://github.com/rodrigocolozio/php2shell-check](https://github.com/rodrigocolozio/php2shell-check) :  ![starts](https://img.shields.io/github/stars/rodrigocolozio/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/rodrigocolozio/php2shell-check.svg)
- [https://github.com/Swordsec/php2shell-guard](https://github.com/Swordsec/php2shell-guard) :  ![starts](https://img.shields.io/github/stars/Swordsec/php2shell-guard.svg) ![forks](https://img.shields.io/github/forks/Swordsec/php2shell-guard.svg)
- [https://github.com/frnmrls/php70-cve-2026-backport](https://github.com/frnmrls/php70-cve-2026-backport) :  ![starts](https://img.shields.io/github/stars/frnmrls/php70-cve-2026-backport.svg) ![forks](https://img.shields.io/github/forks/frnmrls/php70-cve-2026-backport.svg)
- [https://github.com/BoheSama1999/php2shell-exp](https://github.com/BoheSama1999/php2shell-exp) :  ![starts](https://img.shields.io/github/stars/BoheSama1999/php2shell-exp.svg) ![forks](https://img.shields.io/github/forks/BoheSama1999/php2shell-exp.svg)
- [https://github.com/meuhland/php-legacy-windows-builds](https://github.com/meuhland/php-legacy-windows-builds) :  ![starts](https://img.shields.io/github/stars/meuhland/php-legacy-windows-builds.svg) ![forks](https://img.shields.io/github/forks/meuhland/php-legacy-windows-builds.svg)
- [https://github.com/MakFly/php2shell-check](https://github.com/MakFly/php2shell-check) :  ![starts](https://img.shields.io/github/stars/MakFly/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/MakFly/php2shell-check.svg)
- [https://github.com/mspiq/php2shell-scanner](https://github.com/mspiq/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/mspiq/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/mspiq/php2shell-scanner.svg)
- [https://github.com/stufently/php-patched-images](https://github.com/stufently/php-patched-images) :  ![starts](https://img.shields.io/github/stars/stufently/php-patched-images.svg) ![forks](https://img.shields.io/github/forks/stufently/php-patched-images.svg)
- [https://github.com/xbuddhi/php2shell-fix](https://github.com/xbuddhi/php2shell-fix) :  ![starts](https://img.shields.io/github/stars/xbuddhi/php2shell-fix.svg) ![forks](https://img.shields.io/github/forks/xbuddhi/php2shell-fix.svg)
- [https://github.com/viniciusbossle/php74-el7-php2shell](https://github.com/viniciusbossle/php74-el7-php2shell) :  ![starts](https://img.shields.io/github/stars/viniciusbossle/php74-el7-php2shell.svg) ![forks](https://img.shields.io/github/forks/viniciusbossle/php74-el7-php2shell.svg)
- [https://github.com/thegillion/uisp-php2shell-guard](https://github.com/thegillion/uisp-php2shell-guard) :  ![starts](https://img.shields.io/github/stars/thegillion/uisp-php2shell-guard.svg) ![forks](https://img.shields.io/github/forks/thegillion/uisp-php2shell-guard.svg)


## CVE-2026-109255
 FreeRDP 3.0.0 before 3.32.0 contains an integer truncation vulnerability in license_check_stream_length that allows a malicious RDP server to trigger a heap buffer overflow on 32-bit clients. Attackers can send a crafted SERVER_LICENSE_REQUEST with a large scopeCount that bypasses length checks, causing out-of-bounds writes leading to denial of service or remote code execution.

- [https://github.com/D7EAD/CVE-2026-109255](https://github.com/D7EAD/CVE-2026-109255) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-109255.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-109255.svg)


## CVE-2026-107079
 An issue in Systrome Validation & Certification 1.0 allows an attacker to cause a denial of service via the t URL parameter in the qrcode_auth.html component

- [https://github.com/Nishi-Mehta-18/CVE-2026-107079](https://github.com/Nishi-Mehta-18/CVE-2026-107079) :  ![starts](https://img.shields.io/github/stars/Nishi-Mehta-18/CVE-2026-107079.svg) ![forks](https://img.shields.io/github/forks/Nishi-Mehta-18/CVE-2026-107079.svg)


## CVE-2026-106173
 A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiSIEM 7.5.0 may allow attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/tc4dy/CVE-2026-106173-PoC-Exploit](https://github.com/tc4dy/CVE-2026-106173-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-106173-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-106173-PoC-Exploit.svg)


## CVE-2026-104935
 Authentication bypass by spoofing in ICS before version 25.1.3.0 allows a remote unauthenticated attacker to execute arbitrary commands. This does not impact ICS version 22.7R2.14 or prior.

- [https://github.com/maxprog-svg/CVE-2026-104935](https://github.com/maxprog-svg/CVE-2026-104935) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-104935.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-104935.svg)
- [https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-ivanti-ics-guard](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-ivanti-ics-guard) :  ![starts](https://img.shields.io/github/stars/Bluefire-Redteam-Cybersecurity/bluefire-ivanti-ics-guard.svg) ![forks](https://img.shields.io/github/forks/Bluefire-Redteam-Cybersecurity/bluefire-ivanti-ics-guard.svg)


## CVE-2026-104068
 JetBackup plugin for WordPress before 3.1.24.10 contains a symlink-based arbitrary file write vulnerability that allows an authenticated WordPress administrator to write attacker-controlled file contents outside the intended restore destination during backup import and restore. Attackers can craft a backup archive containing a symbolic link that archive extraction follows without validating targets or enforcing destination containment, potentially leading to server-side code execution depending on the writable destination and server configuration.

- [https://github.com/sarvarr1/jetbackup-cve](https://github.com/sarvarr1/jetbackup-cve) :  ![starts](https://img.shields.io/github/stars/sarvarr1/jetbackup-cve.svg) ![forks](https://img.shields.io/github/forks/sarvarr1/jetbackup-cve.svg)


## CVE-2026-102785
 Joomla Extension - yootheme.com - Unauthenticated remote code execution in YOOtheme Pro 5.0.0-5.0.52 - YOOtheme Pro’s publicly accessible image transformation handler incompletely binds normalized image operations and the output destination to its request signature. An unauthenticated remote attacker can reuse a signature disclosed in a legitimate public image URL, inject additional image operations, traverse out of the intended cache directory, and write an attacker-controlled PNG/PHP polyglot to an executable public media directory.

- [https://github.com/BIBILZERODAY/CVE-2026-102785---YooTheme-Mass-Exploit-Webshell.Store-](https://github.com/BIBILZERODAY/CVE-2026-102785---YooTheme-Mass-Exploit-Webshell.Store-) :  ![starts](https://img.shields.io/github/stars/BIBILZERODAY/CVE-2026-102785---YooTheme-Mass-Exploit-Webshell.Store-.svg) ![forks](https://img.shields.io/github/forks/BIBILZERODAY/CVE-2026-102785---YooTheme-Mass-Exploit-Webshell.Store-.svg)


## CVE-2026-97206
 NLnet Labs Unbound, 1.22.0 up to and including version 1.26.1, contains a DNS-over-QUIC (DoQ) lifetime bug reachable by a remote DoQ client under multi-threaded operation. A client-triggered QUIC path migration can enter stream/connection cleanup while a mesh reply still retains a pointer to the DoQ stream. Cleanup frees the DoQ stream and when the pending mesh reply later completes it dereferences a stale pointer leading to a crash.

- [https://github.com/suominen/CVE-2026-97206](https://github.com/suominen/CVE-2026-97206) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-97206.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-97206.svg)


## CVE-2026-96652
 Plex Media Server before 1.43.3.10861 allows SSRF via '/player/timeline'. An attacker using any X-Plex-Token value can include a full URL in the 'protocol' parameter and force the Plex server to POST to the attacker's chosen destination.

- [https://github.com/basesixtythree/B63-POC-CVE-2026-96652](https://github.com/basesixtythree/B63-POC-CVE-2026-96652) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-96652.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-96652.svg)


## CVE-2026-94000
 A flaw was found in the Admin REST API of Keycloak, an open-source identity and access management solution. The issue occurs in the group-membership endpoints where the system fails to check if a group grants administrative privileges before allowing a user to be added. This allows a delegated administrator with limited permissions to add themselves to a high-privilege group, potentially gaining full control over the entire realm.

- [https://github.com/SecFathy/KeycloakESC](https://github.com/SecFathy/KeycloakESC) :  ![starts](https://img.shields.io/github/stars/SecFathy/KeycloakESC.svg) ![forks](https://img.shields.io/github/forks/SecFathy/KeycloakESC.svg)


## CVE-2026-93687
 braces through 3.0.3 contains a stack overflow vulnerability in the recursive AST walkers that lack depth guards. Attackers can supply deeply nested brace patterns under the character limit to exhaust the call stack and terminate the Node.js process with an uncaught RangeError.

- [https://github.com/canmenzo/cve-2026-93687-braces](https://github.com/canmenzo/cve-2026-93687-braces) :  ![starts](https://img.shields.io/github/stars/canmenzo/cve-2026-93687-braces.svg) ![forks](https://img.shields.io/github/forks/canmenzo/cve-2026-93687-braces.svg)


## CVE-2026-91403
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 8u511, 8u511-perf, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1; Oracle GraalVM for JDK: 17.0.21 and  21.0.13; Oracle GraalVM Enterprise Edition: 21.3.20. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 9.1 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).

- [https://github.com/Carl0gonzalez/java-security-update](https://github.com/Carl0gonzalez/java-security-update) :  ![starts](https://img.shields.io/github/stars/Carl0gonzalez/java-security-update.svg) ![forks](https://img.shields.io/github/forks/Carl0gonzalez/java-security-update.svg)
- [https://github.com/andersundsehr/ca-trust-audit](https://github.com/andersundsehr/ca-trust-audit) :  ![starts](https://img.shields.io/github/stars/andersundsehr/ca-trust-audit.svg) ![forks](https://img.shields.io/github/forks/andersundsehr/ca-trust-audit.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/ceterion/netscaler-quickcheck](https://github.com/ceterion/netscaler-quickcheck) :  ![starts](https://img.shields.io/github/stars/ceterion/netscaler-quickcheck.svg) ![forks](https://img.shields.io/github/forks/ceterion/netscaler-quickcheck.svg)


## CVE-2026-86478
2026.1.14042 improper authentication in YouTrack Helpdesk allowed unauthenticated account takeover via a self-asserted email address

- [https://github.com/LHeiakim/CVE-2026-86478-PoC](https://github.com/LHeiakim/CVE-2026-86478-PoC) :  ![starts](https://img.shields.io/github/stars/LHeiakim/CVE-2026-86478-PoC.svg) ![forks](https://img.shields.io/github/forks/LHeiakim/CVE-2026-86478-PoC.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/ChaYeWuu/violin-CVE-2026-64560-OS4.0](https://github.com/ChaYeWuu/violin-CVE-2026-64560-OS4.0) :  ![starts](https://img.shields.io/github/stars/ChaYeWuu/violin-CVE-2026-64560-OS4.0.svg) ![forks](https://img.shields.io/github/forks/ChaYeWuu/violin-CVE-2026-64560-OS4.0.svg)


## CVE-2026-63077
 In JetBrains TeamCity before 2026.1.3, 2025.11.7 unauthenticated remote code execution was possible via the agent polling protocol

- [https://github.com/basesixtythree/B63-POC-CVE-2026-63077](https://github.com/basesixtythree/B63-POC-CVE-2026-63077) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-63077.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-63077.svg)


## CVE-2026-51954
 An issue in Webasyst Framework 4.0.3 and before allows a remote attacker to execute arbitrary code via a crafted OAuth authorization URL with an arbitrary redirect_uri.

- [https://github.com/Envincion/CVE-2026-51954](https://github.com/Envincion/CVE-2026-51954) :  ![starts](https://img.shields.io/github/stars/Envincion/CVE-2026-51954.svg) ![forks](https://img.shields.io/github/forks/Envincion/CVE-2026-51954.svg)
- [https://github.com/envincion1991-cmyk/CVE-2026-51954](https://github.com/envincion1991-cmyk/CVE-2026-51954) :  ![starts](https://img.shields.io/github/stars/envincion1991-cmyk/CVE-2026-51954.svg) ![forks](https://img.shields.io/github/forks/envincion1991-cmyk/CVE-2026-51954.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/zxsos/root-my-s23](https://github.com/zxsos/root-my-s23) :  ![starts](https://img.shields.io/github/stars/zxsos/root-my-s23.svg) ![forks](https://img.shields.io/github/forks/zxsos/root-my-s23.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/ziachi/DirtyFrag](https://github.com/ziachi/DirtyFrag) :  ![starts](https://img.shields.io/github/stars/ziachi/DirtyFrag.svg) ![forks](https://img.shields.io/github/forks/ziachi/DirtyFrag.svg)


## CVE-2026-27739
 The Angular SSR is a server-rise rendering tool for Angular applications. Versions prior to 21.2.0-rc.1, 21.1.5, 20.3.17, and 19.2.21 have a Server-Side Request Forgery (SSRF) vulnerability in the Angular SSR request handling pipeline. The vulnerability exists because Angular’s internal URL reconstruction logic directly trusts and consumes user-controlled HTTP headers specifically the Host and `X-Forwarded-*` family to determine the application's base origin without any validation of the destination domain. Specifically, the framework didn't have checks for the host domain, path and character sanitization, and port validation. This vulnerability manifests in two primary ways: implicit relative URL resolution and explicit manual construction. When successfully exploited, this vulnerability allows for arbitrary internal request steering. This can lead to credential exfiltration, internal network probing, and a confidentiality breach. In order to be vulnerable, the victim application must use Angular SSR (Server-Side Rendering), the application must perform `HttpClient` requests using relative URLs OR manually construct URLs using the unvalidated `Host` / `X-Forwarded-*` headers using the `REQUEST` object, the application server must be reachable by an attacker who can influence these headers without strict validation from a front-facing proxy, and the infrastructure (Cloud, CDN, or Load Balancer) must not sanitize or validate incoming headers. Versions 21.2.0-rc.1, 21.1.5, 20.3.17, and 19.2.21 contain a patch. Some workarounds are available. Avoid using `req.headers` for URL construction. Instead, use trusted variables for base API paths. Those who cannot upgrade immediately should implement a middleware in their `server.ts` to enforce numeric ports and validated hostnames.

- [https://github.com/Mr-Red-007/CVE-2026-27739-POC](https://github.com/Mr-Red-007/CVE-2026-27739-POC) :  ![starts](https://img.shields.io/github/stars/Mr-Red-007/CVE-2026-27739-POC.svg) ![forks](https://img.shields.io/github/forks/Mr-Red-007/CVE-2026-27739-POC.svg)


## CVE-2026-12523
Credits: Disclosed responsibly by Sébastien Féry

- [https://github.com/HORKimhab/CVE-2025-64702-more](https://github.com/HORKimhab/CVE-2025-64702-more) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2025-64702-more.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2025-64702-more.svg)


## CVE-2026-12080
 A flaw was found in the QEMU Guest Agent (qga). A local unprivileged user can exploit a vulnerability in the guest-ssh-add-authorized-keys command handler by manipulating symbolic links. This can occur either through a deterministic directory-symlink bypass or a Time-of-Check to Time-of-Use (TOCTOU) file-symlink race. Successful exploitation allows the attacker to gain ownership of arbitrary root-owned files or directories, leading to root access. This vulnerability requires an external management layer (e.g., libvirt) to trigger the affected code path.

- [https://github.com/M8seven/cve-2026-12080-qemu-guest-agent-authorized-keys](https://github.com/M8seven/cve-2026-12080-qemu-guest-agent-authorized-keys) :  ![starts](https://img.shields.io/github/stars/M8seven/cve-2026-12080-qemu-guest-agent-authorized-keys.svg) ![forks](https://img.shields.io/github/forks/M8seven/cve-2026-12080-qemu-guest-agent-authorized-keys.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/eagle1maledetto/php5.6-wheezy-cve-2026-109618](https://github.com/eagle1maledetto/php5.6-wheezy-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/eagle1maledetto/php5.6-wheezy-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/eagle1maledetto/php5.6-wheezy-cve-2026-109618.svg)
- [https://github.com/mejustbox-byte/CVE-2026-109618-CVE-2026-109619](https://github.com/mejustbox-byte/CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/mejustbox-byte/CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/mejustbox-byte/CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/squiblyza/CVE-2026-109618-CVE-2026-109619](https://github.com/squiblyza/CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/squiblyza/CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/squiblyza/CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/AvaterXXX/CVE-2026-109618-CVE-2026-109619-](https://github.com/AvaterXXX/CVE-2026-109618-CVE-2026-109619-) :  ![starts](https://img.shields.io/github/stars/AvaterXXX/CVE-2026-109618-CVE-2026-109619-.svg) ![forks](https://img.shields.io/github/forks/AvaterXXX/CVE-2026-109618-CVE-2026-109619-.svg)
- [https://github.com/baron-stybd/CVE-2026-109618-CVE-2026-109619](https://github.com/baron-stybd/CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/baron-stybd/CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/baron-stybd/CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/seguridadentrerios/CVE-2026-109618-CVE-2026-109619](https://github.com/seguridadentrerios/CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/seguridadentrerios/CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/seguridadentrerios/CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/daffa001/php-CVE-2026-109618-CVE-2026-109619](https://github.com/daffa001/php-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/daffa001/php-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/daffa001/php-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/LeonelArrua/CVE-2026-109618_CVE-2026-109619_Mitigate](https://github.com/LeonelArrua/CVE-2026-109618_CVE-2026-109619_Mitigate) :  ![starts](https://img.shields.io/github/stars/LeonelArrua/CVE-2026-109618_CVE-2026-109619_Mitigate.svg) ![forks](https://img.shields.io/github/forks/LeonelArrua/CVE-2026-109618_CVE-2026-109619_Mitigate.svg)
- [https://github.com/fardinbarashi/PHP-CVE-2026-109618-and-CVE-2026-109619](https://github.com/fardinbarashi/PHP-CVE-2026-109618-and-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/fardinbarashi/PHP-CVE-2026-109618-and-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/fardinbarashi/PHP-CVE-2026-109618-and-CVE-2026-109619.svg)
- [https://github.com/Certbn/PHP2Shell-CVE-2026-109618-CVE-2026-109619-](https://github.com/Certbn/PHP2Shell-CVE-2026-109618-CVE-2026-109619-) :  ![starts](https://img.shields.io/github/stars/Certbn/PHP2Shell-CVE-2026-109618-CVE-2026-109619-.svg) ![forks](https://img.shields.io/github/forks/Certbn/PHP2Shell-CVE-2026-109618-CVE-2026-109619-.svg)
- [https://github.com/maxprog-svg/PHP2Shell-CVE-2026-109618-CVE-2026-109619](https://github.com/maxprog-svg/PHP2Shell-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/CYB3RW07F/PHP2Shell-CVE-2026-109618-CVE-2026-109619](https://github.com/CYB3RW07F/PHP2Shell-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/CYB3RW07F/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/CYB3RW07F/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/g41277460-cpu/CVE-2026-109618-CVE-2026-109619-php2shell-](https://github.com/g41277460-cpu/CVE-2026-109618-CVE-2026-109619-php2shell-) :  ![starts](https://img.shields.io/github/stars/g41277460-cpu/CVE-2026-109618-CVE-2026-109619-php2shell-.svg) ![forks](https://img.shields.io/github/forks/g41277460-cpu/CVE-2026-109618-CVE-2026-109619-php2shell-.svg)
- [https://github.com/cj667113/OCI-Ansible-Fix-CVE-2026-109618_CVE-2026-109619](https://github.com/cj667113/OCI-Ansible-Fix-CVE-2026-109618_CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/cj667113/OCI-Ansible-Fix-CVE-2026-109618_CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/cj667113/OCI-Ansible-Fix-CVE-2026-109618_CVE-2026-109619.svg)
- [https://github.com/haobachang-1/php2shell-CVE-2026-109618-CVE-2026-109619](https://github.com/haobachang-1/php2shell-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/haobachang-1/php2shell-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/haobachang-1/php2shell-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/swap18plus/php2shell_CVE-2026-109618-and-CVE-2026-109619](https://github.com/swap18plus/php2shell_CVE-2026-109618-and-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/swap18plus/php2shell_CVE-2026-109618-and-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/swap18plus/php2shell_CVE-2026-109618-and-CVE-2026-109619.svg)
- [https://github.com/BIBILZERODAY/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mass-Exploit](https://github.com/BIBILZERODAY/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mass-Exploit) :  ![starts](https://img.shields.io/github/stars/BIBILZERODAY/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mass-Exploit.svg) ![forks](https://img.shields.io/github/forks/BIBILZERODAY/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mass-Exploit.svg)
- [https://github.com/shivabalaj/CVE-2026-109618](https://github.com/shivabalaj/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/shivabalaj/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/shivabalaj/CVE-2026-109618.svg)
- [https://github.com/0xBlackash/CVE-2026-109618](https://github.com/0xBlackash/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-109618.svg)
- [https://github.com/TheMursalin/CVE-2026-109618](https://github.com/TheMursalin/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/TheMursalin/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/TheMursalin/CVE-2026-109618.svg)
- [https://github.com/syrex1013/CVE-2026-109618](https://github.com/syrex1013/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/syrex1013/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/syrex1013/CVE-2026-109618.svg)
- [https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619](https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/debugactiveprocess/CVE-2026-109618](https://github.com/debugactiveprocess/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/debugactiveprocess/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/debugactiveprocess/CVE-2026-109618.svg)
- [https://github.com/WallcroftUK/CVE-2026-109619](https://github.com/WallcroftUK/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/WallcroftUK/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/WallcroftUK/CVE-2026-109619.svg)
- [https://github.com/anldori/CVE-2026-109618](https://github.com/anldori/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/anldori/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/anldori/CVE-2026-109618.svg)
- [https://github.com/santihabib/CVE-2026-109619](https://github.com/santihabib/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/santihabib/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/santihabib/CVE-2026-109619.svg)
- [https://github.com/zhaoboy9692/CVE-2026-109618](https://github.com/zhaoboy9692/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/zhaoboy9692/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/zhaoboy9692/CVE-2026-109618.svg)
- [https://github.com/1Nightlovel/CVE-2026-109619](https://github.com/1Nightlovel/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/1Nightlovel/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/1Nightlovel/CVE-2026-109619.svg)
- [https://github.com/cozybear-dev/cve-2026-109618](https://github.com/cozybear-dev/cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/cozybear-dev/cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cozybear-dev/cve-2026-109618.svg)
- [https://github.com/xvanpan/CVE-2026-109619](https://github.com/xvanpan/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xvanpan/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xvanpan/CVE-2026-109619.svg)
- [https://github.com/syrex1013/CVE-2026-109619](https://github.com/syrex1013/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/syrex1013/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/syrex1013/CVE-2026-109619.svg)
- [https://github.com/alvaroguzmancode/CVE-2026-109618](https://github.com/alvaroguzmancode/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/alvaroguzmancode/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/alvaroguzmancode/CVE-2026-109618.svg)
- [https://github.com/Marciano-Morinigo/php2shell-CVE-2026-109618-CVE-2026-109619-PoC-Lab](https://github.com/Marciano-Morinigo/php2shell-CVE-2026-109618-CVE-2026-109619-PoC-Lab) :  ![starts](https://img.shields.io/github/stars/Marciano-Morinigo/php2shell-CVE-2026-109618-CVE-2026-109619-PoC-Lab.svg) ![forks](https://img.shields.io/github/forks/Marciano-Morinigo/php2shell-CVE-2026-109618-CVE-2026-109619-PoC-Lab.svg)
- [https://github.com/RuanSerraAzul/CVE-2026-109618-POC](https://github.com/RuanSerraAzul/CVE-2026-109618-POC) :  ![starts](https://img.shields.io/github/stars/RuanSerraAzul/CVE-2026-109618-POC.svg) ![forks](https://img.shields.io/github/forks/RuanSerraAzul/CVE-2026-109618-POC.svg)
- [https://github.com/HORKimhab/CVE-2026-109618-619](https://github.com/HORKimhab/CVE-2026-109618-619) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-109618-619.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-109618-619.svg)
- [https://github.com/RuanSerraAzul/CVE-2026-109619-POC](https://github.com/RuanSerraAzul/CVE-2026-109619-POC) :  ![starts](https://img.shields.io/github/stars/RuanSerraAzul/CVE-2026-109619-POC.svg) ![forks](https://img.shields.io/github/forks/RuanSerraAzul/CVE-2026-109619-POC.svg)
- [https://github.com/0k1dok1/CVE-2026-109618-CHECK](https://github.com/0k1dok1/CVE-2026-109618-CHECK) :  ![starts](https://img.shields.io/github/stars/0k1dok1/CVE-2026-109618-CHECK.svg) ![forks](https://img.shields.io/github/forks/0k1dok1/CVE-2026-109618-CHECK.svg)
- [https://github.com/EkaterinaMarchetti/Non-intrusive-PHP2Shell-assessment-for-CVE-2026-109618-and-CVE-2026-109619](https://github.com/EkaterinaMarchetti/Non-intrusive-PHP2Shell-assessment-for-CVE-2026-109618-and-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/EkaterinaMarchetti/Non-intrusive-PHP2Shell-assessment-for-CVE-2026-109618-and-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/EkaterinaMarchetti/Non-intrusive-PHP2Shell-assessment-for-CVE-2026-109618-and-CVE-2026-109619.svg)
- [https://github.com/vitalelele/CVE-2026-109618-PoC](https://github.com/vitalelele/CVE-2026-109618-PoC) :  ![starts](https://img.shields.io/github/stars/vitalelele/CVE-2026-109618-PoC.svg) ![forks](https://img.shields.io/github/forks/vitalelele/CVE-2026-109618-PoC.svg)
- [https://github.com/fmdiscioglu/php-cve-2026-109619-checker](https://github.com/fmdiscioglu/php-cve-2026-109619-checker) :  ![starts](https://img.shields.io/github/stars/fmdiscioglu/php-cve-2026-109619-checker.svg) ![forks](https://img.shields.io/github/forks/fmdiscioglu/php-cve-2026-109619-checker.svg)
- [https://github.com/nukIeer/CVE-2026-109618-109619-checker](https://github.com/nukIeer/CVE-2026-109618-109619-checker) :  ![starts](https://img.shields.io/github/stars/nukIeer/CVE-2026-109618-109619-checker.svg) ![forks](https://img.shields.io/github/forks/nukIeer/CVE-2026-109618-109619-checker.svg)
- [https://github.com/mrmtwoj/php-cve-2026-109618-fixer](https://github.com/mrmtwoj/php-cve-2026-109618-fixer) :  ![starts](https://img.shields.io/github/stars/mrmtwoj/php-cve-2026-109618-fixer.svg) ![forks](https://img.shields.io/github/forks/mrmtwoj/php-cve-2026-109618-fixer.svg)
- [https://github.com/mbadis-dev/php-cve-2026-109618-toolkit](https://github.com/mbadis-dev/php-cve-2026-109618-toolkit) :  ![starts](https://img.shields.io/github/stars/mbadis-dev/php-cve-2026-109618-toolkit.svg) ![forks](https://img.shields.io/github/forks/mbadis-dev/php-cve-2026-109618-toolkit.svg)
- [https://github.com/cred0core/Sigma-rule-CVE-2026-109618](https://github.com/cred0core/Sigma-rule-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/cred0core/Sigma-rule-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cred0core/Sigma-rule-CVE-2026-109618.svg)
- [https://github.com/waksboy/php-cve-2026-109618-109619-tester](https://github.com/waksboy/php-cve-2026-109618-109619-tester) :  ![starts](https://img.shields.io/github/stars/waksboy/php-cve-2026-109618-109619-tester.svg) ![forks](https://img.shields.io/github/forks/waksboy/php-cve-2026-109618-109619-tester.svg)
- [https://github.com/FarhadHosen101/PHP2Shell-CVE-2026-109619](https://github.com/FarhadHosen101/PHP2Shell-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/FarhadHosen101/PHP2Shell-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/FarhadHosen101/PHP2Shell-CVE-2026-109619.svg)
- [https://github.com/leonlai-tw/php-eol-cve-2026-109618-109619](https://github.com/leonlai-tw/php-eol-cve-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/leonlai-tw/php-eol-cve-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/leonlai-tw/php-eol-cve-2026-109618-109619.svg)


## CVE-2026-10699
This issue affects MOVEit Transfer: from 2025.0.0 before 2025.0.8, from 2025.1.0 before 2025.1.4, from 2026.0.0 before 2026.0.1.

- [https://github.com/MX-Qulin/CVE-2026-106991](https://github.com/MX-Qulin/CVE-2026-106991) :  ![starts](https://img.shields.io/github/stars/MX-Qulin/CVE-2026-106991.svg) ![forks](https://img.shields.io/github/forks/MX-Qulin/CVE-2026-106991.svg)


## CVE-2026-6235
 The Sendmachine for WordPress plugin for WordPress is vulnerable to authorization bypass via the 'manage_admin_requests' function in all versions up to, and including, 1.0.20. This is due to the plugin not properly verifying that a user is authorized to perform an action. This makes it possible for unauthenticated attackers to overwrite the plugin's SMTP configuration, which can be leveraged to intercept all outbound emails from the site (including password reset emails).

- [https://github.com/zsy-arch/CVE-2026-62356-POC](https://github.com/zsy-arch/CVE-2026-62356-POC) :  ![starts](https://img.shields.io/github/stars/zsy-arch/CVE-2026-62356-POC.svg) ![forks](https://img.shields.io/github/forks/zsy-arch/CVE-2026-62356-POC.svg)


## CVE-2026-5784
This issue affects DivvyDrive: from 4.8.2.9 before 4.8.3.2.

- [https://github.com/SaiTeja-Erukude/CVE-2026-57845-hf-datasets-rce](https://github.com/SaiTeja-Erukude/CVE-2026-57845-hf-datasets-rce) :  ![starts](https://img.shields.io/github/stars/SaiTeja-Erukude/CVE-2026-57845-hf-datasets-rce.svg) ![forks](https://img.shields.io/github/forks/SaiTeja-Erukude/CVE-2026-57845-hf-datasets-rce.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/1o-ya/php-cve-2026-109618-hotfix-guide](https://github.com/1o-ya/php-cve-2026-109618-hotfix-guide) :  ![starts](https://img.shields.io/github/stars/1o-ya/php-cve-2026-109618-hotfix-guide.svg) ![forks](https://img.shields.io/github/forks/1o-ya/php-cve-2026-109618-hotfix-guide.svg)
- [https://github.com/jsrobinson3/php74-focal-cve-2026-109618](https://github.com/jsrobinson3/php74-focal-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/jsrobinson3/php74-focal-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/jsrobinson3/php74-focal-cve-2026-109618.svg)


## CVE-2025-64702
 quic-go is an implementation of the QUIC protocol in Go. Versions 0.56.0 and below are vulnerable to excessive memory allocation through quic-go's HTTP/3 client and server implementations by sending a QPACK-encoded HEADERS frame that decodes into a large header field section (many unique header names and/or large values). The implementation builds an http.Header (used on the http.Request and http.Response, respectively), while only enforcing limits on the size of the (QPACK-compressed) HEADERS frame, but not on the decoded header, leading to memory exhaustion. This issue is fixed in version 0.57.0.

- [https://github.com/HORKimhab/CVE-2025-64702-more](https://github.com/HORKimhab/CVE-2025-64702-more) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2025-64702-more.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2025-64702-more.svg)


## CVE-2025-54309
 CrushFTP 10 before 10.8.5 and 11 before 11.3.4_23, when the DMZ proxy feature is not used, mishandles AS2 validation and consequently allows remote attackers to obtain admin access via HTTPS, as exploited in the wild in July 2025.

- [https://github.com/Goodworkid0/CrushFTP-AS2-Bypass-Research-CVE-2025-54309](https://github.com/Goodworkid0/CrushFTP-AS2-Bypass-Research-CVE-2025-54309) :  ![starts](https://img.shields.io/github/stars/Goodworkid0/CrushFTP-AS2-Bypass-Research-CVE-2025-54309.svg) ![forks](https://img.shields.io/github/forks/Goodworkid0/CrushFTP-AS2-Bypass-Research-CVE-2025-54309.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/mcpmark-eval-liuhezi/cve-2025-29927-audit](https://github.com/mcpmark-eval-liuhezi/cve-2025-29927-audit) :  ![starts](https://img.shields.io/github/stars/mcpmark-eval-liuhezi/cve-2025-29927-audit.svg) ![forks](https://img.shields.io/github/forks/mcpmark-eval-liuhezi/cve-2025-29927-audit.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/SAIM28826/TEST](https://github.com/SAIM28826/TEST) :  ![starts](https://img.shields.io/github/stars/SAIM28826/TEST.svg) ![forks](https://img.shields.io/github/forks/SAIM28826/TEST.svg)
- [https://github.com/SAIM28826/CVE-2025-14847-poc](https://github.com/SAIM28826/CVE-2025-14847-poc) :  ![starts](https://img.shields.io/github/stars/SAIM28826/CVE-2025-14847-poc.svg) ![forks](https://img.shields.io/github/forks/SAIM28826/CVE-2025-14847-poc.svg)


## CVE-2025-13945
 HTTP3 dissector crash in Wireshark 4.6.0 and 4.6.1 allows denial of service

- [https://github.com/HORKimhab/CVE-2025-64702-more](https://github.com/HORKimhab/CVE-2025-64702-more) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2025-64702-more.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2025-64702-more.svg)


## CVE-2025-9974
 The unified WEBUI application of the ONT/Beacon device contains an input handling flaw that allows authenticated users to trigger unintended system-level command execution. Due to insufficient validation of user-supplied data, a low-privileged authenticated attacker may be able to execute arbitrary commands on the underlying ONT/Beacon operating system, potentially impacting the confidentiality, integrity, and availability of the device.

- [https://github.com/Rajdave69/CVE-2025-9974](https://github.com/Rajdave69/CVE-2025-9974) :  ![starts](https://img.shields.io/github/stars/Rajdave69/CVE-2025-9974.svg) ![forks](https://img.shields.io/github/forks/Rajdave69/CVE-2025-9974.svg)


## CVE-2025-4275
 A vulnerability in the digital signature verification process does not properly validate variable attributes which allows an attacker to bypass signature verification by creating a non-authenticated NVRAM variable. An attacker may to execute arbitrary signed UEFI code and bypass Secure Boot.

- [https://github.com/Dorlander/hydrophobia-scanner](https://github.com/Dorlander/hydrophobia-scanner) :  ![starts](https://img.shields.io/github/stars/Dorlander/hydrophobia-scanner.svg) ![forks](https://img.shields.io/github/forks/Dorlander/hydrophobia-scanner.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/hujiaozhuzhu/CVE-2025-29927__Next.js](https://github.com/hujiaozhuzhu/CVE-2025-29927__Next.js) :  ![starts](https://img.shields.io/github/stars/hujiaozhuzhu/CVE-2025-29927__Next.js.svg) ![forks](https://img.shields.io/github/forks/hujiaozhuzhu/CVE-2025-29927__Next.js.svg)


## CVE-2024-43093
 In shouldHideDocument of ExternalStorageProvider.java, there is a possible bypass of a file path filter designed to prevent access to sensitive directories due to  incorrect unicode normalization. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.

- [https://github.com/xiaoxiaoyu78/gki-unicode-fix](https://github.com/xiaoxiaoyu78/gki-unicode-fix) :  ![starts](https://img.shields.io/github/stars/xiaoxiaoyu78/gki-unicode-fix.svg) ![forks](https://img.shields.io/github/forks/xiaoxiaoyu78/gki-unicode-fix.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/basesixtythree/B63-POC-CVE-2024-36401](https://github.com/basesixtythree/B63-POC-CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2024-36401.svg)


## CVE-2024-30084
 Windows Kernel-Mode Driver Elevation of Privilege Vulnerability

- [https://github.com/m01000xd/CVE-2024-30084](https://github.com/m01000xd/CVE-2024-30084) :  ![starts](https://img.shields.io/github/stars/m01000xd/CVE-2024-30084.svg) ![forks](https://img.shields.io/github/forks/m01000xd/CVE-2024-30084.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/DitohartoPramudya/CVE-2024-24919](https://github.com/DitohartoPramudya/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/DitohartoPramudya/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/DitohartoPramudya/CVE-2024-24919.svg)


## CVE-2023-46604
which fixes this issue.

- [https://github.com/basesixtythree/B63-POC-CVE-2023-46604](https://github.com/basesixtythree/B63-POC-CVE-2023-46604) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2023-46604.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2023-46604.svg)


## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/Conviee/Assignment-](https://github.com/Conviee/Assignment-) :  ![starts](https://img.shields.io/github/stars/Conviee/Assignment-.svg) ![forks](https://img.shields.io/github/forks/Conviee/Assignment-.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/tr3m0x/CVE-2021-41773](https://github.com/tr3m0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/tr3m0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/tr3m0x/CVE-2021-41773.svg)
- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)


## CVE-2020-8203
 Prototype pollution attack when using _.zipObjectDeep in lodash before 4.17.20.

- [https://github.com/mcpmark-eval-liuhezi/audit-cve-2020-8203](https://github.com/mcpmark-eval-liuhezi/audit-cve-2020-8203) :  ![starts](https://img.shields.io/github/stars/mcpmark-eval-liuhezi/audit-cve-2020-8203.svg) ![forks](https://img.shields.io/github/forks/mcpmark-eval-liuhezi/audit-cve-2020-8203.svg)


## CVE-2019-0205
 In Apache Thrift all versions up to and including 0.12.0, a server or client may run into an endless loop when feed with specific input data. Because the issue had already been partially fixed in version 0.11.0, depending on the installed version it affects only certain language bindings.

- [https://github.com/cgarrot/echo-dot-3-doebrite-research](https://github.com/cgarrot/echo-dot-3-doebrite-research) :  ![starts](https://img.shields.io/github/stars/cgarrot/echo-dot-3-doebrite-research.svg) ![forks](https://img.shields.io/github/forks/cgarrot/echo-dot-3-doebrite-research.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/Alexnpc18/Drupalgeddon2-python](https://github.com/Alexnpc18/Drupalgeddon2-python) :  ![starts](https://img.shields.io/github/stars/Alexnpc18/Drupalgeddon2-python.svg) ![forks](https://img.shields.io/github/forks/Alexnpc18/Drupalgeddon2-python.svg)

