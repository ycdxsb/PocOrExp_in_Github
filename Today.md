# Update 2026-10-23
## CVE-2026-111943
 On most platforms, Go uses the given system root certificates. However, in some narrower cases, the system trust stores may not be updated without further action. To defend against the narrower set of cases that may remain affected, a denylist was added in crypto/x509 to return an error when calling Verify with any of the known intermediate certificates that are no longer considered to be trustworthy.

- [https://github.com/phpc0de/CVE-2026-111943-Remediator](https://github.com/phpc0de/CVE-2026-111943-Remediator) :  ![starts](https://img.shields.io/github/stars/phpc0de/CVE-2026-111943-Remediator.svg) ![forks](https://img.shields.io/github/forks/phpc0de/CVE-2026-111943-Remediator.svg)
- [https://github.com/abhishek-bhatkar/emudhra-poc](https://github.com/abhishek-bhatkar/emudhra-poc) :  ![starts](https://img.shields.io/github/stars/abhishek-bhatkar/emudhra-poc.svg) ![forks](https://img.shields.io/github/forks/abhishek-bhatkar/emudhra-poc.svg)


## CVE-2026-110936
 A vulnerability has been identified in Siemens Software Center (All versions  V4.0.9.8). The affected application loads dynamic-link libraries (DLLs) from an uncontrolled search path. This could allow an authenticated local attacker to place a specially crafted DLL in a directory that the application searches, leading to arbitrary code execution with the privileges of the affected application.

- [https://github.com/DAS-Bodhi/CVE-2026-110936-Siemens-Attack](https://github.com/DAS-Bodhi/CVE-2026-110936-Siemens-Attack) :  ![starts](https://img.shields.io/github/stars/DAS-Bodhi/CVE-2026-110936-Siemens-Attack.svg) ![forks](https://img.shields.io/github/forks/DAS-Bodhi/CVE-2026-110936-Siemens-Attack.svg)


## CVE-2026-110899
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Kevin Stover Ninja Forms ninja-forms allows Stored XSS.This issue affects Ninja Forms: from n/a through 3.15.5.

- [https://github.com/synapes620/CVE-2026-110899](https://github.com/synapes620/CVE-2026-110899) :  ![starts](https://img.shields.io/github/stars/synapes620/CVE-2026-110899.svg) ![forks](https://img.shields.io/github/forks/synapes620/CVE-2026-110899.svg)


## CVE-2026-110372
 Incorrect Privilege Assignment vulnerability in Brainstorm Force OttoKit suretriggers allows Privilege Escalation.This issue affects OttoKit: from n/a through 1.1.40.

- [https://github.com/BIBILZERODAY/CVE-2026-110372-MASS-EXPLOIT-WEBSHELL.STORE](https://github.com/BIBILZERODAY/CVE-2026-110372-MASS-EXPLOIT-WEBSHELL.STORE) :  ![starts](https://img.shields.io/github/stars/BIBILZERODAY/CVE-2026-110372-MASS-EXPLOIT-WEBSHELL.STORE.svg) ![forks](https://img.shields.io/github/forks/BIBILZERODAY/CVE-2026-110372-MASS-EXPLOIT-WEBSHELL.STORE.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC) :  ![starts](https://img.shields.io/github/stars/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg) ![forks](https://img.shields.io/github/forks/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg)
- [https://github.com/syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection) :  ![starts](https://img.shields.io/github/stars/syhunt/php2shell-protection.svg) ![forks](https://img.shields.io/github/forks/syhunt/php2shell-protection.svg)
- [https://github.com/HOSTED-POWER/php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard) :  ![starts](https://img.shields.io/github/stars/HOSTED-POWER/php_uploadprogress_guard.svg) ![forks](https://img.shields.io/github/forks/HOSTED-POWER/php_uploadprogress_guard.svg)
- [https://github.com/JoasASantos/php2shell-scanner](https://github.com/JoasASantos/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/JoasASantos/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/JoasASantos/php2shell-scanner.svg)
- [https://github.com/dinosn/php-cve-2026-10961x-lab-poc](https://github.com/dinosn/php-cve-2026-10961x-lab-poc) :  ![starts](https://img.shields.io/github/stars/dinosn/php-cve-2026-10961x-lab-poc.svg) ![forks](https://img.shields.io/github/forks/dinosn/php-cve-2026-10961x-lab-poc.svg)
- [https://github.com/wakemeiflose/php2shell](https://github.com/wakemeiflose/php2shell) :  ![starts](https://img.shields.io/github/stars/wakemeiflose/php2shell.svg) ![forks](https://img.shields.io/github/forks/wakemeiflose/php2shell.svg)
- [https://github.com/murrez/php2shell](https://github.com/murrez/php2shell) :  ![starts](https://img.shields.io/github/stars/murrez/php2shell.svg) ![forks](https://img.shields.io/github/forks/murrez/php2shell.svg)
- [https://github.com/0x4148/CVE-2026-109618-php2shell-lab](https://github.com/0x4148/CVE-2026-109618-php2shell-lab) :  ![starts](https://img.shields.io/github/stars/0x4148/CVE-2026-109618-php2shell-lab.svg) ![forks](https://img.shields.io/github/forks/0x4148/CVE-2026-109618-php2shell-lab.svg)
- [https://github.com/0xrsydn/php2shell-scan](https://github.com/0xrsydn/php2shell-scan) :  ![starts](https://img.shields.io/github/stars/0xrsydn/php2shell-scan.svg) ![forks](https://img.shields.io/github/forks/0xrsydn/php2shell-scan.svg)
- [https://github.com/xuehuolll/php2shell-CVE-2026-109618-109619](https://github.com/xuehuolll/php2shell-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/xuehuolll/php2shell-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/xuehuolll/php2shell-CVE-2026-109618-109619.svg)
- [https://github.com/pentestershell/php2shellbt](https://github.com/pentestershell/php2shellbt) :  ![starts](https://img.shields.io/github/stars/pentestershell/php2shellbt.svg) ![forks](https://img.shields.io/github/forks/pentestershell/php2shellbt.svg)
- [https://github.com/Anton-Barinov/php2shell-patches](https://github.com/Anton-Barinov/php2shell-patches) :  ![starts](https://img.shields.io/github/stars/Anton-Barinov/php2shell-patches.svg) ![forks](https://img.shields.io/github/forks/Anton-Barinov/php2shell-patches.svg)
- [https://github.com/david-alvarez-rosa/php-rce](https://github.com/david-alvarez-rosa/php-rce) :  ![starts](https://img.shields.io/github/stars/david-alvarez-rosa/php-rce.svg) ![forks](https://img.shields.io/github/forks/david-alvarez-rosa/php-rce.svg)
- [https://github.com/godylockz/cve-2026-109618-php2shell](https://github.com/godylockz/cve-2026-109618-php2shell) :  ![starts](https://img.shields.io/github/stars/godylockz/cve-2026-109618-php2shell.svg) ![forks](https://img.shields.io/github/forks/godylockz/cve-2026-109618-php2shell.svg)
- [https://github.com/Whackermelon/Php2Shell-POC](https://github.com/Whackermelon/Php2Shell-POC) :  ![starts](https://img.shields.io/github/stars/Whackermelon/Php2Shell-POC.svg) ![forks](https://img.shields.io/github/forks/Whackermelon/Php2Shell-POC.svg)
- [https://github.com/kuwoo/php2shell-Lab](https://github.com/kuwoo/php2shell-Lab) :  ![starts](https://img.shields.io/github/stars/kuwoo/php2shell-Lab.svg) ![forks](https://img.shields.io/github/forks/kuwoo/php2shell-Lab.svg)
- [https://github.com/slabbdev/php2shell-cve-2026-109618-109619](https://github.com/slabbdev/php2shell-cve-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/slabbdev/php2shell-cve-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/slabbdev/php2shell-cve-2026-109618-109619.svg)
- [https://github.com/ersinkoc/php-fix](https://github.com/ersinkoc/php-fix) :  ![starts](https://img.shields.io/github/stars/ersinkoc/php-fix.svg) ![forks](https://img.shields.io/github/forks/ersinkoc/php-fix.svg)
- [https://github.com/PasqualePillitteri/php2shell-hardening](https://github.com/PasqualePillitteri/php2shell-hardening) :  ![starts](https://img.shields.io/github/stars/PasqualePillitteri/php2shell-hardening.svg) ![forks](https://img.shields.io/github/forks/PasqualePillitteri/php2shell-hardening.svg)
- [https://github.com/Amsozzer1/php2shell-repo-audit](https://github.com/Amsozzer1/php2shell-repo-audit) :  ![starts](https://img.shields.io/github/stars/Amsozzer1/php2shell-repo-audit.svg) ![forks](https://img.shields.io/github/forks/Amsozzer1/php2shell-repo-audit.svg)
- [https://github.com/unlimit0118/CVE-2026-109619-php2shell-poc](https://github.com/unlimit0118/CVE-2026-109619-php2shell-poc) :  ![starts](https://img.shields.io/github/stars/unlimit0118/CVE-2026-109619-php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/unlimit0118/CVE-2026-109619-php2shell-poc.svg)
- [https://github.com/CyberRoute/php2shell-scanner](https://github.com/CyberRoute/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/CyberRoute/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/CyberRoute/php2shell-scanner.svg)
- [https://github.com/revonnet/php-fix](https://github.com/revonnet/php-fix) :  ![starts](https://img.shields.io/github/stars/revonnet/php-fix.svg) ![forks](https://img.shields.io/github/forks/revonnet/php-fix.svg)
- [https://github.com/AbelLykens/php2shell-checker](https://github.com/AbelLykens/php2shell-checker) :  ![starts](https://img.shields.io/github/stars/AbelLykens/php2shell-checker.svg) ![forks](https://img.shields.io/github/forks/AbelLykens/php2shell-checker.svg)
- [https://github.com/Masriyan/php2shell](https://github.com/Masriyan/php2shell) :  ![starts](https://img.shields.io/github/stars/Masriyan/php2shell.svg) ![forks](https://img.shields.io/github/forks/Masriyan/php2shell.svg)
- [https://github.com/Niek/php7](https://github.com/Niek/php7) :  ![starts](https://img.shields.io/github/stars/Niek/php7.svg) ![forks](https://img.shields.io/github/forks/Niek/php7.svg)
- [https://github.com/AmpedWasTaken/PHP2Shell-CVE-2026-109618-CVE-2026-109619](https://github.com/AmpedWasTaken/PHP2Shell-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/AmpedWasTaken/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/AmpedWasTaken/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618](https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/cloudducoeur/ansible-playbook-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cloudducoeur/ansible-playbook-CVE-2026-109618.svg)
- [https://github.com/Galeax/PHP2Shell-Mitigations](https://github.com/Galeax/PHP2Shell-Mitigations) :  ![starts](https://img.shields.io/github/stars/Galeax/PHP2Shell-Mitigations.svg) ![forks](https://img.shields.io/github/forks/Galeax/PHP2Shell-Mitigations.svg)
- [https://github.com/jf0x3f/php2shell-pocs](https://github.com/jf0x3f/php2shell-pocs) :  ![starts](https://img.shields.io/github/stars/jf0x3f/php2shell-pocs.svg) ![forks](https://img.shields.io/github/forks/jf0x3f/php2shell-pocs.svg)
- [https://github.com/bagusindrayana/php-vuln-scan](https://github.com/bagusindrayana/php-vuln-scan) :  ![starts](https://img.shields.io/github/stars/bagusindrayana/php-vuln-scan.svg) ![forks](https://img.shields.io/github/forks/bagusindrayana/php-vuln-scan.svg)
- [https://github.com/mpyw/php-eol-CVE-2026-109618-109619](https://github.com/mpyw/php-eol-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/mpyw/php-eol-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/mpyw/php-eol-CVE-2026-109618-109619.svg)
- [https://github.com/Blue-B/php2shell-guard](https://github.com/Blue-B/php2shell-guard) :  ![starts](https://img.shields.io/github/stars/Blue-B/php2shell-guard.svg) ![forks](https://img.shields.io/github/forks/Blue-B/php2shell-guard.svg)
- [https://github.com/summoningshells/php2shell-check](https://github.com/summoningshells/php2shell-check) :  ![starts](https://img.shields.io/github/stars/summoningshells/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/summoningshells/php2shell-check.svg)
- [https://github.com/mahumadad/php2shell-analysis](https://github.com/mahumadad/php2shell-analysis) :  ![starts](https://img.shields.io/github/stars/mahumadad/php2shell-analysis.svg) ![forks](https://img.shields.io/github/forks/mahumadad/php2shell-analysis.svg)
- [https://github.com/allureluoli/php2shell-lab](https://github.com/allureluoli/php2shell-lab) :  ![starts](https://img.shields.io/github/stars/allureluoli/php2shell-lab.svg) ![forks](https://img.shields.io/github/forks/allureluoli/php2shell-lab.svg)
- [https://github.com/cagritopuz/php2shell](https://github.com/cagritopuz/php2shell) :  ![starts](https://img.shields.io/github/stars/cagritopuz/php2shell.svg) ![forks](https://img.shields.io/github/forks/cagritopuz/php2shell.svg)
- [https://github.com/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619](https://github.com/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/LordX404/php2shell-exploit](https://github.com/LordX404/php2shell-exploit) :  ![starts](https://img.shields.io/github/stars/LordX404/php2shell-exploit.svg) ![forks](https://img.shields.io/github/forks/LordX404/php2shell-exploit.svg)
- [https://github.com/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619](https://github.com/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/Bhavye-Malhotra/php2shell-2026](https://github.com/Bhavye-Malhotra/php2shell-2026) :  ![starts](https://img.shields.io/github/stars/Bhavye-Malhotra/php2shell-2026.svg) ![forks](https://img.shields.io/github/forks/Bhavye-Malhotra/php2shell-2026.svg)
- [https://github.com/1amrahul/php2shell-cve-2026-109618-cve-2026-109619](https://github.com/1amrahul/php2shell-cve-2026-109618-cve-2026-109619) :  ![starts](https://img.shields.io/github/stars/1amrahul/php2shell-cve-2026-109618-cve-2026-109619.svg) ![forks](https://img.shields.io/github/forks/1amrahul/php2shell-cve-2026-109618-cve-2026-109619.svg)
- [https://github.com/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks](https://github.com/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks) :  ![starts](https://img.shields.io/github/stars/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks.svg) ![forks](https://img.shields.io/github/forks/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks.svg)
- [https://github.com/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619](https://github.com/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/orbitron-ai/php2shell-response-kit](https://github.com/orbitron-ai/php2shell-response-kit) :  ![starts](https://img.shields.io/github/stars/orbitron-ai/php2shell-response-kit.svg) ![forks](https://img.shields.io/github/forks/orbitron-ai/php2shell-response-kit.svg)
- [https://github.com/Felix3322/PHP-uniDoS](https://github.com/Felix3322/PHP-uniDoS) :  ![starts](https://img.shields.io/github/stars/Felix3322/PHP-uniDoS.svg) ![forks](https://img.shields.io/github/forks/Felix3322/PHP-uniDoS.svg)
- [https://github.com/Liam-G/php2shell-audit](https://github.com/Liam-G/php2shell-audit) :  ![starts](https://img.shields.io/github/stars/Liam-G/php2shell-audit.svg) ![forks](https://img.shields.io/github/forks/Liam-G/php2shell-audit.svg)
- [https://github.com/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC](https://github.com/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC) :  ![starts](https://img.shields.io/github/stars/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC.svg) ![forks](https://img.shields.io/github/forks/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC.svg)
- [https://github.com/corelight/php2shell-detect](https://github.com/corelight/php2shell-detect) :  ![starts](https://img.shields.io/github/stars/corelight/php2shell-detect.svg) ![forks](https://img.shields.io/github/forks/corelight/php2shell-detect.svg)
- [https://github.com/hypnguyen1209/php2shell](https://github.com/hypnguyen1209/php2shell) :  ![starts](https://img.shields.io/github/stars/hypnguyen1209/php2shell.svg) ![forks](https://img.shields.io/github/forks/hypnguyen1209/php2shell.svg)
- [https://github.com/JohnHansonTheDev/phpreaper](https://github.com/JohnHansonTheDev/phpreaper) :  ![starts](https://img.shields.io/github/stars/JohnHansonTheDev/phpreaper.svg) ![forks](https://img.shields.io/github/forks/JohnHansonTheDev/phpreaper.svg)
- [https://github.com/nesirat/php2shell-guard](https://github.com/nesirat/php2shell-guard) :  ![starts](https://img.shields.io/github/stars/nesirat/php2shell-guard.svg) ![forks](https://img.shields.io/github/forks/nesirat/php2shell-guard.svg)
- [https://github.com/cereZ23/php-up-2026](https://github.com/cereZ23/php-up-2026) :  ![starts](https://img.shields.io/github/stars/cereZ23/php-up-2026.svg) ![forks](https://img.shields.io/github/forks/cereZ23/php-up-2026.svg)
- [https://github.com/julio-romo-muninn/PHP2SHELL](https://github.com/julio-romo-muninn/PHP2SHELL) :  ![starts](https://img.shields.io/github/stars/julio-romo-muninn/PHP2SHELL.svg) ![forks](https://img.shields.io/github/forks/julio-romo-muninn/PHP2SHELL.svg)
- [https://github.com/yetDevs/php2shell-triage](https://github.com/yetDevs/php2shell-triage) :  ![starts](https://img.shields.io/github/stars/yetDevs/php2shell-triage.svg) ![forks](https://img.shields.io/github/forks/yetDevs/php2shell-triage.svg)
- [https://github.com/exch0-wuz-h3r3/php2shell-response-inspector](https://github.com/exch0-wuz-h3r3/php2shell-response-inspector) :  ![starts](https://img.shields.io/github/stars/exch0-wuz-h3r3/php2shell-response-inspector.svg) ![forks](https://img.shields.io/github/forks/exch0-wuz-h3r3/php2shell-response-inspector.svg)
- [https://github.com/TahuCryptsi/php2shell-check](https://github.com/TahuCryptsi/php2shell-check) :  ![starts](https://img.shields.io/github/stars/TahuCryptsi/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/TahuCryptsi/php2shell-check.svg)
- [https://github.com/EthicalHCOP/php2shell-Simple-Checker](https://github.com/EthicalHCOP/php2shell-Simple-Checker) :  ![starts](https://img.shields.io/github/stars/EthicalHCOP/php2shell-Simple-Checker.svg) ![forks](https://img.shields.io/github/forks/EthicalHCOP/php2shell-Simple-Checker.svg)
- [https://github.com/kamalmjt/PHP2SHELL-Patch](https://github.com/kamalmjt/PHP2SHELL-Patch) :  ![starts](https://img.shields.io/github/stars/kamalmjt/PHP2SHELL-Patch.svg) ![forks](https://img.shields.io/github/forks/kamalmjt/PHP2SHELL-Patch.svg)
- [https://github.com/Poellie01/PHP2Shell-Verification-Script](https://github.com/Poellie01/PHP2Shell-Verification-Script) :  ![starts](https://img.shields.io/github/stars/Poellie01/PHP2Shell-Verification-Script.svg) ![forks](https://img.shields.io/github/forks/Poellie01/PHP2Shell-Verification-Script.svg)
- [https://github.com/gumerzzzindo/php2shell-CVE-2026-109618-109619](https://github.com/gumerzzzindo/php2shell-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/gumerzzzindo/php2shell-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/gumerzzzindo/php2shell-CVE-2026-109618-109619.svg)
- [https://github.com/alvarodh5/php2shell](https://github.com/alvarodh5/php2shell) :  ![starts](https://img.shields.io/github/stars/alvarodh5/php2shell.svg) ![forks](https://img.shields.io/github/forks/alvarodh5/php2shell.svg)
- [https://github.com/silastammerik/php2shell-mitigacao](https://github.com/silastammerik/php2shell-mitigacao) :  ![starts](https://img.shields.io/github/stars/silastammerik/php2shell-mitigacao.svg) ![forks](https://img.shields.io/github/forks/silastammerik/php2shell-mitigacao.svg)
- [https://github.com/infiniroot/ansible-mitigate-php2shell](https://github.com/infiniroot/ansible-mitigate-php2shell) :  ![starts](https://img.shields.io/github/stars/infiniroot/ansible-mitigate-php2shell.svg) ![forks](https://img.shields.io/github/forks/infiniroot/ansible-mitigate-php2shell.svg)
- [https://github.com/RemiPelloux/php-session-upload-progress-uaf](https://github.com/RemiPelloux/php-session-upload-progress-uaf) :  ![starts](https://img.shields.io/github/stars/RemiPelloux/php-session-upload-progress-uaf.svg) ![forks](https://img.shields.io/github/forks/RemiPelloux/php-session-upload-progress-uaf.svg)
- [https://github.com/imranulbari/php-security-update-helper](https://github.com/imranulbari/php-security-update-helper) :  ![starts](https://img.shields.io/github/stars/imranulbari/php-security-update-helper.svg) ![forks](https://img.shields.io/github/forks/imranulbari/php-security-update-helper.svg)
- [https://github.com/codewizdevs/php2shell-watcher](https://github.com/codewizdevs/php2shell-watcher) :  ![starts](https://img.shields.io/github/stars/codewizdevs/php2shell-watcher.svg) ![forks](https://img.shields.io/github/forks/codewizdevs/php2shell-watcher.svg)
- [https://github.com/SamJUK/php2shell-check-cve-2026-109618](https://github.com/SamJUK/php2shell-check-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/SamJUK/php2shell-check-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/SamJUK/php2shell-check-cve-2026-109618.svg)
- [https://github.com/cozybear-dev/cve-2026-109619](https://github.com/cozybear-dev/cve-2026-109619) :  ![starts](https://img.shields.io/github/stars/cozybear-dev/cve-2026-109619.svg) ![forks](https://img.shields.io/github/forks/cozybear-dev/cve-2026-109619.svg)
- [https://github.com/santihabib/CVE-2026-109619](https://github.com/santihabib/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/santihabib/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/santihabib/CVE-2026-109619.svg)
- [https://github.com/1Nightlovel/CVE-2026-109619](https://github.com/1Nightlovel/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/1Nightlovel/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/1Nightlovel/CVE-2026-109619.svg)
- [https://github.com/xvanpan/CVE-2026-109619](https://github.com/xvanpan/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xvanpan/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xvanpan/CVE-2026-109619.svg)
- [https://github.com/syrex1013/CVE-2026-109619](https://github.com/syrex1013/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/syrex1013/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/syrex1013/CVE-2026-109619.svg)
- [https://github.com/fmdiscioglu/php-cve-2026-109619-checker](https://github.com/fmdiscioglu/php-cve-2026-109619-checker) :  ![starts](https://img.shields.io/github/stars/fmdiscioglu/php-cve-2026-109619-checker.svg) ![forks](https://img.shields.io/github/forks/fmdiscioglu/php-cve-2026-109619-checker.svg)
- [https://github.com/AvaterXXX/CVE-2026-109618-CVE-2026-109619-](https://github.com/AvaterXXX/CVE-2026-109618-CVE-2026-109619-) :  ![starts](https://img.shields.io/github/stars/AvaterXXX/CVE-2026-109618-CVE-2026-109619-.svg) ![forks](https://img.shields.io/github/forks/AvaterXXX/CVE-2026-109618-CVE-2026-109619-.svg)
- [https://github.com/0ldbaby/php2shell](https://github.com/0ldbaby/php2shell) :  ![starts](https://img.shields.io/github/stars/0ldbaby/php2shell.svg) ![forks](https://img.shields.io/github/forks/0ldbaby/php2shell.svg)
- [https://github.com/basesixtythree/B63-POC-CVE-2026-109619](https://github.com/basesixtythree/B63-POC-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-109619.svg)
- [https://github.com/squiblyza/CVE-2026-109618-CVE-2026-109619](https://github.com/squiblyza/CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/squiblyza/CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/squiblyza/CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/mejustbox-byte/CVE-2026-109618-CVE-2026-109619](https://github.com/mejustbox-byte/CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/mejustbox-byte/CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/mejustbox-byte/CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/CYB3RW07F/PHP2Shell-CVE-2026-109618-CVE-2026-109619](https://github.com/CYB3RW07F/PHP2Shell-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/CYB3RW07F/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/CYB3RW07F/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/daffa001/php-CVE-2026-109618-CVE-2026-109619](https://github.com/daffa001/php-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/daffa001/php-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/daffa001/php-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/LeonelArrua/CVE-2026-109618_CVE-2026-109619_Mitigate](https://github.com/LeonelArrua/CVE-2026-109618_CVE-2026-109619_Mitigate) :  ![starts](https://img.shields.io/github/stars/LeonelArrua/CVE-2026-109618_CVE-2026-109619_Mitigate.svg) ![forks](https://img.shields.io/github/forks/LeonelArrua/CVE-2026-109618_CVE-2026-109619_Mitigate.svg)
- [https://github.com/SeanDishman/php2shell-CVE-2026-109618-CVE-2026-109619](https://github.com/SeanDishman/php2shell-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/SeanDishman/php2shell-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/SeanDishman/php2shell-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/atrailab/php-security-update-helper](https://github.com/atrailab/php-security-update-helper) :  ![starts](https://img.shields.io/github/stars/atrailab/php-security-update-helper.svg) ![forks](https://img.shields.io/github/forks/atrailab/php-security-update-helper.svg)
- [https://github.com/haobachang-1/php2shell-CVE-2026-109618-CVE-2026-109619](https://github.com/haobachang-1/php2shell-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/haobachang-1/php2shell-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/haobachang-1/php2shell-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/cj667113/OCI-Ansible-Fix-CVE-2026-109618_CVE-2026-109619](https://github.com/cj667113/OCI-Ansible-Fix-CVE-2026-109618_CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/cj667113/OCI-Ansible-Fix-CVE-2026-109618_CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/cj667113/OCI-Ansible-Fix-CVE-2026-109618_CVE-2026-109619.svg)
- [https://github.com/Unkn0vv/php2shell](https://github.com/Unkn0vv/php2shell) :  ![starts](https://img.shields.io/github/stars/Unkn0vv/php2shell.svg) ![forks](https://img.shields.io/github/forks/Unkn0vv/php2shell.svg)
- [https://github.com/BIBILZERODAY/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mass-Exploit](https://github.com/BIBILZERODAY/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mass-Exploit) :  ![starts](https://img.shields.io/github/stars/BIBILZERODAY/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mass-Exploit.svg) ![forks](https://img.shields.io/github/forks/BIBILZERODAY/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mass-Exploit.svg)
- [https://github.com/grupooruss/php2shell-test](https://github.com/grupooruss/php2shell-test) :  ![starts](https://img.shields.io/github/stars/grupooruss/php2shell-test.svg) ![forks](https://img.shields.io/github/forks/grupooruss/php2shell-test.svg)
- [https://github.com/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC](https://github.com/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC) :  ![starts](https://img.shields.io/github/stars/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg) ![forks](https://img.shields.io/github/forks/EngOREOO/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg)
- [https://github.com/D1a0y1bb/PHP2Shell-PoC](https://github.com/D1a0y1bb/PHP2Shell-PoC) :  ![starts](https://img.shields.io/github/stars/D1a0y1bb/PHP2Shell-PoC.svg) ![forks](https://img.shields.io/github/forks/D1a0y1bb/PHP2Shell-PoC.svg)
- [https://github.com/nukIeer/php2shell-checker](https://github.com/nukIeer/php2shell-checker) :  ![starts](https://img.shields.io/github/stars/nukIeer/php2shell-checker.svg) ![forks](https://img.shields.io/github/forks/nukIeer/php2shell-checker.svg)
- [https://github.com/mothproof3512/php2shell-scan](https://github.com/mothproof3512/php2shell-scan) :  ![starts](https://img.shields.io/github/stars/mothproof3512/php2shell-scan.svg) ![forks](https://img.shields.io/github/forks/mothproof3512/php2shell-scan.svg)
- [https://github.com/pete-builds/php-security-release-2026-10](https://github.com/pete-builds/php-security-release-2026-10) :  ![starts](https://img.shields.io/github/stars/pete-builds/php-security-release-2026-10.svg) ![forks](https://img.shields.io/github/forks/pete-builds/php-security-release-2026-10.svg)
- [https://github.com/EkaterinaMarchetti/Non-intrusive-PHP2Shell-assessment-for-CVE-2026-109618-and-CVE-2026-109619](https://github.com/EkaterinaMarchetti/Non-intrusive-PHP2Shell-assessment-for-CVE-2026-109618-and-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/EkaterinaMarchetti/Non-intrusive-PHP2Shell-assessment-for-CVE-2026-109618-and-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/EkaterinaMarchetti/Non-intrusive-PHP2Shell-assessment-for-CVE-2026-109618-and-CVE-2026-109619.svg)
- [https://github.com/nukIeer/CVE-2026-109618-109619-checker](https://github.com/nukIeer/CVE-2026-109618-109619-checker) :  ![starts](https://img.shields.io/github/stars/nukIeer/CVE-2026-109618-109619-checker.svg) ![forks](https://img.shields.io/github/forks/nukIeer/CVE-2026-109618-109619-checker.svg)
- [https://github.com/derazo1/php2shell-scanner](https://github.com/derazo1/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/derazo1/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/derazo1/php2shell-scanner.svg)
- [https://github.com/grupooruss/php2shell-assessment-global](https://github.com/grupooruss/php2shell-assessment-global) :  ![starts](https://img.shields.io/github/stars/grupooruss/php2shell-assessment-global.svg) ![forks](https://img.shields.io/github/forks/grupooruss/php2shell-assessment-global.svg)
- [https://github.com/EkaterinaMarchetti/php2shell-assessment-global](https://github.com/EkaterinaMarchetti/php2shell-assessment-global) :  ![starts](https://img.shields.io/github/stars/EkaterinaMarchetti/php2shell-assessment-global.svg) ![forks](https://img.shields.io/github/forks/EkaterinaMarchetti/php2shell-assessment-global.svg)
- [https://github.com/m16a4666/php2shell-fix](https://github.com/m16a4666/php2shell-fix) :  ![starts](https://img.shields.io/github/stars/m16a4666/php2shell-fix.svg) ![forks](https://img.shields.io/github/forks/m16a4666/php2shell-fix.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/ikow/php2shell-poc](https://github.com/ikow/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/ikow/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/ikow/php2shell-poc.svg)
- [https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC) :  ![starts](https://img.shields.io/github/stars/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg) ![forks](https://img.shields.io/github/forks/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC.svg)
- [https://github.com/junaire/CVE-2026-109618-exploit](https://github.com/junaire/CVE-2026-109618-exploit) :  ![starts](https://img.shields.io/github/stars/junaire/CVE-2026-109618-exploit.svg) ![forks](https://img.shields.io/github/forks/junaire/CVE-2026-109618-exploit.svg)
- [https://github.com/syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection) :  ![starts](https://img.shields.io/github/stars/syhunt/php2shell-protection.svg) ![forks](https://img.shields.io/github/forks/syhunt/php2shell-protection.svg)
- [https://github.com/HOSTED-POWER/php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard) :  ![starts](https://img.shields.io/github/stars/HOSTED-POWER/php_uploadprogress_guard.svg) ![forks](https://img.shields.io/github/forks/HOSTED-POWER/php_uploadprogress_guard.svg)
- [https://github.com/Zer061/CVE-2026-109618](https://github.com/Zer061/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/Zer061/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/Zer061/CVE-2026-109618.svg)
- [https://github.com/JoasASantos/php2shell-scanner](https://github.com/JoasASantos/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/JoasASantos/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/JoasASantos/php2shell-scanner.svg)
- [https://github.com/dinosn/php-cve-2026-10961x-lab-poc](https://github.com/dinosn/php-cve-2026-10961x-lab-poc) :  ![starts](https://img.shields.io/github/stars/dinosn/php-cve-2026-10961x-lab-poc.svg) ![forks](https://img.shields.io/github/forks/dinosn/php-cve-2026-10961x-lab-poc.svg)
- [https://github.com/wakemeiflose/php2shell](https://github.com/wakemeiflose/php2shell) :  ![starts](https://img.shields.io/github/stars/wakemeiflose/php2shell.svg) ![forks](https://img.shields.io/github/forks/wakemeiflose/php2shell.svg)
- [https://github.com/syrex1013/php2shell](https://github.com/syrex1013/php2shell) :  ![starts](https://img.shields.io/github/stars/syrex1013/php2shell.svg) ![forks](https://img.shields.io/github/forks/syrex1013/php2shell.svg)
- [https://github.com/enactive-systems/CVE-2026-109618-poc](https://github.com/enactive-systems/CVE-2026-109618-poc) :  ![starts](https://img.shields.io/github/stars/enactive-systems/CVE-2026-109618-poc.svg) ![forks](https://img.shields.io/github/forks/enactive-systems/CVE-2026-109618-poc.svg)
- [https://github.com/Is4yev/php2shell-poc](https://github.com/Is4yev/php2shell-poc) :  ![starts](https://img.shields.io/github/stars/Is4yev/php2shell-poc.svg) ![forks](https://img.shields.io/github/forks/Is4yev/php2shell-poc.svg)
- [https://github.com/mikensec/php2shell-lab](https://github.com/mikensec/php2shell-lab) :  ![starts](https://img.shields.io/github/stars/mikensec/php2shell-lab.svg) ![forks](https://img.shields.io/github/forks/mikensec/php2shell-lab.svg)
- [https://github.com/murrez/php2shell](https://github.com/murrez/php2shell) :  ![starts](https://img.shields.io/github/stars/murrez/php2shell.svg) ![forks](https://img.shields.io/github/forks/murrez/php2shell.svg)
- [https://github.com/0x4148/CVE-2026-109618-php2shell-lab](https://github.com/0x4148/CVE-2026-109618-php2shell-lab) :  ![starts](https://img.shields.io/github/stars/0x4148/CVE-2026-109618-php2shell-lab.svg) ![forks](https://img.shields.io/github/forks/0x4148/CVE-2026-109618-php2shell-lab.svg)
- [https://github.com/xuehuolll/php2shell-CVE-2026-109618-109619](https://github.com/xuehuolll/php2shell-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/xuehuolll/php2shell-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/xuehuolll/php2shell-CVE-2026-109618-109619.svg)
- [https://github.com/0xrsydn/php2shell-scan](https://github.com/0xrsydn/php2shell-scan) :  ![starts](https://img.shields.io/github/stars/0xrsydn/php2shell-scan.svg) ![forks](https://img.shields.io/github/forks/0xrsydn/php2shell-scan.svg)
- [https://github.com/pentestershell/php2shellbt](https://github.com/pentestershell/php2shellbt) :  ![starts](https://img.shields.io/github/stars/pentestershell/php2shellbt.svg) ![forks](https://img.shields.io/github/forks/pentestershell/php2shellbt.svg)
- [https://github.com/Anton-Barinov/php2shell-patches](https://github.com/Anton-Barinov/php2shell-patches) :  ![starts](https://img.shields.io/github/stars/Anton-Barinov/php2shell-patches.svg) ![forks](https://img.shields.io/github/forks/Anton-Barinov/php2shell-patches.svg)
- [https://github.com/david-alvarez-rosa/php-rce](https://github.com/david-alvarez-rosa/php-rce) :  ![starts](https://img.shields.io/github/stars/david-alvarez-rosa/php-rce.svg) ![forks](https://img.shields.io/github/forks/david-alvarez-rosa/php-rce.svg)
- [https://github.com/Gi1gamesh123/php-unserialize-uaf-rce](https://github.com/Gi1gamesh123/php-unserialize-uaf-rce) :  ![starts](https://img.shields.io/github/stars/Gi1gamesh123/php-unserialize-uaf-rce.svg) ![forks](https://img.shields.io/github/forks/Gi1gamesh123/php-unserialize-uaf-rce.svg)
- [https://github.com/godylockz/cve-2026-109618-php2shell](https://github.com/godylockz/cve-2026-109618-php2shell) :  ![starts](https://img.shields.io/github/stars/godylockz/cve-2026-109618-php2shell.svg) ![forks](https://img.shields.io/github/forks/godylockz/cve-2026-109618-php2shell.svg)
- [https://github.com/Whackermelon/Php2Shell-POC](https://github.com/Whackermelon/Php2Shell-POC) :  ![starts](https://img.shields.io/github/stars/Whackermelon/Php2Shell-POC.svg) ![forks](https://img.shields.io/github/forks/Whackermelon/Php2Shell-POC.svg)
- [https://github.com/WoYinDao/CVE-2026-109618-CVSS-9.2-Critical](https://github.com/WoYinDao/CVE-2026-109618-CVSS-9.2-Critical) :  ![starts](https://img.shields.io/github/stars/WoYinDao/CVE-2026-109618-CVSS-9.2-Critical.svg) ![forks](https://img.shields.io/github/forks/WoYinDao/CVE-2026-109618-CVSS-9.2-Critical.svg)
- [https://github.com/slabbdev/php2shell-cve-2026-109618-109619](https://github.com/slabbdev/php2shell-cve-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/slabbdev/php2shell-cve-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/slabbdev/php2shell-cve-2026-109618-109619.svg)
- [https://github.com/kuwoo/php2shell-Lab](https://github.com/kuwoo/php2shell-Lab) :  ![starts](https://img.shields.io/github/stars/kuwoo/php2shell-Lab.svg) ![forks](https://img.shields.io/github/forks/kuwoo/php2shell-Lab.svg)
- [https://github.com/ersinkoc/php-fix](https://github.com/ersinkoc/php-fix) :  ![starts](https://img.shields.io/github/stars/ersinkoc/php-fix.svg) ![forks](https://img.shields.io/github/forks/ersinkoc/php-fix.svg)
- [https://github.com/izdir/php-security-patcher](https://github.com/izdir/php-security-patcher) :  ![starts](https://img.shields.io/github/stars/izdir/php-security-patcher.svg) ![forks](https://img.shields.io/github/forks/izdir/php-security-patcher.svg)
- [https://github.com/PasqualePillitteri/php2shell-hardening](https://github.com/PasqualePillitteri/php2shell-hardening) :  ![starts](https://img.shields.io/github/stars/PasqualePillitteri/php2shell-hardening.svg) ![forks](https://img.shields.io/github/forks/PasqualePillitteri/php2shell-hardening.svg)
- [https://github.com/Amsozzer1/php2shell-repo-audit](https://github.com/Amsozzer1/php2shell-repo-audit) :  ![starts](https://img.shields.io/github/stars/Amsozzer1/php2shell-repo-audit.svg) ![forks](https://img.shields.io/github/forks/Amsozzer1/php2shell-repo-audit.svg)
- [https://github.com/break-the-build/php-multipart-waf-signals](https://github.com/break-the-build/php-multipart-waf-signals) :  ![starts](https://img.shields.io/github/stars/break-the-build/php-multipart-waf-signals.svg) ![forks](https://img.shields.io/github/forks/break-the-build/php-multipart-waf-signals.svg)
- [https://github.com/HackSpeak/CVE-2026-109618](https://github.com/HackSpeak/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-109618.svg)
- [https://github.com/CyberRoute/php2shell-scanner](https://github.com/CyberRoute/php2shell-scanner) :  ![starts](https://img.shields.io/github/stars/CyberRoute/php2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/CyberRoute/php2shell-scanner.svg)
- [https://github.com/revonnet/php-fix](https://github.com/revonnet/php-fix) :  ![starts](https://img.shields.io/github/stars/revonnet/php-fix.svg) ![forks](https://img.shields.io/github/forks/revonnet/php-fix.svg)
- [https://github.com/AbelLykens/php2shell-checker](https://github.com/AbelLykens/php2shell-checker) :  ![starts](https://img.shields.io/github/stars/AbelLykens/php2shell-checker.svg) ![forks](https://img.shields.io/github/forks/AbelLykens/php2shell-checker.svg)
- [https://github.com/Masriyan/php2shell](https://github.com/Masriyan/php2shell) :  ![starts](https://img.shields.io/github/stars/Masriyan/php2shell.svg) ![forks](https://img.shields.io/github/forks/Masriyan/php2shell.svg)
- [https://github.com/Niek/php7](https://github.com/Niek/php7) :  ![starts](https://img.shields.io/github/stars/Niek/php7.svg) ![forks](https://img.shields.io/github/forks/Niek/php7.svg)
- [https://github.com/cyberkiddle/CVE-2026-109618](https://github.com/cyberkiddle/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/cyberkiddle/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cyberkiddle/CVE-2026-109618.svg)
- [https://github.com/Nayrae/CVE-2026-109618](https://github.com/Nayrae/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/Nayrae/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/Nayrae/CVE-2026-109618.svg)
- [https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618](https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/cloudducoeur/ansible-playbook-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cloudducoeur/ansible-playbook-CVE-2026-109618.svg)
- [https://github.com/mpyw/php-eol-CVE-2026-109618-109619](https://github.com/mpyw/php-eol-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/mpyw/php-eol-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/mpyw/php-eol-CVE-2026-109618-109619.svg)
- [https://github.com/lzz0403/CVE-2026-109618-PHP2Shell-poc](https://github.com/lzz0403/CVE-2026-109618-PHP2Shell-poc) :  ![starts](https://img.shields.io/github/stars/lzz0403/CVE-2026-109618-PHP2Shell-poc.svg) ![forks](https://img.shields.io/github/forks/lzz0403/CVE-2026-109618-PHP2Shell-poc.svg)
- [https://github.com/AmpedWasTaken/PHP2Shell-CVE-2026-109618-CVE-2026-109619](https://github.com/AmpedWasTaken/PHP2Shell-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/AmpedWasTaken/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/AmpedWasTaken/PHP2Shell-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/Galeax/PHP2Shell-Mitigations](https://github.com/Galeax/PHP2Shell-Mitigations) :  ![starts](https://img.shields.io/github/stars/Galeax/PHP2Shell-Mitigations.svg) ![forks](https://img.shields.io/github/forks/Galeax/PHP2Shell-Mitigations.svg)
- [https://github.com/jf0x3f/php2shell-pocs](https://github.com/jf0x3f/php2shell-pocs) :  ![starts](https://img.shields.io/github/stars/jf0x3f/php2shell-pocs.svg) ![forks](https://img.shields.io/github/forks/jf0x3f/php2shell-pocs.svg)
- [https://github.com/bagusindrayana/php-vuln-scan](https://github.com/bagusindrayana/php-vuln-scan) :  ![starts](https://img.shields.io/github/stars/bagusindrayana/php-vuln-scan.svg) ![forks](https://img.shields.io/github/forks/bagusindrayana/php-vuln-scan.svg)
- [https://github.com/mnk-works/php2shell-verify](https://github.com/mnk-works/php2shell-verify) :  ![starts](https://img.shields.io/github/stars/mnk-works/php2shell-verify.svg) ![forks](https://img.shields.io/github/forks/mnk-works/php2shell-verify.svg)
- [https://github.com/Chrishow2/php74-apache-sury](https://github.com/Chrishow2/php74-apache-sury) :  ![starts](https://img.shields.io/github/stars/Chrishow2/php74-apache-sury.svg) ![forks](https://img.shields.io/github/forks/Chrishow2/php74-apache-sury.svg)
- [https://github.com/summoningshells/php2shell-check](https://github.com/summoningshells/php2shell-check) :  ![starts](https://img.shields.io/github/stars/summoningshells/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/summoningshells/php2shell-check.svg)
- [https://github.com/Blue-B/php2shell-guard](https://github.com/Blue-B/php2shell-guard) :  ![starts](https://img.shields.io/github/stars/Blue-B/php2shell-guard.svg) ![forks](https://img.shields.io/github/forks/Blue-B/php2shell-guard.svg)
- [https://github.com/allureluoli/php2shell-lab](https://github.com/allureluoli/php2shell-lab) :  ![starts](https://img.shields.io/github/stars/allureluoli/php2shell-lab.svg) ![forks](https://img.shields.io/github/forks/allureluoli/php2shell-lab.svg)
- [https://github.com/geforester/php7.4-focal-php2shell](https://github.com/geforester/php7.4-focal-php2shell) :  ![starts](https://img.shields.io/github/stars/geforester/php7.4-focal-php2shell.svg) ![forks](https://img.shields.io/github/forks/geforester/php7.4-focal-php2shell.svg)
- [https://github.com/mahumadad/php2shell-analysis](https://github.com/mahumadad/php2shell-analysis) :  ![starts](https://img.shields.io/github/stars/mahumadad/php2shell-analysis.svg) ![forks](https://img.shields.io/github/forks/mahumadad/php2shell-analysis.svg)
- [https://github.com/cm-suzuki-ryo/aws-waf-php2shell-post-guard](https://github.com/cm-suzuki-ryo/aws-waf-php2shell-post-guard) :  ![starts](https://img.shields.io/github/stars/cm-suzuki-ryo/aws-waf-php2shell-post-guard.svg) ![forks](https://img.shields.io/github/forks/cm-suzuki-ryo/aws-waf-php2shell-post-guard.svg)
- [https://github.com/cagritopuz/php2shell](https://github.com/cagritopuz/php2shell) :  ![starts](https://img.shields.io/github/stars/cagritopuz/php2shell.svg) ![forks](https://img.shields.io/github/forks/cagritopuz/php2shell.svg)
- [https://github.com/SamJUK/php2shell-check-cve-2026-109618](https://github.com/SamJUK/php2shell-check-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/SamJUK/php2shell-check-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/SamJUK/php2shell-check-cve-2026-109618.svg)
- [https://github.com/gumerzzzindo/php2shell-CVE-2026-109618-109619](https://github.com/gumerzzzindo/php2shell-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/gumerzzzindo/php2shell-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/gumerzzzindo/php2shell-CVE-2026-109618-109619.svg)
- [https://github.com/Bhavye-Malhotra/php2shell-2026](https://github.com/Bhavye-Malhotra/php2shell-2026) :  ![starts](https://img.shields.io/github/stars/Bhavye-Malhotra/php2shell-2026.svg) ![forks](https://img.shields.io/github/forks/Bhavye-Malhotra/php2shell-2026.svg)
- [https://github.com/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619](https://github.com/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/goodcoddeo/pterodactyl_PHP-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619](https://github.com/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/Stensel8/check-for-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks](https://github.com/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks) :  ![starts](https://img.shields.io/github/stars/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks.svg) ![forks](https://img.shields.io/github/forks/zerbaliy3v/php2shell-CVE-2026-109618-CVE-2026-109619-Dorks.svg)
- [https://github.com/1amrahul/php2shell-cve-2026-109618-cve-2026-109619](https://github.com/1amrahul/php2shell-cve-2026-109618-cve-2026-109619) :  ![starts](https://img.shields.io/github/stars/1amrahul/php2shell-cve-2026-109618-cve-2026-109619.svg) ![forks](https://img.shields.io/github/forks/1amrahul/php2shell-cve-2026-109618-cve-2026-109619.svg)
- [https://github.com/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619](https://github.com/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/nirzadokox/php2shell-vulnerability-check-for-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/orbitron-ai/php2shell-response-kit](https://github.com/orbitron-ai/php2shell-response-kit) :  ![starts](https://img.shields.io/github/stars/orbitron-ai/php2shell-response-kit.svg) ![forks](https://img.shields.io/github/forks/orbitron-ai/php2shell-response-kit.svg)
- [https://github.com/Felix3322/PHP-uniDoS](https://github.com/Felix3322/PHP-uniDoS) :  ![starts](https://img.shields.io/github/stars/Felix3322/PHP-uniDoS.svg) ![forks](https://img.shields.io/github/forks/Felix3322/PHP-uniDoS.svg)
- [https://github.com/Liam-G/php2shell-audit](https://github.com/Liam-G/php2shell-audit) :  ![starts](https://img.shields.io/github/stars/Liam-G/php2shell-audit.svg) ![forks](https://img.shields.io/github/forks/Liam-G/php2shell-audit.svg)
- [https://github.com/AsviS/PHP2Shell](https://github.com/AsviS/PHP2Shell) :  ![starts](https://img.shields.io/github/stars/AsviS/PHP2Shell.svg) ![forks](https://img.shields.io/github/forks/AsviS/PHP2Shell.svg)
- [https://github.com/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC](https://github.com/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC) :  ![starts](https://img.shields.io/github/stars/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC.svg) ![forks](https://img.shields.io/github/forks/Fazmin/PHP2Shell-CVE-2026-109618-CVE-2026-109619-Mitigation-Info-PoC.svg)
- [https://github.com/al4n4n/php2shell](https://github.com/al4n4n/php2shell) :  ![starts](https://img.shields.io/github/stars/al4n4n/php2shell.svg) ![forks](https://img.shields.io/github/forks/al4n4n/php2shell.svg)
- [https://github.com/corelight/php2shell-detect](https://github.com/corelight/php2shell-detect) :  ![starts](https://img.shields.io/github/stars/corelight/php2shell-detect.svg) ![forks](https://img.shields.io/github/forks/corelight/php2shell-detect.svg)
- [https://github.com/hypnguyen1209/php2shell](https://github.com/hypnguyen1209/php2shell) :  ![starts](https://img.shields.io/github/stars/hypnguyen1209/php2shell.svg) ![forks](https://img.shields.io/github/forks/hypnguyen1209/php2shell.svg)
- [https://github.com/JohnHansonTheDev/phpreaper](https://github.com/JohnHansonTheDev/phpreaper) :  ![starts](https://img.shields.io/github/stars/JohnHansonTheDev/phpreaper.svg) ![forks](https://img.shields.io/github/forks/JohnHansonTheDev/phpreaper.svg)
- [https://github.com/TREXNEGRO/php2shell](https://github.com/TREXNEGRO/php2shell) :  ![starts](https://img.shields.io/github/stars/TREXNEGRO/php2shell.svg) ![forks](https://img.shields.io/github/forks/TREXNEGRO/php2shell.svg)
- [https://github.com/unbelievable-digital/is-my-php-pwned](https://github.com/unbelievable-digital/is-my-php-pwned) :  ![starts](https://img.shields.io/github/stars/unbelievable-digital/is-my-php-pwned.svg) ![forks](https://img.shields.io/github/forks/unbelievable-digital/is-my-php-pwned.svg)
- [https://github.com/nesirat/php2shell-guard](https://github.com/nesirat/php2shell-guard) :  ![starts](https://img.shields.io/github/stars/nesirat/php2shell-guard.svg) ![forks](https://img.shields.io/github/forks/nesirat/php2shell-guard.svg)
- [https://github.com/san3ncrypt3d/php-oom-corruption-lab](https://github.com/san3ncrypt3d/php-oom-corruption-lab) :  ![starts](https://img.shields.io/github/stars/san3ncrypt3d/php-oom-corruption-lab.svg) ![forks](https://img.shields.io/github/forks/san3ncrypt3d/php-oom-corruption-lab.svg)
- [https://github.com/cereZ23/php-up-2026](https://github.com/cereZ23/php-up-2026) :  ![starts](https://img.shields.io/github/stars/cereZ23/php-up-2026.svg) ![forks](https://img.shields.io/github/forks/cereZ23/php-up-2026.svg)
- [https://github.com/julio-romo-muninn/PHP2SHELL](https://github.com/julio-romo-muninn/PHP2SHELL) :  ![starts](https://img.shields.io/github/stars/julio-romo-muninn/PHP2SHELL.svg) ![forks](https://img.shields.io/github/forks/julio-romo-muninn/PHP2SHELL.svg)
- [https://github.com/yetDevs/php2shell-triage](https://github.com/yetDevs/php2shell-triage) :  ![starts](https://img.shields.io/github/stars/yetDevs/php2shell-triage.svg) ![forks](https://img.shields.io/github/forks/yetDevs/php2shell-triage.svg)
- [https://github.com/exch0-wuz-h3r3/php2shell-response-inspector](https://github.com/exch0-wuz-h3r3/php2shell-response-inspector) :  ![starts](https://img.shields.io/github/stars/exch0-wuz-h3r3/php2shell-response-inspector.svg) ![forks](https://img.shields.io/github/forks/exch0-wuz-h3r3/php2shell-response-inspector.svg)
- [https://github.com/WeaveHubHQ/cf-waf-bypass-check](https://github.com/WeaveHubHQ/cf-waf-bypass-check) :  ![starts](https://img.shields.io/github/stars/WeaveHubHQ/cf-waf-bypass-check.svg) ![forks](https://img.shields.io/github/forks/WeaveHubHQ/cf-waf-bypass-check.svg)
- [https://github.com/appsec-cz/php-eol-patch](https://github.com/appsec-cz/php-eol-patch) :  ![starts](https://img.shields.io/github/stars/appsec-cz/php-eol-patch.svg) ![forks](https://img.shields.io/github/forks/appsec-cz/php-eol-patch.svg)
- [https://github.com/codewizdevs/php2shell-watcher](https://github.com/codewizdevs/php2shell-watcher) :  ![starts](https://img.shields.io/github/stars/codewizdevs/php2shell-watcher.svg) ![forks](https://img.shields.io/github/forks/codewizdevs/php2shell-watcher.svg)
- [https://github.com/slabwren/php2shell-detection](https://github.com/slabwren/php2shell-detection) :  ![starts](https://img.shields.io/github/stars/slabwren/php2shell-detection.svg) ![forks](https://img.shields.io/github/forks/slabwren/php2shell-detection.svg)
- [https://github.com/cseelhoff-ms/php2shell-hunting-pack](https://github.com/cseelhoff-ms/php2shell-hunting-pack) :  ![starts](https://img.shields.io/github/stars/cseelhoff-ms/php2shell-hunting-pack.svg) ![forks](https://img.shields.io/github/forks/cseelhoff-ms/php2shell-hunting-pack.svg)
- [https://github.com/TahuCryptsi/php2shell-check](https://github.com/TahuCryptsi/php2shell-check) :  ![starts](https://img.shields.io/github/stars/TahuCryptsi/php2shell-check.svg) ![forks](https://img.shields.io/github/forks/TahuCryptsi/php2shell-check.svg)
- [https://github.com/darkfibr/php2shell-detect](https://github.com/darkfibr/php2shell-detect) :  ![starts](https://img.shields.io/github/stars/darkfibr/php2shell-detect.svg) ![forks](https://img.shields.io/github/forks/darkfibr/php2shell-detect.svg)
- [https://github.com/EthicalHCOP/php2shell-Simple-Checker](https://github.com/EthicalHCOP/php2shell-Simple-Checker) :  ![starts](https://img.shields.io/github/stars/EthicalHCOP/php2shell-Simple-Checker.svg) ![forks](https://img.shields.io/github/forks/EthicalHCOP/php2shell-Simple-Checker.svg)
- [https://github.com/fufufuwa/php2shell-detect](https://github.com/fufufuwa/php2shell-detect) :  ![starts](https://img.shields.io/github/stars/fufufuwa/php2shell-detect.svg) ![forks](https://img.shields.io/github/forks/fufufuwa/php2shell-detect.svg)
- [https://github.com/kamalmjt/PHP2SHELL-Patch](https://github.com/kamalmjt/PHP2SHELL-Patch) :  ![starts](https://img.shields.io/github/stars/kamalmjt/PHP2SHELL-Patch.svg) ![forks](https://img.shields.io/github/forks/kamalmjt/PHP2SHELL-Patch.svg)
- [https://github.com/Poellie01/PHP2Shell-Verification-Script](https://github.com/Poellie01/PHP2Shell-Verification-Script) :  ![starts](https://img.shields.io/github/stars/Poellie01/PHP2Shell-Verification-Script.svg) ![forks](https://img.shields.io/github/forks/Poellie01/PHP2Shell-Verification-Script.svg)
- [https://github.com/alvarodh5/php2shell](https://github.com/alvarodh5/php2shell) :  ![starts](https://img.shields.io/github/stars/alvarodh5/php2shell.svg) ![forks](https://img.shields.io/github/forks/alvarodh5/php2shell.svg)
- [https://github.com/silastammerik/php2shell-mitigacao](https://github.com/silastammerik/php2shell-mitigacao) :  ![starts](https://img.shields.io/github/stars/silastammerik/php2shell-mitigacao.svg) ![forks](https://img.shields.io/github/forks/silastammerik/php2shell-mitigacao.svg)
- [https://github.com/RemiPelloux/php-session-upload-progress-uaf](https://github.com/RemiPelloux/php-session-upload-progress-uaf) :  ![starts](https://img.shields.io/github/stars/RemiPelloux/php-session-upload-progress-uaf.svg) ![forks](https://img.shields.io/github/forks/RemiPelloux/php-session-upload-progress-uaf.svg)
- [https://github.com/imranulbari/php-security-update-helper](https://github.com/imranulbari/php-security-update-helper) :  ![starts](https://img.shields.io/github/stars/imranulbari/php-security-update-helper.svg) ![forks](https://img.shields.io/github/forks/imranulbari/php-security-update-helper.svg)
- [https://github.com/0xBlackash/CVE-2026-109618](https://github.com/0xBlackash/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-109618.svg)
- [https://github.com/syrex1013/CVE-2026-109618](https://github.com/syrex1013/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/syrex1013/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/syrex1013/CVE-2026-109618.svg)
- [https://github.com/debugactiveprocess/CVE-2026-109618](https://github.com/debugactiveprocess/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/debugactiveprocess/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/debugactiveprocess/CVE-2026-109618.svg)
- [https://github.com/alvaroguzmancode/CVE-2026-109618](https://github.com/alvaroguzmancode/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/alvaroguzmancode/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/alvaroguzmancode/CVE-2026-109618.svg)
- [https://github.com/cozybear-dev/cve-2026-109618](https://github.com/cozybear-dev/cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/cozybear-dev/cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cozybear-dev/cve-2026-109618.svg)


## CVE-2026-104736
 The LearnPress plugin for WordPress is vulnerable to PHP Object Injection in versions up to, and including, 4.4.10 via deserialization of untrusted input from the 'checkout-email' request parameter during the checkout AJAX action. The value is passed through sanitize_text_field(), which does not strip serialized object syntax, then stored in the LearnPress session table and later fed to LP_Helper::maybe_unserialize() → unserialize() (without an allowed_classes restriction) by LP_Session_Handler::get() on subsequent requests. This makes it possible for unauthenticated attackers to inject a PHP Object.

- [https://github.com/BIBILZERODAY/CVE-2026-104736-Mass-Webshell-CVE](https://github.com/BIBILZERODAY/CVE-2026-104736-Mass-Webshell-CVE) :  ![starts](https://img.shields.io/github/stars/BIBILZERODAY/CVE-2026-104736-Mass-Webshell-CVE.svg) ![forks](https://img.shields.io/github/forks/BIBILZERODAY/CVE-2026-104736-Mass-Webshell-CVE.svg)


## CVE-2026-102764
 The vulnerability exists within internal components of BeyondTrust’s Remote Support product. The components did not adequately validate the origin of the messages it received. Under the right conditions, this could allow an attacker to perform file operations on the appliance.

- [https://github.com/maxprog-svg/CVE-2026-102764](https://github.com/maxprog-svg/CVE-2026-102764) :  ![starts](https://img.shields.io/github/stars/maxprog-svg/CVE-2026-102764.svg) ![forks](https://img.shields.io/github/forks/maxprog-svg/CVE-2026-102764.svg)


## CVE-2026-97859
 Seven Gitea API routes under `/api/v1/users/{username}` (followers, following, following/{target}, starred, subscriptions, keys and gpg_keys) were registered without the `individualPermsChecker` middleware that enforces the visibility of the target user. An authenticated user could therefore read the followers, following list, starred and watched repositories and public SSH and GPG keys of a user with limited or private visibility, whom they could not otherwise see. The issue was fixed in 1.27.3 and 28.0.0 and disclosed with 28.2.0.

- [https://github.com/ahiamaduuche-sys/CVE-2026-97859-AnalysisS](https://github.com/ahiamaduuche-sys/CVE-2026-97859-AnalysisS) :  ![starts](https://img.shields.io/github/stars/ahiamaduuche-sys/CVE-2026-97859-AnalysisS.svg) ![forks](https://img.shields.io/github/forks/ahiamaduuche-sys/CVE-2026-97859-AnalysisS.svg)
- [https://github.com/ahiamaduuche-sys/CVE-2026-97859-Analysis](https://github.com/ahiamaduuche-sys/CVE-2026-97859-Analysis) :  ![starts](https://img.shields.io/github/stars/ahiamaduuche-sys/CVE-2026-97859-Analysis.svg) ![forks](https://img.shields.io/github/forks/ahiamaduuche-sys/CVE-2026-97859-Analysis.svg)
- [https://github.com/ahiamaduuche-sys/CVE-2026-97859-CYB-Analysis](https://github.com/ahiamaduuche-sys/CVE-2026-97859-CYB-Analysis) :  ![starts](https://img.shields.io/github/stars/ahiamaduuche-sys/CVE-2026-97859-CYB-Analysis.svg) ![forks](https://img.shields.io/github/forks/ahiamaduuche-sys/CVE-2026-97859-CYB-Analysis.svg)
- [https://github.com/ahiamaduuche-sys/CVE-2026-97859-Cybersecurity-Analysis](https://github.com/ahiamaduuche-sys/CVE-2026-97859-Cybersecurity-Analysis) :  ![starts](https://img.shields.io/github/stars/ahiamaduuche-sys/CVE-2026-97859-Cybersecurity-Analysis.svg) ![forks](https://img.shields.io/github/forks/ahiamaduuche-sys/CVE-2026-97859-Cybersecurity-Analysis.svg)


## CVE-2026-97629
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/PhiNode-Labs/nginx-cve-2026-97629](https://github.com/PhiNode-Labs/nginx-cve-2026-97629) :  ![starts](https://img.shields.io/github/stars/PhiNode-Labs/nginx-cve-2026-97629.svg) ![forks](https://img.shields.io/github/forks/PhiNode-Labs/nginx-cve-2026-97629.svg)


## CVE-2026-96652
 Plex Media Server before 1.43.3.10861 allows SSRF via '/player/timeline'. An attacker using any X-Plex-Token value can include a full URL in the 'protocol' parameter and force the Plex server to POST to the attacker's chosen destination.

- [https://github.com/w116tjb/plex2shell-windows-hunt](https://github.com/w116tjb/plex2shell-windows-hunt) :  ![starts](https://img.shields.io/github/stars/w116tjb/plex2shell-windows-hunt.svg) ![forks](https://img.shields.io/github/forks/w116tjb/plex2shell-windows-hunt.svg)


## CVE-2026-92209
The specific flaw exists within the authentication mechanism controlling access to the Redis database. The issue results from using insufficient entropy in the generation of credentials. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of the service account. Was ZDI-CAN-30984.

- [https://github.com/do4choo/CVE-2026-92209_NoMachine_LPE](https://github.com/do4choo/CVE-2026-92209_NoMachine_LPE) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-92209_NoMachine_LPE.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-92209_NoMachine_LPE.svg)


## CVE-2026-92208
The specific flaw exists within the parsing of mDNS resource records. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a heap-based buffer. An attacker can leverage this vulnerability to execute code in the context of the service account. Was ZDI-CAN-30982.

- [https://github.com/do4choo/CVE-2026-92208_remote_mDNS_overflow](https://github.com/do4choo/CVE-2026-92208_remote_mDNS_overflow) :  ![starts](https://img.shields.io/github/stars/do4choo/CVE-2026-92208_remote_mDNS_overflow.svg) ![forks](https://img.shields.io/github/forks/do4choo/CVE-2026-92208_remote_mDNS_overflow.svg)


## CVE-2026-91858
 FopProducer transforms the incoming XSL-FO message body by creating a javax.xml.transform.TransformerFactory through TransformerFactory.newInstance() and enabling only FEATURE_SECURE_PROCESSING before running an identity transform over the body. On the JDK's built-in transformer, that feature alone already empties the accessExternalDTD and accessExternalStylesheet limits, so an external DTD or entity is refused. When a third-party JAXP TransformerFactory such as Saxon-HE is on the classpath, for example because the application also uses camel-xslt-saxon or camel-saxon, TransformerFactory.newInstance() returns that implementation instead, and FEATURE_SECURE_PROCESSING on its own does not restrict external resource access on it. A DOCTYPE with an external subset, or an external general entity, declared in the XSL-FO document is then resolved and expanded while the body is transformed. An external sender whose XSL-FO reaches a fop producer could therefore read files readable by the Camel process and cause the process to issue requests to hosts the document names. camel-fop does not bring such a factory itself, and excludes Xalan, so a default deployment using the JDK transformer is not affected; the issue is reachable only where another component has placed an alternative JAXP TransformerFactory on the classpath. Releases on the 4.14.x line and earlier reached end of life before this issue was resolved and do not receive a fix.

- [https://github.com/oscerd/CVE-2026-91858](https://github.com/oscerd/CVE-2026-91858) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-91858.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-91858.svg)


## CVE-2026-88901
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. camel-smooks now parses the XML body with a javax.xml.parsers.DocumentBuilder that does not resolve external general or parameter entities and does not load external DTDs, and hands Smooks the resulting document, matching the secure XML processing configuration used by org.apache.camel.converter.jaxp.XmlConverter and the other Camel XML components. This hardening is applied only when the Smooks configuration parses XML with its default reader, so EDI, CSV, JSON and custom-reader configurations, and the marshalling direction, are unchanged. A new allowExternalEntities option, disabled by default, restores the previous behaviour for trusted legacy configurations that rely on external entity resolution. The camel-4.14.x releases stream and earlier reached end of life before this issue was resolved and will not receive a fix, so deployments on those lines must move to a supported release. For deployments that cannot upgrade immediately, do not apply camel-smooks to XML received from untrusted senders.

- [https://github.com/oscerd/CVE-2026-88901](https://github.com/oscerd/CVE-2026-88901) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-88901.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-88901.svg)


## CVE-2026-88900
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.1. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.5. The 4.14.x releases stream and earlier, and the 4.15.x to 4.17.x and 4.19.x to 4.21.x release lines, reached end of life before this issue was resolved and will not receive a fix, so deployments on those lines must move to a supported release.

- [https://github.com/oscerd/CVE-2026-88900](https://github.com/oscerd/CVE-2026-88900) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-88900.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-88900.svg)


## CVE-2026-86478
2026.1.14042 improper authentication in YouTrack Helpdesk allowed unauthenticated account takeover via a self-asserted email address

- [https://github.com/LHeiakim/CVE-2026-86478](https://github.com/LHeiakim/CVE-2026-86478) :  ![starts](https://img.shields.io/github/stars/LHeiakim/CVE-2026-86478.svg) ![forks](https://img.shields.io/github/forks/LHeiakim/CVE-2026-86478.svg)


## CVE-2026-85317
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. The cache key now includes every field that shapes the token, so entries are no longer shared between endpoints that differ in any of them. For deployments that cannot upgrade immediately, run endpoints that differ in scope, resource indicator or token endpoint in separate JVMs so that they do not share the cache.

- [https://github.com/oscerd/CVE-2026-85317](https://github.com/oscerd/CVE-2026-85317) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85317.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85317.svg)


## CVE-2026-85316
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. Proxy mode is now selected by an exact path match rather than by prefix. For deployments that cannot upgrade immediately, rename any endpoint path that begins with proxy but is not intended to be a proxy.

- [https://github.com/oscerd/CVE-2026-85316](https://github.com/oscerd/CVE-2026-85316) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85316.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85316.svg)


## CVE-2026-85315
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. A muteException consumer option, defaulting to true, puts a generic description in the status instead of the route exception's message. Set muteException=false to restore the previous output. For deployments that cannot upgrade immediately, map failures onto an explicit status in an onException handler so the framework never copies the exception message into the description.

- [https://github.com/oscerd/CVE-2026-85315](https://github.com/oscerd/CVE-2026-85315) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85315.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85315.svg)


## CVE-2026-77680
Related: CVE-2025-32907

- [https://github.com/OJ01-creates/CVE-2026-77680-Security-Analysis](https://github.com/OJ01-creates/CVE-2026-77680-Security-Analysis) :  ![starts](https://img.shields.io/github/stars/OJ01-creates/CVE-2026-77680-Security-Analysis.svg) ![forks](https://img.shields.io/github/forks/OJ01-creates/CVE-2026-77680-Security-Analysis.svg)


## CVE-2026-72867
 Dokploy is a free, self-hostable Platform as a Service (PaaS). From 0.29.3 until 0.29.13, the incomplete fix for CVE-2026-45628 leaves packages/server/src/db/schema/compose.ts branch fields without server-side validation, allowing a direct compose.update request to store a malicious customGitBranch, branch, gitlabBranch, bitbucketBranch, or giteaBranch. A low-privileged authenticated user can trigger compose.deploy, which passes the stored branch to shell-based Git clone commands in packages/server/src/utils/providers/git.ts, github.ts, gitlab.ts, bitbucket.ts, and gitea.ts, resulting in arbitrary host command execution. This issue is fixed in version 0.29.13.

- [https://github.com/WoYinDao/CVE-2026-72867-CVSS-9.9-Critical](https://github.com/WoYinDao/CVE-2026-72867-CVSS-9.9-Critical) :  ![starts](https://img.shields.io/github/stars/WoYinDao/CVE-2026-72867-CVSS-9.9-Critical.svg) ![forks](https://img.shields.io/github/forks/WoYinDao/CVE-2026-72867-CVSS-9.9-Critical.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/Tersurrr/Orga-Tersur-Daniel-CVE-2026-63030](https://github.com/Tersurrr/Orga-Tersur-Daniel-CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/Tersurrr/Orga-Tersur-Daniel-CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/Tersurrr/Orga-Tersur-Daniel-CVE-2026-63030.svg)
- [https://github.com/Githu836/PoC-for-CVE-2026-63030](https://github.com/Githu836/PoC-for-CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/Githu836/PoC-for-CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/Githu836/PoC-for-CVE-2026-63030.svg)
- [https://github.com/0xIIDe231/wp2shell2026](https://github.com/0xIIDe231/wp2shell2026) :  ![starts](https://img.shields.io/github/stars/0xIIDe231/wp2shell2026.svg) ![forks](https://img.shields.io/github/forks/0xIIDe231/wp2shell2026.svg)


## CVE-2026-59774
 Gitea's Org-mode markup renderer processes INCLUDE directives supplied to the repository markup endpoint without preventing access to server-side files. An unauthenticated attacker can use a suitable public repository to read files accessible to the Gitea service account. If the disclosed files include app.ini and its INTERNAL_TOKEN, the attacker can chain the disclosure with internal logger access to modify a Git hook and execute commands as the Gitea service account.

- [https://github.com/asvorg/CVE-2026-59774-poc](https://github.com/asvorg/CVE-2026-59774-poc) :  ![starts](https://img.shields.io/github/stars/asvorg/CVE-2026-59774-poc.svg) ![forks](https://img.shields.io/github/forks/asvorg/CVE-2026-59774-poc.svg)


## CVE-2026-56190
 Use of uninitialized resource in Windows RDP allows an unauthorized attacker to execute code over a network.

- [https://github.com/danarhirany300-ctrl/CVE-2026-56190-RDP-Analysis](https://github.com/danarhirany300-ctrl/CVE-2026-56190-RDP-Analysis) :  ![starts](https://img.shields.io/github/stars/danarhirany300-ctrl/CVE-2026-56190-RDP-Analysis.svg) ![forks](https://img.shields.io/github/forks/danarhirany300-ctrl/CVE-2026-56190-RDP-Analysis.svg)


## CVE-2026-52887
 NocoBase is an AI-powered no-code/low-code platform for building business applications and enterprise solutions. Prior to 2.0.61, NocoBase @nocobase/plugin-notification-in-app-message exposed GET /api/myInAppChannels:list, where the filter[latestMsgReceiveTimestamp][$lt] value was inserted into a Sequelize.literal() template string without escaping or parameter binding, allowing a signed-up authenticated user to run stacked PostgreSQL statements and potentially execute commands with COPY ... TO PROGRAM. This vulnerability is fixed in 2.0.61.

- [https://github.com/pentrestion/nocobase-cve-2026-52887](https://github.com/pentrestion/nocobase-cve-2026-52887) :  ![starts](https://img.shields.io/github/stars/pentrestion/nocobase-cve-2026-52887.svg) ![forks](https://img.shields.io/github/forks/pentrestion/nocobase-cve-2026-52887.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/Thhc10/CVE-2026-41651](https://github.com/Thhc10/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/Thhc10/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/Thhc10/CVE-2026-41651.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/dntaskmehow/MARABUSE](https://github.com/dntaskmehow/MARABUSE) :  ![starts](https://img.shields.io/github/stars/dntaskmehow/MARABUSE.svg) ![forks](https://img.shields.io/github/forks/dntaskmehow/MARABUSE.svg)


## CVE-2026-29014
 MetInfo CMS versions 7.9, 8.0, and 8.1 contain an unauthenticated PHP code injection vulnerability that allows remote attackers to execute arbitrary code by sending crafted requests with malicious PHP code. Attackers can exploit insufficient input neutralization in the execution path to achieve remote code execution and gain full control over the affected server.

- [https://github.com/kandasirah/php-rce-2026](https://github.com/kandasirah/php-rce-2026) :  ![starts](https://img.shields.io/github/stars/kandasirah/php-rce-2026.svg) ![forks](https://img.shields.io/github/forks/kandasirah/php-rce-2026.svg)


## CVE-2026-20312
The vulnerabilities tracked by CVE-2026-20312 are related to Cleartext storage of sensitive information issues that are grouped under the Common Weakness Enumeration (CWE) CWE-312.

- [https://github.com/syrex1013/CVE-2026-2031226](https://github.com/syrex1013/CVE-2026-2031226) :  ![starts](https://img.shields.io/github/stars/syrex1013/CVE-2026-2031226.svg) ![forks](https://img.shields.io/github/forks/syrex1013/CVE-2026-2031226.svg)


## CVE-2026-11645
 Out of bounds read and write in V8 in Google Chrome prior to 149.0.7827.103 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/emlinhax/CVE-2026-11645-poc](https://github.com/emlinhax/CVE-2026-11645-poc) :  ![starts](https://img.shields.io/github/stars/emlinhax/CVE-2026-11645-poc.svg) ![forks](https://img.shields.io/github/forks/emlinhax/CVE-2026-11645-poc.svg)


## CVE-2026-11149
 Insufficient validation of untrusted input in Extensions in Google Chrome prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to perform privilege escalation via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/CaterMaoZi/CVE-2026-111497-POC](https://github.com/CaterMaoZi/CVE-2026-111497-POC) :  ![starts](https://img.shields.io/github/stars/CaterMaoZi/CVE-2026-111497-POC.svg) ![forks](https://img.shields.io/github/forks/CaterMaoZi/CVE-2026-111497-POC.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/1Nightlovel/CVE-2026-109618](https://github.com/1Nightlovel/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/1Nightlovel/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/1Nightlovel/CVE-2026-109618.svg)
- [https://github.com/xvanpan/CVE-2026-109618](https://github.com/xvanpan/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/xvanpan/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/xvanpan/CVE-2026-109618.svg)
- [https://github.com/zhaoboy9692/CVE-2026-109618_](https://github.com/zhaoboy9692/CVE-2026-109618_) :  ![starts](https://img.shields.io/github/stars/zhaoboy9692/CVE-2026-109618_.svg) ![forks](https://img.shields.io/github/forks/zhaoboy9692/CVE-2026-109618_.svg)
- [https://github.com/charindithjaindu/CVE-2026-109618](https://github.com/charindithjaindu/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/charindithjaindu/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/charindithjaindu/CVE-2026-109618.svg)
- [https://github.com/zenzue/CVE-2026-109618_19](https://github.com/zenzue/CVE-2026-109618_19) :  ![starts](https://img.shields.io/github/stars/zenzue/CVE-2026-109618_19.svg) ![forks](https://img.shields.io/github/forks/zenzue/CVE-2026-109618_19.svg)
- [https://github.com/mefulton/CVE-2026-109618-analysis](https://github.com/mefulton/CVE-2026-109618-analysis) :  ![starts](https://img.shields.io/github/stars/mefulton/CVE-2026-109618-analysis.svg) ![forks](https://img.shields.io/github/forks/mefulton/CVE-2026-109618-analysis.svg)
- [https://github.com/nsrg-fmlorg/php-cve-2026-109618](https://github.com/nsrg-fmlorg/php-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/nsrg-fmlorg/php-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/nsrg-fmlorg/php-cve-2026-109618.svg)
- [https://github.com/pruiz/php-CVE-2026-109618](https://github.com/pruiz/php-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/pruiz/php-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/pruiz/php-CVE-2026-109618.svg)
- [https://github.com/hoehyeonlab/php-cve-2026-109618-check](https://github.com/hoehyeonlab/php-cve-2026-109618-check) :  ![starts](https://img.shields.io/github/stars/hoehyeonlab/php-cve-2026-109618-check.svg) ![forks](https://img.shields.io/github/forks/hoehyeonlab/php-cve-2026-109618-check.svg)
- [https://github.com/ivanscm/php80-cve-2026-109618](https://github.com/ivanscm/php80-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/ivanscm/php80-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/ivanscm/php80-cve-2026-109618.svg)
- [https://github.com/sorenjohanson/crowdsec-cve-2026-109618-rule](https://github.com/sorenjohanson/crowdsec-cve-2026-109618-rule) :  ![starts](https://img.shields.io/github/stars/sorenjohanson/crowdsec-cve-2026-109618-rule.svg) ![forks](https://img.shields.io/github/forks/sorenjohanson/crowdsec-cve-2026-109618-rule.svg)
- [https://github.com/fmdiscioglu/php-cve-2026-109618-checker](https://github.com/fmdiscioglu/php-cve-2026-109618-checker) :  ![starts](https://img.shields.io/github/stars/fmdiscioglu/php-cve-2026-109618-checker.svg) ![forks](https://img.shields.io/github/forks/fmdiscioglu/php-cve-2026-109618-checker.svg)
- [https://github.com/skwirrel/php-cve-2026-109618-check](https://github.com/skwirrel/php-cve-2026-109618-check) :  ![starts](https://img.shields.io/github/stars/skwirrel/php-cve-2026-109618-check.svg) ![forks](https://img.shields.io/github/forks/skwirrel/php-cve-2026-109618-check.svg)
- [https://github.com/vperetti/php-cve-2026-109618-109619-backports](https://github.com/vperetti/php-cve-2026-109618-109619-backports) :  ![starts](https://img.shields.io/github/stars/vperetti/php-cve-2026-109618-109619-backports.svg) ![forks](https://img.shields.io/github/forks/vperetti/php-cve-2026-109618-109619-backports.svg)
- [https://github.com/basesixtythree/B63-POC-CVE-2026-109618](https://github.com/basesixtythree/B63-POC-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/basesixtythree/B63-POC-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/basesixtythree/B63-POC-CVE-2026-109618.svg)
- [https://github.com/jsrobinson3/php74-focal-cve-2026-109618](https://github.com/jsrobinson3/php74-focal-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/jsrobinson3/php74-focal-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/jsrobinson3/php74-focal-cve-2026-109618.svg)
- [https://github.com/1o-ya/php-cve-2026-109618-hotfix-guide](https://github.com/1o-ya/php-cve-2026-109618-hotfix-guide) :  ![starts](https://img.shields.io/github/stars/1o-ya/php-cve-2026-109618-hotfix-guide.svg) ![forks](https://img.shields.io/github/forks/1o-ya/php-cve-2026-109618-hotfix-guide.svg)
- [https://github.com/lushinshang/php2shell-cve-2026-109618](https://github.com/lushinshang/php2shell-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/lushinshang/php2shell-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/lushinshang/php2shell-cve-2026-109618.svg)
- [https://github.com/wind884/CVE-2026-109618-109619-PHP2Shell](https://github.com/wind884/CVE-2026-109618-109619-PHP2Shell) :  ![starts](https://img.shields.io/github/stars/wind884/CVE-2026-109618-109619-PHP2Shell.svg) ![forks](https://img.shields.io/github/forks/wind884/CVE-2026-109618-109619-PHP2Shell.svg)
- [https://github.com/sxyrxyy/php2shell-cve-2026-109618-check](https://github.com/sxyrxyy/php2shell-cve-2026-109618-check) :  ![starts](https://img.shields.io/github/stars/sxyrxyy/php2shell-cve-2026-109618-check.svg) ![forks](https://img.shields.io/github/forks/sxyrxyy/php2shell-cve-2026-109618-check.svg)
- [https://github.com/DandanLLab/PHP-5.6.40-CVE-2026-109618-109619](https://github.com/DandanLLab/PHP-5.6.40-CVE-2026-109618-109619) :  ![starts](https://img.shields.io/github/stars/DandanLLab/PHP-5.6.40-CVE-2026-109618-109619.svg) ![forks](https://img.shields.io/github/forks/DandanLLab/PHP-5.6.40-CVE-2026-109618-109619.svg)
- [https://github.com/waksboy/fixed-fpm-cve-2026-109618-and-109619-images](https://github.com/waksboy/fixed-fpm-cve-2026-109618-and-109619-images) :  ![starts](https://img.shields.io/github/stars/waksboy/fixed-fpm-cve-2026-109618-and-109619-images.svg) ![forks](https://img.shields.io/github/forks/waksboy/fixed-fpm-cve-2026-109618-and-109619-images.svg)
- [https://github.com/rdwr-namikb/php2shell-cve-2026-109618-109619-lab](https://github.com/rdwr-namikb/php2shell-cve-2026-109618-109619-lab) :  ![starts](https://img.shields.io/github/stars/rdwr-namikb/php2shell-cve-2026-109618-109619-lab.svg) ![forks](https://img.shields.io/github/forks/rdwr-namikb/php2shell-cve-2026-109618-109619-lab.svg)
- [https://github.com/adriyansyah-mf/CVE-2026-109618-109619-PHP-session.upload_progress-Exploit-](https://github.com/adriyansyah-mf/CVE-2026-109618-109619-PHP-session.upload_progress-Exploit-) :  ![starts](https://img.shields.io/github/stars/adriyansyah-mf/CVE-2026-109618-109619-PHP-session.upload_progress-Exploit-.svg) ![forks](https://img.shields.io/github/forks/adriyansyah-mf/CVE-2026-109618-109619-PHP-session.upload_progress-Exploit-.svg)
- [https://github.com/OmerAti/php-5.6.40-CVE-2026-109618-109619.patch](https://github.com/OmerAti/php-5.6.40-CVE-2026-109618-109619.patch) :  ![starts](https://img.shields.io/github/stars/OmerAti/php-5.6.40-CVE-2026-109618-109619.patch.svg) ![forks](https://img.shields.io/github/forks/OmerAti/php-5.6.40-CVE-2026-109618-109619.patch.svg)


## CVE-2026-10548
 A security flaw has been discovered in NousResearch hermes-agent up to 2026.4.23. This affects the function _sync_anthropic_entry_from_credentials_file of the file agent/credential_pool.py of the component Credential Pool Synchronization. The manipulation results in improper authentication. The attack must be initiated from a local position. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/CaterMaoZi/CVE-2026-105482-POC](https://github.com/CaterMaoZi/CVE-2026-105482-POC) :  ![starts](https://img.shields.io/github/stars/CaterMaoZi/CVE-2026-105482-POC.svg) ![forks](https://img.shields.io/github/forks/CaterMaoZi/CVE-2026-105482-POC.svg)


## CVE-2026-9618
 The PeachPay — Payments & Express Checkout for WooCommerce (supports Stripe, PayPal, Square, Authorize.net, NMI) plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 1.120.46. This is due to missing or incorrect nonce validation on the peachpay_stripe_handle_admin_actions function. This makes it possible for unauthenticated attackers to permanently delete all stored Stripe credentials — including publishable keys, secret keys, webhook secrets, and Apple Pay configuration — from the WordPress database, disabling Stripe payment processing for the store via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/SleepTheGod/cve-2026-9618-Patch](https://github.com/SleepTheGod/cve-2026-9618-Patch) :  ![starts](https://img.shields.io/github/stars/SleepTheGod/cve-2026-9618-Patch.svg) ![forks](https://img.shields.io/github/forks/SleepTheGod/cve-2026-9618-Patch.svg)


## CVE-2026-5562
 A vulnerability was identified in provectus kafka-ui up to 0.7.2. This impacts the function validateAccess of the file /api/smartfilters/testexecutions of the component Endpoint. The manipulation leads to code injection. The attack can be initiated remotely. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/personne-lambda/CVE-2026-5562-Exploit](https://github.com/personne-lambda/CVE-2026-5562-Exploit) :  ![starts](https://img.shields.io/github/stars/personne-lambda/CVE-2026-5562-Exploit.svg) ![forks](https://img.shields.io/github/forks/personne-lambda/CVE-2026-5562-Exploit.svg)


## CVE-2026-5195
 A flaw has been found in code-projects Student Membership System 1.0. This issue affects some unknown processing of the component User Registration Handler. Executing a manipulation can lead to sql injection. The attack can be launched remotely.

- [https://github.com/Envincion/CVE-2026-51954](https://github.com/Envincion/CVE-2026-51954) :  ![starts](https://img.shields.io/github/stars/Envincion/CVE-2026-51954.svg) ![forks](https://img.shields.io/github/forks/Envincion/CVE-2026-51954.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/euriconicacio/copy-fail-CVE-2026-31431-poc](https://github.com/euriconicacio/copy-fail-CVE-2026-31431-poc) :  ![starts](https://img.shields.io/github/stars/euriconicacio/copy-fail-CVE-2026-31431-poc.svg) ![forks](https://img.shields.io/github/forks/euriconicacio/copy-fail-CVE-2026-31431-poc.svg)


## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/ko456123mo-jpg/zero-x-deploy](https://github.com/ko456123mo-jpg/zero-x-deploy) :  ![starts](https://img.shields.io/github/stars/ko456123mo-jpg/zero-x-deploy.svg) ![forks](https://img.shields.io/github/forks/ko456123mo-jpg/zero-x-deploy.svg)


## CVE-2025-69413
 In Gitea before 1.25.2, /api/v1/user has different responses for failed authentication depending on whether a username exists.

- [https://github.com/fuad00/CVE-2025-69413-PoC](https://github.com/fuad00/CVE-2025-69413-PoC) :  ![starts](https://img.shields.io/github/stars/fuad00/CVE-2025-69413-PoC.svg) ![forks](https://img.shields.io/github/forks/fuad00/CVE-2025-69413-PoC.svg)


## CVE-2025-69212
 OpenSTAManager is an open source management software for technical assistance and invoicing. In 2.9.8 and earlier, a critical OS Command Injection vulnerability exists in the P7M (signed XML) file decoding functionality. An authenticated attacker can upload a ZIP file containing a .p7m file with a malicious filename to execute arbitrary system commands on the server.

- [https://github.com/d0lf1/htb-enigma-poc](https://github.com/d0lf1/htb-enigma-poc) :  ![starts](https://img.shields.io/github/stars/d0lf1/htb-enigma-poc.svg) ![forks](https://img.shields.io/github/forks/d0lf1/htb-enigma-poc.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2025-63353
 A vulnerability in FiberHome GPON ONU HG6145F1 RP4423 allows the device's factory default Wi-Fi password (WPA/WPA2 pre-shared key) to be predicted from the SSID. The device generates default passwords using a deterministic algorithm that derives the router passphrase from the SSID, enabling an attacker who can observe the SSID to predict the default password without authentication or user interaction.

- [https://github.com/code-fanatic/fiberhome-password-calculator](https://github.com/code-fanatic/fiberhome-password-calculator) :  ![starts](https://img.shields.io/github/stars/code-fanatic/fiberhome-password-calculator.svg) ![forks](https://img.shields.io/github/forks/code-fanatic/fiberhome-password-calculator.svg)


## CVE-2025-50460
 A remote code execution (RCE) vulnerability exists in the ms-swift project version 3.3.0 due to unsafe deserialization in tests/run.py using yaml.load() from the PyYAML library (versions = 5.3.1). If an attacker can control the content of the YAML configuration file passed to the --run_config parameter, arbitrary code can be executed during deserialization. This can lead to full system compromise. The vulnerability is triggered when a malicious YAML file is loaded, allowing the execution of arbitrary Python commands such as os.system(). It is recommended to upgrade PyYAML to version 5.4 or higher, and to use yaml.safe_load() to mitigate the issue.

- [https://github.com/ferralon-demo/ms-swift-yaml-load-rce](https://github.com/ferralon-demo/ms-swift-yaml-load-rce) :  ![starts](https://img.shields.io/github/stars/ferralon-demo/ms-swift-yaml-load-rce.svg) ![forks](https://img.shields.io/github/forks/ferralon-demo/ms-swift-yaml-load-rce.svg)


## CVE-2025-48561
 In multiple locations, there is a possible way to access data displayed on the screen due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Ife-cyb/CYB-401-Pixnapping-CVE-2025-48561](https://github.com/Ife-cyb/CYB-401-Pixnapping-CVE-2025-48561) :  ![starts](https://img.shields.io/github/stars/Ife-cyb/CYB-401-Pixnapping-CVE-2025-48561.svg) ![forks](https://img.shields.io/github/forks/Ife-cyb/CYB-401-Pixnapping-CVE-2025-48561.svg)


## CVE-2025-27509
 fleetdm/fleet is an open source device management, built on osquery. In vulnerable versions of Fleet, an attacker could craft a specially-formed SAML response to forge authentication assertions, provision a new administrative user account if Just-In-Time (JIT) provisioning is enabled, or create new accounts tied to forged assertions if f MDM enrollment is enabled. This vulnerability is fixed in 4.64.2, 4.63.2, 4.62.4, and 4.58.1.

- [https://github.com/Chillov3k/poc-cve-2025-27509](https://github.com/Chillov3k/poc-cve-2025-27509) :  ![starts](https://img.shields.io/github/stars/Chillov3k/poc-cve-2025-27509.svg) ![forks](https://img.shields.io/github/forks/Chillov3k/poc-cve-2025-27509.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/ferralon-demo/gogs-symlink-chain](https://github.com/ferralon-demo/gogs-symlink-chain) :  ![starts](https://img.shields.io/github/stars/ferralon-demo/gogs-symlink-chain.svg) ![forks](https://img.shields.io/github/forks/ferralon-demo/gogs-symlink-chain.svg)


## CVE-2025-7771
 ThrottleStop.sys, a legitimate driver, exposes two IOCTL interfaces that allow arbitrary read and write access to physical memory via the MmMapIoSpace function. This insecure implementation can be exploited by a malicious user-mode application to patch the running Windows kernel and invoke arbitrary kernel functions with ring-0 privileges. The vulnerability enables local attackers to execute arbitrary code in kernel context, resulting in privilege escalation and potential follow-on attacks, such as disabling security software or bypassing kernel-level protections. ThrottleStop.sys version 3.0.0.0 and possibly others are affected. Apply updates per vendor instructions.

- [https://github.com/datcathuh/CiGaslight](https://github.com/datcathuh/CiGaslight) :  ![starts](https://img.shields.io/github/stars/datcathuh/CiGaslight.svg) ![forks](https://img.shields.io/github/forks/datcathuh/CiGaslight.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2024-55947
 Gogs is an open source self-hosted Git service. A malicious user is able to write a file to an arbitrary path on the server to gain SSH access to the server. The vulnerability is fixed in 0.13.1.

- [https://github.com/ferralon-demo/gogs-symlink-chain](https://github.com/ferralon-demo/gogs-symlink-chain) :  ![starts](https://img.shields.io/github/stars/ferralon-demo/gogs-symlink-chain.svg) ![forks](https://img.shields.io/github/forks/ferralon-demo/gogs-symlink-chain.svg)


## CVE-2024-45846
 An arbitrary code execution vulnerability exists in versions 23.10.3.0 up to 24.7.4.1 of the MindsDB platform, when the Weaviate integration is installed on the server. If a specially crafted ‘SELECT WHERE’ clause containing Python code is run against a database created with the Weaviate engine, the code will be passed to an eval function and executed on the server.

- [https://github.com/ferralon-demo/mindsdb-vectordb-eval-rce](https://github.com/ferralon-demo/mindsdb-vectordb-eval-rce) :  ![starts](https://img.shields.io/github/stars/ferralon-demo/mindsdb-vectordb-eval-rce.svg) ![forks](https://img.shields.io/github/forks/ferralon-demo/mindsdb-vectordb-eval-rce.svg)


## CVE-2024-45337
 Applications and libraries which misuse connection.serverAuthenticate (via callback field ServerConfig.PublicKeyCallback) may be susceptible to an authorization bypass. The documentation for ServerConfig.PublicKeyCallback says that "A call to this function does not guarantee that the key offered is in fact used to authenticate." Specifically, the SSH protocol allows clients to inquire about whether a public key is acceptable before proving control of the corresponding private key. PublicKeyCallback may be called with multiple keys, and the order in which the keys were provided cannot be used to infer which key the client successfully authenticated with, if any. Some applications, which store the key(s) passed to PublicKeyCallback (or derived information) and make security relevant determinations based on it once the connection is established, may make incorrect assumptions. For example, an attacker may send public keys A and B, and then authenticate with A. PublicKeyCallback would be called only twice, first with A and then with B. A vulnerable application may then make authorization decisions based on key B for which the attacker does not actually control the private key. Since this API is widely misused, as a partial mitigation golang.org/x/cry...@v0.31.0 enforces the property that, when successfully authenticating via public key, the last key passed to ServerConfig.PublicKeyCallback will be the key used to authenticate the connection. PublicKeyCallback will now be called multiple times with the same key, if necessary. Note that the client may still not control the last key passed to PublicKeyCallback if the connection is then authenticated with a different method, such as PasswordCallback, KeyboardInteractiveCallback, or NoClientAuth. Users should be using the Extensions field of the Permissions return value from the various authentication callbacks to record data associated with the authentication attempt instead of referencing external state. Once the connection is established the state corresponding to the successful authentication attempt can be retrieved via the ServerConn.Permissions field. Note that some third-party libraries misuse the Permissions type by sharing it across authentication attempts; users of third-party libraries should refer to the relevant projects for guidance.

- [https://github.com/ferralon-demo/gitea-cve-2024-45337](https://github.com/ferralon-demo/gitea-cve-2024-45337) :  ![starts](https://img.shields.io/github/stars/ferralon-demo/gitea-cve-2024-45337.svg) ![forks](https://img.shields.io/github/forks/ferralon-demo/gitea-cve-2024-45337.svg)


## CVE-2024-32868
 ZITADEL provides users the possibility to use Time-based One-Time-Password (TOTP) and One-Time-Password (OTP) through SMS and Email. While ZITADEL already gives administrators the option to define a `Lockout Policy` with a maximum amount of failed password check attempts, there was no such mechanism for (T)OTP checks. This issue has been patched in version 2.50.0.

- [https://github.com/taiwoonileowo16-creator/CVE-2024-32868-Assignment-1](https://github.com/taiwoonileowo16-creator/CVE-2024-32868-Assignment-1) :  ![starts](https://img.shields.io/github/stars/taiwoonileowo16-creator/CVE-2024-32868-Assignment-1.svg) ![forks](https://img.shields.io/github/forks/taiwoonileowo16-creator/CVE-2024-32868-Assignment-1.svg)


## CVE-2024-22203
 Whoogle Search is a self-hosted metasearch engine. In versions prior to 0.8.4, the `element` method in `app/routes.py` does not validate the user-controlled `src_type` and `element_url` variables and passes them to the `send` method which sends a GET request on lines 339-343 in `request.py`, which leads to a server-side request forgery. This issue allows for crafting GET requests to internal and external resources on behalf of the server. For example, this issue would allow for accessing resources on the internal network that the server has access to, even though these resources may not be accessible on the internet. This issue is fixed in version 0.8.4.

- [https://github.com/ferralon-demo/whoogle-search-ssrf-path-traversal](https://github.com/ferralon-demo/whoogle-search-ssrf-path-traversal) :  ![starts](https://img.shields.io/github/stars/ferralon-demo/whoogle-search-ssrf-path-traversal.svg) ![forks](https://img.shields.io/github/forks/ferralon-demo/whoogle-search-ssrf-path-traversal.svg)


## CVE-2024-14027
a71874379ec8 ("xattr: switch to CLASS(fd)").

- [https://github.com/lcfr-eth/CVE-2024-14027_slop](https://github.com/lcfr-eth/CVE-2024-14027_slop) :  ![starts](https://img.shields.io/github/stars/lcfr-eth/CVE-2024-14027_slop.svg) ![forks](https://img.shields.io/github/forks/lcfr-eth/CVE-2024-14027_slop.svg)


## CVE-2024-10006
 A vulnerability was identified in Consul and Consul Enterprise (“Consul”) such that using Headers in L7 traffic intentions could bypass HTTP header based access rules.

- [https://github.com/ReadyStackFree/consul](https://github.com/ReadyStackFree/consul) :  ![starts](https://img.shields.io/github/stars/ReadyStackFree/consul.svg) ![forks](https://img.shields.io/github/forks/ReadyStackFree/consul.svg)


## CVE-2024-10005
 A vulnerability was identified in Consul and Consul Enterprise (“Consul”) such that using URL paths in L7 traffic intentions could bypass HTTP request path-based access rules.

- [https://github.com/ReadyStackFree/consul](https://github.com/ReadyStackFree/consul) :  ![starts](https://img.shields.io/github/stars/ReadyStackFree/consul.svg) ![forks](https://img.shields.io/github/forks/ReadyStackFree/consul.svg)


## CVE-2024-9264
 The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.

- [https://github.com/ferralon-demo/grafana-cve-2024-9264-duckdb-rce](https://github.com/ferralon-demo/grafana-cve-2024-9264-duckdb-rce) :  ![starts](https://img.shields.io/github/stars/ferralon-demo/grafana-cve-2024-9264-duckdb-rce.svg) ![forks](https://img.shields.io/github/forks/ferralon-demo/grafana-cve-2024-9264-duckdb-rce.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/Mohamedboukerche22/php2shell-extension](https://github.com/Mohamedboukerche22/php2shell-extension) :  ![starts](https://img.shields.io/github/stars/Mohamedboukerche22/php2shell-extension.svg) ![forks](https://img.shields.io/github/forks/Mohamedboukerche22/php2shell-extension.svg)


## CVE-2023-47250
 In mprivacy-tools before 2.0.406g in m-privacy TightGate-Pro Server, broken Access Control on X11 server sockets allows authenticated attackers (with access to a VNC session) to access the X11 desktops of other users by specifying their DISPLAY ID. This allows complete control of their desktop, including the ability to inject keystrokes and perform a keylogging attack.

- [https://github.com/christinasm1th/CVE-2023-47250-break-fix](https://github.com/christinasm1th/CVE-2023-47250-break-fix) :  ![starts](https://img.shields.io/github/stars/christinasm1th/CVE-2023-47250-break-fix.svg) ![forks](https://img.shields.io/github/forks/christinasm1th/CVE-2023-47250-break-fix.svg)


## CVE-2023-46604
which fixes this issue.

- [https://github.com/Theocyg/CVE-2023-46604](https://github.com/Theocyg/CVE-2023-46604) :  ![starts](https://img.shields.io/github/stars/Theocyg/CVE-2023-46604.svg) ![forks](https://img.shields.io/github/forks/Theocyg/CVE-2023-46604.svg)


## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/k9yk5zkn76-op/-CVE-2023-34362-Analysis](https://github.com/k9yk5zkn76-op/-CVE-2023-34362-Analysis) :  ![starts](https://img.shields.io/github/stars/k9yk5zkn76-op/-CVE-2023-34362-Analysis.svg) ![forks](https://img.shields.io/github/forks/k9yk5zkn76-op/-CVE-2023-34362-Analysis.svg)


## CVE-2023-32681
 Requests is a HTTP library. Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint. This is a product of how we use `rebuild_proxies` to reattach the `Proxy-Authorization` header to requests. For HTTP connections sent through the tunnel, the proxy will identify the header in the request itself and remove it prior to forwarding to the destination server. However when sent over HTTPS, the `Proxy-Authorization` header must be sent in the CONNECT request as the proxy has no visibility into the tunneled request. This results in Requests forwarding proxy credentials to the destination server unintentionally, allowing a malicious actor to potentially exfiltrate sensitive information. This issue has been patched in version 2.31.0.

- [https://github.com/mcpmark-eval-liuhezi/requests-sec-notes](https://github.com/mcpmark-eval-liuhezi/requests-sec-notes) :  ![starts](https://img.shields.io/github/stars/mcpmark-eval-liuhezi/requests-sec-notes.svg) ![forks](https://img.shields.io/github/forks/mcpmark-eval-liuhezi/requests-sec-notes.svg)


## CVE-2023-0482
 In RESTEasy the insecure File.createTempFile() is used in the DataSourceProvider, FileProvider and Mime4JWorkaround classes which creates temp files with insecure permissions that could be read by a local user.

- [https://github.com/Bethel904/CVE-2023-0482-Analysis](https://github.com/Bethel904/CVE-2023-0482-Analysis) :  ![starts](https://img.shields.io/github/stars/Bethel904/CVE-2023-0482-Analysis.svg) ![forks](https://img.shields.io/github/forks/Bethel904/CVE-2023-0482-Analysis.svg)


## CVE-2023-0297
 Code Injection in GitHub repository pyload/pyload prior to 0.5.0b3.dev31.

- [https://github.com/ferralon-demo/pyload-js2py-rce](https://github.com/ferralon-demo/pyload-js2py-rce) :  ![starts](https://img.shields.io/github/stars/ferralon-demo/pyload-js2py-rce.svg) ![forks](https://img.shields.io/github/forks/ferralon-demo/pyload-js2py-rce.svg)


## CVE-2022-36551
 A Server Side Request Forgery (SSRF) in the Data Import module in Heartex - Label Studio Community Edition versions 1.5.0 and earlier allows an authenticated user to access arbitrary files on the system. Furthermore, self-registration is enabled by default in these versions of Label Studio enabling a remote attacker to create a new account and then exploit the SSRF.

- [https://github.com/ferralon-demo/label-studio-url-import-ssrf](https://github.com/ferralon-demo/label-studio-url-import-ssrf) :  ![starts](https://img.shields.io/github/stars/ferralon-demo/label-studio-url-import-ssrf.svg) ![forks](https://img.shields.io/github/forks/ferralon-demo/label-studio-url-import-ssrf.svg)


## CVE-2022-30190
Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability.

- [https://github.com/jamespelumi79-ctrl/CVE-2022-30190-Follina-Research](https://github.com/jamespelumi79-ctrl/CVE-2022-30190-Follina-Research) :  ![starts](https://img.shields.io/github/stars/jamespelumi79-ctrl/CVE-2022-30190-Follina-Research.svg) ![forks](https://img.shields.io/github/forks/jamespelumi79-ctrl/CVE-2022-30190-Follina-Research.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/beulahhh-coder/-CVE-2022-22965-Spring4Shell](https://github.com/beulahhh-coder/-CVE-2022-22965-Spring4Shell) :  ![starts](https://img.shields.io/github/stars/beulahhh-coder/-CVE-2022-22965-Spring4Shell.svg) ![forks](https://img.shields.io/github/forks/beulahhh-coder/-CVE-2022-22965-Spring4Shell.svg)


## CVE-2022-2296
 Use after free in Chrome OS Shell in Google Chrome on Chrome OS prior to 103.0.5060.114 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via direct UI interactions.

- [https://github.com/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt](https://github.com/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt) :  ![starts](https://img.shields.io/github/stars/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt.svg) ![forks](https://img.shields.io/github/forks/aditidutta696-dev/Spring4Shell-CVE-2022-22965-Exploitation-Attempt.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/morgenm/dirtypipe](https://github.com/morgenm/dirtypipe) :  ![starts](https://img.shields.io/github/stars/morgenm/dirtypipe.svg) ![forks](https://img.shields.io/github/forks/morgenm/dirtypipe.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/mcpmark-eval-liuhezi/log4shell-audit-lab](https://github.com/mcpmark-eval-liuhezi/log4shell-audit-lab) :  ![starts](https://img.shields.io/github/stars/mcpmark-eval-liuhezi/log4shell-audit-lab.svg) ![forks](https://img.shields.io/github/forks/mcpmark-eval-liuhezi/log4shell-audit-lab.svg)


## CVE-2021-34527
Note that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as “PrintNightmare”, documented in CVE-2021-34527.

- [https://github.com/honouroladosu7-cpu/CVE-2021-34527_PrintNightmare.md](https://github.com/honouroladosu7-cpu/CVE-2021-34527_PrintNightmare.md) :  ![starts](https://img.shields.io/github/stars/honouroladosu7-cpu/CVE-2021-34527_PrintNightmare.md.svg) ![forks](https://img.shields.io/github/forks/honouroladosu7-cpu/CVE-2021-34527_PrintNightmare.md.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/ifeoluwaayodeji/CVE-2021-26855-Analysis](https://github.com/ifeoluwaayodeji/CVE-2021-26855-Analysis) :  ![starts](https://img.shields.io/github/stars/ifeoluwaayodeji/CVE-2021-26855-Analysis.svg) ![forks](https://img.shields.io/github/forks/ifeoluwaayodeji/CVE-2021-26855-Analysis.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/calonnuotcabe/CVE-2021-3156](https://github.com/calonnuotcabe/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/calonnuotcabe/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/calonnuotcabe/CVE-2021-3156.svg)


## CVE-2020-13927
 The previous default setting for Airflow's Experimental API was to allow all API requests without authentication, but this poses security risks to users who miss this fact. From Airflow 1.10.11 the default has been changed to deny all requests by default and is documented at https://airflow.apache.org/docs/1.10.11/security.html#api-authentication. Note this change fixes it for new installs but existing users need to change their config to default `[api]auth_backend = airflow.api.auth.backend.deny_all` as mentioned in the Updating Guide: https://github.com/apache/airflow/blob/1.10.11/UPDATING.md#experimental-api-will-deny-all-request-by-default

- [https://github.com/ferralon-demo/airflow-experimental-api-rce](https://github.com/ferralon-demo/airflow-experimental-api-rce) :  ![starts](https://img.shields.io/github/stars/ferralon-demo/airflow-experimental-api-rce.svg) ![forks](https://img.shields.io/github/forks/ferralon-demo/airflow-experimental-api-rce.svg)


## CVE-2020-4949
 IBM WebSphere Application Server 7.0, 8.0, 8.5, and 9.0 is vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 192025.

- [https://github.com/Anuhimen/CVE-2020-4949-Analysis](https://github.com/Anuhimen/CVE-2020-4949-Analysis) :  ![starts](https://img.shields.io/github/stars/Anuhimen/CVE-2020-4949-Analysis.svg) ![forks](https://img.shields.io/github/forks/Anuhimen/CVE-2020-4949-Analysis.svg)


## CVE-2020-1712
 A heap use-after-free vulnerability was found in systemd before version v245-rc1, where asynchronous Polkit queries are performed while handling dbus messages. A local unprivileged attacker can abuse this flaw to crash systemd services or potentially execute code and elevate their privileges, by sending specially crafted dbus messages.

- [https://github.com/davidajagbe/Vulnerability-assessment](https://github.com/davidajagbe/Vulnerability-assessment) :  ![starts](https://img.shields.io/github/stars/davidajagbe/Vulnerability-assessment.svg) ![forks](https://img.shields.io/github/forks/davidajagbe/Vulnerability-assessment.svg)


## CVE-2020-1472
When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/Divineokoduwa/CVE-2020-1472-Zerologon-Vulnerability-Assessment](https://github.com/Divineokoduwa/CVE-2020-1472-Zerologon-Vulnerability-Assessment) :  ![starts](https://img.shields.io/github/stars/Divineokoduwa/CVE-2020-1472-Zerologon-Vulnerability-Assessment.svg) ![forks](https://img.shields.io/github/forks/Divineokoduwa/CVE-2020-1472-Zerologon-Vulnerability-Assessment.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/AVA-CEO/CVE-2018-10933-Assessment-](https://github.com/AVA-CEO/CVE-2018-10933-Assessment-) :  ![starts](https://img.shields.io/github/stars/AVA-CEO/CVE-2018-10933-Assessment-.svg) ![forks](https://img.shields.io/github/forks/AVA-CEO/CVE-2018-10933-Assessment-.svg)


## CVE-2017-20001
 The AES encryption project 7.x and 8.x for Drupal does not sufficiently prevent attackers from decrypting data, aka SA-CONTRIB-2017-027. NOTE: This project is not covered by Drupal's security advisory policy.

- [https://github.com/abiolaexcellence1-sketch/vulnerability-](https://github.com/abiolaexcellence1-sketch/vulnerability-) :  ![starts](https://img.shields.io/github/stars/abiolaexcellence1-sketch/vulnerability-.svg) ![forks](https://img.shields.io/github/forks/abiolaexcellence1-sketch/vulnerability-.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/Ethel087/CVE-2017-5638-Apache-Struts-Analysis](https://github.com/Ethel087/CVE-2017-5638-Apache-Struts-Analysis) :  ![starts](https://img.shields.io/github/stars/Ethel087/CVE-2017-5638-Apache-Struts-Analysis.svg) ![forks](https://img.shields.io/github/forks/Ethel087/CVE-2017-5638-Apache-Struts-Analysis.svg)


## CVE-2006-3685
 PHP remote file inclusion vulnerability in CzarNews 1.12 through 1.14 allows remote attackers to execute arbitrary PHP code via a URL in the tpath parameter to cn_config.php.  NOTE: the news.php vector is already covered by CVE-2005-0859.

- [https://github.com/rubo77/czarnews](https://github.com/rubo77/czarnews) :  ![starts](https://img.shields.io/github/stars/rubo77/czarnews.svg) ![forks](https://img.shields.io/github/forks/rubo77/czarnews.svg)


## CVE-2006-1641
 Multiple SQL injection vulnerabilities in CzarNews 1.14 allow remote attackers to execute arbitrary SQL commands via the (1) usern or (2) passw parameters to (a) cn_auth.php, (3) s parameter to (b) news.php, or (4) a parameter to (c) dpost.php.

- [https://github.com/rubo77/czarnews](https://github.com/rubo77/czarnews) :  ![starts](https://img.shields.io/github/stars/rubo77/czarnews.svg) ![forks](https://img.shields.io/github/forks/rubo77/czarnews.svg)


## CVE-2006-1640
 Cross-site scripting (XSS) vulnerability in news.php in CzarNews 1.14 allows remote attackers to inject arbitrary web script or HTML via the email parameter.

- [https://github.com/rubo77/czarnews](https://github.com/rubo77/czarnews) :  ![starts](https://img.shields.io/github/stars/rubo77/czarnews.svg) ![forks](https://img.shields.io/github/forks/rubo77/czarnews.svg)


## CVE-2005-0859
 PHP remote file inclusion vulnerability in CzarNews 1.13b allows remote attackers to execute arbitrary PHP code via the tpath parameter to (1) headlines.php or (2) news.php.  NOTE: some sources have reported the "dir" parameter as being affected; however, this is likely a cut-and-paste error from the wrong section of the original vulnerability report.  Also, the news.php version was later reported to be in 1.12 through 1.14.

- [https://github.com/rubo77/czarnews](https://github.com/rubo77/czarnews) :  ![starts](https://img.shields.io/github/stars/rubo77/czarnews.svg) ![forks](https://img.shields.io/github/forks/rubo77/czarnews.svg)

