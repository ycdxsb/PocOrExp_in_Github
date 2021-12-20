## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0 and 2.12.3.



- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

- [https://github.com/fox-it/log4j-finder](https://github.com/fox-it/log4j-finder) :  ![starts](https://img.shields.io/github/stars/fox-it/log4j-finder.svg) ![forks](https://img.shields.io/github/forks/fox-it/log4j-finder.svg)

- [https://github.com/dtact/divd-2021-00038--log4j-scanner](https://github.com/dtact/divd-2021-00038--log4j-scanner) :  ![starts](https://img.shields.io/github/stars/dtact/divd-2021-00038--log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/dtact/divd-2021-00038--log4j-scanner.svg)

- [https://github.com/hupe1980/scan4log4shell](https://github.com/hupe1980/scan4log4shell) :  ![starts](https://img.shields.io/github/stars/hupe1980/scan4log4shell.svg) ![forks](https://img.shields.io/github/forks/hupe1980/scan4log4shell.svg)

- [https://github.com/cckuailong/Log4j_dos_CVE-2021-45105](https://github.com/cckuailong/Log4j_dos_CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/cckuailong/Log4j_dos_CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/cckuailong/Log4j_dos_CVE-2021-45105.svg)

- [https://github.com/tejas-nagchandi/CVE-2021-45105](https://github.com/tejas-nagchandi/CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/tejas-nagchandi/CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/tejas-nagchandi/CVE-2021-45105.svg)

- [https://github.com/pravin-pp/log4j2-CVE-2021-45105](https://github.com/pravin-pp/log4j2-CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/pravin-pp/log4j2-CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/pravin-pp/log4j2-CVE-2021-45105.svg)

- [https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105](https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105.svg)

## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in a denial of service (DOS) attack. Log4j 2.15.0 makes a best-effort attempt to restrict JNDI LDAP lookups to localhost by default. Log4j 2.16.0 fixes this issue by removing support for message lookup patterns and disabling JNDI functionality by default.



- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

- [https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words](https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words) :  ![starts](https://img.shields.io/github/stars/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words.svg) ![forks](https://img.shields.io/github/forks/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words.svg)

- [https://github.com/mergebase/log4j-detector](https://github.com/mergebase/log4j-detector) :  ![starts](https://img.shields.io/github/stars/mergebase/log4j-detector.svg) ![forks](https://img.shields.io/github/forks/mergebase/log4j-detector.svg)

- [https://github.com/fox-it/log4j-finder](https://github.com/fox-it/log4j-finder) :  ![starts](https://img.shields.io/github/stars/fox-it/log4j-finder.svg) ![forks](https://img.shields.io/github/forks/fox-it/log4j-finder.svg)

- [https://github.com/dtact/divd-2021-00038--log4j-scanner](https://github.com/dtact/divd-2021-00038--log4j-scanner) :  ![starts](https://img.shields.io/github/stars/dtact/divd-2021-00038--log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/dtact/divd-2021-00038--log4j-scanner.svg)

- [https://github.com/1lann/log4shelldetect](https://github.com/1lann/log4shelldetect) :  ![starts](https://img.shields.io/github/stars/1lann/log4shelldetect.svg) ![forks](https://img.shields.io/github/forks/1lann/log4shelldetect.svg)

- [https://github.com/alexbakker/log4shell-tools](https://github.com/alexbakker/log4shell-tools) :  ![starts](https://img.shields.io/github/stars/alexbakker/log4shell-tools.svg) ![forks](https://img.shields.io/github/forks/alexbakker/log4shell-tools.svg)

- [https://github.com/darkarnium/Log4j-CVE-Detect](https://github.com/darkarnium/Log4j-CVE-Detect) :  ![starts](https://img.shields.io/github/stars/darkarnium/Log4j-CVE-Detect.svg) ![forks](https://img.shields.io/github/forks/darkarnium/Log4j-CVE-Detect.svg)

- [https://github.com/cckuailong/Log4j_CVE-2021-45046](https://github.com/cckuailong/Log4j_CVE-2021-45046) :  ![starts](https://img.shields.io/github/stars/cckuailong/Log4j_CVE-2021-45046.svg) ![forks](https://img.shields.io/github/forks/cckuailong/Log4j_CVE-2021-45046.svg)

- [https://github.com/xsultan/log4jshield](https://github.com/xsultan/log4jshield) :  ![starts](https://img.shields.io/github/stars/xsultan/log4jshield.svg) ![forks](https://img.shields.io/github/forks/xsultan/log4jshield.svg)

- [https://github.com/hupe1980/scan4log4shell](https://github.com/hupe1980/scan4log4shell) :  ![starts](https://img.shields.io/github/stars/hupe1980/scan4log4shell.svg) ![forks](https://img.shields.io/github/forks/hupe1980/scan4log4shell.svg)

- [https://github.com/DXC-StrikeForce/Burp-Log4j-HammerTime](https://github.com/DXC-StrikeForce/Burp-Log4j-HammerTime) :  ![starts](https://img.shields.io/github/stars/DXC-StrikeForce/Burp-Log4j-HammerTime.svg) ![forks](https://img.shields.io/github/forks/DXC-StrikeForce/Burp-Log4j-HammerTime.svg)

- [https://github.com/HynekPetrak/log4shell_finder](https://github.com/HynekPetrak/log4shell_finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell_finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell_finder.svg)

- [https://github.com/mergebase/log4j-samples](https://github.com/mergebase/log4j-samples) :  ![starts](https://img.shields.io/github/stars/mergebase/log4j-samples.svg) ![forks](https://img.shields.io/github/forks/mergebase/log4j-samples.svg)

- [https://github.com/BobTheShoplifter/CVE-2021-45046-Info](https://github.com/BobTheShoplifter/CVE-2021-45046-Info) :  ![starts](https://img.shields.io/github/stars/BobTheShoplifter/CVE-2021-45046-Info.svg) ![forks](https://img.shields.io/github/forks/BobTheShoplifter/CVE-2021-45046-Info.svg)

- [https://github.com/TheInterception/Log4J-Simulation-Tool](https://github.com/TheInterception/Log4J-Simulation-Tool) :  ![starts](https://img.shields.io/github/stars/TheInterception/Log4J-Simulation-Tool.svg) ![forks](https://img.shields.io/github/forks/TheInterception/Log4J-Simulation-Tool.svg)

- [https://github.com/Aschen/log4j-patched](https://github.com/Aschen/log4j-patched) :  ![starts](https://img.shields.io/github/stars/Aschen/log4j-patched.svg) ![forks](https://img.shields.io/github/forks/Aschen/log4j-patched.svg)

- [https://github.com/andalik/log4j-filescan](https://github.com/andalik/log4j-filescan) :  ![starts](https://img.shields.io/github/stars/andalik/log4j-filescan.svg) ![forks](https://img.shields.io/github/forks/andalik/log4j-filescan.svg)

- [https://github.com/gitlab-de/log4j-resources](https://github.com/gitlab-de/log4j-resources) :  ![starts](https://img.shields.io/github/stars/gitlab-de/log4j-resources.svg) ![forks](https://img.shields.io/github/forks/gitlab-de/log4j-resources.svg)

- [https://github.com/at-bay/log4j-checker](https://github.com/at-bay/log4j-checker) :  ![starts](https://img.shields.io/github/stars/at-bay/log4j-checker.svg) ![forks](https://img.shields.io/github/forks/at-bay/log4j-checker.svg)

- [https://github.com/juergenhoetzel/log4j2go](https://github.com/juergenhoetzel/log4j2go) :  ![starts](https://img.shields.io/github/stars/juergenhoetzel/log4j2go.svg) ![forks](https://img.shields.io/github/forks/juergenhoetzel/log4j2go.svg)

- [https://github.com/tejas-nagchandi/CVE-2021-45046](https://github.com/tejas-nagchandi/CVE-2021-45046) :  ![starts](https://img.shields.io/github/stars/tejas-nagchandi/CVE-2021-45046.svg) ![forks](https://img.shields.io/github/forks/tejas-nagchandi/CVE-2021-45046.svg)

- [https://github.com/ludy-dev/cve-2021-45046](https://github.com/ludy-dev/cve-2021-45046) :  ![starts](https://img.shields.io/github/stars/ludy-dev/cve-2021-45046.svg) ![forks](https://img.shields.io/github/forks/ludy-dev/cve-2021-45046.svg)

- [https://github.com/pravin-pp/log4j2-CVE-2021-45046](https://github.com/pravin-pp/log4j2-CVE-2021-45046) :  ![starts](https://img.shields.io/github/stars/pravin-pp/log4j2-CVE-2021-45046.svg) ![forks](https://img.shields.io/github/forks/pravin-pp/log4j2-CVE-2021-45046.svg)

- [https://github.com/DANSI/PowerShell-Log4J-Scanner](https://github.com/DANSI/PowerShell-Log4J-Scanner) :  ![starts](https://img.shields.io/github/stars/DANSI/PowerShell-Log4J-Scanner.svg) ![forks](https://img.shields.io/github/forks/DANSI/PowerShell-Log4J-Scanner.svg)

- [https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105](https://github.com/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105) :  ![starts](https://img.shields.io/github/stars/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105.svg) ![forks](https://img.shields.io/github/forks/thedevappsecguy/Log4J-Mitigation-CVE-2021-44228--CVE-2021-45046--CVE-2021-45105.svg)

- [https://github.com/trickyearlobe/inspec-log4j](https://github.com/trickyearlobe/inspec-log4j) :  ![starts](https://img.shields.io/github/stars/trickyearlobe/inspec-log4j.svg) ![forks](https://img.shields.io/github/forks/trickyearlobe/inspec-log4j.svg)

- [https://github.com/sudo6/l4shunter](https://github.com/sudo6/l4shunter) :  ![starts](https://img.shields.io/github/stars/sudo6/l4shunter.svg) ![forks](https://img.shields.io/github/forks/sudo6/l4shunter.svg)

- [https://github.com/benarculus/detecting-cve-2021-44228](https://github.com/benarculus/detecting-cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/benarculus/detecting-cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/benarculus/detecting-cve-2021-44228.svg)

- [https://github.com/lukepasek/log4jjndilookupremove](https://github.com/lukepasek/log4jjndilookupremove) :  ![starts](https://img.shields.io/github/stars/lukepasek/log4jjndilookupremove.svg) ![forks](https://img.shields.io/github/forks/lukepasek/log4jjndilookupremove.svg)

- [https://github.com/nagten/JndiLookupRemoval](https://github.com/nagten/JndiLookupRemoval) :  ![starts](https://img.shields.io/github/stars/nagten/JndiLookupRemoval.svg) ![forks](https://img.shields.io/github/forks/nagten/JndiLookupRemoval.svg)

## CVE-2021-45043
 HD-Network Real-time Monitoring System 2.0 allows ../ directory traversal to read /etc/shadow via the /language/lang s_Language parameter.



- [https://github.com/g30rgyth3d4rk/cve-2021-45043](https://github.com/g30rgyth3d4rk/cve-2021-45043) :  ![starts](https://img.shields.io/github/stars/g30rgyth3d4rk/cve-2021-45043.svg) ![forks](https://img.shields.io/github/forks/g30rgyth3d4rk/cve-2021-45043.svg)

## CVE-2021-44827
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/full-disclosure/CVE-2021-44827](https://github.com/full-disclosure/CVE-2021-44827) :  ![starts](https://img.shields.io/github/stars/full-disclosure/CVE-2021-44827.svg) ![forks](https://img.shields.io/github/forks/full-disclosure/CVE-2021-44827.svg)

## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.



- [https://github.com/fullhunt/log4j-scan](https://github.com/fullhunt/log4j-scan) :  ![starts](https://img.shields.io/github/stars/fullhunt/log4j-scan.svg) ![forks](https://img.shields.io/github/forks/fullhunt/log4j-scan.svg)

- [https://github.com/NCSC-NL/log4shell](https://github.com/NCSC-NL/log4shell) :  ![starts](https://img.shields.io/github/stars/NCSC-NL/log4shell.svg) ![forks](https://img.shields.io/github/forks/NCSC-NL/log4shell.svg)

- [https://github.com/kozmer/log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc) :  ![starts](https://img.shields.io/github/stars/kozmer/log4j-shell-poc.svg) ![forks](https://img.shields.io/github/forks/kozmer/log4j-shell-poc.svg)

- [https://github.com/christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app) :  ![starts](https://img.shields.io/github/stars/christophetd/log4shell-vulnerable-app.svg) ![forks](https://img.shields.io/github/forks/christophetd/log4shell-vulnerable-app.svg)

- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

- [https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words](https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words) :  ![starts](https://img.shields.io/github/stars/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words.svg) ![forks](https://img.shields.io/github/forks/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words.svg)

- [https://github.com/mergebase/log4j-detector](https://github.com/mergebase/log4j-detector) :  ![starts](https://img.shields.io/github/stars/mergebase/log4j-detector.svg) ![forks](https://img.shields.io/github/forks/mergebase/log4j-detector.svg)

- [https://github.com/corretto/hotpatch-for-apache-log4j2](https://github.com/corretto/hotpatch-for-apache-log4j2) :  ![starts](https://img.shields.io/github/stars/corretto/hotpatch-for-apache-log4j2.svg) ![forks](https://img.shields.io/github/forks/corretto/hotpatch-for-apache-log4j2.svg)

- [https://github.com/fox-it/log4j-finder](https://github.com/fox-it/log4j-finder) :  ![starts](https://img.shields.io/github/stars/fox-it/log4j-finder.svg) ![forks](https://img.shields.io/github/forks/fox-it/log4j-finder.svg)

- [https://github.com/hillu/local-log4j-vuln-scanner](https://github.com/hillu/local-log4j-vuln-scanner) :  ![starts](https://img.shields.io/github/stars/hillu/local-log4j-vuln-scanner.svg) ![forks](https://img.shields.io/github/forks/hillu/local-log4j-vuln-scanner.svg)

- [https://github.com/Diverto/nse-log4shell](https://github.com/Diverto/nse-log4shell) :  ![starts](https://img.shields.io/github/stars/Diverto/nse-log4shell.svg) ![forks](https://img.shields.io/github/forks/Diverto/nse-log4shell.svg)

- [https://github.com/jas502n/Log4j2-CVE-2021-44228](https://github.com/jas502n/Log4j2-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/jas502n/Log4j2-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/jas502n/Log4j2-CVE-2021-44228.svg)

- [https://github.com/leonjza/log4jpwn](https://github.com/leonjza/log4jpwn) :  ![starts](https://img.shields.io/github/stars/leonjza/log4jpwn.svg) ![forks](https://img.shields.io/github/forks/leonjza/log4jpwn.svg)

- [https://github.com/back2root/log4shell-rex](https://github.com/back2root/log4shell-rex) :  ![starts](https://img.shields.io/github/stars/back2root/log4shell-rex.svg) ![forks](https://img.shields.io/github/forks/back2root/log4shell-rex.svg)

- [https://github.com/rubo77/log4j_checker_beta](https://github.com/rubo77/log4j_checker_beta) :  ![starts](https://img.shields.io/github/stars/rubo77/log4j_checker_beta.svg) ![forks](https://img.shields.io/github/forks/rubo77/log4j_checker_beta.svg)

- [https://github.com/CERTCC/CVE-2021-44228_scanner](https://github.com/CERTCC/CVE-2021-44228_scanner) :  ![starts](https://img.shields.io/github/stars/CERTCC/CVE-2021-44228_scanner.svg) ![forks](https://img.shields.io/github/forks/CERTCC/CVE-2021-44228_scanner.svg)

- [https://github.com/HyCraftHD/Log4J-RCE-Proof-Of-Concept](https://github.com/HyCraftHD/Log4J-RCE-Proof-Of-Concept) :  ![starts](https://img.shields.io/github/stars/HyCraftHD/Log4J-RCE-Proof-Of-Concept.svg) ![forks](https://img.shields.io/github/forks/HyCraftHD/Log4J-RCE-Proof-Of-Concept.svg)

- [https://github.com/alexandre-lavoie/python-log4rce](https://github.com/alexandre-lavoie/python-log4rce) :  ![starts](https://img.shields.io/github/stars/alexandre-lavoie/python-log4rce.svg) ![forks](https://img.shields.io/github/forks/alexandre-lavoie/python-log4rce.svg)

- [https://github.com/adilsoybali/Log4j-RCE-Scanner](https://github.com/adilsoybali/Log4j-RCE-Scanner) :  ![starts](https://img.shields.io/github/stars/adilsoybali/Log4j-RCE-Scanner.svg) ![forks](https://img.shields.io/github/forks/adilsoybali/Log4j-RCE-Scanner.svg)

- [https://github.com/0xInfection/LogMePwn](https://github.com/0xInfection/LogMePwn) :  ![starts](https://img.shields.io/github/stars/0xInfection/LogMePwn.svg) ![forks](https://img.shields.io/github/forks/0xInfection/LogMePwn.svg)

- [https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes](https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes) :  ![starts](https://img.shields.io/github/stars/mubix/CVE-2021-44228-Log4Shell-Hashes.svg) ![forks](https://img.shields.io/github/forks/mubix/CVE-2021-44228-Log4Shell-Hashes.svg)

- [https://github.com/yahoo/check-log4j](https://github.com/yahoo/check-log4j) :  ![starts](https://img.shields.io/github/stars/yahoo/check-log4j.svg) ![forks](https://img.shields.io/github/forks/yahoo/check-log4j.svg)

- [https://github.com/takito1812/log4j-detect](https://github.com/takito1812/log4j-detect) :  ![starts](https://img.shields.io/github/stars/takito1812/log4j-detect.svg) ![forks](https://img.shields.io/github/forks/takito1812/log4j-detect.svg)

- [https://github.com/curated-intel/Log4Shell-IOCs](https://github.com/curated-intel/Log4Shell-IOCs) :  ![starts](https://img.shields.io/github/stars/curated-intel/Log4Shell-IOCs.svg) ![forks](https://img.shields.io/github/forks/curated-intel/Log4Shell-IOCs.svg)

- [https://github.com/NorthwaveSecurity/log4jcheck](https://github.com/NorthwaveSecurity/log4jcheck) :  ![starts](https://img.shields.io/github/stars/NorthwaveSecurity/log4jcheck.svg) ![forks](https://img.shields.io/github/forks/NorthwaveSecurity/log4jcheck.svg)

- [https://github.com/simonis/Log4jPatch](https://github.com/simonis/Log4jPatch) :  ![starts](https://img.shields.io/github/stars/simonis/Log4jPatch.svg) ![forks](https://img.shields.io/github/forks/simonis/Log4jPatch.svg)

- [https://github.com/boundaryx/cloudrasp-log4j2](https://github.com/boundaryx/cloudrasp-log4j2) :  ![starts](https://img.shields.io/github/stars/boundaryx/cloudrasp-log4j2.svg) ![forks](https://img.shields.io/github/forks/boundaryx/cloudrasp-log4j2.svg)

- [https://github.com/BinaryDefense/log4j-honeypot-flask](https://github.com/BinaryDefense/log4j-honeypot-flask) :  ![starts](https://img.shields.io/github/stars/BinaryDefense/log4j-honeypot-flask.svg) ![forks](https://img.shields.io/github/forks/BinaryDefense/log4j-honeypot-flask.svg)

- [https://github.com/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent](https://github.com/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent) :  ![starts](https://img.shields.io/github/stars/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent.svg) ![forks](https://img.shields.io/github/forks/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent.svg)

- [https://github.com/f0ng/log4j2burpscanner](https://github.com/f0ng/log4j2burpscanner) :  ![starts](https://img.shields.io/github/stars/f0ng/log4j2burpscanner.svg) ![forks](https://img.shields.io/github/forks/f0ng/log4j2burpscanner.svg)

- [https://github.com/MalwareTech/Log4jTools](https://github.com/MalwareTech/Log4jTools) :  ![starts](https://img.shields.io/github/stars/MalwareTech/Log4jTools.svg) ![forks](https://img.shields.io/github/forks/MalwareTech/Log4jTools.svg)

- [https://github.com/Adikso/minecraft-log4j-honeypot](https://github.com/Adikso/minecraft-log4j-honeypot) :  ![starts](https://img.shields.io/github/stars/Adikso/minecraft-log4j-honeypot.svg) ![forks](https://img.shields.io/github/forks/Adikso/minecraft-log4j-honeypot.svg)

- [https://github.com/nccgroup/log4j-jndi-be-gone](https://github.com/nccgroup/log4j-jndi-be-gone) :  ![starts](https://img.shields.io/github/stars/nccgroup/log4j-jndi-be-gone.svg) ![forks](https://img.shields.io/github/forks/nccgroup/log4j-jndi-be-gone.svg)

- [https://github.com/0-x-2-2/CVE-2021-44228](https://github.com/0-x-2-2/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/0-x-2-2/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/0-x-2-2/CVE-2021-44228.svg)

- [https://github.com/thomaspatzke/Log4Pot](https://github.com/thomaspatzke/Log4Pot) :  ![starts](https://img.shields.io/github/stars/thomaspatzke/Log4Pot.svg) ![forks](https://img.shields.io/github/forks/thomaspatzke/Log4Pot.svg)

- [https://github.com/0xDexter0us/Log4J-Scanner](https://github.com/0xDexter0us/Log4J-Scanner) :  ![starts](https://img.shields.io/github/stars/0xDexter0us/Log4J-Scanner.svg) ![forks](https://img.shields.io/github/forks/0xDexter0us/Log4J-Scanner.svg)

- [https://github.com/CreeperHost/Log4jPatcher](https://github.com/CreeperHost/Log4jPatcher) :  ![starts](https://img.shields.io/github/stars/CreeperHost/Log4jPatcher.svg) ![forks](https://img.shields.io/github/forks/CreeperHost/Log4jPatcher.svg)

- [https://github.com/authomize/log4j-log4shell-affected](https://github.com/authomize/log4j-log4shell-affected) :  ![starts](https://img.shields.io/github/stars/authomize/log4j-log4shell-affected.svg) ![forks](https://img.shields.io/github/forks/authomize/log4j-log4shell-affected.svg)

- [https://github.com/CodeShield-Security/Log4JShell-Bytecode-Detector](https://github.com/CodeShield-Security/Log4JShell-Bytecode-Detector) :  ![starts](https://img.shields.io/github/stars/CodeShield-Security/Log4JShell-Bytecode-Detector.svg) ![forks](https://img.shields.io/github/forks/CodeShield-Security/Log4JShell-Bytecode-Detector.svg)

- [https://github.com/RedDrip7/Log4Shell_CVE-2021-44228_related_attacks_IOCs](https://github.com/RedDrip7/Log4Shell_CVE-2021-44228_related_attacks_IOCs) :  ![starts](https://img.shields.io/github/stars/RedDrip7/Log4Shell_CVE-2021-44228_related_attacks_IOCs.svg) ![forks](https://img.shields.io/github/forks/RedDrip7/Log4Shell_CVE-2021-44228_related_attacks_IOCs.svg)

- [https://github.com/greymd/CVE-2021-44228](https://github.com/greymd/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/greymd/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/greymd/CVE-2021-44228.svg)

- [https://github.com/stripe/log4j-remediation-tools](https://github.com/stripe/log4j-remediation-tools) :  ![starts](https://img.shields.io/github/stars/stripe/log4j-remediation-tools.svg) ![forks](https://img.shields.io/github/forks/stripe/log4j-remediation-tools.svg)

- [https://github.com/dtact/divd-2021-00038--log4j-scanner](https://github.com/dtact/divd-2021-00038--log4j-scanner) :  ![starts](https://img.shields.io/github/stars/dtact/divd-2021-00038--log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/dtact/divd-2021-00038--log4j-scanner.svg)

- [https://github.com/infiniroot/nginx-mitigate-log4shell](https://github.com/infiniroot/nginx-mitigate-log4shell) :  ![starts](https://img.shields.io/github/stars/infiniroot/nginx-mitigate-log4shell.svg) ![forks](https://img.shields.io/github/forks/infiniroot/nginx-mitigate-log4shell.svg)

- [https://github.com/1lann/log4shelldetect](https://github.com/1lann/log4shelldetect) :  ![starts](https://img.shields.io/github/stars/1lann/log4shelldetect.svg) ![forks](https://img.shields.io/github/forks/1lann/log4shelldetect.svg)

- [https://github.com/alexbakker/log4shell-tools](https://github.com/alexbakker/log4shell-tools) :  ![starts](https://img.shields.io/github/stars/alexbakker/log4shell-tools.svg) ![forks](https://img.shields.io/github/forks/alexbakker/log4shell-tools.svg)

- [https://github.com/rwincey/CVE-2021-44228-Log4j-Payloads](https://github.com/rwincey/CVE-2021-44228-Log4j-Payloads) :  ![starts](https://img.shields.io/github/stars/rwincey/CVE-2021-44228-Log4j-Payloads.svg) ![forks](https://img.shields.io/github/forks/rwincey/CVE-2021-44228-Log4j-Payloads.svg)

- [https://github.com/bigsizeme/Log4j-check](https://github.com/bigsizeme/Log4j-check) :  ![starts](https://img.shields.io/github/stars/bigsizeme/Log4j-check.svg) ![forks](https://img.shields.io/github/forks/bigsizeme/Log4j-check.svg)

- [https://github.com/qingtengyun/cve-2021-44228-qingteng-online-patch](https://github.com/qingtengyun/cve-2021-44228-qingteng-online-patch) :  ![starts](https://img.shields.io/github/stars/qingtengyun/cve-2021-44228-qingteng-online-patch.svg) ![forks](https://img.shields.io/github/forks/qingtengyun/cve-2021-44228-qingteng-online-patch.svg)

- [https://github.com/redhuntlabs/Log4JHunt](https://github.com/redhuntlabs/Log4JHunt) :  ![starts](https://img.shields.io/github/stars/redhuntlabs/Log4JHunt.svg) ![forks](https://img.shields.io/github/forks/redhuntlabs/Log4JHunt.svg)

- [https://github.com/dwisiswant0/look4jar](https://github.com/dwisiswant0/look4jar) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/look4jar.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/look4jar.svg)

- [https://github.com/darkarnium/Log4j-CVE-Detect](https://github.com/darkarnium/Log4j-CVE-Detect) :  ![starts](https://img.shields.io/github/stars/darkarnium/Log4j-CVE-Detect.svg) ![forks](https://img.shields.io/github/forks/darkarnium/Log4j-CVE-Detect.svg)

- [https://github.com/mufeedvh/log4jail](https://github.com/mufeedvh/log4jail) :  ![starts](https://img.shields.io/github/stars/mufeedvh/log4jail.svg) ![forks](https://img.shields.io/github/forks/mufeedvh/log4jail.svg)

- [https://github.com/blake-fm/vcenter-log4j](https://github.com/blake-fm/vcenter-log4j) :  ![starts](https://img.shields.io/github/stars/blake-fm/vcenter-log4j.svg) ![forks](https://img.shields.io/github/forks/blake-fm/vcenter-log4j.svg)

- [https://github.com/tippexs/nginx-njs-waf-cve2021-44228](https://github.com/tippexs/nginx-njs-waf-cve2021-44228) :  ![starts](https://img.shields.io/github/stars/tippexs/nginx-njs-waf-cve2021-44228.svg) ![forks](https://img.shields.io/github/forks/tippexs/nginx-njs-waf-cve2021-44228.svg)

- [https://github.com/lhotari/log4shell-mitigation-tester](https://github.com/lhotari/log4shell-mitigation-tester) :  ![starts](https://img.shields.io/github/stars/lhotari/log4shell-mitigation-tester.svg) ![forks](https://img.shields.io/github/forks/lhotari/log4shell-mitigation-tester.svg)

- [https://github.com/Glease/Healer](https://github.com/Glease/Healer) :  ![starts](https://img.shields.io/github/stars/Glease/Healer.svg) ![forks](https://img.shields.io/github/forks/Glease/Healer.svg)

- [https://github.com/pedrohavay/exploit-CVE-2021-44228](https://github.com/pedrohavay/exploit-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/pedrohavay/exploit-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/pedrohavay/exploit-CVE-2021-44228.svg)

- [https://github.com/giterlizzi/nmap-log4shell](https://github.com/giterlizzi/nmap-log4shell) :  ![starts](https://img.shields.io/github/stars/giterlizzi/nmap-log4shell.svg) ![forks](https://img.shields.io/github/forks/giterlizzi/nmap-log4shell.svg)

- [https://github.com/For-ACGN/Log4Shell](https://github.com/For-ACGN/Log4Shell) :  ![starts](https://img.shields.io/github/stars/For-ACGN/Log4Shell.svg) ![forks](https://img.shields.io/github/forks/For-ACGN/Log4Shell.svg)

- [https://github.com/corelight/cve-2021-44228](https://github.com/corelight/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/corelight/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/corelight/cve-2021-44228.svg)

- [https://github.com/zsolt-halo/Log4J-Log4Shell-CVE-2021-44228-Spring-Boot-Test-Service](https://github.com/zsolt-halo/Log4J-Log4Shell-CVE-2021-44228-Spring-Boot-Test-Service) :  ![starts](https://img.shields.io/github/stars/zsolt-halo/Log4J-Log4Shell-CVE-2021-44228-Spring-Boot-Test-Service.svg) ![forks](https://img.shields.io/github/forks/zsolt-halo/Log4J-Log4Shell-CVE-2021-44228-Spring-Boot-Test-Service.svg)

- [https://github.com/o7-Fire/Log4Shell](https://github.com/o7-Fire/Log4Shell) :  ![starts](https://img.shields.io/github/stars/o7-Fire/Log4Shell.svg) ![forks](https://img.shields.io/github/forks/o7-Fire/Log4Shell.svg)

- [https://github.com/xsultan/log4jshield](https://github.com/xsultan/log4jshield) :  ![starts](https://img.shields.io/github/stars/xsultan/log4jshield.svg) ![forks](https://img.shields.io/github/forks/xsultan/log4jshield.svg)

- [https://github.com/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs](https://github.com/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs) :  ![starts](https://img.shields.io/github/stars/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs.svg) ![forks](https://img.shields.io/github/forks/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs.svg)

- [https://github.com/cyberxml/log4j-poc](https://github.com/cyberxml/log4j-poc) :  ![starts](https://img.shields.io/github/stars/cyberxml/log4j-poc.svg) ![forks](https://img.shields.io/github/forks/cyberxml/log4j-poc.svg)

- [https://github.com/toramanemre/log4j-rce-detect-waf-bypass](https://github.com/toramanemre/log4j-rce-detect-waf-bypass) :  ![starts](https://img.shields.io/github/stars/toramanemre/log4j-rce-detect-waf-bypass.svg) ![forks](https://img.shields.io/github/forks/toramanemre/log4j-rce-detect-waf-bypass.svg)

- [https://github.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228](https://github.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228.svg)

- [https://github.com/faisalfs10x/Log4j2-CVE-2021-44228-revshell](https://github.com/faisalfs10x/Log4j2-CVE-2021-44228-revshell) :  ![starts](https://img.shields.io/github/stars/faisalfs10x/Log4j2-CVE-2021-44228-revshell.svg) ![forks](https://img.shields.io/github/forks/faisalfs10x/Log4j2-CVE-2021-44228-revshell.svg)

- [https://github.com/twseptian/Spring-Boot-Log4j-CVE-2021-44228-Docker-Lab](https://github.com/twseptian/Spring-Boot-Log4j-CVE-2021-44228-Docker-Lab) :  ![starts](https://img.shields.io/github/stars/twseptian/Spring-Boot-Log4j-CVE-2021-44228-Docker-Lab.svg) ![forks](https://img.shields.io/github/forks/twseptian/Spring-Boot-Log4j-CVE-2021-44228-Docker-Lab.svg)

- [https://github.com/Azeemering/CVE-2021-44228-DFIR-Notes](https://github.com/Azeemering/CVE-2021-44228-DFIR-Notes) :  ![starts](https://img.shields.io/github/stars/Azeemering/CVE-2021-44228-DFIR-Notes.svg) ![forks](https://img.shields.io/github/forks/Azeemering/CVE-2021-44228-DFIR-Notes.svg)

- [https://github.com/ab0x90/CVE-2021-44228_PoC](https://github.com/ab0x90/CVE-2021-44228_PoC) :  ![starts](https://img.shields.io/github/stars/ab0x90/CVE-2021-44228_PoC.svg) ![forks](https://img.shields.io/github/forks/ab0x90/CVE-2021-44228_PoC.svg)

- [https://github.com/robertdebock/ansible-role-cve_2021_44228](https://github.com/robertdebock/ansible-role-cve_2021_44228) :  ![starts](https://img.shields.io/github/stars/robertdebock/ansible-role-cve_2021_44228.svg) ![forks](https://img.shields.io/github/forks/robertdebock/ansible-role-cve_2021_44228.svg)

- [https://github.com/hupe1980/scan4log4shell](https://github.com/hupe1980/scan4log4shell) :  ![starts](https://img.shields.io/github/stars/hupe1980/scan4log4shell.svg) ![forks](https://img.shields.io/github/forks/hupe1980/scan4log4shell.svg)

- [https://github.com/momos1337/Log4j-RCE](https://github.com/momos1337/Log4j-RCE) :  ![starts](https://img.shields.io/github/stars/momos1337/Log4j-RCE.svg) ![forks](https://img.shields.io/github/forks/momos1337/Log4j-RCE.svg)

- [https://github.com/claranet/ansible-role-log4shell](https://github.com/claranet/ansible-role-log4shell) :  ![starts](https://img.shields.io/github/stars/claranet/ansible-role-log4shell.svg) ![forks](https://img.shields.io/github/forks/claranet/ansible-role-log4shell.svg)

- [https://github.com/ssl/scan4log4j](https://github.com/ssl/scan4log4j) :  ![starts](https://img.shields.io/github/stars/ssl/scan4log4j.svg) ![forks](https://img.shields.io/github/forks/ssl/scan4log4j.svg)

- [https://github.com/qingtengyun/cve-2021-44228-qingteng-patch](https://github.com/qingtengyun/cve-2021-44228-qingteng-patch) :  ![starts](https://img.shields.io/github/stars/qingtengyun/cve-2021-44228-qingteng-patch.svg) ![forks](https://img.shields.io/github/forks/qingtengyun/cve-2021-44228-qingteng-patch.svg)

- [https://github.com/DXC-StrikeForce/Burp-Log4j-HammerTime](https://github.com/DXC-StrikeForce/Burp-Log4j-HammerTime) :  ![starts](https://img.shields.io/github/stars/DXC-StrikeForce/Burp-Log4j-HammerTime.svg) ![forks](https://img.shields.io/github/forks/DXC-StrikeForce/Burp-Log4j-HammerTime.svg)

- [https://github.com/jacobtread/L4J-Vuln-Patch](https://github.com/jacobtread/L4J-Vuln-Patch) :  ![starts](https://img.shields.io/github/stars/jacobtread/L4J-Vuln-Patch.svg) ![forks](https://img.shields.io/github/forks/jacobtread/L4J-Vuln-Patch.svg)

- [https://github.com/phoswald/sample-ldap-exploit](https://github.com/phoswald/sample-ldap-exploit) :  ![starts](https://img.shields.io/github/stars/phoswald/sample-ldap-exploit.svg) ![forks](https://img.shields.io/github/forks/phoswald/sample-ldap-exploit.svg)

- [https://github.com/nkoneko/VictimApp](https://github.com/nkoneko/VictimApp) :  ![starts](https://img.shields.io/github/stars/nkoneko/VictimApp.svg) ![forks](https://img.shields.io/github/forks/nkoneko/VictimApp.svg)

- [https://github.com/fireeye/CVE-2021-44228](https://github.com/fireeye/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/fireeye/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/fireeye/CVE-2021-44228.svg)

- [https://github.com/KeysAU/Get-log4j-Windows.ps1](https://github.com/KeysAU/Get-log4j-Windows.ps1) :  ![starts](https://img.shields.io/github/stars/KeysAU/Get-log4j-Windows.ps1.svg) ![forks](https://img.shields.io/github/forks/KeysAU/Get-log4j-Windows.ps1.svg)

- [https://github.com/rakutentech/jndi-ldap-test-server](https://github.com/rakutentech/jndi-ldap-test-server) :  ![starts](https://img.shields.io/github/stars/rakutentech/jndi-ldap-test-server.svg) ![forks](https://img.shields.io/github/forks/rakutentech/jndi-ldap-test-server.svg)

- [https://github.com/mitiga/log4shell-cloud-scanner](https://github.com/mitiga/log4shell-cloud-scanner) :  ![starts](https://img.shields.io/github/stars/mitiga/log4shell-cloud-scanner.svg) ![forks](https://img.shields.io/github/forks/mitiga/log4shell-cloud-scanner.svg)

- [https://github.com/kubearmor/log4j-CVE-2021-44228](https://github.com/kubearmor/log4j-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/kubearmor/log4j-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/kubearmor/log4j-CVE-2021-44228.svg)

- [https://github.com/lfama/log4j_checker](https://github.com/lfama/log4j_checker) :  ![starts](https://img.shields.io/github/stars/lfama/log4j_checker.svg) ![forks](https://img.shields.io/github/forks/lfama/log4j_checker.svg)

- [https://github.com/DragonSurvivalEU/RCE](https://github.com/DragonSurvivalEU/RCE) :  ![starts](https://img.shields.io/github/stars/DragonSurvivalEU/RCE.svg) ![forks](https://img.shields.io/github/forks/DragonSurvivalEU/RCE.svg)

- [https://github.com/KosmX/CVE-2021-44228-example](https://github.com/KosmX/CVE-2021-44228-example) :  ![starts](https://img.shields.io/github/stars/KosmX/CVE-2021-44228-example.svg) ![forks](https://img.shields.io/github/forks/KosmX/CVE-2021-44228-example.svg)

- [https://github.com/obscuritylabs/log4shell-poc-lab](https://github.com/obscuritylabs/log4shell-poc-lab) :  ![starts](https://img.shields.io/github/stars/obscuritylabs/log4shell-poc-lab.svg) ![forks](https://img.shields.io/github/forks/obscuritylabs/log4shell-poc-lab.svg)

- [https://github.com/immunityinc/Log4j-JNDIServer](https://github.com/immunityinc/Log4j-JNDIServer) :  ![starts](https://img.shields.io/github/stars/immunityinc/Log4j-JNDIServer.svg) ![forks](https://img.shields.io/github/forks/immunityinc/Log4j-JNDIServer.svg)

- [https://github.com/StandB/CVE-2021-44228-poc](https://github.com/StandB/CVE-2021-44228-poc) :  ![starts](https://img.shields.io/github/stars/StandB/CVE-2021-44228-poc.svg) ![forks](https://img.shields.io/github/forks/StandB/CVE-2021-44228-poc.svg)

- [https://github.com/AlexandreHeroux/Fix-CVE-2021-44228](https://github.com/AlexandreHeroux/Fix-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/AlexandreHeroux/Fix-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/AlexandreHeroux/Fix-CVE-2021-44228.svg)

- [https://github.com/sunnyvale-it/CVE-2021-44228-PoC](https://github.com/sunnyvale-it/CVE-2021-44228-PoC) :  ![starts](https://img.shields.io/github/stars/sunnyvale-it/CVE-2021-44228-PoC.svg) ![forks](https://img.shields.io/github/forks/sunnyvale-it/CVE-2021-44228-PoC.svg)

- [https://github.com/zlepper/CVE-2021-44228-Test-Server](https://github.com/zlepper/CVE-2021-44228-Test-Server) :  ![starts](https://img.shields.io/github/stars/zlepper/CVE-2021-44228-Test-Server.svg) ![forks](https://img.shields.io/github/forks/zlepper/CVE-2021-44228-Test-Server.svg)

- [https://github.com/ycdxsb/Log4Shell-CVE-2021-44228-ENV](https://github.com/ycdxsb/Log4Shell-CVE-2021-44228-ENV) :  ![starts](https://img.shields.io/github/stars/ycdxsb/Log4Shell-CVE-2021-44228-ENV.svg) ![forks](https://img.shields.io/github/forks/ycdxsb/Log4Shell-CVE-2021-44228-ENV.svg)

- [https://github.com/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228](https://github.com/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228.svg)

- [https://github.com/mss/log4shell-hotfix-side-effect](https://github.com/mss/log4shell-hotfix-side-effect) :  ![starts](https://img.shields.io/github/stars/mss/log4shell-hotfix-side-effect.svg) ![forks](https://img.shields.io/github/forks/mss/log4shell-hotfix-side-effect.svg)

- [https://github.com/Occamsec/log4j-checker](https://github.com/Occamsec/log4j-checker) :  ![starts](https://img.shields.io/github/stars/Occamsec/log4j-checker.svg) ![forks](https://img.shields.io/github/forks/Occamsec/log4j-checker.svg)

## CVE-2021-44217
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/Hyperkopite/CVE-2021-44217](https://github.com/Hyperkopite/CVE-2021-44217) :  ![starts](https://img.shields.io/github/stars/Hyperkopite/CVE-2021-44217.svg) ![forks](https://img.shields.io/github/forks/Hyperkopite/CVE-2021-44217.svg)

## CVE-2021-44077
 Zoho ManageEngine ServiceDesk Plus before 11306, ServiceDesk Plus MSP before 10530, and SupportCenter Plus before 11014 are vulnerable to unauthenticated remote code execution. This is related to /RestAPI URLs in a servlet, and ImportTechnicians in the Struts configuration.



- [https://github.com/horizon3ai/CVE-2021-44077](https://github.com/horizon3ai/CVE-2021-44077) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2021-44077.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2021-44077.svg)

## CVE-2021-43936
 The software allows the attacker to upload or transfer files of dangerous types to the WebHMI portal, that may be automatically processed within the product's environment or lead to arbitrary code execution.



- [https://github.com/LongWayHomie/CVE-2021-43936](https://github.com/LongWayHomie/CVE-2021-43936) :  ![starts](https://img.shields.io/github/stars/LongWayHomie/CVE-2021-43936.svg) ![forks](https://img.shields.io/github/forks/LongWayHomie/CVE-2021-43936.svg)

## CVE-2021-43883
 Windows Installer Elevation of Privilege Vulnerability



- [https://github.com/jbaines-r7/shakeitoff](https://github.com/jbaines-r7/shakeitoff) :  ![starts](https://img.shields.io/github/stars/jbaines-r7/shakeitoff.svg) ![forks](https://img.shields.io/github/forks/jbaines-r7/shakeitoff.svg)

## CVE-2021-43799
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/scopion/CVE-2021-43799](https://github.com/scopion/CVE-2021-43799) :  ![starts](https://img.shields.io/github/stars/scopion/CVE-2021-43799.svg) ![forks](https://img.shields.io/github/forks/scopion/CVE-2021-43799.svg)

## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.



- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)

- [https://github.com/jas502n/Grafana-CVE-2021-43798](https://github.com/jas502n/Grafana-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/jas502n/Grafana-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/jas502n/Grafana-CVE-2021-43798.svg)

- [https://github.com/A-D-Team/grafanaExp](https://github.com/A-D-Team/grafanaExp) :  ![starts](https://img.shields.io/github/stars/A-D-Team/grafanaExp.svg) ![forks](https://img.shields.io/github/forks/A-D-Team/grafanaExp.svg)

- [https://github.com/Mr-xn/CVE-2021-43798](https://github.com/Mr-xn/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2021-43798.svg)

- [https://github.com/zer0yu/CVE-2021-43798](https://github.com/zer0yu/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/zer0yu/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/zer0yu/CVE-2021-43798.svg)

- [https://github.com/ScorpionsMAX/CVE-2021-43798-Grafana-POC](https://github.com/ScorpionsMAX/CVE-2021-43798-Grafana-POC) :  ![starts](https://img.shields.io/github/stars/ScorpionsMAX/CVE-2021-43798-Grafana-POC.svg) ![forks](https://img.shields.io/github/forks/ScorpionsMAX/CVE-2021-43798-Grafana-POC.svg)

- [https://github.com/j-jasson/CVE-2021-43798-grafana_fileread](https://github.com/j-jasson/CVE-2021-43798-grafana_fileread) :  ![starts](https://img.shields.io/github/stars/j-jasson/CVE-2021-43798-grafana_fileread.svg) ![forks](https://img.shields.io/github/forks/j-jasson/CVE-2021-43798-grafana_fileread.svg)

- [https://github.com/taythebot/CVE-2021-43798](https://github.com/taythebot/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/taythebot/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/taythebot/CVE-2021-43798.svg)

- [https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798](https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/pedrohavay/exploit-grafana-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/pedrohavay/exploit-grafana-CVE-2021-43798.svg)

- [https://github.com/culprits/Grafana_POC-CVE-2021-43798](https://github.com/culprits/Grafana_POC-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/culprits/Grafana_POC-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/culprits/Grafana_POC-CVE-2021-43798.svg)

- [https://github.com/asaotomo/CVE-2021-43798-Grafana-Exp](https://github.com/asaotomo/CVE-2021-43798-Grafana-Exp) :  ![starts](https://img.shields.io/github/stars/asaotomo/CVE-2021-43798-Grafana-Exp.svg) ![forks](https://img.shields.io/github/forks/asaotomo/CVE-2021-43798-Grafana-Exp.svg)

- [https://github.com/kenuosec/grafanaExp](https://github.com/kenuosec/grafanaExp) :  ![starts](https://img.shields.io/github/stars/kenuosec/grafanaExp.svg) ![forks](https://img.shields.io/github/forks/kenuosec/grafanaExp.svg)

- [https://github.com/z3n70/CVE-2021-43798](https://github.com/z3n70/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/z3n70/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/z3n70/CVE-2021-43798.svg)

- [https://github.com/Ryze-T/CVE-2021-43798](https://github.com/Ryze-T/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/Ryze-T/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/Ryze-T/CVE-2021-43798.svg)

- [https://github.com/Awrrays/Grafana-CVE-2021-43798](https://github.com/Awrrays/Grafana-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/Awrrays/Grafana-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/Awrrays/Grafana-CVE-2021-43798.svg)

- [https://github.com/s1gh/CVE-2021-43798](https://github.com/s1gh/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/s1gh/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/s1gh/CVE-2021-43798.svg)

- [https://github.com/fanygit/Grafana-CVE-2021-43798Exp](https://github.com/fanygit/Grafana-CVE-2021-43798Exp) :  ![starts](https://img.shields.io/github/stars/fanygit/Grafana-CVE-2021-43798Exp.svg) ![forks](https://img.shields.io/github/forks/fanygit/Grafana-CVE-2021-43798Exp.svg)

- [https://github.com/k3rwin/CVE-2021-43798-Grafana-](https://github.com/k3rwin/CVE-2021-43798-Grafana-) :  ![starts](https://img.shields.io/github/stars/k3rwin/CVE-2021-43798-Grafana-.svg) ![forks](https://img.shields.io/github/forks/k3rwin/CVE-2021-43798-Grafana-.svg)

- [https://github.com/gixxyboy/CVE-2021-43798](https://github.com/gixxyboy/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/gixxyboy/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/gixxyboy/CVE-2021-43798.svg)

- [https://github.com/LongWayHomie/CVE-2021-43798](https://github.com/LongWayHomie/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/LongWayHomie/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/LongWayHomie/CVE-2021-43798.svg)

- [https://github.com/julesbozouklian/CVE-2021-43798](https://github.com/julesbozouklian/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/julesbozouklian/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/julesbozouklian/CVE-2021-43798.svg)

- [https://github.com/JiuBanSec/Grafana-CVE-2021-43798](https://github.com/JiuBanSec/Grafana-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/JiuBanSec/Grafana-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/JiuBanSec/Grafana-CVE-2021-43798.svg)

- [https://github.com/lfz97/CVE-2021-43798-Grafana-File-Read](https://github.com/lfz97/CVE-2021-43798-Grafana-File-Read) :  ![starts](https://img.shields.io/github/stars/lfz97/CVE-2021-43798-Grafana-File-Read.svg) ![forks](https://img.shields.io/github/forks/lfz97/CVE-2021-43798-Grafana-File-Read.svg)

## CVE-2021-43778
 Barcode is a GLPI plugin for printing barcodes and QR codes. GLPI instances version 2.x prior to version 2.6.1 with the barcode plugin installed are vulnerable to a path traversal vulnerability. This issue was patched in version 2.6.1. As a workaround, delete the `front/send.php` file.



- [https://github.com/AK-blank/CVE-2021-43778](https://github.com/AK-blank/CVE-2021-43778) :  ![starts](https://img.shields.io/github/stars/AK-blank/CVE-2021-43778.svg) ![forks](https://img.shields.io/github/forks/AK-blank/CVE-2021-43778.svg)

## CVE-2021-43617
 Laravel Framework through 8.70.2 does not sufficiently block the upload of executable PHP content because Illuminate/Validation/Concerns/ValidatesAttributes.php lacks a check for .phar files, which are handled as application/x-httpd-php on systems based on Debian. NOTE: this CVE Record is for Laravel Framework, and is unrelated to any reports concerning incorrectly written user applications for image upload.



- [https://github.com/kombat1/CVE-2021-43617](https://github.com/kombat1/CVE-2021-43617) :  ![starts](https://img.shields.io/github/stars/kombat1/CVE-2021-43617.svg) ![forks](https://img.shields.io/github/forks/kombat1/CVE-2021-43617.svg)

## CVE-2021-43616
 The npm ci command in npm 7.x and 8.x through 8.1.3 proceeds with an installation even if dependency information in package-lock.json differs from package.json. This behavior is inconsistent with the documentation, and makes it easier for attackers to install malware that was supposed to have been blocked by an exact version match requirement in package-lock.json.



- [https://github.com/icatalina/CVE-2021-43616](https://github.com/icatalina/CVE-2021-43616) :  ![starts](https://img.shields.io/github/stars/icatalina/CVE-2021-43616.svg) ![forks](https://img.shields.io/github/forks/icatalina/CVE-2021-43616.svg)

## CVE-2021-43557
 The uri-block plugin in Apache APISIX before 2.10.2 uses $request_uri without verification. The $request_uri is the full original request URI without normalization. This makes it possible to construct a URI to bypass the block list on some occasions. For instance, when the block list contains &quot;^/internal/&quot;, a URI like `//internal/` can be used to bypass it. Some other plugins also have the same issue. And it may affect the developer's custom plugin.



- [https://github.com/xvnpw/k8s-CVE-2021-43557-poc](https://github.com/xvnpw/k8s-CVE-2021-43557-poc) :  ![starts](https://img.shields.io/github/stars/xvnpw/k8s-CVE-2021-43557-poc.svg) ![forks](https://img.shields.io/github/forks/xvnpw/k8s-CVE-2021-43557-poc.svg)

## CVE-2021-43471
 In Canon LBP223 printers, the System Manager Mode login does not require an account password or PIN. An attacker can remotely shut down the device after entering the background, creating a denial of service vulnerability.



- [https://github.com/cxaqhq/CVE-2021-43471](https://github.com/cxaqhq/CVE-2021-43471) :  ![starts](https://img.shields.io/github/stars/cxaqhq/CVE-2021-43471.svg) ![forks](https://img.shields.io/github/forks/cxaqhq/CVE-2021-43471.svg)

## CVE-2021-43469
 VINGA WR-N300U 77.102.1.4853 is affected by a command execution vulnerability in the goahead component.



- [https://github.com/badboycxcc/CVE-2021-43469](https://github.com/badboycxcc/CVE-2021-43469) :  ![starts](https://img.shields.io/github/stars/badboycxcc/CVE-2021-43469.svg) ![forks](https://img.shields.io/github/forks/badboycxcc/CVE-2021-43469.svg)

## CVE-2021-43361
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/bartutku/CVE-2021-43361](https://github.com/bartutku/CVE-2021-43361) :  ![starts](https://img.shields.io/github/stars/bartutku/CVE-2021-43361.svg) ![forks](https://img.shields.io/github/forks/bartutku/CVE-2021-43361.svg)

## CVE-2021-43326
 Automox Agent before 32 on Windows incorrectly sets permissions on a temporary directory.



- [https://github.com/gfoss/CVE-2021-43326_Exploit](https://github.com/gfoss/CVE-2021-43326_Exploit) :  ![starts](https://img.shields.io/github/stars/gfoss/CVE-2021-43326_Exploit.svg) ![forks](https://img.shields.io/github/forks/gfoss/CVE-2021-43326_Exploit.svg)

## CVE-2021-43267
 An issue was discovered in net/tipc/crypto.c in the Linux kernel before 5.14.16. The Transparent Inter-Process Communication (TIPC) functionality allows remote attackers to exploit insufficient validation of user-supplied sizes for the MSG_CRYPTO message type.



- [https://github.com/ohnonoyesyes/CVE-2021-43267](https://github.com/ohnonoyesyes/CVE-2021-43267) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2021-43267.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2021-43267.svg)

- [https://github.com/DarkSprings/CVE-2021-43267-POC](https://github.com/DarkSprings/CVE-2021-43267-POC) :  ![starts](https://img.shields.io/github/stars/DarkSprings/CVE-2021-43267-POC.svg) ![forks](https://img.shields.io/github/forks/DarkSprings/CVE-2021-43267-POC.svg)

## CVE-2021-43141
 Cross Site Scripting (XSS) vulnerability exists in Sourcecodester Simple Subscription Website 1.0 via the id parameter in plan_application.



- [https://github.com/Dir0x/CVE-2021-43141](https://github.com/Dir0x/CVE-2021-43141) :  ![starts](https://img.shields.io/github/stars/Dir0x/CVE-2021-43141.svg) ![forks](https://img.shields.io/github/forks/Dir0x/CVE-2021-43141.svg)

## CVE-2021-43140
 SQL Injection vulnerability exists in Sourcecodester. Simple Subscription Website 1.0. via the login.



- [https://github.com/Dir0x/CVE-2021-43140](https://github.com/Dir0x/CVE-2021-43140) :  ![starts](https://img.shields.io/github/stars/Dir0x/CVE-2021-43140.svg) ![forks](https://img.shields.io/github/forks/Dir0x/CVE-2021-43140.svg)

## CVE-2021-43032
 In XenForo through 2.2.7, a threat actor with access to the admin panel can create a new Advertisement via the Advertising function, and save an XSS payload in the body of the HTML document. This payload will execute globally on the client side.



- [https://github.com/SakuraSamuraii/CVE-2021-43032](https://github.com/SakuraSamuraii/CVE-2021-43032) :  ![starts](https://img.shields.io/github/stars/SakuraSamuraii/CVE-2021-43032.svg) ![forks](https://img.shields.io/github/forks/SakuraSamuraii/CVE-2021-43032.svg)

## CVE-2021-42835
 An issue was discovered in Plex Media Server through 1.24.4.5081-e362dc1ee. An attacker (with a foothold in a endpoint via a low-privileged user account) can access the exposed RPC service of the update service component. This RPC functionality allows the attacker to interact with the RPC functionality and execute code from a path of his choice (local, or remote via SMB) because of a TOCTOU race condition. This code execution is in the context of the Plex update service (which runs as SYSTEM).



- [https://github.com/netanelc305/PlEXcalaison](https://github.com/netanelc305/PlEXcalaison) :  ![starts](https://img.shields.io/github/stars/netanelc305/PlEXcalaison.svg) ![forks](https://img.shields.io/github/forks/netanelc305/PlEXcalaison.svg)

## CVE-2021-42694
 An issue was discovered in the character definitions of the Unicode Specification through 14.0. The specification allows an adversary to produce source code identifiers such as function names using homoglyphs that render visually identical to a target identifier. Adversaries can leverage this to inject code via adversarial identifier definitions in upstream software dependencies invoked deceptively in downstream software.



- [https://github.com/js-on/CVE-2021-42694](https://github.com/js-on/CVE-2021-42694) :  ![starts](https://img.shields.io/github/stars/js-on/CVE-2021-42694.svg) ![forks](https://img.shields.io/github/forks/js-on/CVE-2021-42694.svg)

- [https://github.com/hffaust/CVE-2021-42574_and_CVE-2021-42694](https://github.com/hffaust/CVE-2021-42574_and_CVE-2021-42694) :  ![starts](https://img.shields.io/github/stars/hffaust/CVE-2021-42574_and_CVE-2021-42694.svg) ![forks](https://img.shields.io/github/forks/hffaust/CVE-2021-42574_and_CVE-2021-42694.svg)

- [https://github.com/pierDipi/unicode-control-characters-action](https://github.com/pierDipi/unicode-control-characters-action) :  ![starts](https://img.shields.io/github/stars/pierDipi/unicode-control-characters-action.svg) ![forks](https://img.shields.io/github/forks/pierDipi/unicode-control-characters-action.svg)

## CVE-2021-42671
 An incorrect access control vulnerability exists in Sourcecodester Engineers Online Portal in PHP in nia_munoz_monitoring_system/admin/uploads. An attacker can leverage this vulnerability in order to bypass access controls and access all the files uploaded to the web server without the need of authentication or authorization.



- [https://github.com/TheHackingRabbi/CVE-2021-42671](https://github.com/TheHackingRabbi/CVE-2021-42671) :  ![starts](https://img.shields.io/github/stars/TheHackingRabbi/CVE-2021-42671.svg) ![forks](https://img.shields.io/github/forks/TheHackingRabbi/CVE-2021-42671.svg)

## CVE-2021-42670
 A SQL injection vulnerability exists in Sourcecodester Engineers Online Portal in PHP via the id parameter to the announcements_student.php web page. As a result a malicious user can extract sensitive data from the web server and in some cases use this vulnerability in order to get a remote code execution on the remote web server.



- [https://github.com/TheHackingRabbi/CVE-2021-42670](https://github.com/TheHackingRabbi/CVE-2021-42670) :  ![starts](https://img.shields.io/github/stars/TheHackingRabbi/CVE-2021-42670.svg) ![forks](https://img.shields.io/github/forks/TheHackingRabbi/CVE-2021-42670.svg)

## CVE-2021-42669
 A file upload vulnerability exists in Sourcecodester Engineers Online Portal in PHP via dashboard_teacher.php, which allows changing the avatar through teacher_avatar.php. Once an avatar gets uploaded it is getting uploaded to the /admin/uploads/ directory, and is accessible by all users. By uploading a php webshell containing &quot;&lt;?php system($_GET[&quot;cmd&quot;]); ?&gt;&quot; the attacker can execute commands on the web server with - /admin/uploads/php-webshell?cmd=id.



- [https://github.com/TheHackingRabbi/CVE-2021-42669](https://github.com/TheHackingRabbi/CVE-2021-42669) :  ![starts](https://img.shields.io/github/stars/TheHackingRabbi/CVE-2021-42669.svg) ![forks](https://img.shields.io/github/forks/TheHackingRabbi/CVE-2021-42669.svg)

## CVE-2021-42668
 A SQL Injection vulnerability exists in Sourcecodester Engineers Online Portal in PHP via the id parameter in the my_classmates.php web page.. As a result, an attacker can extract sensitive data from the web server and in some cases can use this vulnerability in order to get a remote code execution on the remote web server.



- [https://github.com/TheHackingRabbi/CVE-2021-42668](https://github.com/TheHackingRabbi/CVE-2021-42668) :  ![starts](https://img.shields.io/github/stars/TheHackingRabbi/CVE-2021-42668.svg) ![forks](https://img.shields.io/github/forks/TheHackingRabbi/CVE-2021-42668.svg)

## CVE-2021-42667
 A SQL Injection vulnerability exists in Sourcecodester Online Event Booking and Reservation System in PHP in event-management/views. An attacker can leverage this vulnerability in order to manipulate the sql query performed. As a result he can extract sensitive data from the web server and in some cases he can use this vulnerability in order to get a remote code execution on the remote web server.



- [https://github.com/TheHackingRabbi/CVE-2021-42667](https://github.com/TheHackingRabbi/CVE-2021-42667) :  ![starts](https://img.shields.io/github/stars/TheHackingRabbi/CVE-2021-42667.svg) ![forks](https://img.shields.io/github/forks/TheHackingRabbi/CVE-2021-42667.svg)

## CVE-2021-42666
 A SQL Injection vulnerability exists in Sourcecodester Engineers Online Portal in PHP via the id parameter to quiz_question.php, which could let a malicious user extract sensitive data from the web server and in some cases use this vulnerability in order to get a remote code execution on the remote web server.



- [https://github.com/TheHackingRabbi/CVE-2021-42666](https://github.com/TheHackingRabbi/CVE-2021-42666) :  ![starts](https://img.shields.io/github/stars/TheHackingRabbi/CVE-2021-42666.svg) ![forks](https://img.shields.io/github/forks/TheHackingRabbi/CVE-2021-42666.svg)

## CVE-2021-42665
 An SQL Injection vulnerability exists in Sourcecodester Engineers Online Portal in PHP via the login form inside of index.php, which can allow an attacker to bypass authentication.



- [https://github.com/TheHackingRabbi/CVE-2021-42665](https://github.com/TheHackingRabbi/CVE-2021-42665) :  ![starts](https://img.shields.io/github/stars/TheHackingRabbi/CVE-2021-42665.svg) ![forks](https://img.shields.io/github/forks/TheHackingRabbi/CVE-2021-42665.svg)

## CVE-2021-42664
 A Stored Cross Site Scripting (XSS) Vulneraibiilty exists in Sourcecodester Engineers Online Portal in PHP via the (1) Quiz title and (2) quiz description parameters to add_quiz.php. An attacker can leverage this vulnerability in order to run javascript commands on the web server surfers behalf, which can lead to cookie stealing and more.



- [https://github.com/TheHackingRabbi/CVE-2021-42664](https://github.com/TheHackingRabbi/CVE-2021-42664) :  ![starts](https://img.shields.io/github/stars/TheHackingRabbi/CVE-2021-42664.svg) ![forks](https://img.shields.io/github/forks/TheHackingRabbi/CVE-2021-42664.svg)

## CVE-2021-42663
 An HTML injection vulnerability exists in Sourcecodester Online Event Booking and Reservation System in PHP/MySQL via the msg parameter to /event-management/index.php. An attacker can leverage this vulnerability in order to change the visibility of the website. Once the target user clicks on a given link he will display the content of the HTML code of the attacker's choice.



- [https://github.com/TheHackingRabbi/CVE-2021-42663](https://github.com/TheHackingRabbi/CVE-2021-42663) :  ![starts](https://img.shields.io/github/stars/TheHackingRabbi/CVE-2021-42663.svg) ![forks](https://img.shields.io/github/forks/TheHackingRabbi/CVE-2021-42663.svg)

## CVE-2021-42662
 A Stored Cross Site Scripting (XSS) vulnerability exists in Sourcecodester Online Event Booking and Reservation System in PHP/MySQL via the Holiday reason parameter. An attacker can leverage this vulnerability in order to run javascript commands on the web server surfers behalf, which can lead to cookie stealing and more.



- [https://github.com/TheHackingRabbi/CVE-2021-42662](https://github.com/TheHackingRabbi/CVE-2021-42662) :  ![starts](https://img.shields.io/github/stars/TheHackingRabbi/CVE-2021-42662.svg) ![forks](https://img.shields.io/github/forks/TheHackingRabbi/CVE-2021-42662.svg)

## CVE-2021-42574
 An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It permits the visual reordering of characters via control sequences, which can be used to craft source code that renders different logic than the logical ordering of tokens ingested by compilers and interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted vulnerabilities are introduced invisibly to human reviewers.



- [https://github.com/js-on/CVE-2021-42574](https://github.com/js-on/CVE-2021-42574) :  ![starts](https://img.shields.io/github/stars/js-on/CVE-2021-42574.svg) ![forks](https://img.shields.io/github/forks/js-on/CVE-2021-42574.svg)

- [https://github.com/maweil/bidi_char_detector](https://github.com/maweil/bidi_char_detector) :  ![starts](https://img.shields.io/github/stars/maweil/bidi_char_detector.svg) ![forks](https://img.shields.io/github/forks/maweil/bidi_char_detector.svg)

- [https://github.com/waseeld/CVE-2021-42574](https://github.com/waseeld/CVE-2021-42574) :  ![starts](https://img.shields.io/github/stars/waseeld/CVE-2021-42574.svg) ![forks](https://img.shields.io/github/forks/waseeld/CVE-2021-42574.svg)

- [https://github.com/shiomiyan/CVE-2021-42574](https://github.com/shiomiyan/CVE-2021-42574) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-42574.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-42574.svg)

- [https://github.com/hffaust/CVE-2021-42574_and_CVE-2021-42694](https://github.com/hffaust/CVE-2021-42574_and_CVE-2021-42694) :  ![starts](https://img.shields.io/github/stars/hffaust/CVE-2021-42574_and_CVE-2021-42694.svg) ![forks](https://img.shields.io/github/forks/hffaust/CVE-2021-42574_and_CVE-2021-42694.svg)

- [https://github.com/pierDipi/unicode-control-characters-action](https://github.com/pierDipi/unicode-control-characters-action) :  ![starts](https://img.shields.io/github/stars/pierDipi/unicode-control-characters-action.svg) ![forks](https://img.shields.io/github/forks/pierDipi/unicode-control-characters-action.svg)

## CVE-2021-42550
 In logback version 1.2.7 and prior versions, an attacker with the required privileges to edit configurations files could craft a malicious configuration allowing to execute arbitrary code loaded from LDAP servers.



- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

## CVE-2021-42342
 An issue was discovered in GoAhead 4.x and 5.x before 5.1.5. In the file upload filter, user form variables can be passed to CGI scripts without being prefixed with the CGI prefix. This permits tunneling untrusted environment variables into vulnerable CGI scripts.



- [https://github.com/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-](https://github.com/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-) :  ![starts](https://img.shields.io/github/stars/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-.svg) ![forks](https://img.shields.io/github/forks/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-.svg)

## CVE-2021-42327
 dp_link_settings_write in drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_debugfs.c in the Linux kernel through 5.14.14 allows a heap-based buffer overflow by an attacker who can write a string to the AMD GPU display drivers debug filesystem. There are no checks on size within parse_write_buffer_into_params when it uses the size of copy_from_user to copy a userspace buffer into a 40-byte heap buffer.



- [https://github.com/docfate111/CVE-2021-42327](https://github.com/docfate111/CVE-2021-42327) :  ![starts](https://img.shields.io/github/stars/docfate111/CVE-2021-42327.svg) ![forks](https://img.shields.io/github/forks/docfate111/CVE-2021-42327.svg)

## CVE-2021-42325
 Froxlor through 0.10.29.1 allows SQL injection in Database/Manager/DbManagerMySQL.php via a custom DB name.



- [https://github.com/AK-blank/CVE-2021-42325-](https://github.com/AK-blank/CVE-2021-42325-) :  ![starts](https://img.shields.io/github/stars/AK-blank/CVE-2021-42325-.svg) ![forks](https://img.shields.io/github/forks/AK-blank/CVE-2021-42325-.svg)

## CVE-2021-42321
 Microsoft Exchange Server Remote Code Execution Vulnerability



- [https://github.com/DarkSprings/CVE-2021-42321](https://github.com/DarkSprings/CVE-2021-42321) :  ![starts](https://img.shields.io/github/stars/DarkSprings/CVE-2021-42321.svg) ![forks](https://img.shields.io/github/forks/DarkSprings/CVE-2021-42321.svg)

## CVE-2021-42292
 Microsoft Excel Security Feature Bypass Vulnerability



- [https://github.com/corelight/CVE-2021-42292](https://github.com/corelight/CVE-2021-42292) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2021-42292.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2021-42292.svg)

## CVE-2021-42287
 Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42278, CVE-2021-42282, CVE-2021-42291.



- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)

- [https://github.com/cube0x0/noPac](https://github.com/cube0x0/noPac) :  ![starts](https://img.shields.io/github/stars/cube0x0/noPac.svg) ![forks](https://img.shields.io/github/forks/cube0x0/noPac.svg)

- [https://github.com/WazeHell/sam-the-admin](https://github.com/WazeHell/sam-the-admin) :  ![starts](https://img.shields.io/github/stars/WazeHell/sam-the-admin.svg) ![forks](https://img.shields.io/github/forks/WazeHell/sam-the-admin.svg)

- [https://github.com/Ridter/noPac](https://github.com/Ridter/noPac) :  ![starts](https://img.shields.io/github/stars/Ridter/noPac.svg) ![forks](https://img.shields.io/github/forks/Ridter/noPac.svg)

- [https://github.com/waterrr/noPac](https://github.com/waterrr/noPac) :  ![starts](https://img.shields.io/github/stars/waterrr/noPac.svg) ![forks](https://img.shields.io/github/forks/waterrr/noPac.svg)

## CVE-2021-42278
 Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42282, CVE-2021-42287, CVE-2021-42291.



- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)

- [https://github.com/cube0x0/noPac](https://github.com/cube0x0/noPac) :  ![starts](https://img.shields.io/github/stars/cube0x0/noPac.svg) ![forks](https://img.shields.io/github/forks/cube0x0/noPac.svg)

- [https://github.com/WazeHell/sam-the-admin](https://github.com/WazeHell/sam-the-admin) :  ![starts](https://img.shields.io/github/stars/WazeHell/sam-the-admin.svg) ![forks](https://img.shields.io/github/forks/WazeHell/sam-the-admin.svg)

- [https://github.com/ly4k/Pachine](https://github.com/ly4k/Pachine) :  ![starts](https://img.shields.io/github/stars/ly4k/Pachine.svg) ![forks](https://img.shields.io/github/forks/ly4k/Pachine.svg)

- [https://github.com/Ridter/noPac](https://github.com/Ridter/noPac) :  ![starts](https://img.shields.io/github/stars/Ridter/noPac.svg) ![forks](https://img.shields.io/github/forks/Ridter/noPac.svg)

- [https://github.com/waterrr/noPac](https://github.com/waterrr/noPac) :  ![starts](https://img.shields.io/github/stars/waterrr/noPac.svg) ![forks](https://img.shields.io/github/forks/waterrr/noPac.svg)

## CVE-2021-42261
 Revisor Video Management System (VMS) before 2.0.0 has a directory traversal vulnerability. Successful exploitation could allow an attacker to traverse the file system to access files or directories that are outside of restricted directory on the remote server. This could lead to the disclosure of sensitive data on the vulnerable server.



- [https://github.com/jet-pentest/CVE-2021-42261](https://github.com/jet-pentest/CVE-2021-42261) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2021-42261.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2021-42261.svg)

## CVE-2021-42071
 In Visual Tools DVR VX16 4.2.28.0, an unauthenticated attacker can achieve remote command execution via shell metacharacters in the cgi-bin/slogin/login.py User-Agent HTTP header.



- [https://github.com/adubaldo/CVE-2021-42071](https://github.com/adubaldo/CVE-2021-42071) :  ![starts](https://img.shields.io/github/stars/adubaldo/CVE-2021-42071.svg) ![forks](https://img.shields.io/github/forks/adubaldo/CVE-2021-42071.svg)

## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.



- [https://github.com/inbug-team/CVE-2021-41773_CVE-2021-42013](https://github.com/inbug-team/CVE-2021-41773_CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/inbug-team/CVE-2021-41773_CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/inbug-team/CVE-2021-41773_CVE-2021-42013.svg)

- [https://github.com/MrCl0wnLab/SimplesApachePathTraversal](https://github.com/MrCl0wnLab/SimplesApachePathTraversal) :  ![starts](https://img.shields.io/github/stars/MrCl0wnLab/SimplesApachePathTraversal.svg) ![forks](https://img.shields.io/github/forks/MrCl0wnLab/SimplesApachePathTraversal.svg)

- [https://github.com/im-hanzou/apachrot](https://github.com/im-hanzou/apachrot) :  ![starts](https://img.shields.io/github/stars/im-hanzou/apachrot.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/apachrot.svg)

- [https://github.com/Ls4ss/CVE-2021-41773_CVE-2021-42013](https://github.com/Ls4ss/CVE-2021-41773_CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/Ls4ss/CVE-2021-41773_CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/Ls4ss/CVE-2021-41773_CVE-2021-42013.svg)

- [https://github.com/Vulnmachines/cve-2021-42013](https://github.com/Vulnmachines/cve-2021-42013) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/cve-2021-42013.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/cve-2021-42013.svg)

- [https://github.com/Zeop-CyberSec/apache_normalize_path](https://github.com/Zeop-CyberSec/apache_normalize_path) :  ![starts](https://img.shields.io/github/stars/Zeop-CyberSec/apache_normalize_path.svg) ![forks](https://img.shields.io/github/forks/Zeop-CyberSec/apache_normalize_path.svg)

- [https://github.com/andrea-mattioli/apache-exploit-CVE-2021-42013](https://github.com/andrea-mattioli/apache-exploit-CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/andrea-mattioli/apache-exploit-CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/andrea-mattioli/apache-exploit-CVE-2021-42013.svg)

- [https://github.com/ahmad4fifz/CVE-2021-42013](https://github.com/ahmad4fifz/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/ahmad4fifz/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/ahmad4fifz/CVE-2021-42013.svg)

- [https://github.com/theLSA/apache-httpd-path-traversal-checker](https://github.com/theLSA/apache-httpd-path-traversal-checker) :  ![starts](https://img.shields.io/github/stars/theLSA/apache-httpd-path-traversal-checker.svg) ![forks](https://img.shields.io/github/forks/theLSA/apache-httpd-path-traversal-checker.svg)

- [https://github.com/5gstudent/cve-2021-41773-and-cve-2021-42013](https://github.com/5gstudent/cve-2021-41773-and-cve-2021-42013) :  ![starts](https://img.shields.io/github/stars/5gstudent/cve-2021-41773-and-cve-2021-42013.svg) ![forks](https://img.shields.io/github/forks/5gstudent/cve-2021-41773-and-cve-2021-42013.svg)

- [https://github.com/TheLastVvV/CVE-2021-42013_Reverse-Shell](https://github.com/TheLastVvV/CVE-2021-42013_Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-42013_Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-42013_Reverse-Shell.svg)

- [https://github.com/Hydragyrum/CVE-2021-41773-Playground](https://github.com/Hydragyrum/CVE-2021-41773-Playground) :  ![starts](https://img.shields.io/github/stars/Hydragyrum/CVE-2021-41773-Playground.svg) ![forks](https://img.shields.io/github/forks/Hydragyrum/CVE-2021-41773-Playground.svg)

- [https://github.com/ksanchezcld/httpd-2.4.49](https://github.com/ksanchezcld/httpd-2.4.49) :  ![starts](https://img.shields.io/github/stars/ksanchezcld/httpd-2.4.49.svg) ![forks](https://img.shields.io/github/forks/ksanchezcld/httpd-2.4.49.svg)

- [https://github.com/vulf/CVE-2021-41773_42013](https://github.com/vulf/CVE-2021-41773_42013) :  ![starts](https://img.shields.io/github/stars/vulf/CVE-2021-41773_42013.svg) ![forks](https://img.shields.io/github/forks/vulf/CVE-2021-41773_42013.svg)

- [https://github.com/TheLastVvV/CVE-2021-42013](https://github.com/TheLastVvV/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-42013.svg)

- [https://github.com/robotsense1337/CVE-2021-42013](https://github.com/robotsense1337/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/robotsense1337/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/robotsense1337/CVE-2021-42013.svg)

- [https://github.com/corelight/CVE-2021-41773](https://github.com/corelight/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2021-41773.svg)

- [https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt](https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt) :  ![starts](https://img.shields.io/github/stars/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt.svg) ![forks](https://img.shields.io/github/forks/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt.svg)

- [https://github.com/LayarKacaSiber/CVE-2021-42013](https://github.com/LayarKacaSiber/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-42013.svg)

- [https://github.com/walnutsecurity/cve-2021-42013](https://github.com/walnutsecurity/cve-2021-42013) :  ![starts](https://img.shields.io/github/stars/walnutsecurity/cve-2021-42013.svg) ![forks](https://img.shields.io/github/forks/walnutsecurity/cve-2021-42013.svg)

- [https://github.com/xMohamed0/CVE-2021-42013-ApacheRCE](https://github.com/xMohamed0/CVE-2021-42013-ApacheRCE) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-42013-ApacheRCE.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-42013-ApacheRCE.svg)

- [https://github.com/twseptian/CVE-2021-42013-Docker-Lab](https://github.com/twseptian/CVE-2021-42013-Docker-Lab) :  ![starts](https://img.shields.io/github/stars/twseptian/CVE-2021-42013-Docker-Lab.svg) ![forks](https://img.shields.io/github/forks/twseptian/CVE-2021-42013-Docker-Lab.svg)

- [https://github.com/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit](https://github.com/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit) :  ![starts](https://img.shields.io/github/stars/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit.svg) ![forks](https://img.shields.io/github/forks/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit.svg)

## CVE-2021-42008
 The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.



- [https://github.com/0xdevil/CVE-2021-42008](https://github.com/0xdevil/CVE-2021-42008) :  ![starts](https://img.shields.io/github/stars/0xdevil/CVE-2021-42008.svg) ![forks](https://img.shields.io/github/forks/0xdevil/CVE-2021-42008.svg)

- [https://github.com/numanturle/CVE-2021-42008](https://github.com/numanturle/CVE-2021-42008) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2021-42008.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2021-42008.svg)

## CVE-2021-41962
 Cross Site Scripting (XSS) vulnerability exists in Sourcecodester Vehicle Service Management System 1.0 via the Owner fullname parameter in a Send Service Request in vehicle_service.



- [https://github.com/lohyt/-CVE-2021-41962](https://github.com/lohyt/-CVE-2021-41962) :  ![starts](https://img.shields.io/github/stars/lohyt/-CVE-2021-41962.svg) ![forks](https://img.shields.io/github/forks/lohyt/-CVE-2021-41962.svg)

## CVE-2021-41822
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/badboycxcc/CVE-2021-41822](https://github.com/badboycxcc/CVE-2021-41822) :  ![starts](https://img.shields.io/github/stars/badboycxcc/CVE-2021-41822.svg) ![forks](https://img.shields.io/github/forks/badboycxcc/CVE-2021-41822.svg)

## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.



- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)

- [https://github.com/blasty/CVE-2021-41773](https://github.com/blasty/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/blasty/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/blasty/CVE-2021-41773.svg)

- [https://github.com/inbug-team/CVE-2021-41773_CVE-2021-42013](https://github.com/inbug-team/CVE-2021-41773_CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/inbug-team/CVE-2021-41773_CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/inbug-team/CVE-2021-41773_CVE-2021-42013.svg)

- [https://github.com/MrCl0wnLab/SimplesApachePathTraversal](https://github.com/MrCl0wnLab/SimplesApachePathTraversal) :  ![starts](https://img.shields.io/github/stars/MrCl0wnLab/SimplesApachePathTraversal.svg) ![forks](https://img.shields.io/github/forks/MrCl0wnLab/SimplesApachePathTraversal.svg)

- [https://github.com/HightechSec/scarce-apache2](https://github.com/HightechSec/scarce-apache2) :  ![starts](https://img.shields.io/github/stars/HightechSec/scarce-apache2.svg) ![forks](https://img.shields.io/github/forks/HightechSec/scarce-apache2.svg)

- [https://github.com/iilegacyyii/PoC-CVE-2021-41773](https://github.com/iilegacyyii/PoC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/iilegacyyii/PoC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/iilegacyyii/PoC-CVE-2021-41773.svg)

- [https://github.com/lorddemon/CVE-2021-41773-PoC](https://github.com/lorddemon/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/lorddemon/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/lorddemon/CVE-2021-41773-PoC.svg)

- [https://github.com/Vulnmachines/cve-2021-41773](https://github.com/Vulnmachines/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/cve-2021-41773.svg)

- [https://github.com/justakazh/mass_cve-2021-41773](https://github.com/justakazh/mass_cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/justakazh/mass_cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/justakazh/mass_cve-2021-41773.svg)

- [https://github.com/im-hanzou/apachrot](https://github.com/im-hanzou/apachrot) :  ![starts](https://img.shields.io/github/stars/im-hanzou/apachrot.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/apachrot.svg)

- [https://github.com/ZephrFish/CVE-2021-41773-PoC](https://github.com/ZephrFish/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2021-41773-PoC.svg)

- [https://github.com/Ls4ss/CVE-2021-41773_CVE-2021-42013](https://github.com/Ls4ss/CVE-2021-41773_CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/Ls4ss/CVE-2021-41773_CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/Ls4ss/CVE-2021-41773_CVE-2021-42013.svg)

- [https://github.com/hackingyseguridad/nmap](https://github.com/hackingyseguridad/nmap) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/nmap.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/nmap.svg)

- [https://github.com/Zeop-CyberSec/apache_normalize_path](https://github.com/Zeop-CyberSec/apache_normalize_path) :  ![starts](https://img.shields.io/github/stars/Zeop-CyberSec/apache_normalize_path.svg) ![forks](https://img.shields.io/github/forks/Zeop-CyberSec/apache_normalize_path.svg)

- [https://github.com/creadpag/CVE-2021-41773-POC](https://github.com/creadpag/CVE-2021-41773-POC) :  ![starts](https://img.shields.io/github/stars/creadpag/CVE-2021-41773-POC.svg) ![forks](https://img.shields.io/github/forks/creadpag/CVE-2021-41773-POC.svg)

- [https://github.com/zeronine9/CVE-2021-41773](https://github.com/zeronine9/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zeronine9/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zeronine9/CVE-2021-41773.svg)

- [https://github.com/BlueTeamSteve/CVE-2021-41773](https://github.com/BlueTeamSteve/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/BlueTeamSteve/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/BlueTeamSteve/CVE-2021-41773.svg)

- [https://github.com/numanturle/CVE-2021-41773](https://github.com/numanturle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2021-41773.svg)

- [https://github.com/RyouYoo/CVE-2021-41773](https://github.com/RyouYoo/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RyouYoo/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RyouYoo/CVE-2021-41773.svg)

- [https://github.com/Balgogan/CVE-2021-41773](https://github.com/Balgogan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Balgogan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Balgogan/CVE-2021-41773.svg)

- [https://github.com/knqyf263/CVE-2021-41773](https://github.com/knqyf263/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2021-41773.svg)

- [https://github.com/1nhann/CVE-2021-41773](https://github.com/1nhann/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/1nhann/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/1nhann/CVE-2021-41773.svg)

- [https://github.com/TishcaTpx/POC-CVE-2021-41773](https://github.com/TishcaTpx/POC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TishcaTpx/POC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TishcaTpx/POC-CVE-2021-41773.svg)

- [https://github.com/ComdeyOverflow/CVE-2021-41773](https://github.com/ComdeyOverflow/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ComdeyOverflow/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ComdeyOverflow/CVE-2021-41773.svg)

- [https://github.com/itsecurityco/CVE-2021-41773](https://github.com/itsecurityco/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/itsecurityco/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/itsecurityco/CVE-2021-41773.svg)

- [https://github.com/apapedulimu/Apachuk](https://github.com/apapedulimu/Apachuk) :  ![starts](https://img.shields.io/github/stars/apapedulimu/Apachuk.svg) ![forks](https://img.shields.io/github/forks/apapedulimu/Apachuk.svg)

- [https://github.com/ahmad4fifz/CVE-2021-42013](https://github.com/ahmad4fifz/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/ahmad4fifz/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/ahmad4fifz/CVE-2021-42013.svg)

- [https://github.com/cgddgc/CVE-2021-41773-42013](https://github.com/cgddgc/CVE-2021-41773-42013) :  ![starts](https://img.shields.io/github/stars/cgddgc/CVE-2021-41773-42013.svg) ![forks](https://img.shields.io/github/forks/cgddgc/CVE-2021-41773-42013.svg)

- [https://github.com/shellreaper/CVE-2021-41773](https://github.com/shellreaper/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shellreaper/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shellreaper/CVE-2021-41773.svg)

- [https://github.com/theLSA/apache-httpd-path-traversal-checker](https://github.com/theLSA/apache-httpd-path-traversal-checker) :  ![starts](https://img.shields.io/github/stars/theLSA/apache-httpd-path-traversal-checker.svg) ![forks](https://img.shields.io/github/forks/theLSA/apache-httpd-path-traversal-checker.svg)

- [https://github.com/0xRar/CVE-2021-41773](https://github.com/0xRar/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xRar/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xRar/CVE-2021-41773.svg)

- [https://github.com/superzerosec/CVE-2021-41773](https://github.com/superzerosec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/superzerosec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/superzerosec/CVE-2021-41773.svg)

- [https://github.com/5gstudent/cve-2021-41773-and-cve-2021-42013](https://github.com/5gstudent/cve-2021-41773-and-cve-2021-42013) :  ![starts](https://img.shields.io/github/stars/5gstudent/cve-2021-41773-and-cve-2021-42013.svg) ![forks](https://img.shields.io/github/forks/5gstudent/cve-2021-41773-and-cve-2021-42013.svg)

- [https://github.com/habibiefaried/CVE-2021-41773-PoC](https://github.com/habibiefaried/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/habibiefaried/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/habibiefaried/CVE-2021-41773-PoC.svg)

- [https://github.com/jheeree/Simple-CVE-2021-41773-checker](https://github.com/jheeree/Simple-CVE-2021-41773-checker) :  ![starts](https://img.shields.io/github/stars/jheeree/Simple-CVE-2021-41773-checker.svg) ![forks](https://img.shields.io/github/forks/jheeree/Simple-CVE-2021-41773-checker.svg)

- [https://github.com/onsecuredev/CVE-2021-41773](https://github.com/onsecuredev/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-41773.svg)

- [https://github.com/masahiro331/CVE-2021-41773](https://github.com/masahiro331/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/masahiro331/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/masahiro331/CVE-2021-41773.svg)

- [https://github.com/AssassinUKG/CVE-2021-41773](https://github.com/AssassinUKG/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/AssassinUKG/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/AssassinUKG/CVE-2021-41773.svg)

- [https://github.com/r00tVen0m/CVE-2021-41773](https://github.com/r00tVen0m/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/r00tVen0m/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/r00tVen0m/CVE-2021-41773.svg)

- [https://github.com/mohwahyudi/cve-2021-41773](https://github.com/mohwahyudi/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mohwahyudi/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mohwahyudi/cve-2021-41773.svg)

- [https://github.com/twseptian/CVE-2021-41773](https://github.com/twseptian/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/twseptian/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/twseptian/CVE-2021-41773.svg)

- [https://github.com/cloudbyteelias/CVE-2021-41773](https://github.com/cloudbyteelias/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/cloudbyteelias/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/cloudbyteelias/CVE-2021-41773.svg)

- [https://github.com/vinhjaxt/CVE-2021-41773-exploit](https://github.com/vinhjaxt/CVE-2021-41773-exploit) :  ![starts](https://img.shields.io/github/stars/vinhjaxt/CVE-2021-41773-exploit.svg) ![forks](https://img.shields.io/github/forks/vinhjaxt/CVE-2021-41773-exploit.svg)

- [https://github.com/jhye0n/CVE-2021-41773](https://github.com/jhye0n/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/jhye0n/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/jhye0n/CVE-2021-41773.svg)

- [https://github.com/Hydragyrum/CVE-2021-41773-Playground](https://github.com/Hydragyrum/CVE-2021-41773-Playground) :  ![starts](https://img.shields.io/github/stars/Hydragyrum/CVE-2021-41773-Playground.svg) ![forks](https://img.shields.io/github/forks/Hydragyrum/CVE-2021-41773-Playground.svg)

- [https://github.com/Sakura-nee/CVE-2021-41773](https://github.com/Sakura-nee/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Sakura-nee/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Sakura-nee/CVE-2021-41773.svg)

- [https://github.com/ksanchezcld/httpd-2.4.49](https://github.com/ksanchezcld/httpd-2.4.49) :  ![starts](https://img.shields.io/github/stars/ksanchezcld/httpd-2.4.49.svg) ![forks](https://img.shields.io/github/forks/ksanchezcld/httpd-2.4.49.svg)

- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)

- [https://github.com/jbovet/CVE-2021-41773](https://github.com/jbovet/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/jbovet/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/jbovet/CVE-2021-41773.svg)

- [https://github.com/corelight/CVE-2021-41773](https://github.com/corelight/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2021-41773.svg)

- [https://github.com/vulf/CVE-2021-41773_42013](https://github.com/vulf/CVE-2021-41773_42013) :  ![starts](https://img.shields.io/github/stars/vulf/CVE-2021-41773_42013.svg) ![forks](https://img.shields.io/github/forks/vulf/CVE-2021-41773_42013.svg)

- [https://github.com/ahmad4fifz/CVE-2021-41773](https://github.com/ahmad4fifz/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ahmad4fifz/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ahmad4fifz/CVE-2021-41773.svg)

- [https://github.com/n3k00n3/CVE-2021-41773](https://github.com/n3k00n3/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/n3k00n3/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/n3k00n3/CVE-2021-41773.svg)

- [https://github.com/fnatalucci/CVE-2021-41773-RCE](https://github.com/fnatalucci/CVE-2021-41773-RCE) :  ![starts](https://img.shields.io/github/stars/fnatalucci/CVE-2021-41773-RCE.svg) ![forks](https://img.shields.io/github/forks/fnatalucci/CVE-2021-41773-RCE.svg)

- [https://github.com/EagleTube/CVE-2021-41773](https://github.com/EagleTube/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/EagleTube/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/EagleTube/CVE-2021-41773.svg)

- [https://github.com/PentesterGuruji/CVE-2021-41773](https://github.com/PentesterGuruji/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/PentesterGuruji/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/PentesterGuruji/CVE-2021-41773.svg)

- [https://github.com/ranggaggngntt/CVE-2021-41773](https://github.com/ranggaggngntt/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ranggaggngntt/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ranggaggngntt/CVE-2021-41773.svg)

- [https://github.com/b1tsec/CVE-2021-41773](https://github.com/b1tsec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/b1tsec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/b1tsec/CVE-2021-41773.svg)

- [https://github.com/BabyTeam1024/CVE-2021-41773](https://github.com/BabyTeam1024/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/CVE-2021-41773.svg)

- [https://github.com/LetouRaphael/Poc-CVE-2021-41773](https://github.com/LetouRaphael/Poc-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LetouRaphael/Poc-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LetouRaphael/Poc-CVE-2021-41773.svg)

- [https://github.com/kubota/POC-CVE-2021-41773](https://github.com/kubota/POC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/kubota/POC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/kubota/POC-CVE-2021-41773.svg)

- [https://github.com/0xAlmighty/CVE-2021-41773-PoC](https://github.com/0xAlmighty/CVE-2021-41773-PoC) :  ![starts](https://img.shields.io/github/stars/0xAlmighty/CVE-2021-41773-PoC.svg) ![forks](https://img.shields.io/github/forks/0xAlmighty/CVE-2021-41773-PoC.svg)

- [https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt](https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt) :  ![starts](https://img.shields.io/github/stars/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt.svg) ![forks](https://img.shields.io/github/forks/pisut4152/Sigma-Rule-for-CVE-2021-41773-and-CVE-2021-42013-exploitation-attempt.svg)

- [https://github.com/TAI-REx/cve-2021-41773-nse](https://github.com/TAI-REx/cve-2021-41773-nse) :  ![starts](https://img.shields.io/github/stars/TAI-REx/cve-2021-41773-nse.svg) ![forks](https://img.shields.io/github/forks/TAI-REx/cve-2021-41773-nse.svg)

- [https://github.com/mr-exo/CVE-2021-41773](https://github.com/mr-exo/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/mr-exo/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mr-exo/CVE-2021-41773.svg)

- [https://github.com/KAB8345/CVE-2021-41773](https://github.com/KAB8345/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/KAB8345/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/KAB8345/CVE-2021-41773.svg)

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)

- [https://github.com/MazX0p/CVE-2021-41773](https://github.com/MazX0p/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/MazX0p/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MazX0p/CVE-2021-41773.svg)

- [https://github.com/lopqto/CVE-2021-41773_Honeypot](https://github.com/lopqto/CVE-2021-41773_Honeypot) :  ![starts](https://img.shields.io/github/stars/lopqto/CVE-2021-41773_Honeypot.svg) ![forks](https://img.shields.io/github/forks/lopqto/CVE-2021-41773_Honeypot.svg)

- [https://github.com/LudovicPatho/CVE-2021-41773](https://github.com/LudovicPatho/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LudovicPatho/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LudovicPatho/CVE-2021-41773.svg)

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)

- [https://github.com/i6c/MASS_CVE-2021-41773](https://github.com/i6c/MASS_CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/i6c/MASS_CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/i6c/MASS_CVE-2021-41773.svg)

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)

- [https://github.com/scarmandef/CVE-2021-41773](https://github.com/scarmandef/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/scarmandef/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/scarmandef/CVE-2021-41773.svg)

- [https://github.com/vida00/Scanner-CVE-2021-41773](https://github.com/vida00/Scanner-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/vida00/Scanner-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vida00/Scanner-CVE-2021-41773.svg)

- [https://github.com/walnutsecurity/cve-2021-41773](https://github.com/walnutsecurity/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/walnutsecurity/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/walnutsecurity/cve-2021-41773.svg)

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)

- [https://github.com/TheLastVvV/CVE-2021-41773](https://github.com/TheLastVvV/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41773.svg)

- [https://github.com/qwutony/CVE-2021-41773](https://github.com/qwutony/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/qwutony/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/qwutony/CVE-2021-41773.svg)

- [https://github.com/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit](https://github.com/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit) :  ![starts](https://img.shields.io/github/stars/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit.svg) ![forks](https://img.shields.io/github/forks/IcmpOff/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution-Exploit.svg)

## CVE-2021-41730
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/IBUILI/CVE-2021-41730](https://github.com/IBUILI/CVE-2021-41730) :  ![starts](https://img.shields.io/github/stars/IBUILI/CVE-2021-41730.svg) ![forks](https://img.shields.io/github/forks/IBUILI/CVE-2021-41730.svg)

## CVE-2021-41728
 Cross Site Scripting (XSS) vulnerability exists in Sourcecodester News247 CMS 1.0 via the search function in articles.



- [https://github.com/Dir0x/CVE-2021-41728](https://github.com/Dir0x/CVE-2021-41728) :  ![starts](https://img.shields.io/github/stars/Dir0x/CVE-2021-41728.svg) ![forks](https://img.shields.io/github/forks/Dir0x/CVE-2021-41728.svg)

## CVE-2021-41653
 The PING function on the TP-Link TL-WR840N EU v5 router with firmware through TL-WR840N(EU)_V5_171211 is vulnerable to remote code execution via a crafted payload in an IP address input field.



- [https://github.com/ohnonoyesyes/CVE-2021-41653](https://github.com/ohnonoyesyes/CVE-2021-41653) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2021-41653.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2021-41653.svg)

## CVE-2021-41651
 A blind SQL injection vulnerability exists in the Raymart DG / Ahmed Helal Hotel-mgmt-system. A malicious attacker can retrieve sensitive database information and interact with the database using the vulnerable cid parameter in process_update_profile.php.



- [https://github.com/MobiusBinary/CVE-2021-41651](https://github.com/MobiusBinary/CVE-2021-41651) :  ![starts](https://img.shields.io/github/stars/MobiusBinary/CVE-2021-41651.svg) ![forks](https://img.shields.io/github/forks/MobiusBinary/CVE-2021-41651.svg)

## CVE-2021-41649
 An un-authenticated SQL Injection exists in PuneethReddyHC online-shopping-system-advanced through the /homeaction.php cat_id parameter. Using a post request does not sanitize the user input.



- [https://github.com/MobiusBinary/CVE-2021-41649](https://github.com/MobiusBinary/CVE-2021-41649) :  ![starts](https://img.shields.io/github/stars/MobiusBinary/CVE-2021-41649.svg) ![forks](https://img.shields.io/github/forks/MobiusBinary/CVE-2021-41649.svg)

## CVE-2021-41648
 An un-authenticated SQL Injection exists in PuneethReddyHC online-shopping-system-advanced through the /action.php prId parameter. Using a post request does not sanitize the user input.



- [https://github.com/MobiusBinary/CVE-2021-41648](https://github.com/MobiusBinary/CVE-2021-41648) :  ![starts](https://img.shields.io/github/stars/MobiusBinary/CVE-2021-41648.svg) ![forks](https://img.shields.io/github/forks/MobiusBinary/CVE-2021-41648.svg)

## CVE-2021-41647
 An un-authenticated error-based and time-based blind SQL injection vulnerability exists in Kaushik Jadhav Online Food Ordering Web App 1.0. An attacker can exploit the vulnerable &quot;username&quot; parameter in login.php and retrieve sensitive database information, as well as add an administrative user.



- [https://github.com/MobiusBinary/CVE-2021-41647](https://github.com/MobiusBinary/CVE-2021-41647) :  ![starts](https://img.shields.io/github/stars/MobiusBinary/CVE-2021-41647.svg) ![forks](https://img.shields.io/github/forks/MobiusBinary/CVE-2021-41647.svg)

## CVE-2021-41646
 Remote Code Execution (RCE) vulnerability exists in Sourcecodester Online Reviewer System 1.0 by uploading a maliciously crafted PHP file that bypasses the image upload filters..



- [https://github.com/hax3xploit/CVE-2021-41646](https://github.com/hax3xploit/CVE-2021-41646) :  ![starts](https://img.shields.io/github/stars/hax3xploit/CVE-2021-41646.svg) ![forks](https://img.shields.io/github/forks/hax3xploit/CVE-2021-41646.svg)

## CVE-2021-41645
 Remote Code Execution (RCE) vulnerability exists in Sourcecodester Budget and Expense Tracker System 1.0 that allows a remote malicious user to inject arbitrary code via the image upload field. .



- [https://github.com/hax3xploit/CVE-2021-41645](https://github.com/hax3xploit/CVE-2021-41645) :  ![starts](https://img.shields.io/github/stars/hax3xploit/CVE-2021-41645.svg) ![forks](https://img.shields.io/github/forks/hax3xploit/CVE-2021-41645.svg)

## CVE-2021-41644
 Remote Code Exection (RCE) vulnerability exists in Sourcecodester Online Food Ordering System 2.0 via a maliciously crafted PHP file that bypasses the image upload filters.



- [https://github.com/hax3xploit/CVE-2021-41644](https://github.com/hax3xploit/CVE-2021-41644) :  ![starts](https://img.shields.io/github/stars/hax3xploit/CVE-2021-41644.svg) ![forks](https://img.shields.io/github/forks/hax3xploit/CVE-2021-41644.svg)

## CVE-2021-41643
 Remote Code Execution (RCE) vulnerability exists in Sourcecodester Church Management System 1.0 via the image upload field.



- [https://github.com/hax3xploit/CVE-2021-41643](https://github.com/hax3xploit/CVE-2021-41643) :  ![starts](https://img.shields.io/github/stars/hax3xploit/CVE-2021-41643.svg) ![forks](https://img.shields.io/github/forks/hax3xploit/CVE-2021-41643.svg)

## CVE-2021-41511
 The username and password field of login in Lodging Reservation Management System V1 can give access to any user by using SQL injection to bypass authentication.



- [https://github.com/Ni7inSharma/CVE-2021-41511](https://github.com/Ni7inSharma/CVE-2021-41511) :  ![starts](https://img.shields.io/github/stars/Ni7inSharma/CVE-2021-41511.svg) ![forks](https://img.shields.io/github/forks/Ni7inSharma/CVE-2021-41511.svg)

## CVE-2021-41381
 Payara Micro Community 5.2021.6 and below allows Directory Traversal.



- [https://github.com/Net-hunter121/CVE-2021-41381](https://github.com/Net-hunter121/CVE-2021-41381) :  ![starts](https://img.shields.io/github/stars/Net-hunter121/CVE-2021-41381.svg) ![forks](https://img.shields.io/github/forks/Net-hunter121/CVE-2021-41381.svg)

## CVE-2021-41379
 Windows Installer Elevation of Privilege Vulnerability



- [https://github.com/jbaines-r7/shakeitoff](https://github.com/jbaines-r7/shakeitoff) :  ![starts](https://img.shields.io/github/stars/jbaines-r7/shakeitoff.svg) ![forks](https://img.shields.io/github/forks/jbaines-r7/shakeitoff.svg)

## CVE-2021-41351
 Microsoft Edge (Chrome based) Spoofing on IE Mode



- [https://github.com/JaneMandy/CVE-2021-41351-POC](https://github.com/JaneMandy/CVE-2021-41351-POC) :  ![starts](https://img.shields.io/github/stars/JaneMandy/CVE-2021-41351-POC.svg) ![forks](https://img.shields.io/github/forks/JaneMandy/CVE-2021-41351-POC.svg)

## CVE-2021-41277
 Metabase is an open source data analytics platform. In affected versions a security issue has been discovered with the custom GeoJSON map (`admin-&gt;settings-&gt;maps-&gt;custom maps-&gt;add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded. This issue is fixed in a new maintenance release (0.40.5 and 1.40.5), and any subsequent release after that. If you&#8217;re unable to upgrade immediately, you can mitigate this by including rules in your reverse proxy or load balancer or WAF to provide a validation filter before the application.



- [https://github.com/zer0yu/CVE-2021-41277](https://github.com/zer0yu/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/zer0yu/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/zer0yu/CVE-2021-41277.svg)

- [https://github.com/Seals6/CVE-2021-41277](https://github.com/Seals6/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/Seals6/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/Seals6/CVE-2021-41277.svg)

- [https://github.com/tahtaciburak/CVE-2021-41277](https://github.com/tahtaciburak/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/tahtaciburak/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/tahtaciburak/CVE-2021-41277.svg)

- [https://github.com/z3n70/CVE-2021-41277](https://github.com/z3n70/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/z3n70/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/z3n70/CVE-2021-41277.svg)

- [https://github.com/Vulnmachines/Metabase_CVE-2021-41277](https://github.com/Vulnmachines/Metabase_CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/Metabase_CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/Metabase_CVE-2021-41277.svg)

- [https://github.com/kap1ush0n/CVE-2021-41277](https://github.com/kap1ush0n/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/kap1ush0n/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/kap1ush0n/CVE-2021-41277.svg)

- [https://github.com/TheLastVvV/CVE-2021-41277](https://github.com/TheLastVvV/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/TheLastVvV/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/TheLastVvV/CVE-2021-41277.svg)

- [https://github.com/Henry4E36/Metabase-cve-2021-41277](https://github.com/Henry4E36/Metabase-cve-2021-41277) :  ![starts](https://img.shields.io/github/stars/Henry4E36/Metabase-cve-2021-41277.svg) ![forks](https://img.shields.io/github/forks/Henry4E36/Metabase-cve-2021-41277.svg)

- [https://github.com/kaizensecurity/CVE-2021-41277](https://github.com/kaizensecurity/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/kaizensecurity/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/kaizensecurity/CVE-2021-41277.svg)

## CVE-2021-41157
 FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. By default, SIP requests of the type SUBSCRIBE are not authenticated in the affected versions of FreeSWITCH. Abuse of this security issue allows attackers to subscribe to user agent event notifications without the need to authenticate. This abuse poses privacy concerns and might lead to social engineering or similar attacks. For example, attackers may be able to monitor the status of target SIP extensions. Although this issue was fixed in version v1.10.6, installations upgraded to the fixed version of FreeSWITCH from an older version, may still be vulnerable if the configuration is not updated accordingly. Software upgrades do not update the configuration by default. SIP SUBSCRIBE messages should be authenticated by default so that FreeSWITCH administrators do not need to explicitly set the `auth-subscriptions` parameter. When following such a recommendation, a new parameter can be introduced to explicitly disable authentication.



- [https://github.com/0xInfection/PewSWITCH](https://github.com/0xInfection/PewSWITCH) :  ![starts](https://img.shields.io/github/stars/0xInfection/PewSWITCH.svg) ![forks](https://img.shields.io/github/forks/0xInfection/PewSWITCH.svg)

## CVE-2021-41090
 Grafana Agent is a telemetry collector for sending metrics, logs, and trace data to the opinionated Grafana observability stack. Prior to versions 0.20.1 and 0.21.2, inline secrets defined within a metrics instance config are exposed in plaintext over two endpoints: metrics instance configs defined in the base YAML file are exposed at `/-/config` and metrics instance configs defined for the scraping service are exposed at `/agent/api/v1/configs/:key`. Inline secrets will be exposed to anyone being able to reach these endpoints. If HTTPS with client authentication is not configured, these endpoints are accessible to unauthenticated users. Secrets found in these sections are used for delivering metrics to a Prometheus Remote Write system, authenticating against a system for discovering Prometheus targets, and authenticating against a system for collecting metrics. This does not apply for non-inlined secrets, such as `*_file` based secrets. This issue is patched in Grafana Agent versions 0.20.1 and 0.21.2. A few workarounds are available. Users who cannot upgrade should use non-inline secrets where possible. Users may also desire to restrict API access to Grafana Agent with some combination of restricting the network interfaces Grafana Agent listens on through `http_listen_address` in the `server` block, configuring Grafana Agent to use HTTPS with client authentication, and/or using firewall rules to restrict external access to Grafana Agent's API.



- [https://github.com/0xAgun/grafana_lfi](https://github.com/0xAgun/grafana_lfi) :  ![starts](https://img.shields.io/github/stars/0xAgun/grafana_lfi.svg) ![forks](https://img.shields.io/github/forks/0xAgun/grafana_lfi.svg)

## CVE-2021-41081
 Zoho ManageEngine Network Configuration Manager before &#65279;&#65279;125465 is vulnerable to SQL Injection in a configuration search.



- [https://github.com/sudaiv/CVE-2021-41081](https://github.com/sudaiv/CVE-2021-41081) :  ![starts](https://img.shields.io/github/stars/sudaiv/CVE-2021-41081.svg) ![forks](https://img.shields.io/github/forks/sudaiv/CVE-2021-41081.svg)

## CVE-2021-41074
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/dillonkirsch/CVE-2021-41074](https://github.com/dillonkirsch/CVE-2021-41074) :  ![starts](https://img.shields.io/github/stars/dillonkirsch/CVE-2021-41074.svg) ![forks](https://img.shields.io/github/forks/dillonkirsch/CVE-2021-41074.svg)

## CVE-2021-40978
 ** DISPUTED ** The mkdocs 1.2.2 built-in dev-server allows directory traversal using the port 8000, enabling remote exploitation to obtain :sensitive information. NOTE: the vendor has disputed this as described in https://github.com/mkdocs/mkdocs/issues/2601.] and https://github.com/nisdn/CVE-2021-40978/issues/1.



- [https://github.com/nisdn/CVE-2021-40978](https://github.com/nisdn/CVE-2021-40978) :  ![starts](https://img.shields.io/github/stars/nisdn/CVE-2021-40978.svg) ![forks](https://img.shields.io/github/forks/nisdn/CVE-2021-40978.svg)

## CVE-2021-40875
 Improper Access Control in Gurock TestRail versions &lt; 7.2.0.3014 resulted in sensitive information exposure. A threat actor can access the /files.md5 file on the client side of a Gurock TestRail application, disclosing a full list of application files and the corresponding file paths. The corresponding file paths can be tested, and in some cases, result in the disclosure of hardcoded credentials, API keys, or other sensitive data.



- [https://github.com/SakuraSamuraii/derailed](https://github.com/SakuraSamuraii/derailed) :  ![starts](https://img.shields.io/github/stars/SakuraSamuraii/derailed.svg) ![forks](https://img.shields.io/github/forks/SakuraSamuraii/derailed.svg)

## CVE-2021-40870
 An issue was discovered in Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal.



- [https://github.com/0xAgun/CVE-2021-40870](https://github.com/0xAgun/CVE-2021-40870) :  ![starts](https://img.shields.io/github/stars/0xAgun/CVE-2021-40870.svg) ![forks](https://img.shields.io/github/forks/0xAgun/CVE-2021-40870.svg)

- [https://github.com/onsecuredev/CVE-2021-40870](https://github.com/onsecuredev/CVE-2021-40870) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-40870.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-40870.svg)

- [https://github.com/JoyGhoshs/CVE-2021-40870](https://github.com/JoyGhoshs/CVE-2021-40870) :  ![starts](https://img.shields.io/github/stars/JoyGhoshs/CVE-2021-40870.svg) ![forks](https://img.shields.io/github/forks/JoyGhoshs/CVE-2021-40870.svg)

## CVE-2021-40865
 An Unsafe Deserialization vulnerability exists in the worker services of the Apache Storm supervisor server allowing pre-auth Remote Code Execution (RCE). Apache Storm 2.2.x users should upgrade to version 2.2.1 or 2.3.0. Apache Storm 2.1.x users should upgrade to version 2.1.1. Apache Storm 1.x users should upgrade to version 1.2.4



- [https://github.com/hktalent/CVE-2021-40865](https://github.com/hktalent/CVE-2021-40865) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE-2021-40865.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE-2021-40865.svg)

## CVE-2021-40845
 The web part of Zenitel AlphaCom XE Audio Server through 11.2.3.10, called AlphaWeb XE, does not restrict file upload in the Custom Scripts section at php/index.php. Neither the content nor extension of the uploaded files is checked, allowing execution of PHP code under the /cmd directory.



- [https://github.com/ricardojoserf/CVE-2021-40845](https://github.com/ricardojoserf/CVE-2021-40845) :  ![starts](https://img.shields.io/github/stars/ricardojoserf/CVE-2021-40845.svg) ![forks](https://img.shields.io/github/forks/ricardojoserf/CVE-2021-40845.svg)

## CVE-2021-40839
 The rencode package through 1.0.6 for Python allows an infinite loop in typecode decoding (such as via ;\x2f\x7f), enabling a remote attack that consumes CPU and memory.



- [https://github.com/itlabbet/CVE-2021-40839](https://github.com/itlabbet/CVE-2021-40839) :  ![starts](https://img.shields.io/github/stars/itlabbet/CVE-2021-40839.svg) ![forks](https://img.shields.io/github/forks/itlabbet/CVE-2021-40839.svg)

## CVE-2021-40539
 Zoho ManageEngine ADSelfService Plus version 6113 and prior is vulnerable to REST API authentication bypass with resultant remote code execution.



- [https://github.com/synacktiv/CVE-2021-40539](https://github.com/synacktiv/CVE-2021-40539) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2021-40539.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2021-40539.svg)

- [https://github.com/DarkSprings/CVE-2021-40539](https://github.com/DarkSprings/CVE-2021-40539) :  ![starts](https://img.shields.io/github/stars/DarkSprings/CVE-2021-40539.svg) ![forks](https://img.shields.io/github/forks/DarkSprings/CVE-2021-40539.svg)

## CVE-2021-40531
 An issue discovered in sketch before version 75,that allows for library feeds to be used to bypass file quarantine which results in remote code execution.



- [https://github.com/jonpalmisc/CVE-2021-40531](https://github.com/jonpalmisc/CVE-2021-40531) :  ![starts](https://img.shields.io/github/stars/jonpalmisc/CVE-2021-40531.svg) ![forks](https://img.shields.io/github/forks/jonpalmisc/CVE-2021-40531.svg)

## CVE-2021-40514
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/war4uthor/CVE-2021-40514](https://github.com/war4uthor/CVE-2021-40514) :  ![starts](https://img.shields.io/github/stars/war4uthor/CVE-2021-40514.svg) ![forks](https://img.shields.io/github/forks/war4uthor/CVE-2021-40514.svg)

## CVE-2021-40513
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/war4uthor/CVE-2021-40513](https://github.com/war4uthor/CVE-2021-40513) :  ![starts](https://img.shields.io/github/stars/war4uthor/CVE-2021-40513.svg) ![forks](https://img.shields.io/github/forks/war4uthor/CVE-2021-40513.svg)

## CVE-2021-40512
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/war4uthor/CVE-2021-40512](https://github.com/war4uthor/CVE-2021-40512) :  ![starts](https://img.shields.io/github/stars/war4uthor/CVE-2021-40512.svg) ![forks](https://img.shields.io/github/forks/war4uthor/CVE-2021-40512.svg)

## CVE-2021-40492
 A reflected XSS vulnerability exists in multiple pages in version 22 of the Gibbon application that allows for arbitrary execution of JavaScript (gibbonCourseClassID, gibbonPersonID, subpage, currentDate, or allStudents to index.php).



- [https://github.com/5qu1n7/CVE-2021-40492](https://github.com/5qu1n7/CVE-2021-40492) :  ![starts](https://img.shields.io/github/stars/5qu1n7/CVE-2021-40492.svg) ![forks](https://img.shields.io/github/forks/5qu1n7/CVE-2021-40492.svg)

## CVE-2021-40449
 Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-40450, CVE-2021-41357.



- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)

- [https://github.com/ly4k/CallbackHell](https://github.com/ly4k/CallbackHell) :  ![starts](https://img.shields.io/github/stars/ly4k/CallbackHell.svg) ![forks](https://img.shields.io/github/forks/ly4k/CallbackHell.svg)

- [https://github.com/KaLendsi/CVE-2021-40449-Exploit](https://github.com/KaLendsi/CVE-2021-40449-Exploit) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2021-40449-Exploit.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2021-40449-Exploit.svg)

- [https://github.com/Kristal-g/CVE-2021-40449_poc](https://github.com/Kristal-g/CVE-2021-40449_poc) :  ![starts](https://img.shields.io/github/stars/Kristal-g/CVE-2021-40449_poc.svg) ![forks](https://img.shields.io/github/forks/Kristal-g/CVE-2021-40449_poc.svg)

- [https://github.com/hakivvi/CVE-2021-40449](https://github.com/hakivvi/CVE-2021-40449) :  ![starts](https://img.shields.io/github/stars/hakivvi/CVE-2021-40449.svg) ![forks](https://img.shields.io/github/forks/hakivvi/CVE-2021-40449.svg)

- [https://github.com/CppXL/cve-2021-40449-poc](https://github.com/CppXL/cve-2021-40449-poc) :  ![starts](https://img.shields.io/github/stars/CppXL/cve-2021-40449-poc.svg) ![forks](https://img.shields.io/github/forks/CppXL/cve-2021-40449-poc.svg)

## CVE-2021-40447
 Windows Print Spooler Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-38667, CVE-2021-38671.



- [https://github.com/Tomparte/PrintNightmare](https://github.com/Tomparte/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/Tomparte/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/Tomparte/PrintNightmare.svg)

## CVE-2021-40444
 Microsoft MSHTML Remote Code Execution Vulnerability



- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)

- [https://github.com/lockedbyte/CVE-2021-40444](https://github.com/lockedbyte/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/lockedbyte/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/lockedbyte/CVE-2021-40444.svg)

- [https://github.com/klezVirus/CVE-2021-40444](https://github.com/klezVirus/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/klezVirus/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/klezVirus/CVE-2021-40444.svg)

- [https://github.com/aslitsecurity/CVE-2021-40444_builders](https://github.com/aslitsecurity/CVE-2021-40444_builders) :  ![starts](https://img.shields.io/github/stars/aslitsecurity/CVE-2021-40444_builders.svg) ![forks](https://img.shields.io/github/forks/aslitsecurity/CVE-2021-40444_builders.svg)

- [https://github.com/Udyz/CVE-2021-40444-Sample](https://github.com/Udyz/CVE-2021-40444-Sample) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2021-40444-Sample.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2021-40444-Sample.svg)

- [https://github.com/Edubr2020/CVE-2021-40444--CABless](https://github.com/Edubr2020/CVE-2021-40444--CABless) :  ![starts](https://img.shields.io/github/stars/Edubr2020/CVE-2021-40444--CABless.svg) ![forks](https://img.shields.io/github/forks/Edubr2020/CVE-2021-40444--CABless.svg)

- [https://github.com/k8gege/CVE-2021-40444](https://github.com/k8gege/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/k8gege/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/k8gege/CVE-2021-40444.svg)

- [https://github.com/ozergoker/CVE-2021-40444](https://github.com/ozergoker/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/ozergoker/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/ozergoker/CVE-2021-40444.svg)

- [https://github.com/34zY/Microsoft-Office-Word-MSHTML-Remote-Code-Execution-Exploit](https://github.com/34zY/Microsoft-Office-Word-MSHTML-Remote-Code-Execution-Exploit) :  ![starts](https://img.shields.io/github/stars/34zY/Microsoft-Office-Word-MSHTML-Remote-Code-Execution-Exploit.svg) ![forks](https://img.shields.io/github/forks/34zY/Microsoft-Office-Word-MSHTML-Remote-Code-Execution-Exploit.svg)

- [https://github.com/rfcxv/CVE-2021-40444-POC](https://github.com/rfcxv/CVE-2021-40444-POC) :  ![starts](https://img.shields.io/github/stars/rfcxv/CVE-2021-40444-POC.svg) ![forks](https://img.shields.io/github/forks/rfcxv/CVE-2021-40444-POC.svg)

- [https://github.com/mansk1es/Caboom](https://github.com/mansk1es/Caboom) :  ![starts](https://img.shields.io/github/stars/mansk1es/Caboom.svg) ![forks](https://img.shields.io/github/forks/mansk1es/Caboom.svg)

- [https://github.com/Udyz/CVE-2021-40444-CAB](https://github.com/Udyz/CVE-2021-40444-CAB) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2021-40444-CAB.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2021-40444-CAB.svg)

- [https://github.com/aydianosec/CVE2021-40444](https://github.com/aydianosec/CVE2021-40444) :  ![starts](https://img.shields.io/github/stars/aydianosec/CVE2021-40444.svg) ![forks](https://img.shields.io/github/forks/aydianosec/CVE2021-40444.svg)

- [https://github.com/H0j3n/CVE-2021-40444](https://github.com/H0j3n/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/H0j3n/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/H0j3n/CVE-2021-40444.svg)

- [https://github.com/DarkSprings/CVE-2021-40444](https://github.com/DarkSprings/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/DarkSprings/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/DarkSprings/CVE-2021-40444.svg)

- [https://github.com/fengjixuchui/CVE-2021-40444-docx-Generate](https://github.com/fengjixuchui/CVE-2021-40444-docx-Generate) :  ![starts](https://img.shields.io/github/stars/fengjixuchui/CVE-2021-40444-docx-Generate.svg) ![forks](https://img.shields.io/github/forks/fengjixuchui/CVE-2021-40444-docx-Generate.svg)

- [https://github.com/0xK4gura/CVE-2021-40444-POC](https://github.com/0xK4gura/CVE-2021-40444-POC) :  ![starts](https://img.shields.io/github/stars/0xK4gura/CVE-2021-40444-POC.svg) ![forks](https://img.shields.io/github/forks/0xK4gura/CVE-2021-40444-POC.svg)

- [https://github.com/bambooqj/CVE-2021-40444_EXP_JS](https://github.com/bambooqj/CVE-2021-40444_EXP_JS) :  ![starts](https://img.shields.io/github/stars/bambooqj/CVE-2021-40444_EXP_JS.svg) ![forks](https://img.shields.io/github/forks/bambooqj/CVE-2021-40444_EXP_JS.svg)

- [https://github.com/vysecurity/CVE-2021-40444](https://github.com/vysecurity/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/vysecurity/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/vysecurity/CVE-2021-40444.svg)

- [https://github.com/nightrelax/Exploit-PoC-CVE-2021-40444-inject-ma-doc-vao-docx](https://github.com/nightrelax/Exploit-PoC-CVE-2021-40444-inject-ma-doc-vao-docx) :  ![starts](https://img.shields.io/github/stars/nightrelax/Exploit-PoC-CVE-2021-40444-inject-ma-doc-vao-docx.svg) ![forks](https://img.shields.io/github/forks/nightrelax/Exploit-PoC-CVE-2021-40444-inject-ma-doc-vao-docx.svg)

- [https://github.com/LazarusReborn/Docx-Exploit-2021](https://github.com/LazarusReborn/Docx-Exploit-2021) :  ![starts](https://img.shields.io/github/stars/LazarusReborn/Docx-Exploit-2021.svg) ![forks](https://img.shields.io/github/forks/LazarusReborn/Docx-Exploit-2021.svg)

- [https://github.com/InfoSecPolkCounty/CVE2021-40444-document-Scanner](https://github.com/InfoSecPolkCounty/CVE2021-40444-document-Scanner) :  ![starts](https://img.shields.io/github/stars/InfoSecPolkCounty/CVE2021-40444-document-Scanner.svg) ![forks](https://img.shields.io/github/forks/InfoSecPolkCounty/CVE2021-40444-document-Scanner.svg)

- [https://github.com/zaneGittins/CVE-2021-40444-evtx](https://github.com/zaneGittins/CVE-2021-40444-evtx) :  ![starts](https://img.shields.io/github/stars/zaneGittins/CVE-2021-40444-evtx.svg) ![forks](https://img.shields.io/github/forks/zaneGittins/CVE-2021-40444-evtx.svg)

- [https://github.com/YxZi5/Detection-CVE_2021_40444](https://github.com/YxZi5/Detection-CVE_2021_40444) :  ![starts](https://img.shields.io/github/stars/YxZi5/Detection-CVE_2021_40444.svg) ![forks](https://img.shields.io/github/forks/YxZi5/Detection-CVE_2021_40444.svg)

- [https://github.com/js-on/CVE-2021-40444](https://github.com/js-on/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/js-on/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/js-on/CVE-2021-40444.svg)

- [https://github.com/gh0stxplt/CVE-2021-40444-URL-Extractor](https://github.com/gh0stxplt/CVE-2021-40444-URL-Extractor) :  ![starts](https://img.shields.io/github/stars/gh0stxplt/CVE-2021-40444-URL-Extractor.svg) ![forks](https://img.shields.io/github/forks/gh0stxplt/CVE-2021-40444-URL-Extractor.svg)

- [https://github.com/Zeop-CyberSec/word_mshtml](https://github.com/Zeop-CyberSec/word_mshtml) :  ![starts](https://img.shields.io/github/stars/Zeop-CyberSec/word_mshtml.svg) ![forks](https://img.shields.io/github/forks/Zeop-CyberSec/word_mshtml.svg)

- [https://github.com/factionsypho/TIC4301_Project](https://github.com/factionsypho/TIC4301_Project) :  ![starts](https://img.shields.io/github/stars/factionsypho/TIC4301_Project.svg) ![forks](https://img.shields.io/github/forks/factionsypho/TIC4301_Project.svg)

- [https://github.com/khoaduynu/CVE-2021-40444](https://github.com/khoaduynu/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/khoaduynu/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/khoaduynu/CVE-2021-40444.svg)

- [https://github.com/jamesrep/cve-2021-40444](https://github.com/jamesrep/cve-2021-40444) :  ![starts](https://img.shields.io/github/stars/jamesrep/cve-2021-40444.svg) ![forks](https://img.shields.io/github/forks/jamesrep/cve-2021-40444.svg)

- [https://github.com/Alexcot25051999/CVE-2021-40444](https://github.com/Alexcot25051999/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/Alexcot25051999/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/Alexcot25051999/CVE-2021-40444.svg)

- [https://github.com/lisinan988/CVE-2021-40444-exp](https://github.com/lisinan988/CVE-2021-40444-exp) :  ![starts](https://img.shields.io/github/stars/lisinan988/CVE-2021-40444-exp.svg) ![forks](https://img.shields.io/github/forks/lisinan988/CVE-2021-40444-exp.svg)

- [https://github.com/TiagoSergio/CVE-2021-40444](https://github.com/TiagoSergio/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/TiagoSergio/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/TiagoSergio/CVE-2021-40444.svg)

- [https://github.com/vanhohen/MSHTML-CVE-2021-40444](https://github.com/vanhohen/MSHTML-CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/vanhohen/MSHTML-CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/vanhohen/MSHTML-CVE-2021-40444.svg)

- [https://github.com/Immersive-Labs-Sec/cve-2021-40444-analysis](https://github.com/Immersive-Labs-Sec/cve-2021-40444-analysis) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/cve-2021-40444-analysis.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/cve-2021-40444-analysis.svg)

- [https://github.com/amartinsec/MSHTMHell](https://github.com/amartinsec/MSHTMHell) :  ![starts](https://img.shields.io/github/stars/amartinsec/MSHTMHell.svg) ![forks](https://img.shields.io/github/forks/amartinsec/MSHTMHell.svg)

- [https://github.com/kal1gh0st/CVE-2021-40444_CAB_archives](https://github.com/kal1gh0st/CVE-2021-40444_CAB_archives) :  ![starts](https://img.shields.io/github/stars/kal1gh0st/CVE-2021-40444_CAB_archives.svg) ![forks](https://img.shields.io/github/forks/kal1gh0st/CVE-2021-40444_CAB_archives.svg)

- [https://github.com/KnoooW/CVE-2021-40444-docx-Generate](https://github.com/KnoooW/CVE-2021-40444-docx-Generate) :  ![starts](https://img.shields.io/github/stars/KnoooW/CVE-2021-40444-docx-Generate.svg) ![forks](https://img.shields.io/github/forks/KnoooW/CVE-2021-40444-docx-Generate.svg)

## CVE-2021-40438
 A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.



- [https://github.com/sixpacksecurity/CVE-2021-40438](https://github.com/sixpacksecurity/CVE-2021-40438) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-40438.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-40438.svg)

- [https://github.com/xiaojiangxl/CVE-2021-40438](https://github.com/xiaojiangxl/CVE-2021-40438) :  ![starts](https://img.shields.io/github/stars/xiaojiangxl/CVE-2021-40438.svg) ![forks](https://img.shields.io/github/forks/xiaojiangxl/CVE-2021-40438.svg)

- [https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-40438-exploitation-attempt](https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-40438-exploitation-attempt) :  ![starts](https://img.shields.io/github/stars/pisut4152/Sigma-Rule-for-CVE-2021-40438-exploitation-attempt.svg) ![forks](https://img.shields.io/github/forks/pisut4152/Sigma-Rule-for-CVE-2021-40438-exploitation-attempt.svg)

- [https://github.com/BabyTeam1024/CVE-2021-40438](https://github.com/BabyTeam1024/CVE-2021-40438) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/CVE-2021-40438.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/CVE-2021-40438.svg)

- [https://github.com/ericmann/apache-cve-poc](https://github.com/ericmann/apache-cve-poc) :  ![starts](https://img.shields.io/github/stars/ericmann/apache-cve-poc.svg) ![forks](https://img.shields.io/github/forks/ericmann/apache-cve-poc.svg)

## CVE-2021-40375
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/DCKento/CVE-2021-40375](https://github.com/DCKento/CVE-2021-40375) :  ![starts](https://img.shields.io/github/stars/DCKento/CVE-2021-40375.svg) ![forks](https://img.shields.io/github/forks/DCKento/CVE-2021-40375.svg)

## CVE-2021-40374
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/DCKento/CVE-2021-40374](https://github.com/DCKento/CVE-2021-40374) :  ![starts](https://img.shields.io/github/stars/DCKento/CVE-2021-40374.svg) ![forks](https://img.shields.io/github/forks/DCKento/CVE-2021-40374.svg)

## CVE-2021-40373
 playSMS before 1.4.5 allows Arbitrary Code Execution by entering PHP code at the #tabs-information-page of core_main_config, and then executing that code via the index.php?app=main&amp;inc=core_welcome URI.



- [https://github.com/maikroservice/CVE-2021-40373](https://github.com/maikroservice/CVE-2021-40373) :  ![starts](https://img.shields.io/github/stars/maikroservice/CVE-2021-40373.svg) ![forks](https://img.shields.io/github/forks/maikroservice/CVE-2021-40373.svg)

## CVE-2021-40353
 A SQL injection vulnerability exists in version 8.0 of openSIS when MySQL or MariaDB is used as the application database. An attacker can then issue the SQL command through the index.php USERNAME parameter. NOTE: this issue may exist because of an incomplete fix for CVE-2020-6637.



- [https://github.com/5qu1n7/CVE-2021-40353](https://github.com/5qu1n7/CVE-2021-40353) :  ![starts](https://img.shields.io/github/stars/5qu1n7/CVE-2021-40353.svg) ![forks](https://img.shields.io/github/forks/5qu1n7/CVE-2021-40353.svg)

## CVE-2021-40352
 OpenEMR 6.0.0 has a pnotes_print.php?noteid= Insecure Direct Object Reference vulnerability via which an attacker can read the messages of all users.



- [https://github.com/allenenosh/CVE-2021-40352](https://github.com/allenenosh/CVE-2021-40352) :  ![starts](https://img.shields.io/github/stars/allenenosh/CVE-2021-40352.svg) ![forks](https://img.shields.io/github/forks/allenenosh/CVE-2021-40352.svg)

## CVE-2021-40346
 An integer overflow exists in HAProxy 2.0 through 2.5 in htx_add_header that can be exploited to perform an HTTP request smuggling attack, allowing an attacker to bypass all configured http-request HAProxy ACLs and possibly other ACLs.



- [https://github.com/knqyf263/CVE-2021-40346](https://github.com/knqyf263/CVE-2021-40346) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2021-40346.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2021-40346.svg)

- [https://github.com/donky16/CVE-2021-40346-POC](https://github.com/donky16/CVE-2021-40346-POC) :  ![starts](https://img.shields.io/github/stars/donky16/CVE-2021-40346-POC.svg) ![forks](https://img.shields.io/github/forks/donky16/CVE-2021-40346-POC.svg)

- [https://github.com/alikarimi999/CVE-2021-40346](https://github.com/alikarimi999/CVE-2021-40346) :  ![starts](https://img.shields.io/github/stars/alikarimi999/CVE-2021-40346.svg) ![forks](https://img.shields.io/github/forks/alikarimi999/CVE-2021-40346.svg)

- [https://github.com/Vulnmachines/HAProxy_CVE-2021-40346](https://github.com/Vulnmachines/HAProxy_CVE-2021-40346) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/HAProxy_CVE-2021-40346.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/HAProxy_CVE-2021-40346.svg)

## CVE-2021-40223
 Rittal CMC PU III Web management (version V3.11.00_2) fails to sanitize user input on several parameters of the configuration (User Configuration dialog, Task Configuration dialog and set logging filter dialog). This allows an attacker to backdoor the device with HTML and browser-interpreted content (such as JavaScript or other client-side scripts). The XSS payload will be triggered when the user accesses some specific sections of the application.



- [https://github.com/asang17/CVE-2021-40223](https://github.com/asang17/CVE-2021-40223) :  ![starts](https://img.shields.io/github/stars/asang17/CVE-2021-40223.svg) ![forks](https://img.shields.io/github/forks/asang17/CVE-2021-40223.svg)

## CVE-2021-40222
 Rittal CMC PU III Web management Version affected: V3.11.00_2. Version fixed: V3.17.10 is affected by a remote code execution vulnerablity. It is possible to introduce shell code to create a reverse shell in the PU-Hostname field of the TCP/IP Configuration dialog. Web application fails to sanitize user input on Network TCP/IP configuration page. This allows the attacker to inject commands as root on the device which will be executed once the data is received.



- [https://github.com/asang17/CVE-2021-40222](https://github.com/asang17/CVE-2021-40222) :  ![starts](https://img.shields.io/github/stars/asang17/CVE-2021-40222.svg) ![forks](https://img.shields.io/github/forks/asang17/CVE-2021-40222.svg)

## CVE-2021-40154
 NXP LPC55S69 devices before A3 have a buffer over-read via a crafted wlength value in a GET Descriptor Configuration request during use of USB In-System Programming (ISP) mode. This discloses protected flash memory.



- [https://github.com/Xen1thLabs-AE/CVE-2021-40154](https://github.com/Xen1thLabs-AE/CVE-2021-40154) :  ![starts](https://img.shields.io/github/stars/Xen1thLabs-AE/CVE-2021-40154.svg) ![forks](https://img.shields.io/github/forks/Xen1thLabs-AE/CVE-2021-40154.svg)

## CVE-2021-40101
 An issue was discovered in Concrete CMS before 8.5.7. The Dashboard allows a user's password to be changed without a prompt for the current password.



- [https://github.com/S1lkys/CVE-2021-40101](https://github.com/S1lkys/CVE-2021-40101) :  ![starts](https://img.shields.io/github/stars/S1lkys/CVE-2021-40101.svg) ![forks](https://img.shields.io/github/forks/S1lkys/CVE-2021-40101.svg)

## CVE-2021-39685
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/szymonh/inspector-gadget](https://github.com/szymonh/inspector-gadget) :  ![starts](https://img.shields.io/github/stars/szymonh/inspector-gadget.svg) ![forks](https://img.shields.io/github/forks/szymonh/inspector-gadget.svg)

## CVE-2021-39512
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/guusec/CVE-2021-39512-BigTreeCMS-v4.4.14-AccountTakeOver](https://github.com/guusec/CVE-2021-39512-BigTreeCMS-v4.4.14-AccountTakeOver) :  ![starts](https://img.shields.io/github/stars/guusec/CVE-2021-39512-BigTreeCMS-v4.4.14-AccountTakeOver.svg) ![forks](https://img.shields.io/github/forks/guusec/CVE-2021-39512-BigTreeCMS-v4.4.14-AccountTakeOver.svg)

## CVE-2021-39476
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/W4RCL0UD/CVE-2021-39476](https://github.com/W4RCL0UD/CVE-2021-39476) :  ![starts](https://img.shields.io/github/stars/W4RCL0UD/CVE-2021-39476.svg) ![forks](https://img.shields.io/github/forks/W4RCL0UD/CVE-2021-39476.svg)

## CVE-2021-39475
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/W4RCL0UD/CVE-2021-39475](https://github.com/W4RCL0UD/CVE-2021-39475) :  ![starts](https://img.shields.io/github/stars/W4RCL0UD/CVE-2021-39475.svg) ![forks](https://img.shields.io/github/forks/W4RCL0UD/CVE-2021-39475.svg)

## CVE-2021-39433
 A local file inclusion (LFI) vulnerability exists in version BIQS IT Biqs-drive v1.83 and below when sending a specific payload as the file parameter to download/index.php. This allows the attacker to read arbitrary files from the server with the permissions of the configured web-user.



- [https://github.com/PinkDraconian/CVE-2021-39433](https://github.com/PinkDraconian/CVE-2021-39433) :  ![starts](https://img.shields.io/github/stars/PinkDraconian/CVE-2021-39433.svg) ![forks](https://img.shields.io/github/forks/PinkDraconian/CVE-2021-39433.svg)

## CVE-2021-39379
 A SQL Injection vulnerability exists in openSIS 8.0 when MySQL (MariaDB) is being used as the application database. A malicious attacker can issue SQL commands to the MySQL (MariaDB) database through the ResetUserInfo.php password_stn_id parameter.



- [https://github.com/security-n/CVE-2021-39379](https://github.com/security-n/CVE-2021-39379) :  ![starts](https://img.shields.io/github/stars/security-n/CVE-2021-39379.svg) ![forks](https://img.shields.io/github/forks/security-n/CVE-2021-39379.svg)

## CVE-2021-39378
 A SQL Injection vulnerability exists in openSIS 8.0 when MySQL (MariaDB) is being used as the application database. A malicious attacker can issue SQL commands to the MySQL (MariaDB) database through the NamesList.php str parameter.



- [https://github.com/security-n/CVE-2021-39378](https://github.com/security-n/CVE-2021-39378) :  ![starts](https://img.shields.io/github/stars/security-n/CVE-2021-39378.svg) ![forks](https://img.shields.io/github/forks/security-n/CVE-2021-39378.svg)

## CVE-2021-39377
 A SQL Injection vulnerability exists in openSIS 8.0 when MySQL (MariaDB) is being used as the application database. A malicious attacker can issue SQL commands to the MySQL (MariaDB) database through the index.php username parameter.



- [https://github.com/security-n/CVE-2021-39377](https://github.com/security-n/CVE-2021-39377) :  ![starts](https://img.shields.io/github/stars/security-n/CVE-2021-39377.svg) ![forks](https://img.shields.io/github/forks/security-n/CVE-2021-39377.svg)

## CVE-2021-39316
 The Zoomsounds plugin &lt;= 6.45 for WordPress allows arbitrary files, including sensitive configuration files such as wp-config.php, to be downloaded via the `dzsap_download` action using directory traversal in the `link` parameter.



- [https://github.com/anggoroexe/Mass-CVE-2021-39316](https://github.com/anggoroexe/Mass-CVE-2021-39316) :  ![starts](https://img.shields.io/github/stars/anggoroexe/Mass-CVE-2021-39316.svg) ![forks](https://img.shields.io/github/forks/anggoroexe/Mass-CVE-2021-39316.svg)

## CVE-2021-39287
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/Fearless523/CVE-2021-39287-Stored-XSS](https://github.com/Fearless523/CVE-2021-39287-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/Fearless523/CVE-2021-39287-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/Fearless523/CVE-2021-39287-Stored-XSS.svg)

## CVE-2021-39274
 In XeroSecurity Sn1per 9.0 (free version), insecure directory permissions (0777) are set during installation, allowing an unprivileged user to modify the main application and the application configuration file. This results in arbitrary code execution with root privileges.



- [https://github.com/nikip72/CVE-2021-39273-CVE-2021-39274](https://github.com/nikip72/CVE-2021-39273-CVE-2021-39274) :  ![starts](https://img.shields.io/github/stars/nikip72/CVE-2021-39273-CVE-2021-39274.svg) ![forks](https://img.shields.io/github/forks/nikip72/CVE-2021-39273-CVE-2021-39274.svg)

## CVE-2021-39273
 In XeroSecurity Sn1per 9.0 (free version), insecure permissions (0777) are set upon application execution, allowing an unprivileged user to modify the application, modules, and configuration files. This leads to arbitrary code execution with root privileges.



- [https://github.com/nikip72/CVE-2021-39273-CVE-2021-39274](https://github.com/nikip72/CVE-2021-39273-CVE-2021-39274) :  ![starts](https://img.shields.io/github/stars/nikip72/CVE-2021-39273-CVE-2021-39274.svg) ![forks](https://img.shields.io/github/forks/nikip72/CVE-2021-39273-CVE-2021-39274.svg)

## CVE-2021-39150
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to request data from internal resources that are not publicly available only by manipulating the processed input stream with a Java runtime version 14 to 8. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. If you rely on XStream's default blacklist of the [Security Framework](https://x-stream.github.io/security.html#framework), you will have to use at least version 1.4.18.



- [https://github.com/zwjjustdoit/Xstream-1.4.17](https://github.com/zwjjustdoit/Xstream-1.4.17) :  ![starts](https://img.shields.io/github/stars/zwjjustdoit/Xstream-1.4.17.svg) ![forks](https://img.shields.io/github/forks/zwjjustdoit/Xstream-1.4.17.svg)

## CVE-2021-39144
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker has sufficient rights to execute commands of the host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.



- [https://github.com/zwjjustdoit/Xstream-1.4.17](https://github.com/zwjjustdoit/Xstream-1.4.17) :  ![starts](https://img.shields.io/github/stars/zwjjustdoit/Xstream-1.4.17.svg) ![forks](https://img.shields.io/github/forks/zwjjustdoit/Xstream-1.4.17.svg)

## CVE-2021-39141
 XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.



- [https://github.com/zwjjustdoit/Xstream-1.4.17](https://github.com/zwjjustdoit/Xstream-1.4.17) :  ![starts](https://img.shields.io/github/stars/zwjjustdoit/Xstream-1.4.17.svg) ![forks](https://img.shields.io/github/forks/zwjjustdoit/Xstream-1.4.17.svg)

## CVE-2021-39115
 Affected versions of Atlassian Jira Service Management Server and Data Center allow remote attackers with &quot;Jira Administrators&quot; access to execute arbitrary Java code or run arbitrary system commands via a Server_Side Template Injection vulnerability in the Email Template feature. The affected versions are before version 4.13.9, and from version 4.14.0 before 4.18.0.



- [https://github.com/PetrusViet/CVE-2021-39115](https://github.com/PetrusViet/CVE-2021-39115) :  ![starts](https://img.shields.io/github/stars/PetrusViet/CVE-2021-39115.svg) ![forks](https://img.shields.io/github/forks/PetrusViet/CVE-2021-39115.svg)

## CVE-2021-38759
 Raspberry Pi OS through 5.10 has the raspberry default password for the pi account. If not changed, attackers can gain administrator privileges.



- [https://github.com/joanbono/CVE-2021-38759](https://github.com/joanbono/CVE-2021-38759) :  ![starts](https://img.shields.io/github/stars/joanbono/CVE-2021-38759.svg) ![forks](https://img.shields.io/github/forks/joanbono/CVE-2021-38759.svg)

## CVE-2021-38710
 ** DISPUTED ** Static (Persistent) XSS Vulnerability exists in version 4.3.0 of Yclas when using the install/view/form.php script. An attacker can store XSS in the database through the vulnerable SITE_NAME parameter. NOTE: a requirement for an XSS payload to be introduced during a product's initial installation makes a vulnerability report largely irrelevant.



- [https://github.com/security-n/CVE-2021-38710](https://github.com/security-n/CVE-2021-38710) :  ![starts](https://img.shields.io/github/stars/security-n/CVE-2021-38710.svg) ![forks](https://img.shields.io/github/forks/security-n/CVE-2021-38710.svg)

## CVE-2021-38707
 Persistent cross-site scripting (XSS) vulnerabilities in ClinicCases 7.3.3 allow low-privileged attackers to introduce arbitrary JavaScript to account parameters. The XSS payloads will execute in the browser of any user who views the relevant content. This can result in account takeover via session token theft.



- [https://github.com/sudonoodle/CVE-2021-38707](https://github.com/sudonoodle/CVE-2021-38707) :  ![starts](https://img.shields.io/github/stars/sudonoodle/CVE-2021-38707.svg) ![forks](https://img.shields.io/github/forks/sudonoodle/CVE-2021-38707.svg)

## CVE-2021-38706
 messages_load.php in ClinicCases 7.3.3 suffers from a blind SQL injection vulnerability, which allows low-privileged attackers to execute arbitrary SQL commands through a vulnerable parameter.



- [https://github.com/sudonoodle/CVE-2021-38706](https://github.com/sudonoodle/CVE-2021-38706) :  ![starts](https://img.shields.io/github/stars/sudonoodle/CVE-2021-38706.svg) ![forks](https://img.shields.io/github/forks/sudonoodle/CVE-2021-38706.svg)

## CVE-2021-38705
 ClinicCases 7.3.3 is affected by Cross-Site Request Forgery (CSRF). A successful attack would consist of an authenticated user following a malicious link, resulting in arbitrary actions being carried out with the privilege level of the targeted user. This can be exploited to create a secondary administrator account for the attacker.



- [https://github.com/sudonoodle/CVE-2021-38705](https://github.com/sudonoodle/CVE-2021-38705) :  ![starts](https://img.shields.io/github/stars/sudonoodle/CVE-2021-38705.svg) ![forks](https://img.shields.io/github/forks/sudonoodle/CVE-2021-38705.svg)

## CVE-2021-38704
 Multiple reflected cross-site scripting (XSS) vulnerabilities in ClinicCases 7.3.3 allow unauthenticated attackers to introduce arbitrary JavaScript by crafting a malicious URL. This can result in account takeover via session token theft.



- [https://github.com/sudonoodle/CVE-2021-38704](https://github.com/sudonoodle/CVE-2021-38704) :  ![starts](https://img.shields.io/github/stars/sudonoodle/CVE-2021-38704.svg) ![forks](https://img.shields.io/github/forks/sudonoodle/CVE-2021-38704.svg)

## CVE-2021-38699
 TastyIgniter 3.0.7 allows XSS via /account, /reservation, /admin/dashboard, and /admin/system_logs.



- [https://github.com/HuskyHacks/CVE-2021-38699-Reflected-XSS](https://github.com/HuskyHacks/CVE-2021-38699-Reflected-XSS) :  ![starts](https://img.shields.io/github/stars/HuskyHacks/CVE-2021-38699-Reflected-XSS.svg) ![forks](https://img.shields.io/github/forks/HuskyHacks/CVE-2021-38699-Reflected-XSS.svg)

- [https://github.com/Justin-1993/CVE-2021-38699](https://github.com/Justin-1993/CVE-2021-38699) :  ![starts](https://img.shields.io/github/stars/Justin-1993/CVE-2021-38699.svg) ![forks](https://img.shields.io/github/forks/Justin-1993/CVE-2021-38699.svg)

- [https://github.com/HuskyHacks/CVE-2021-38699-Stored-XSS](https://github.com/HuskyHacks/CVE-2021-38699-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/HuskyHacks/CVE-2021-38699-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/HuskyHacks/CVE-2021-38699-Stored-XSS.svg)

## CVE-2021-38666
 Remote Desktop Client Remote Code Execution Vulnerability



- [https://github.com/DarkSprings/CVE-2021-38666-poc](https://github.com/DarkSprings/CVE-2021-38666-poc) :  ![starts](https://img.shields.io/github/stars/DarkSprings/CVE-2021-38666-poc.svg) ![forks](https://img.shields.io/github/forks/DarkSprings/CVE-2021-38666-poc.svg)

- [https://github.com/JaneMandy/CVE-2021-38666](https://github.com/JaneMandy/CVE-2021-38666) :  ![starts](https://img.shields.io/github/stars/JaneMandy/CVE-2021-38666.svg) ![forks](https://img.shields.io/github/forks/JaneMandy/CVE-2021-38666.svg)

## CVE-2021-38647
 Open Management Infrastructure Remote Code Execution Vulnerability



- [https://github.com/horizon3ai/CVE-2021-38647](https://github.com/horizon3ai/CVE-2021-38647) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2021-38647.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2021-38647.svg)

- [https://github.com/AlteredSecurity/CVE-2021-38647](https://github.com/AlteredSecurity/CVE-2021-38647) :  ![starts](https://img.shields.io/github/stars/AlteredSecurity/CVE-2021-38647.svg) ![forks](https://img.shields.io/github/forks/AlteredSecurity/CVE-2021-38647.svg)

- [https://github.com/marcosimioni/omigood](https://github.com/marcosimioni/omigood) :  ![starts](https://img.shields.io/github/stars/marcosimioni/omigood.svg) ![forks](https://img.shields.io/github/forks/marcosimioni/omigood.svg)

- [https://github.com/midoxnet/CVE-2021-38647](https://github.com/midoxnet/CVE-2021-38647) :  ![starts](https://img.shields.io/github/stars/midoxnet/CVE-2021-38647.svg) ![forks](https://img.shields.io/github/forks/midoxnet/CVE-2021-38647.svg)

- [https://github.com/corelight/CVE-2021-38647](https://github.com/corelight/CVE-2021-38647) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2021-38647.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2021-38647.svg)

- [https://github.com/Vulnmachines/OMIGOD_cve-2021-38647](https://github.com/Vulnmachines/OMIGOD_cve-2021-38647) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/OMIGOD_cve-2021-38647.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/OMIGOD_cve-2021-38647.svg)

- [https://github.com/Immersive-Labs-Sec/cve-2021-38647](https://github.com/Immersive-Labs-Sec/cve-2021-38647) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/cve-2021-38647.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/cve-2021-38647.svg)

- [https://github.com/SimenBai/CVE-2021-38647-POC-and-Demo-environment](https://github.com/SimenBai/CVE-2021-38647-POC-and-Demo-environment) :  ![starts](https://img.shields.io/github/stars/SimenBai/CVE-2021-38647-POC-and-Demo-environment.svg) ![forks](https://img.shields.io/github/forks/SimenBai/CVE-2021-38647-POC-and-Demo-environment.svg)

- [https://github.com/fr34kyy/omigod](https://github.com/fr34kyy/omigod) :  ![starts](https://img.shields.io/github/stars/fr34kyy/omigod.svg) ![forks](https://img.shields.io/github/forks/fr34kyy/omigod.svg)

- [https://github.com/abousteif/cve-2021-38647](https://github.com/abousteif/cve-2021-38647) :  ![starts](https://img.shields.io/github/stars/abousteif/cve-2021-38647.svg) ![forks](https://img.shields.io/github/forks/abousteif/cve-2021-38647.svg)

- [https://github.com/m1thryn/CVE-2021-38647](https://github.com/m1thryn/CVE-2021-38647) :  ![starts](https://img.shields.io/github/stars/m1thryn/CVE-2021-38647.svg) ![forks](https://img.shields.io/github/forks/m1thryn/CVE-2021-38647.svg)

- [https://github.com/craig-m-unsw/omigod-lab](https://github.com/craig-m-unsw/omigod-lab) :  ![starts](https://img.shields.io/github/stars/craig-m-unsw/omigod-lab.svg) ![forks](https://img.shields.io/github/forks/craig-m-unsw/omigod-lab.svg)

## CVE-2021-38639
 Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-36975.



- [https://github.com/DarkSprings/CVE-2021-38639](https://github.com/DarkSprings/CVE-2021-38639) :  ![starts](https://img.shields.io/github/stars/DarkSprings/CVE-2021-38639.svg) ![forks](https://img.shields.io/github/forks/DarkSprings/CVE-2021-38639.svg)

## CVE-2021-38619
 openBaraza HCM 3.1.6 does not properly neutralize user-controllable input: an unauthenticated remote attacker can conduct a stored cross-site scripting (XSS) attack against an administrative user from hr/subscription.jsp and hr/application.jsp and and hr/index.jsp (with view=).



- [https://github.com/charlesbickel/CVE-2021-38619](https://github.com/charlesbickel/CVE-2021-38619) :  ![starts](https://img.shields.io/github/stars/charlesbickel/CVE-2021-38619.svg) ![forks](https://img.shields.io/github/forks/charlesbickel/CVE-2021-38619.svg)

## CVE-2021-38603
 PluXML 5.8.7 allows core/admin/profil.php stored XSS via the Information field.



- [https://github.com/KielVaughn/CVE-2021-38603](https://github.com/KielVaughn/CVE-2021-38603) :  ![starts](https://img.shields.io/github/stars/KielVaughn/CVE-2021-38603.svg) ![forks](https://img.shields.io/github/forks/KielVaughn/CVE-2021-38603.svg)

## CVE-2021-38602
 PluXML 5.8.7 allows Article Editing stored XSS via Headline or Content.



- [https://github.com/KielVaughn/CVE-2021-38602](https://github.com/KielVaughn/CVE-2021-38602) :  ![starts](https://img.shields.io/github/stars/KielVaughn/CVE-2021-38602.svg) ![forks](https://img.shields.io/github/forks/KielVaughn/CVE-2021-38602.svg)

## CVE-2021-38601
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/hmaverickadams/CVE-2021-38601](https://github.com/hmaverickadams/CVE-2021-38601) :  ![starts](https://img.shields.io/github/stars/hmaverickadams/CVE-2021-38601.svg) ![forks](https://img.shields.io/github/forks/hmaverickadams/CVE-2021-38601.svg)

## CVE-2021-38600
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/hmaverickadams/CVE-2021-38600](https://github.com/hmaverickadams/CVE-2021-38600) :  ![starts](https://img.shields.io/github/stars/hmaverickadams/CVE-2021-38600.svg) ![forks](https://img.shields.io/github/forks/hmaverickadams/CVE-2021-38600.svg)

## CVE-2021-38583
 openBaraza HCM 3.1.6 does not properly neutralize user-controllable input, which allows reflected cross-site scripting (XSS) on multiple pages: hr/subscription.jsp and hr/application.jsp and and hr/index.jsp (with view= and data=).



- [https://github.com/charlesbickel/CVE-2021-38583](https://github.com/charlesbickel/CVE-2021-38583) :  ![starts](https://img.shields.io/github/stars/charlesbickel/CVE-2021-38583.svg) ![forks](https://img.shields.io/github/forks/charlesbickel/CVE-2021-38583.svg)

## CVE-2021-38314
 The Gutenberg Template Library &amp; Redux Framework plugin &lt;= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site&#8217;s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.



- [https://github.com/onsecuredev/CVE-2021-38314](https://github.com/onsecuredev/CVE-2021-38314) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-38314.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-38314.svg)

- [https://github.com/phrantom/cve-2021-38314](https://github.com/phrantom/cve-2021-38314) :  ![starts](https://img.shields.io/github/stars/phrantom/cve-2021-38314.svg) ![forks](https://img.shields.io/github/forks/phrantom/cve-2021-38314.svg)

- [https://github.com/shubhayu-64/CVE-2021-38314](https://github.com/shubhayu-64/CVE-2021-38314) :  ![starts](https://img.shields.io/github/stars/shubhayu-64/CVE-2021-38314.svg) ![forks](https://img.shields.io/github/forks/shubhayu-64/CVE-2021-38314.svg)

## CVE-2021-38295
 In Apache CouchDB, a malicious user with permission to create documents in a database is able to attach a HTML attachment to a document. If a CouchDB admin opens that attachment in a browser, e.g. via the CouchDB admin interface Fauxton, any JavaScript code embedded in that HTML attachment will be executed within the security context of that admin. A similar route is available with the already deprecated _show and _list functionality. This privilege escalation vulnerability allows an attacker to add or remove data in any database or make configuration changes. This issue affected Apache CouchDB prior to 3.1.2



- [https://github.com/ProfessionallyEvil/CVE-2021-38295-PoC](https://github.com/ProfessionallyEvil/CVE-2021-38295-PoC) :  ![starts](https://img.shields.io/github/stars/ProfessionallyEvil/CVE-2021-38295-PoC.svg) ![forks](https://img.shields.io/github/forks/ProfessionallyEvil/CVE-2021-38295-PoC.svg)

## CVE-2021-38185
 GNU cpio through 2.13 allows attackers to execute arbitrary code via a crafted pattern file, because of a dstring.c ds_fgetstr integer overflow that triggers an out-of-bounds heap write. NOTE: it is unclear whether there are common cases where the pattern file, associated with the -E option, is untrusted data.



- [https://github.com/fangqyi/cpiopwn](https://github.com/fangqyi/cpiopwn) :  ![starts](https://img.shields.io/github/stars/fangqyi/cpiopwn.svg) ![forks](https://img.shields.io/github/forks/fangqyi/cpiopwn.svg)

## CVE-2021-38149
 index.php/admin/add_user in Chikitsa Patient Management System 2.0.0 allows XSS.



- [https://github.com/jboogie15/CVE-2021-38149](https://github.com/jboogie15/CVE-2021-38149) :  ![starts](https://img.shields.io/github/stars/jboogie15/CVE-2021-38149.svg) ![forks](https://img.shields.io/github/forks/jboogie15/CVE-2021-38149.svg)

## CVE-2021-38001
 Type confusion in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.



- [https://github.com/Peterpan0927/TFC-Chrome-v8-bug-CVE-2021-38001-poc](https://github.com/Peterpan0927/TFC-Chrome-v8-bug-CVE-2021-38001-poc) :  ![starts](https://img.shields.io/github/stars/Peterpan0927/TFC-Chrome-v8-bug-CVE-2021-38001-poc.svg) ![forks](https://img.shields.io/github/forks/Peterpan0927/TFC-Chrome-v8-bug-CVE-2021-38001-poc.svg)

- [https://github.com/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc](https://github.com/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc) :  ![starts](https://img.shields.io/github/stars/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc.svg) ![forks](https://img.shields.io/github/forks/maldiohead/TFC-Chrome-v8-bug-CVE-2021-38001-poc.svg)

## CVE-2021-37980
 Inappropriate implementation in Sandbox in Google Chrome prior to 94.0.4606.81 allowed a remote attacker to potentially bypass site isolation via Windows.



- [https://github.com/ZeusBox/CVE-2021-37980](https://github.com/ZeusBox/CVE-2021-37980) :  ![starts](https://img.shields.io/github/stars/ZeusBox/CVE-2021-37980.svg) ![forks](https://img.shields.io/github/forks/ZeusBox/CVE-2021-37980.svg)

## CVE-2021-37850
 ESET was made aware of a vulnerability in its consumer and business products for macOS that enables a user logged on to the system to stop the ESET daemon, effectively disabling the protection of the ESET security product until a system reboot.



- [https://github.com/p1atdev/CVE-2021-37850](https://github.com/p1atdev/CVE-2021-37850) :  ![starts](https://img.shields.io/github/stars/p1atdev/CVE-2021-37850.svg) ![forks](https://img.shields.io/github/forks/p1atdev/CVE-2021-37850.svg)

## CVE-2021-37833
 A reflected cross-site scripting (XSS) vulnerability exists in multiple pages in version 3.0.2 of the Hotel Druid application that allows for arbitrary execution of JavaScript commands.



- [https://github.com/dievus/CVE-2021-37833](https://github.com/dievus/CVE-2021-37833) :  ![starts](https://img.shields.io/github/stars/dievus/CVE-2021-37833.svg) ![forks](https://img.shields.io/github/forks/dievus/CVE-2021-37833.svg)

## CVE-2021-37832
 A SQL injection vulnerability exists in version 3.0.2 of Hotel Druid when SQLite is being used as the application database. A malicious attacker can issue SQL commands to the SQLite database through the vulnerable idappartamenti parameter.



- [https://github.com/dievus/CVE-2021-37832](https://github.com/dievus/CVE-2021-37832) :  ![starts](https://img.shields.io/github/stars/dievus/CVE-2021-37832.svg) ![forks](https://img.shields.io/github/forks/dievus/CVE-2021-37832.svg)

- [https://github.com/AK-blank/CVE-2021-37832](https://github.com/AK-blank/CVE-2021-37832) :  ![starts](https://img.shields.io/github/stars/AK-blank/CVE-2021-37832.svg) ![forks](https://img.shields.io/github/forks/AK-blank/CVE-2021-37832.svg)

## CVE-2021-37748
 Multiple buffer overflows in the limited configuration shell (/sbin/gs_config) on Grandstream HT801 devices before 1.0.29 allow remote authenticated users to execute arbitrary code as root via a crafted manage_if setting, thus bypassing the intended restrictions of this shell and taking full control of the device. There are default weak credentials that can be used to authenticate.



- [https://github.com/SECFORCE/CVE-2021-37748](https://github.com/SECFORCE/CVE-2021-37748) :  ![starts](https://img.shields.io/github/stars/SECFORCE/CVE-2021-37748.svg) ![forks](https://img.shields.io/github/forks/SECFORCE/CVE-2021-37748.svg)

## CVE-2021-37678
 TensorFlow is an end-to-end open source platform for machine learning. In affected versions TensorFlow and Keras can be tricked to perform arbitrary code execution when deserializing a Keras model from YAML format. The [implementation](https://github.com/tensorflow/tensorflow/blob/460e000de3a83278fb00b61a16d161b1964f15f4/tensorflow/python/keras/saving/model_config.py#L66-L104) uses `yaml.unsafe_load` which can perform arbitrary code execution on the input. Given that YAML format support requires a significant amount of work, we have removed it for now. We have patched the issue in GitHub commit 23d6383eb6c14084a8fc3bdf164043b974818012. The fix will be included in TensorFlow 2.6.0. We will also cherrypick this commit on TensorFlow 2.5.1, TensorFlow 2.4.3, and TensorFlow 2.3.4, as these are also affected and still in supported range.



- [https://github.com/fran-CICS/ExploitTensorflowCVE-2021-37678](https://github.com/fran-CICS/ExploitTensorflowCVE-2021-37678) :  ![starts](https://img.shields.io/github/stars/fran-CICS/ExploitTensorflowCVE-2021-37678.svg) ![forks](https://img.shields.io/github/forks/fran-CICS/ExploitTensorflowCVE-2021-37678.svg)

## CVE-2021-37624
 FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to version 1.10.7, FreeSWITCH does not authenticate SIP MESSAGE requests, leading to spam and message spoofing. By default, SIP requests of the type MESSAGE (RFC 3428) are not authenticated in the affected versions of FreeSWITCH. MESSAGE requests are relayed to SIP user agents registered with the FreeSWITCH server without requiring any authentication. Although this behaviour can be changed by setting the `auth-messages` parameter to `true`, it is not the default setting. Abuse of this security issue allows attackers to send SIP MESSAGE messages to any SIP user agent that is registered with the server without requiring authentication. Additionally, since no authentication is required, chat messages can be spoofed to appear to come from trusted entities. Therefore, abuse can lead to spam and enable social engineering, phishing and similar attacks. This issue is patched in version 1.10.7. Maintainers recommend that this SIP message type is authenticated by default so that FreeSWITCH administrators do not need to be explicitly set the `auth-messages` parameter. When following such a recommendation, a new parameter can be introduced to explicitly disable authentication.



- [https://github.com/0xInfection/PewSWITCH](https://github.com/0xInfection/PewSWITCH) :  ![starts](https://img.shields.io/github/stars/0xInfection/PewSWITCH.svg) ![forks](https://img.shields.io/github/forks/0xInfection/PewSWITCH.svg)

## CVE-2021-37589
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/lucaregne/CVE-2021-37589](https://github.com/lucaregne/CVE-2021-37589) :  ![starts](https://img.shields.io/github/stars/lucaregne/CVE-2021-37589.svg) ![forks](https://img.shields.io/github/forks/lucaregne/CVE-2021-37589.svg)

## CVE-2021-37580
 A flaw was found in Apache ShenYu Admin. The incorrect use of JWT in ShenyuAdminBootstrap allows an attacker to bypass authentication. This issue affected Apache ShenYu 2.3.0 and 2.4.0



- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)

- [https://github.com/fengwenhua/CVE-2021-37580](https://github.com/fengwenhua/CVE-2021-37580) :  ![starts](https://img.shields.io/github/stars/fengwenhua/CVE-2021-37580.svg) ![forks](https://img.shields.io/github/forks/fengwenhua/CVE-2021-37580.svg)

- [https://github.com/Liang2580/CVE-2021-37580](https://github.com/Liang2580/CVE-2021-37580) :  ![starts](https://img.shields.io/github/stars/Liang2580/CVE-2021-37580.svg) ![forks](https://img.shields.io/github/forks/Liang2580/CVE-2021-37580.svg)

- [https://github.com/rabbitsafe/CVE-2021-37580](https://github.com/rabbitsafe/CVE-2021-37580) :  ![starts](https://img.shields.io/github/stars/rabbitsafe/CVE-2021-37580.svg) ![forks](https://img.shields.io/github/forks/rabbitsafe/CVE-2021-37580.svg)

- [https://github.com/ZororoZ/CVE-2021-37580](https://github.com/ZororoZ/CVE-2021-37580) :  ![starts](https://img.shields.io/github/stars/ZororoZ/CVE-2021-37580.svg) ![forks](https://img.shields.io/github/forks/ZororoZ/CVE-2021-37580.svg)

- [https://github.com/Wing-song/CVE-2021-37580](https://github.com/Wing-song/CVE-2021-37580) :  ![starts](https://img.shields.io/github/stars/Wing-song/CVE-2021-37580.svg) ![forks](https://img.shields.io/github/forks/Wing-song/CVE-2021-37580.svg)

- [https://github.com/Osyanina/westone-CVE-2021-37580-scanner](https://github.com/Osyanina/westone-CVE-2021-37580-scanner) :  ![starts](https://img.shields.io/github/stars/Osyanina/westone-CVE-2021-37580-scanner.svg) ![forks](https://img.shields.io/github/forks/Osyanina/westone-CVE-2021-37580-scanner.svg)

## CVE-2021-37152
 Multiple XSS issues exist in Sonatype Nexus Repository Manager 3 before 3.33.0. An authenticated attacker with the ability to add HTML files to a repository could redirect users to Nexus Repository Manager&#8217;s pages with code modifications.



- [https://github.com/SecurityAnalysts/CVE-2021-37152](https://github.com/SecurityAnalysts/CVE-2021-37152) :  ![starts](https://img.shields.io/github/stars/SecurityAnalysts/CVE-2021-37152.svg) ![forks](https://img.shields.io/github/forks/SecurityAnalysts/CVE-2021-37152.svg)

## CVE-2021-36958
 Windows Print Spooler Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-36936, CVE-2021-36947.



- [https://github.com/Tomparte/PrintNightmare](https://github.com/Tomparte/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/Tomparte/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/Tomparte/PrintNightmare.svg)

## CVE-2021-36949
 Microsoft Azure Active Directory Connect Authentication Bypass Vulnerability



- [https://github.com/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability](https://github.com/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability) :  ![starts](https://img.shields.io/github/stars/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability.svg) ![forks](https://img.shields.io/github/forks/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability.svg)

## CVE-2021-36934
 Windows Elevation of Privilege Vulnerability



- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)

- [https://github.com/cube0x0/CVE-2021-36934](https://github.com/cube0x0/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/cube0x0/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/cube0x0/CVE-2021-36934.svg)

- [https://github.com/HuskyHacks/ShadowSteal](https://github.com/HuskyHacks/ShadowSteal) :  ![starts](https://img.shields.io/github/stars/HuskyHacks/ShadowSteal.svg) ![forks](https://img.shields.io/github/forks/HuskyHacks/ShadowSteal.svg)

- [https://github.com/FireFart/hivenightmare](https://github.com/FireFart/hivenightmare) :  ![starts](https://img.shields.io/github/stars/FireFart/hivenightmare.svg) ![forks](https://img.shields.io/github/forks/FireFart/hivenightmare.svg)

- [https://github.com/WiredPulse/Invoke-HiveNightmare](https://github.com/WiredPulse/Invoke-HiveNightmare) :  ![starts](https://img.shields.io/github/stars/WiredPulse/Invoke-HiveNightmare.svg) ![forks](https://img.shields.io/github/forks/WiredPulse/Invoke-HiveNightmare.svg)

- [https://github.com/JoranSlingerland/CVE-2021-36934](https://github.com/JoranSlingerland/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/JoranSlingerland/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/JoranSlingerland/CVE-2021-36934.svg)

- [https://github.com/exploitblizzard/CVE-2021-36934](https://github.com/exploitblizzard/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/exploitblizzard/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/exploitblizzard/CVE-2021-36934.svg)

- [https://github.com/romarroca/SeriousSam](https://github.com/romarroca/SeriousSam) :  ![starts](https://img.shields.io/github/stars/romarroca/SeriousSam.svg) ![forks](https://img.shields.io/github/forks/romarroca/SeriousSam.svg)

- [https://github.com/n3tsurge/CVE-2021-36934](https://github.com/n3tsurge/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/n3tsurge/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/n3tsurge/CVE-2021-36934.svg)

- [https://github.com/CrackerCat/HiveNightmare](https://github.com/CrackerCat/HiveNightmare) :  ![starts](https://img.shields.io/github/stars/CrackerCat/HiveNightmare.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/HiveNightmare.svg)

- [https://github.com/Wh04m1001/VSSCopy](https://github.com/Wh04m1001/VSSCopy) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/VSSCopy.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/VSSCopy.svg)

- [https://github.com/chron1k/oxide_hive](https://github.com/chron1k/oxide_hive) :  ![starts](https://img.shields.io/github/stars/chron1k/oxide_hive.svg) ![forks](https://img.shields.io/github/forks/chron1k/oxide_hive.svg)

- [https://github.com/grishinpv/poc_CVE-2021-36934](https://github.com/grishinpv/poc_CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/grishinpv/poc_CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/grishinpv/poc_CVE-2021-36934.svg)

- [https://github.com/bytesizedalex/CVE-2021-36934](https://github.com/bytesizedalex/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/bytesizedalex/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/bytesizedalex/CVE-2021-36934.svg)

- [https://github.com/VertigoRay/CVE-2021-36934](https://github.com/VertigoRay/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/VertigoRay/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/VertigoRay/CVE-2021-36934.svg)

- [https://github.com/irissentinel/CVE-2021-36934](https://github.com/irissentinel/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/irissentinel/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/irissentinel/CVE-2021-36934.svg)

- [https://github.com/OlivierLaflamme/CVE-2021-36934-export-shadow-volume-POC](https://github.com/OlivierLaflamme/CVE-2021-36934-export-shadow-volume-POC) :  ![starts](https://img.shields.io/github/stars/OlivierLaflamme/CVE-2021-36934-export-shadow-volume-POC.svg) ![forks](https://img.shields.io/github/forks/OlivierLaflamme/CVE-2021-36934-export-shadow-volume-POC.svg)

- [https://github.com/WiredPulse/Invoke-HiveDreams](https://github.com/WiredPulse/Invoke-HiveDreams) :  ![starts](https://img.shields.io/github/stars/WiredPulse/Invoke-HiveDreams.svg) ![forks](https://img.shields.io/github/forks/WiredPulse/Invoke-HiveDreams.svg)

- [https://github.com/Sp00p64/PyNightmare](https://github.com/Sp00p64/PyNightmare) :  ![starts](https://img.shields.io/github/stars/Sp00p64/PyNightmare.svg) ![forks](https://img.shields.io/github/forks/Sp00p64/PyNightmare.svg)

- [https://github.com/wolf0x/PSHiveNightmare](https://github.com/wolf0x/PSHiveNightmare) :  ![starts](https://img.shields.io/github/stars/wolf0x/PSHiveNightmare.svg) ![forks](https://img.shields.io/github/forks/wolf0x/PSHiveNightmare.svg)

- [https://github.com/tda90/CVE-2021-36934](https://github.com/tda90/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/tda90/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/tda90/CVE-2021-36934.svg)

- [https://github.com/websecnl/CVE-2021-36934](https://github.com/websecnl/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/websecnl/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/websecnl/CVE-2021-36934.svg)

- [https://github.com/0x0D1n/CVE-2021-36934](https://github.com/0x0D1n/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/0x0D1n/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/0x0D1n/CVE-2021-36934.svg)

- [https://github.com/shaktavist/SeriousSam](https://github.com/shaktavist/SeriousSam) :  ![starts](https://img.shields.io/github/stars/shaktavist/SeriousSam.svg) ![forks](https://img.shields.io/github/forks/shaktavist/SeriousSam.svg)

- [https://github.com/jmaddington/Serious-Sam---CVE-2021-36934-Mitigation-for-Datto-RMM](https://github.com/jmaddington/Serious-Sam---CVE-2021-36934-Mitigation-for-Datto-RMM) :  ![starts](https://img.shields.io/github/stars/jmaddington/Serious-Sam---CVE-2021-36934-Mitigation-for-Datto-RMM.svg) ![forks](https://img.shields.io/github/forks/jmaddington/Serious-Sam---CVE-2021-36934-Mitigation-for-Datto-RMM.svg)

- [https://github.com/wolf0x/HiveNightmare](https://github.com/wolf0x/HiveNightmare) :  ![starts](https://img.shields.io/github/stars/wolf0x/HiveNightmare.svg) ![forks](https://img.shields.io/github/forks/wolf0x/HiveNightmare.svg)

## CVE-2021-36808
 A local attacker could bypass the app password using a race condition in Sophos Secure Workspace for Android before version 9.7.3115.



- [https://github.com/ctuIhu/CVE-2021-36808](https://github.com/ctuIhu/CVE-2021-36808) :  ![starts](https://img.shields.io/github/stars/ctuIhu/CVE-2021-36808.svg) ![forks](https://img.shields.io/github/forks/ctuIhu/CVE-2021-36808.svg)

## CVE-2021-36799
 ** UNSUPPORTED WHEN ASSIGNED ** KNX ETS5 through 5.7.6 uses the hard-coded password ETS5Password, with a salt value of Ivan Medvedev, allowing local users to read project information. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.



- [https://github.com/robertguetzkow/ets5-password-recovery](https://github.com/robertguetzkow/ets5-password-recovery) :  ![starts](https://img.shields.io/github/stars/robertguetzkow/ets5-password-recovery.svg) ![forks](https://img.shields.io/github/forks/robertguetzkow/ets5-password-recovery.svg)

## CVE-2021-36798
 A Denial-of-Service (DoS) vulnerability was discovered in Team Server in HelpSystems Cobalt Strike 4.2 and 4.3. It allows remote attackers to crash the C2 server thread and block beacons' communication with it.



- [https://github.com/JamVayne/CobaltStrikeDos](https://github.com/JamVayne/CobaltStrikeDos) :  ![starts](https://img.shields.io/github/stars/JamVayne/CobaltStrikeDos.svg) ![forks](https://img.shields.io/github/forks/JamVayne/CobaltStrikeDos.svg)

- [https://github.com/burpheart/CS_mock](https://github.com/burpheart/CS_mock) :  ![starts](https://img.shields.io/github/stars/burpheart/CS_mock.svg) ![forks](https://img.shields.io/github/forks/burpheart/CS_mock.svg)

- [https://github.com/M-Kings/CVE-2021-36798](https://github.com/M-Kings/CVE-2021-36798) :  ![starts](https://img.shields.io/github/stars/M-Kings/CVE-2021-36798.svg) ![forks](https://img.shields.io/github/forks/M-Kings/CVE-2021-36798.svg)

## CVE-2021-36749
 In the Druid ingestion system, the InputSource is used for reading data from a certain data source. However, the HTTP InputSource allows authenticated users to read data from other sources than intended, such as the local file system, with the privileges of the Druid server process. This is not an elevation of privilege when users access Druid directly, since Druid also provides the Local InputSource, which allows the same level of access. But it is problematic when users interact with Druid indirectly through an application that allows users to specify the HTTP InputSource, but not the Local InputSource. In this case, users could bypass the application-level restriction by passing a file URL to the HTTP InputSource. This issue was previously mentioned as being fixed in 0.21.0 as per CVE-2021-26920 but was not fixed in 0.21.0 or 0.21.1.



- [https://github.com/Sma11New/PocList](https://github.com/Sma11New/PocList) :  ![starts](https://img.shields.io/github/stars/Sma11New/PocList.svg) ![forks](https://img.shields.io/github/forks/Sma11New/PocList.svg)

- [https://github.com/BrucessKING/CVE-2021-36749](https://github.com/BrucessKING/CVE-2021-36749) :  ![starts](https://img.shields.io/github/stars/BrucessKING/CVE-2021-36749.svg) ![forks](https://img.shields.io/github/forks/BrucessKING/CVE-2021-36749.svg)

- [https://github.com/dorkerdevil/CVE-2021-36749](https://github.com/dorkerdevil/CVE-2021-36749) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-36749.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-36749.svg)

- [https://github.com/zwlsix/apache_druid_CVE-2021-36749](https://github.com/zwlsix/apache_druid_CVE-2021-36749) :  ![starts](https://img.shields.io/github/stars/zwlsix/apache_druid_CVE-2021-36749.svg) ![forks](https://img.shields.io/github/forks/zwlsix/apache_druid_CVE-2021-36749.svg)

- [https://github.com/Jun-5heng/CVE-2021-36749](https://github.com/Jun-5heng/CVE-2021-36749) :  ![starts](https://img.shields.io/github/stars/Jun-5heng/CVE-2021-36749.svg) ![forks](https://img.shields.io/github/forks/Jun-5heng/CVE-2021-36749.svg)

## CVE-2021-36747
 Blackboard Learn through 9.1 allows XSS by an authenticated user via the Feedback to Learner form.



- [https://github.com/cseasholtz/CVE-2021-36747](https://github.com/cseasholtz/CVE-2021-36747) :  ![starts](https://img.shields.io/github/stars/cseasholtz/CVE-2021-36747.svg) ![forks](https://img.shields.io/github/forks/cseasholtz/CVE-2021-36747.svg)

## CVE-2021-36582
 In Kooboo CMS 2.1.1.0, it is possible to upload a remote shell (e.g., aspx) to the server and then call upon it to receive a reverse shell from the victim server. The files are uploaded to /Content/Template/root/reverse-shell.aspx and can be simply triggered by browsing that URL.



- [https://github.com/l00neyhacker/CVE-2021-36582](https://github.com/l00neyhacker/CVE-2021-36582) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2021-36582.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2021-36582.svg)

## CVE-2021-36581
 Kooboo CMS 2.1.1.0 is vulnerable to Insecure file upload. It is possible to upload any file extension to the server. The server does not verify the extension of the file and the tester was able to upload an aspx to the server.



- [https://github.com/l00neyhacker/CVE-2021-36581](https://github.com/l00neyhacker/CVE-2021-36581) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2021-36581.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2021-36581.svg)

## CVE-2021-36563
 The CheckMK management web console (versions 1.5.0 to 2.0.0) does not sanitise user input in various parameters of the WATO module. This allows an attacker to open a backdoor on the device with HTML content and interpreted by the browser (such as JavaScript or other client-side scripts), the XSS payload will be triggered when the user accesses some specific sections of the application. In the same sense a very dangerous potential way would be when an attacker who has the monitor role (not administrator) manages to get a stored XSS to steal the secretAutomation (for the use of the API in administrator mode) and thus be able to create another administrator user who has high privileges on the CheckMK monitoring web console. Another way is that persistent XSS allows an attacker to modify the displayed content or change the victim's information. Successful exploitation requires access to the web management interface, either with valid credentials or with a hijacked session.



- [https://github.com/Edgarloyola/CVE-2021-36563](https://github.com/Edgarloyola/CVE-2021-36563) :  ![starts](https://img.shields.io/github/stars/Edgarloyola/CVE-2021-36563.svg) ![forks](https://img.shields.io/github/forks/Edgarloyola/CVE-2021-36563.svg)

## CVE-2021-36394
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/dinhbaouit/CVE-2021-36394](https://github.com/dinhbaouit/CVE-2021-36394) :  ![starts](https://img.shields.io/github/stars/dinhbaouit/CVE-2021-36394.svg) ![forks](https://img.shields.io/github/forks/dinhbaouit/CVE-2021-36394.svg)

## CVE-2021-36260
 A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.



- [https://github.com/Aiminsun/CVE-2021-36260](https://github.com/Aiminsun/CVE-2021-36260) :  ![starts](https://img.shields.io/github/stars/Aiminsun/CVE-2021-36260.svg) ![forks](https://img.shields.io/github/forks/Aiminsun/CVE-2021-36260.svg)

- [https://github.com/rabbitsafe/CVE-2021-36260](https://github.com/rabbitsafe/CVE-2021-36260) :  ![starts](https://img.shields.io/github/stars/rabbitsafe/CVE-2021-36260.svg) ![forks](https://img.shields.io/github/forks/rabbitsafe/CVE-2021-36260.svg)

- [https://github.com/TaroballzChen/CVE-2021-36260-metasploit](https://github.com/TaroballzChen/CVE-2021-36260-metasploit) :  ![starts](https://img.shields.io/github/stars/TaroballzChen/CVE-2021-36260-metasploit.svg) ![forks](https://img.shields.io/github/forks/TaroballzChen/CVE-2021-36260-metasploit.svg)

- [https://github.com/tuntin9x/CheckHKRCE](https://github.com/tuntin9x/CheckHKRCE) :  ![starts](https://img.shields.io/github/stars/tuntin9x/CheckHKRCE.svg) ![forks](https://img.shields.io/github/forks/tuntin9x/CheckHKRCE.svg)

## CVE-2021-35975
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/trump88/CVE-2021-35975](https://github.com/trump88/CVE-2021-35975) :  ![starts](https://img.shields.io/github/stars/trump88/CVE-2021-35975.svg) ![forks](https://img.shields.io/github/forks/trump88/CVE-2021-35975.svg)

## CVE-2021-35956
 Stored cross-site scripting (XSS) in the embedded webserver of AKCP sensorProbe before SP480-20210624 enables remote authenticated attackers to introduce arbitrary JavaScript via the Sensor Description, Email (from/to/cc), System Name, and System Location fields.



- [https://github.com/tcbutler320/CVE-2021-35956](https://github.com/tcbutler320/CVE-2021-35956) :  ![starts](https://img.shields.io/github/stars/tcbutler320/CVE-2021-35956.svg) ![forks](https://img.shields.io/github/forks/tcbutler320/CVE-2021-35956.svg)

## CVE-2021-35616
 Vulnerability in the Oracle Transportation Management product of Oracle Supply Chain (component: UI Infrastructure). The supported version that is affected is 6.4.3. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Transportation Management. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Transportation Management accessible data as well as unauthorized read access to a subset of Oracle Transportation Management accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N).



- [https://github.com/Ofirhamam/OracleOTM](https://github.com/Ofirhamam/OracleOTM) :  ![starts](https://img.shields.io/github/stars/Ofirhamam/OracleOTM.svg) ![forks](https://img.shields.io/github/forks/Ofirhamam/OracleOTM.svg)

## CVE-2021-35492
 Wowza Streaming Engine through 4.8.11+5 could allow an authenticated, remote attacker to exhaust filesystem resources via the /enginemanager/server/vhost/historical.jsdata vhost parameter. This is due to the insufficient management of available filesystem resources. An attacker could exploit this vulnerability through the Virtual Host Monitoring section by requesting random virtual-host historical data and exhausting available filesystem resources. A successful exploit could allow the attacker to cause database errors and cause the device to become unresponsive to web-based management. (Manual intervention is required to free filesystem resources and return the application to an operational state.)



- [https://github.com/N4nj0/CVE-2021-35492](https://github.com/N4nj0/CVE-2021-35492) :  ![starts](https://img.shields.io/github/stars/N4nj0/CVE-2021-35492.svg) ![forks](https://img.shields.io/github/forks/N4nj0/CVE-2021-35492.svg)

## CVE-2021-35464
 ForgeRock AM server before 7.0 has a Java deserialization vulnerability in the jato.pageSession parameter on multiple pages. The exploitation does not require authentication, and remote code execution can be triggered by sending a single crafted /ccversion/* request to the server. The vulnerability exists due to the usage of Sun ONE Application Framework (JATO) found in versions of Java 8 or earlier



- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)

- [https://github.com/Y4er/openam-CVE-2021-35464](https://github.com/Y4er/openam-CVE-2021-35464) :  ![starts](https://img.shields.io/github/stars/Y4er/openam-CVE-2021-35464.svg) ![forks](https://img.shields.io/github/forks/Y4er/openam-CVE-2021-35464.svg)

- [https://github.com/rood8008/CVE-2021-35464](https://github.com/rood8008/CVE-2021-35464) :  ![starts](https://img.shields.io/github/stars/rood8008/CVE-2021-35464.svg) ![forks](https://img.shields.io/github/forks/rood8008/CVE-2021-35464.svg)

## CVE-2021-35448
 Emote Interactive Remote Mouse 3.008 on Windows allows attackers to execute arbitrary programs as Administrator by using the Image Transfer Folder feature to navigate to cmd.exe. It binds to local ports to listen for incoming connections.



- [https://github.com/LeoBreaker1411/CVE-2021-35448](https://github.com/LeoBreaker1411/CVE-2021-35448) :  ![starts](https://img.shields.io/github/stars/LeoBreaker1411/CVE-2021-35448.svg) ![forks](https://img.shields.io/github/forks/LeoBreaker1411/CVE-2021-35448.svg)

## CVE-2021-35296
 An issue in the administrator authentication panel of PTCL HG150-Ub v3.0 allows attackers to bypass authentication via modification of the cookie value and Response Path.



- [https://github.com/afaq1337/CVE-2021-35296](https://github.com/afaq1337/CVE-2021-35296) :  ![starts](https://img.shields.io/github/stars/afaq1337/CVE-2021-35296.svg) ![forks](https://img.shields.io/github/forks/afaq1337/CVE-2021-35296.svg)

## CVE-2021-35215
 Insecure deserialization leading to Remote Code Execution was detected in the Orion Platform version 2020.2.5. Authentication is required to exploit this vulnerability.



- [https://github.com/Y4er/CVE-2021-35215](https://github.com/Y4er/CVE-2021-35215) :  ![starts](https://img.shields.io/github/stars/Y4er/CVE-2021-35215.svg) ![forks](https://img.shields.io/github/forks/Y4er/CVE-2021-35215.svg)

## CVE-2021-35211
 Microsoft discovered a remote code execution (RCE) vulnerability in the SolarWinds Serv-U product utilizing a Remote Memory Escape Vulnerability. If exploited, a threat actor may be able to gain privileged access to the machine hosting Serv-U Only. SolarWinds Serv-U Managed File Transfer and Serv-U Secure FTP for Windows before 15.2.3 HF2 are affected by this vulnerability.



- [https://github.com/NattiSamson/Serv-U-CVE-2021-35211](https://github.com/NattiSamson/Serv-U-CVE-2021-35211) :  ![starts](https://img.shields.io/github/stars/NattiSamson/Serv-U-CVE-2021-35211.svg) ![forks](https://img.shields.io/github/forks/NattiSamson/Serv-U-CVE-2021-35211.svg)

## CVE-2021-35042
 Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL injection if order_by is untrusted input from a client of a web application.



- [https://github.com/YouGina/CVE-2021-35042](https://github.com/YouGina/CVE-2021-35042) :  ![starts](https://img.shields.io/github/stars/YouGina/CVE-2021-35042.svg) ![forks](https://img.shields.io/github/forks/YouGina/CVE-2021-35042.svg)

- [https://github.com/r4vi/CVE-2021-35042](https://github.com/r4vi/CVE-2021-35042) :  ![starts](https://img.shields.io/github/stars/r4vi/CVE-2021-35042.svg) ![forks](https://img.shields.io/github/forks/r4vi/CVE-2021-35042.svg)

- [https://github.com/mrlihd/CVE-2021-35042](https://github.com/mrlihd/CVE-2021-35042) :  ![starts](https://img.shields.io/github/stars/mrlihd/CVE-2021-35042.svg) ![forks](https://img.shields.io/github/forks/mrlihd/CVE-2021-35042.svg)

## CVE-2021-34730
 A vulnerability in the Universal Plug-and-Play (UPnP) service of Cisco Small Business RV110W, RV130, RV130W, and RV215W Routers could allow an unauthenticated, remote attacker to execute arbitrary code or cause an affected device to restart unexpectedly, resulting in a denial of service (DoS) condition. This vulnerability is due to improper validation of incoming UPnP traffic. An attacker could exploit this vulnerability by sending a crafted UPnP request to an affected device. A successful exploit could allow the attacker to execute arbitrary code as the root user on the underlying operating system or cause the device to reload, resulting in a DoS condition. Cisco has not released software updates that address this vulnerability.



- [https://github.com/badmonkey7/CVE-2021-34730](https://github.com/badmonkey7/CVE-2021-34730) :  ![starts](https://img.shields.io/github/stars/badmonkey7/CVE-2021-34730.svg) ![forks](https://img.shields.io/github/forks/badmonkey7/CVE-2021-34730.svg)

## CVE-2021-34646
 Versions up to, and including, 5.4.3, of the Booster for WooCommerce WordPress plugin are vulnerable to authentication bypass via the process_email_verification function due to a random token generation weakness in the reset_and_mail_activation_link function found in the ~/includes/class-wcj-emails-verification.php file. This allows attackers to impersonate users and trigger an email address verification for arbitrary accounts, including administrative accounts, and automatically be logged in as that user, including any site administrators. This requires the Email Verification module to be active in the plugin and the Login User After Successful Verification setting to be enabled, which it is by default.



- [https://github.com/motikan2010/CVE-2021-34646](https://github.com/motikan2010/CVE-2021-34646) :  ![starts](https://img.shields.io/github/stars/motikan2010/CVE-2021-34646.svg) ![forks](https://img.shields.io/github/forks/motikan2010/CVE-2021-34646.svg)

## CVE-2021-34558
 The crypto/tls package of Go through 1.16.5 does not properly assert that the type of public key in an X.509 certificate matches the expected type when doing a RSA based key exchange, allowing a malicious TLS server to cause a TLS client to panic.



- [https://github.com/alexzorin/cve-2021-34558](https://github.com/alexzorin/cve-2021-34558) :  ![starts](https://img.shields.io/github/stars/alexzorin/cve-2021-34558.svg) ![forks](https://img.shields.io/github/forks/alexzorin/cve-2021-34558.svg)

## CVE-2021-34527
 Windows Print Spooler Remote Code Execution Vulnerability



- [https://github.com/cube0x0/CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/cube0x0/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/cube0x0/CVE-2021-1675.svg)

- [https://github.com/byt3bl33d3r/ItWasAllADream](https://github.com/byt3bl33d3r/ItWasAllADream) :  ![starts](https://img.shields.io/github/stars/byt3bl33d3r/ItWasAllADream.svg) ![forks](https://img.shields.io/github/forks/byt3bl33d3r/ItWasAllADream.svg)

- [https://github.com/hlldz/CVE-2021-1675-LPE](https://github.com/hlldz/CVE-2021-1675-LPE) :  ![starts](https://img.shields.io/github/stars/hlldz/CVE-2021-1675-LPE.svg) ![forks](https://img.shields.io/github/forks/hlldz/CVE-2021-1675-LPE.svg)

- [https://github.com/BeetleChunks/SpoolSploit](https://github.com/BeetleChunks/SpoolSploit) :  ![starts](https://img.shields.io/github/stars/BeetleChunks/SpoolSploit.svg) ![forks](https://img.shields.io/github/forks/BeetleChunks/SpoolSploit.svg)

- [https://github.com/JohnHammond/CVE-2021-34527](https://github.com/JohnHammond/CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/JohnHammond/CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/JohnHammond/CVE-2021-34527.svg)

- [https://github.com/ly4k/PrintNightmare](https://github.com/ly4k/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/ly4k/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/ly4k/PrintNightmare.svg)

- [https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527](https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/nemo-wq/PrintNightmare-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/nemo-wq/PrintNightmare-CVE-2021-34527.svg)

- [https://github.com/evilashz/CVE-2021-1675-LPE-EXP](https://github.com/evilashz/CVE-2021-1675-LPE-EXP) :  ![starts](https://img.shields.io/github/stars/evilashz/CVE-2021-1675-LPE-EXP.svg) ![forks](https://img.shields.io/github/forks/evilashz/CVE-2021-1675-LPE-EXP.svg)

- [https://github.com/JumpsecLabs/PrintNightmare](https://github.com/JumpsecLabs/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/JumpsecLabs/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/JumpsecLabs/PrintNightmare.svg)

- [https://github.com/CnOxx1/CVE-2021-34527-1675](https://github.com/CnOxx1/CVE-2021-34527-1675) :  ![starts](https://img.shields.io/github/stars/CnOxx1/CVE-2021-34527-1675.svg) ![forks](https://img.shields.io/github/forks/CnOxx1/CVE-2021-34527-1675.svg)

- [https://github.com/glshnu/PrintNightmare](https://github.com/glshnu/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/glshnu/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/glshnu/PrintNightmare.svg)

- [https://github.com/Tomparte/PrintNightmare](https://github.com/Tomparte/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/Tomparte/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/Tomparte/PrintNightmare.svg)

- [https://github.com/dywhoami/CVE-2021-34527-Scanner-Based-On-cube0x0-POC](https://github.com/dywhoami/CVE-2021-34527-Scanner-Based-On-cube0x0-POC) :  ![starts](https://img.shields.io/github/stars/dywhoami/CVE-2021-34527-Scanner-Based-On-cube0x0-POC.svg) ![forks](https://img.shields.io/github/forks/dywhoami/CVE-2021-34527-Scanner-Based-On-cube0x0-POC.svg)

- [https://github.com/0xirison/PrintNightmare-Patcher](https://github.com/0xirison/PrintNightmare-Patcher) :  ![starts](https://img.shields.io/github/stars/0xirison/PrintNightmare-Patcher.svg) ![forks](https://img.shields.io/github/forks/0xirison/PrintNightmare-Patcher.svg)

- [https://github.com/Amaranese/CVE-2021-34527](https://github.com/Amaranese/CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/Amaranese/CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/Amaranese/CVE-2021-34527.svg)

- [https://github.com/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527](https://github.com/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527.svg)

- [https://github.com/rdboboia/disable-RegisterSpoolerRemoteRpcEndPoint](https://github.com/rdboboia/disable-RegisterSpoolerRemoteRpcEndPoint) :  ![starts](https://img.shields.io/github/stars/rdboboia/disable-RegisterSpoolerRemoteRpcEndPoint.svg) ![forks](https://img.shields.io/github/forks/rdboboia/disable-RegisterSpoolerRemoteRpcEndPoint.svg)

- [https://github.com/pyonghe/PrintNightMareChecker](https://github.com/pyonghe/PrintNightMareChecker) :  ![starts](https://img.shields.io/github/stars/pyonghe/PrintNightMareChecker.svg) ![forks](https://img.shields.io/github/forks/pyonghe/PrintNightMareChecker.svg)

- [https://github.com/DenizSe/CVE-2021-34527](https://github.com/DenizSe/CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/DenizSe/CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/DenizSe/CVE-2021-34527.svg)

- [https://github.com/glorisonlai/printnightmare](https://github.com/glorisonlai/printnightmare) :  ![starts](https://img.shields.io/github/stars/glorisonlai/printnightmare.svg) ![forks](https://img.shields.io/github/forks/glorisonlai/printnightmare.svg)

- [https://github.com/fardinbarashi/Fix-CVE-2021-34527](https://github.com/fardinbarashi/Fix-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/fardinbarashi/Fix-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/fardinbarashi/Fix-CVE-2021-34527.svg)

- [https://github.com/officedrone/CVE-2021-34527-workaround](https://github.com/officedrone/CVE-2021-34527-workaround) :  ![starts](https://img.shields.io/github/stars/officedrone/CVE-2021-34527-workaround.svg) ![forks](https://img.shields.io/github/forks/officedrone/CVE-2021-34527-workaround.svg)

- [https://github.com/powershellpr0mpt/PrintNightmare-CVE-2021-34527](https://github.com/powershellpr0mpt/PrintNightmare-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/powershellpr0mpt/PrintNightmare-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/powershellpr0mpt/PrintNightmare-CVE-2021-34527.svg)

- [https://github.com/WidespreadPandemic/CVE-2021-34527_ACL_mitigation](https://github.com/WidespreadPandemic/CVE-2021-34527_ACL_mitigation) :  ![starts](https://img.shields.io/github/stars/WidespreadPandemic/CVE-2021-34527_ACL_mitigation.svg) ![forks](https://img.shields.io/github/forks/WidespreadPandemic/CVE-2021-34527_ACL_mitigation.svg)

- [https://github.com/Eutectico/Printnightmare](https://github.com/Eutectico/Printnightmare) :  ![starts](https://img.shields.io/github/stars/Eutectico/Printnightmare.svg) ![forks](https://img.shields.io/github/forks/Eutectico/Printnightmare.svg)

- [https://github.com/geekbrett/CVE-2021-34527-PrintNightmare-Workaround](https://github.com/geekbrett/CVE-2021-34527-PrintNightmare-Workaround) :  ![starts](https://img.shields.io/github/stars/geekbrett/CVE-2021-34527-PrintNightmare-Workaround.svg) ![forks](https://img.shields.io/github/forks/geekbrett/CVE-2021-34527-PrintNightmare-Workaround.svg)

- [https://github.com/vinaysudheer/Disable-Spooler-Service-PrintNightmare-CVE-2021-34527](https://github.com/vinaysudheer/Disable-Spooler-Service-PrintNightmare-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/vinaysudheer/Disable-Spooler-Service-PrintNightmare-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/vinaysudheer/Disable-Spooler-Service-PrintNightmare-CVE-2021-34527.svg)

- [https://github.com/syntaxbearror/PowerShell-PrintNightmare](https://github.com/syntaxbearror/PowerShell-PrintNightmare) :  ![starts](https://img.shields.io/github/stars/syntaxbearror/PowerShell-PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/syntaxbearror/PowerShell-PrintNightmare.svg)

## CVE-2021-34523
 Microsoft Exchange Server Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-33768, CVE-2021-34470.



- [https://github.com/hosch3n/ProxyVulns](https://github.com/hosch3n/ProxyVulns) :  ![starts](https://img.shields.io/github/stars/hosch3n/ProxyVulns.svg) ![forks](https://img.shields.io/github/forks/hosch3n/ProxyVulns.svg)

- [https://github.com/Udyz/proxyshell-auto](https://github.com/Udyz/proxyshell-auto) :  ![starts](https://img.shields.io/github/stars/Udyz/proxyshell-auto.svg) ![forks](https://img.shields.io/github/forks/Udyz/proxyshell-auto.svg)

- [https://github.com/horizon3ai/proxyshell](https://github.com/horizon3ai/proxyshell) :  ![starts](https://img.shields.io/github/stars/horizon3ai/proxyshell.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/proxyshell.svg)

- [https://github.com/mithridates1313/ProxyShell_POC](https://github.com/mithridates1313/ProxyShell_POC) :  ![starts](https://img.shields.io/github/stars/mithridates1313/ProxyShell_POC.svg) ![forks](https://img.shields.io/github/forks/mithridates1313/ProxyShell_POC.svg)

## CVE-2021-34496
 Windows GDI Information Disclosure Vulnerability



- [https://github.com/fkm75P8YjLkb/CVE-2021-34496](https://github.com/fkm75P8YjLkb/CVE-2021-34496) :  ![starts](https://img.shields.io/github/stars/fkm75P8YjLkb/CVE-2021-34496.svg) ![forks](https://img.shields.io/github/forks/fkm75P8YjLkb/CVE-2021-34496.svg)

## CVE-2021-34486
 Windows Event Tracing Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-26425, CVE-2021-34487.



- [https://github.com/KaLendsi/CVE-2021-34486](https://github.com/KaLendsi/CVE-2021-34486) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2021-34486.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2021-34486.svg)

- [https://github.com/b1tg/CVE-2021-34486-exp](https://github.com/b1tg/CVE-2021-34486-exp) :  ![starts](https://img.shields.io/github/stars/b1tg/CVE-2021-34486-exp.svg) ![forks](https://img.shields.io/github/forks/b1tg/CVE-2021-34486-exp.svg)

## CVE-2021-34481
 Windows Print Spooler Elevation of Privilege Vulnerability



- [https://github.com/vanpn/CVE-2021-34481](https://github.com/vanpn/CVE-2021-34481) :  ![starts](https://img.shields.io/github/stars/vanpn/CVE-2021-34481.svg) ![forks](https://img.shields.io/github/forks/vanpn/CVE-2021-34481.svg)

## CVE-2021-34473
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.



- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)

- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)

- [https://github.com/hosch3n/ProxyVulns](https://github.com/hosch3n/ProxyVulns) :  ![starts](https://img.shields.io/github/stars/hosch3n/ProxyVulns.svg) ![forks](https://img.shields.io/github/forks/hosch3n/ProxyVulns.svg)

- [https://github.com/psc4re/NSE-scripts](https://github.com/psc4re/NSE-scripts) :  ![starts](https://img.shields.io/github/stars/psc4re/NSE-scripts.svg) ![forks](https://img.shields.io/github/forks/psc4re/NSE-scripts.svg)

- [https://github.com/Udyz/proxyshell-auto](https://github.com/Udyz/proxyshell-auto) :  ![starts](https://img.shields.io/github/stars/Udyz/proxyshell-auto.svg) ![forks](https://img.shields.io/github/forks/Udyz/proxyshell-auto.svg)

- [https://github.com/cyberheartmi9/Proxyshell-Scanner](https://github.com/cyberheartmi9/Proxyshell-Scanner) :  ![starts](https://img.shields.io/github/stars/cyberheartmi9/Proxyshell-Scanner.svg) ![forks](https://img.shields.io/github/forks/cyberheartmi9/Proxyshell-Scanner.svg)

- [https://github.com/phamphuqui1998/CVE-2021-34473](https://github.com/phamphuqui1998/CVE-2021-34473) :  ![starts](https://img.shields.io/github/stars/phamphuqui1998/CVE-2021-34473.svg) ![forks](https://img.shields.io/github/forks/phamphuqui1998/CVE-2021-34473.svg)

- [https://github.com/horizon3ai/proxyshell](https://github.com/horizon3ai/proxyshell) :  ![starts](https://img.shields.io/github/stars/horizon3ai/proxyshell.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/proxyshell.svg)

- [https://github.com/mithridates1313/ProxyShell_POC](https://github.com/mithridates1313/ProxyShell_POC) :  ![starts](https://img.shields.io/github/stars/mithridates1313/ProxyShell_POC.svg) ![forks](https://img.shields.io/github/forks/mithridates1313/ProxyShell_POC.svg)

- [https://github.com/je6k/CVE-2021-34473-Exchange-ProxyShell](https://github.com/je6k/CVE-2021-34473-Exchange-ProxyShell) :  ![starts](https://img.shields.io/github/stars/je6k/CVE-2021-34473-Exchange-ProxyShell.svg) ![forks](https://img.shields.io/github/forks/je6k/CVE-2021-34473-Exchange-ProxyShell.svg)

- [https://github.com/RaouzRouik/CVE-2021-34473-scanner](https://github.com/RaouzRouik/CVE-2021-34473-scanner) :  ![starts](https://img.shields.io/github/stars/RaouzRouik/CVE-2021-34473-scanner.svg) ![forks](https://img.shields.io/github/forks/RaouzRouik/CVE-2021-34473-scanner.svg)

## CVE-2021-34470
 Microsoft Exchange Server Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-33768, CVE-2021-34523.



- [https://github.com/technion/CVE-2021-34470scanner](https://github.com/technion/CVE-2021-34470scanner) :  ![starts](https://img.shields.io/github/stars/technion/CVE-2021-34470scanner.svg) ![forks](https://img.shields.io/github/forks/technion/CVE-2021-34470scanner.svg)

## CVE-2021-34429
 For Eclipse Jetty versions 9.4.37-9.4.42, 10.0.1-10.0.5 &amp; 11.0.1-11.0.5, URIs can be crafted using some encoded characters to access the content of the WEB-INF directory and/or bypass some security constraints. This is a variation of the vulnerability reported in CVE-2021-28164/GHSA-v7ff-8wcx-gmc5.



- [https://github.com/ColdFusionX/CVE-2021-34429](https://github.com/ColdFusionX/CVE-2021-34429) :  ![starts](https://img.shields.io/github/stars/ColdFusionX/CVE-2021-34429.svg) ![forks](https://img.shields.io/github/forks/ColdFusionX/CVE-2021-34429.svg)

## CVE-2021-34371
 Neo4j through 3.4.18 (with the shell server enabled) exposes an RMI service that arbitrarily deserializes Java objects, e.g., through setSessionVariable. An attacker can abuse this for remote code execution because there are dependencies with exploitable gadget chains.



- [https://github.com/zwjjustdoit/CVE-2021-34371.jar](https://github.com/zwjjustdoit/CVE-2021-34371.jar) :  ![starts](https://img.shields.io/github/stars/zwjjustdoit/CVE-2021-34371.jar.svg) ![forks](https://img.shields.io/github/forks/zwjjustdoit/CVE-2021-34371.jar.svg)

## CVE-2021-34045
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/Al1ex/CVE-2021-34045](https://github.com/Al1ex/CVE-2021-34045) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-34045.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-34045.svg)

- [https://github.com/MzzdToT/CVE-2021-34045](https://github.com/MzzdToT/CVE-2021-34045) :  ![starts](https://img.shields.io/github/stars/MzzdToT/CVE-2021-34045.svg) ![forks](https://img.shields.io/github/forks/MzzdToT/CVE-2021-34045.svg)

## CVE-2021-33909
 fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an unprivileged user, aka CID-8cae8cd89f05.



- [https://github.com/Liang2580/CVE-2021-33909](https://github.com/Liang2580/CVE-2021-33909) :  ![starts](https://img.shields.io/github/stars/Liang2580/CVE-2021-33909.svg) ![forks](https://img.shields.io/github/forks/Liang2580/CVE-2021-33909.svg)

- [https://github.com/ChrisTheCoolHut/CVE-2021-33909](https://github.com/ChrisTheCoolHut/CVE-2021-33909) :  ![starts](https://img.shields.io/github/stars/ChrisTheCoolHut/CVE-2021-33909.svg) ![forks](https://img.shields.io/github/forks/ChrisTheCoolHut/CVE-2021-33909.svg)

- [https://github.com/bbinfosec43/CVE-2021-33909](https://github.com/bbinfosec43/CVE-2021-33909) :  ![starts](https://img.shields.io/github/stars/bbinfosec43/CVE-2021-33909.svg) ![forks](https://img.shields.io/github/forks/bbinfosec43/CVE-2021-33909.svg)

- [https://github.com/baerwolf/cve-2021-33909](https://github.com/baerwolf/cve-2021-33909) :  ![starts](https://img.shields.io/github/stars/baerwolf/cve-2021-33909.svg) ![forks](https://img.shields.io/github/forks/baerwolf/cve-2021-33909.svg)

- [https://github.com/ikramimamoglu/AmIAHuman-CVE-2021-33909](https://github.com/ikramimamoglu/AmIAHuman-CVE-2021-33909) :  ![starts](https://img.shields.io/github/stars/ikramimamoglu/AmIAHuman-CVE-2021-33909.svg) ![forks](https://img.shields.io/github/forks/ikramimamoglu/AmIAHuman-CVE-2021-33909.svg)

## CVE-2021-33879
 Tencent GameLoop before 4.1.21.90 downloaded updates over an insecure HTTP connection. A malicious attacker in an MITM position could spoof the contents of an XML document describing an update package, replacing a download URL with one pointing to an arbitrary Windows executable. Because the only integrity check would be a comparison of the downloaded file's MD5 checksum to the one contained within the XML document, the downloaded executable would then be executed on the victim's machine.



- [https://github.com/mmiszczyk/cve-2021-33879](https://github.com/mmiszczyk/cve-2021-33879) :  ![starts](https://img.shields.io/github/stars/mmiszczyk/cve-2021-33879.svg) ![forks](https://img.shields.io/github/forks/mmiszczyk/cve-2021-33879.svg)

## CVE-2021-33831
 api/account/register in the TH Wildau COVID-19 Contact Tracing application through 2021-09-01 has Incorrect Access Control. An attacker can interfere with tracing of infection chains by creating 500 random users within 2500 seconds.



- [https://github.com/lanmarc77/CVE-2021-33831](https://github.com/lanmarc77/CVE-2021-33831) :  ![starts](https://img.shields.io/github/stars/lanmarc77/CVE-2021-33831.svg) ![forks](https://img.shields.io/github/forks/lanmarc77/CVE-2021-33831.svg)

## CVE-2021-33766
 Microsoft Exchange Information Disclosure Vulnerability



- [https://github.com/bhdresh/CVE-2021-33766](https://github.com/bhdresh/CVE-2021-33766) :  ![starts](https://img.shields.io/github/stars/bhdresh/CVE-2021-33766.svg) ![forks](https://img.shields.io/github/forks/bhdresh/CVE-2021-33766.svg)

- [https://github.com/demossl/CVE-2021-33766-ProxyToken](https://github.com/demossl/CVE-2021-33766-ProxyToken) :  ![starts](https://img.shields.io/github/stars/demossl/CVE-2021-33766-ProxyToken.svg) ![forks](https://img.shields.io/github/forks/demossl/CVE-2021-33766-ProxyToken.svg)

## CVE-2021-33739
 Microsoft DWM Core Library Elevation of Privilege Vulnerability



- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)

- [https://github.com/freeide2017/CVE-2021-33739-POC](https://github.com/freeide2017/CVE-2021-33739-POC) :  ![starts](https://img.shields.io/github/stars/freeide2017/CVE-2021-33739-POC.svg) ![forks](https://img.shields.io/github/forks/freeide2017/CVE-2021-33739-POC.svg)

- [https://github.com/giwon9977/CVE-2021-33739_PoC](https://github.com/giwon9977/CVE-2021-33739_PoC) :  ![starts](https://img.shields.io/github/stars/giwon9977/CVE-2021-33739_PoC.svg) ![forks](https://img.shields.io/github/forks/giwon9977/CVE-2021-33739_PoC.svg)

## CVE-2021-33624
 In kernel/bpf/verifier.c in the Linux kernel before 5.12.13, a branch can be mispredicted (e.g., because of type confusion) and consequently an unprivileged BPF program can read arbitrary memory locations via a side-channel attack, aka CID-9183671af6db.



- [https://github.com/Kakashiiiiy/CVE-2021-33624](https://github.com/Kakashiiiiy/CVE-2021-33624) :  ![starts](https://img.shields.io/github/stars/Kakashiiiiy/CVE-2021-33624.svg) ![forks](https://img.shields.io/github/forks/Kakashiiiiy/CVE-2021-33624.svg)

## CVE-2021-33564
 An argument injection vulnerability in the Dragonfly gem before 1.4.0 for Ruby allows remote attackers to read and write to arbitrary files via a crafted URL when the verify_url option is disabled. This may lead to code execution. The problem occurs because the generate and process features mishandle use of the ImageMagick convert utility.



- [https://github.com/mlr0p/CVE-2021-33564](https://github.com/mlr0p/CVE-2021-33564) :  ![starts](https://img.shields.io/github/stars/mlr0p/CVE-2021-33564.svg) ![forks](https://img.shields.io/github/forks/mlr0p/CVE-2021-33564.svg)

- [https://github.com/dorkerdevil/CVE-2021-33564](https://github.com/dorkerdevil/CVE-2021-33564) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-33564.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-33564.svg)

## CVE-2021-33560
 Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encryption because it lacks exponent blinding to address a side-channel attack against mpi_powm, and the window size is not chosen appropriately. This, for example, affects use of ElGamal in OpenPGP.



- [https://github.com/IBM/PGP-client-checker-CVE-2021-33560](https://github.com/IBM/PGP-client-checker-CVE-2021-33560) :  ![starts](https://img.shields.io/github/stars/IBM/PGP-client-checker-CVE-2021-33560.svg) ![forks](https://img.shields.io/github/forks/IBM/PGP-client-checker-CVE-2021-33560.svg)

## CVE-2021-33558
 Boa 0.94.13 allows remote attackers to obtain sensitive information via a misconfiguration involving backup.html, preview.html, js/log.js, log.html, email.html, online-users.html, and config.js.



- [https://github.com/mdanzaruddin/CVE-2021-33558.](https://github.com/mdanzaruddin/CVE-2021-33558.) :  ![starts](https://img.shields.io/github/stars/mdanzaruddin/CVE-2021-33558..svg) ![forks](https://img.shields.io/github/forks/mdanzaruddin/CVE-2021-33558..svg)

## CVE-2021-33045
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.



- [https://github.com/bp2008/DahuaLoginBypass](https://github.com/bp2008/DahuaLoginBypass) :  ![starts](https://img.shields.io/github/stars/bp2008/DahuaLoginBypass.svg) ![forks](https://img.shields.io/github/forks/bp2008/DahuaLoginBypass.svg)

- [https://github.com/dongpohezui/cve-2021-33045](https://github.com/dongpohezui/cve-2021-33045) :  ![starts](https://img.shields.io/github/stars/dongpohezui/cve-2021-33045.svg) ![forks](https://img.shields.io/github/forks/dongpohezui/cve-2021-33045.svg)

## CVE-2021-33044
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.



- [https://github.com/bp2008/DahuaLoginBypass](https://github.com/bp2008/DahuaLoginBypass) :  ![starts](https://img.shields.io/github/stars/bp2008/DahuaLoginBypass.svg) ![forks](https://img.shields.io/github/forks/bp2008/DahuaLoginBypass.svg)

- [https://github.com/dorkerdevil/CVE-2021-33044](https://github.com/dorkerdevil/CVE-2021-33044) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-33044.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-33044.svg)

## CVE-2021-33026
 The Flask-Caching extension through 1.10.1 for Flask relies on Pickle for serialization, which may lead to remote code execution or local privilege escalation. If an attacker gains access to cache storage (e.g., filesystem, Memcached, Redis, etc.), they can construct a crafted payload, poison the cache, and execute Python code.



- [https://github.com/CarlosG13/CVE-2021-33026](https://github.com/CarlosG13/CVE-2021-33026) :  ![starts](https://img.shields.io/github/stars/CarlosG13/CVE-2021-33026.svg) ![forks](https://img.shields.io/github/forks/CarlosG13/CVE-2021-33026.svg)

## CVE-2021-32849
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/ohnonoyesyes/CVE-2021-32849](https://github.com/ohnonoyesyes/CVE-2021-32849) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2021-32849.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2021-32849.svg)

## CVE-2021-32819
 Squirrelly is a template engine implemented in JavaScript that works out of the box with ExpressJS. Squirrelly mixes pure template data with engine configuration options through the Express render API. By overwriting internal configuration options remote code execution may be triggered in downstream applications. There is currently no fix for these issues as of the publication of this CVE. The latest version of squirrelly is currently 8.0.8. For complete details refer to the referenced GHSL-2021-023.



- [https://github.com/Abady0x1/CVE-2021-32819](https://github.com/Abady0x1/CVE-2021-32819) :  ![starts](https://img.shields.io/github/stars/Abady0x1/CVE-2021-32819.svg) ![forks](https://img.shields.io/github/forks/Abady0x1/CVE-2021-32819.svg)

## CVE-2021-32804
 The npm package &quot;tar&quot; (aka node-tar) before versions 6.1.1, 5.0.6, 4.4.14, and 3.3.2 has a arbitrary File Creation/Overwrite vulnerability due to insufficient absolute path sanitization. node-tar aims to prevent extraction of absolute file paths by turning absolute paths into relative paths when the `preservePaths` flag is not set to `true`. This is achieved by stripping the absolute path root from any absolute file paths contained in a tar file. For example `/home/user/.bashrc` would turn into `home/user/.bashrc`. This logic was insufficient when file paths contained repeated path roots such as `////home/user/.bashrc`. `node-tar` would only strip a single path root from such paths. When given an absolute file path with repeating path roots, the resulting path (e.g. `///home/user/.bashrc`) would still resolve to an absolute path, thus allowing arbitrary file creation and overwrite. This issue was addressed in releases 3.2.2, 4.4.14, 5.0.6 and 6.1.1. Users may work around this vulnerability without upgrading by creating a custom `onentry` method which sanitizes the `entry.path` or a `filter` method which removes entries with absolute paths. See referenced GitHub Advisory for details. Be aware of CVE-2021-32803 which fixes a similar bug in later versions of tar.



- [https://github.com/yamory/CVE-2021-32804](https://github.com/yamory/CVE-2021-32804) :  ![starts](https://img.shields.io/github/stars/yamory/CVE-2021-32804.svg) ![forks](https://img.shields.io/github/forks/yamory/CVE-2021-32804.svg)

## CVE-2021-32789
 woocommerce-gutenberg-products-block is a feature plugin for WooCommerce Gutenberg Blocks. An SQL injection vulnerability impacts all WooCommerce sites running the WooCommerce Blocks feature plugin between version 2.5.0 and prior to version 2.5.16. Via a carefully crafted URL, an exploit can be executed against the `wc/store/products/collection-data?calculate_attribute_counts[][taxonomy]` endpoint that allows the execution of a read only sql query. There are patches for many versions of this package, starting with version 2.5.16. There are no known workarounds aside from upgrading.



- [https://github.com/andnorack/CVE-2021-32789](https://github.com/andnorack/CVE-2021-32789) :  ![starts](https://img.shields.io/github/stars/andnorack/CVE-2021-32789.svg) ![forks](https://img.shields.io/github/forks/andnorack/CVE-2021-32789.svg)

## CVE-2021-32724
 check-spelling is a github action which provides CI spell checking. In affected versions and for a repository with the [check-spelling action](https://github.com/marketplace/actions/check-spelling) enabled that triggers on `pull_request_target` (or `schedule`), an attacker can send a crafted Pull Request that causes a `GITHUB_TOKEN` to be exposed. With the `GITHUB_TOKEN`, it's possible to push commits to the repository bypassing standard approval processes. Commits to the repository could then steal any/all secrets available to the repository. As a workaround users may can either: [Disable the workflow](https://docs.github.com/en/actions/managing-workflow-runs/disabling-and-enabling-a-workflow) until you've fixed all branches or Set repository to [Allow specific actions](https://docs.github.com/en/github/administering-a-repository/managing-repository-settings/disabling-or-limiting-github-actions-for-a-repository#allowing-specific-actions-to-run). check-spelling isn't a verified creator and it certainly won't be anytime soon. You could then explicitly add other actions that your repository uses. Set repository [Workflow permissions](https://docs.github.com/en/github/administering-a-repository/managing-repository-settings/disabling-or-limiting-github-actions-for-a-repository#setting-the-permissions-of-the-github_token-for-your-repository) to `Read repository contents permission`. Workflows using `check-spelling/check-spelling@main` will get the fix automatically. Workflows using a pinned sha or tagged version will need to change the affected workflows for all repository branches to the latest version. Users can verify who and which Pull Requests have been running the action by looking up the spelling.yml action in the Actions tab of their repositories, e.g., https://github.com/check-spelling/check-spelling/actions/workflows/spelling.yml - you can filter PRs by adding ?query=event%3Apull_request_target, e.g., https://github.com/check-spelling/check-spelling/actions/workflows/spelling.yml?query=event%3Apull_request_target.



- [https://github.com/MaximeSchlegel/CVE-2021-32724-Target](https://github.com/MaximeSchlegel/CVE-2021-32724-Target) :  ![starts](https://img.shields.io/github/stars/MaximeSchlegel/CVE-2021-32724-Target.svg) ![forks](https://img.shields.io/github/forks/MaximeSchlegel/CVE-2021-32724-Target.svg)

## CVE-2021-32644
 Ampache is an open source web based audio/video streaming application and file manager. Due to a lack of input filtering versions 4.x.y are vulnerable to code injection in random.php. The attack requires user authentication to access the random.php page unless the site is running in demo mode. This issue has been resolved in 4.4.3.



- [https://github.com/dnr6419/CVE-2021-32644](https://github.com/dnr6419/CVE-2021-32644) :  ![starts](https://img.shields.io/github/stars/dnr6419/CVE-2021-32644.svg) ![forks](https://img.shields.io/github/forks/dnr6419/CVE-2021-32644.svg)

## CVE-2021-32537
 Realtek HAD contains a driver crashed vulnerability which allows local side attackers to send a special string to the kernel driver in a user&#8217;s mode. Due to unexpected commands, the kernel driver will cause the system crashed.



- [https://github.com/0vercl0k/CVE-2021-32537](https://github.com/0vercl0k/CVE-2021-32537) :  ![starts](https://img.shields.io/github/stars/0vercl0k/CVE-2021-32537.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/CVE-2021-32537.svg)

## CVE-2021-32471
 Insufficient input validation in the Marvin Minsky 1967 implementation of the Universal Turing Machine allows program users to execute arbitrary code via crafted data. For example, a tape head may have an unexpected location after the processing of input composed of As and Bs (instead of 0s and 1s). NOTE: the discoverer states &quot;this vulnerability has no real-world implications.&quot;



- [https://github.com/intrinsic-propensity/turing-machine](https://github.com/intrinsic-propensity/turing-machine) :  ![starts](https://img.shields.io/github/stars/intrinsic-propensity/turing-machine.svg) ![forks](https://img.shields.io/github/forks/intrinsic-propensity/turing-machine.svg)

## CVE-2021-32202
 In CS-Cart version 4.11.1, it is possible to induce copy-paste XSS by manipulating the &quot;post description&quot; filed in the blog post creation page.



- [https://github.com/l00neyhacker/CVE-2021-32202](https://github.com/l00neyhacker/CVE-2021-32202) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2021-32202.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2021-32202.svg)

## CVE-2021-31955
 Windows Kernel Information Disclosure Vulnerability



- [https://github.com/freeide/CVE-2021-31955-POC](https://github.com/freeide/CVE-2021-31955-POC) :  ![starts](https://img.shields.io/github/stars/freeide/CVE-2021-31955-POC.svg) ![forks](https://img.shields.io/github/forks/freeide/CVE-2021-31955-POC.svg)

## CVE-2021-31862
 SysAid 20.4.74 allows XSS via the KeepAlive.jsp stamp parameter without any authentication.



- [https://github.com/RobertDra/CVE-2021-31862](https://github.com/RobertDra/CVE-2021-31862) :  ![starts](https://img.shields.io/github/stars/RobertDra/CVE-2021-31862.svg) ![forks](https://img.shields.io/github/forks/RobertDra/CVE-2021-31862.svg)

## CVE-2021-31856
 A SQL Injection vulnerability in the REST API in Layer5 Meshery 0.5.2 allows an attacker to execute arbitrary SQL commands via the /experimental/patternfiles endpoint (order parameter in GetMesheryPatterns in models/meshery_pattern_persister.go).



- [https://github.com/ssst0n3/CVE-2021-31856](https://github.com/ssst0n3/CVE-2021-31856) :  ![starts](https://img.shields.io/github/stars/ssst0n3/CVE-2021-31856.svg) ![forks](https://img.shields.io/github/forks/ssst0n3/CVE-2021-31856.svg)

## CVE-2021-31796
 An inadequate encryption vulnerability discovered in CyberArk Credential Provider before 12.1 may lead to Information Disclosure. An attacker may realistically have enough information that the number of possible keys (for a credential file) is only one, and the number is usually not higher than 2^36.



- [https://github.com/unmanarc/CACredDecoder](https://github.com/unmanarc/CACredDecoder) :  ![starts](https://img.shields.io/github/stars/unmanarc/CACredDecoder.svg) ![forks](https://img.shields.io/github/forks/unmanarc/CACredDecoder.svg)

## CVE-2021-31762
 Webmin 1.973 is affected by Cross Site Request Forgery (CSRF) to create a privileged user through Webmin's add users feature, and then get a reverse shell through Webmin's running process feature.



- [https://github.com/electronicbots/CVE-2021-31762](https://github.com/electronicbots/CVE-2021-31762) :  ![starts](https://img.shields.io/github/stars/electronicbots/CVE-2021-31762.svg) ![forks](https://img.shields.io/github/forks/electronicbots/CVE-2021-31762.svg)

- [https://github.com/Mesh3l911/CVE-2021-31762](https://github.com/Mesh3l911/CVE-2021-31762) :  ![starts](https://img.shields.io/github/stars/Mesh3l911/CVE-2021-31762.svg) ![forks](https://img.shields.io/github/forks/Mesh3l911/CVE-2021-31762.svg)

## CVE-2021-31761
 Webmin 1.973 is affected by reflected Cross Site Scripting (XSS) to achieve Remote Command Execution through Webmin's running process feature.



- [https://github.com/electronicbots/CVE-2021-31761](https://github.com/electronicbots/CVE-2021-31761) :  ![starts](https://img.shields.io/github/stars/electronicbots/CVE-2021-31761.svg) ![forks](https://img.shields.io/github/forks/electronicbots/CVE-2021-31761.svg)

- [https://github.com/Mesh3l911/CVE-2021-31761](https://github.com/Mesh3l911/CVE-2021-31761) :  ![starts](https://img.shields.io/github/stars/Mesh3l911/CVE-2021-31761.svg) ![forks](https://img.shields.io/github/forks/Mesh3l911/CVE-2021-31761.svg)

## CVE-2021-31760
 Webmin 1.973 is affected by Cross Site Request Forgery (CSRF) to achieve Remote Command Execution (RCE) through Webmin's running process feature.



- [https://github.com/Mesh3l911/CVE-2021-31760](https://github.com/Mesh3l911/CVE-2021-31760) :  ![starts](https://img.shields.io/github/stars/Mesh3l911/CVE-2021-31760.svg) ![forks](https://img.shields.io/github/forks/Mesh3l911/CVE-2021-31760.svg)

- [https://github.com/electronicbots/CVE-2021-31760](https://github.com/electronicbots/CVE-2021-31760) :  ![starts](https://img.shields.io/github/stars/electronicbots/CVE-2021-31760.svg) ![forks](https://img.shields.io/github/forks/electronicbots/CVE-2021-31760.svg)

## CVE-2021-31728
 Incorrect access control in zam64.sys, zam32.sys in MalwareFox AntiMalware 2.74.0.150 allows a non-privileged process to open a handle to \.\ZemanaAntiMalware, register itself with the driver by sending IOCTL 0x80002010, allocate executable memory using a flaw in IOCTL 0x80002040, install a hook with IOCTL 0x80002044 and execute the executable memory using this hook with IOCTL 0x80002014 or 0x80002018, this exposes ring 0 code execution in the context of the driver allowing the non-privileged process to elevate privileges.



- [https://github.com/irql0/CVE-2021-31728](https://github.com/irql0/CVE-2021-31728) :  ![starts](https://img.shields.io/github/stars/irql0/CVE-2021-31728.svg) ![forks](https://img.shields.io/github/forks/irql0/CVE-2021-31728.svg)

## CVE-2021-31727
 Incorrect access control in zam64.sys, zam32.sys in MalwareFox AntiMalware 2.74.0.150 where IOCTL's 0x80002014, 0x80002018 expose unrestricted disk read/write capabilities respectively. A non-privileged process can open a handle to \.\ZemanaAntiMalware, register with the driver using IOCTL 0x80002010 and send these IOCTL's to escalate privileges by overwriting the boot sector or overwriting critical code in the pagefile.



- [https://github.com/irql0/CVE-2021-31728](https://github.com/irql0/CVE-2021-31728) :  ![starts](https://img.shields.io/github/stars/irql0/CVE-2021-31728.svg) ![forks](https://img.shields.io/github/forks/irql0/CVE-2021-31728.svg)

## CVE-2021-31703
 Frontier ichris through 5.18 allows users to upload malicious executable files that might later be downloaded and run by any client user.



- [https://github.com/l00neyhacker/CVE-2021-31703](https://github.com/l00neyhacker/CVE-2021-31703) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2021-31703.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2021-31703.svg)

## CVE-2021-31702
 Frontier ichris through 5.18 mishandles making a DNS request for the hostname in the HTTP Host header, as demonstrated by submitting 127.0.0.1 multiple times for DoS.



- [https://github.com/l00neyhacker/CVE-2021-31702](https://github.com/l00neyhacker/CVE-2021-31702) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2021-31702.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2021-31702.svg)

## CVE-2021-31630
 Command Injection in Open PLC Webserver v3 allows remote attackers to execute arbitrary code via the &quot;Hardware Layer Code Box&quot; component on the &quot;/hardware&quot; page of the application.



- [https://github.com/h3v0x/CVE-2021-31630-OpenPLC_RCE](https://github.com/h3v0x/CVE-2021-31630-OpenPLC_RCE) :  ![starts](https://img.shields.io/github/stars/h3v0x/CVE-2021-31630-OpenPLC_RCE.svg) ![forks](https://img.shields.io/github/forks/h3v0x/CVE-2021-31630-OpenPLC_RCE.svg)

## CVE-2021-31207
 Microsoft Exchange Server Security Feature Bypass Vulnerability



- [https://github.com/hosch3n/ProxyVulns](https://github.com/hosch3n/ProxyVulns) :  ![starts](https://img.shields.io/github/stars/hosch3n/ProxyVulns.svg) ![forks](https://img.shields.io/github/forks/hosch3n/ProxyVulns.svg)

- [https://github.com/Udyz/proxyshell-auto](https://github.com/Udyz/proxyshell-auto) :  ![starts](https://img.shields.io/github/stars/Udyz/proxyshell-auto.svg) ![forks](https://img.shields.io/github/forks/Udyz/proxyshell-auto.svg)

- [https://github.com/horizon3ai/proxyshell](https://github.com/horizon3ai/proxyshell) :  ![starts](https://img.shields.io/github/stars/horizon3ai/proxyshell.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/proxyshell.svg)

- [https://github.com/mithridates1313/ProxyShell_POC](https://github.com/mithridates1313/ProxyShell_POC) :  ![starts](https://img.shields.io/github/stars/mithridates1313/ProxyShell_POC.svg) ![forks](https://img.shields.io/github/forks/mithridates1313/ProxyShell_POC.svg)

## CVE-2021-31206
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-34473.



- [https://github.com/Udyz/proxyshell-auto](https://github.com/Udyz/proxyshell-auto) :  ![starts](https://img.shields.io/github/stars/Udyz/proxyshell-auto.svg) ![forks](https://img.shields.io/github/forks/Udyz/proxyshell-auto.svg)

## CVE-2021-31196
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31206, CVE-2021-34473.



- [https://github.com/hosch3n/ProxyVulns](https://github.com/hosch3n/ProxyVulns) :  ![starts](https://img.shields.io/github/stars/hosch3n/ProxyVulns.svg) ![forks](https://img.shields.io/github/forks/hosch3n/ProxyVulns.svg)

## CVE-2021-31195
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31198.



- [https://github.com/hosch3n/ProxyVulns](https://github.com/hosch3n/ProxyVulns) :  ![starts](https://img.shields.io/github/stars/hosch3n/ProxyVulns.svg) ![forks](https://img.shields.io/github/forks/hosch3n/ProxyVulns.svg)

## CVE-2021-31184
 Microsoft Windows Infrared Data Association (IrDA) Information Disclosure Vulnerability



- [https://github.com/waleedassar/CVE-2021-31184](https://github.com/waleedassar/CVE-2021-31184) :  ![starts](https://img.shields.io/github/stars/waleedassar/CVE-2021-31184.svg) ![forks](https://img.shields.io/github/forks/waleedassar/CVE-2021-31184.svg)

## CVE-2021-31166
 HTTP Protocol Stack Remote Code Execution Vulnerability



- [https://github.com/0vercl0k/CVE-2021-31166](https://github.com/0vercl0k/CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/0vercl0k/CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/CVE-2021-31166.svg)

- [https://github.com/corelight/CVE-2021-31166](https://github.com/corelight/CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2021-31166.svg)

- [https://github.com/antx-code/CVE-2021-31166](https://github.com/antx-code/CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/antx-code/CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/antx-code/CVE-2021-31166.svg)

- [https://github.com/zha0gongz1/CVE-2021-31166](https://github.com/zha0gongz1/CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/zha0gongz1/CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/zha0gongz1/CVE-2021-31166.svg)

- [https://github.com/y0g3sh-99/CVE-2021-31166-Exploit](https://github.com/y0g3sh-99/CVE-2021-31166-Exploit) :  ![starts](https://img.shields.io/github/stars/y0g3sh-99/CVE-2021-31166-Exploit.svg) ![forks](https://img.shields.io/github/forks/y0g3sh-99/CVE-2021-31166-Exploit.svg)

- [https://github.com/Frankmock/CVE-2021-31166-detection-rules](https://github.com/Frankmock/CVE-2021-31166-detection-rules) :  ![starts](https://img.shields.io/github/stars/Frankmock/CVE-2021-31166-detection-rules.svg) ![forks](https://img.shields.io/github/forks/Frankmock/CVE-2021-31166-detection-rules.svg)

- [https://github.com/phil-fly/poc](https://github.com/phil-fly/poc) :  ![starts](https://img.shields.io/github/stars/phil-fly/poc.svg) ![forks](https://img.shields.io/github/forks/phil-fly/poc.svg)

- [https://github.com/zecopro/CVE-2021-31166](https://github.com/zecopro/CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/zecopro/CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/zecopro/CVE-2021-31166.svg)

- [https://github.com/Udyz/CVE-2021-31166](https://github.com/Udyz/CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2021-31166.svg)

- [https://github.com/ConMiko/CVE-2021-31166-exploit](https://github.com/ConMiko/CVE-2021-31166-exploit) :  ![starts](https://img.shields.io/github/stars/ConMiko/CVE-2021-31166-exploit.svg) ![forks](https://img.shields.io/github/forks/ConMiko/CVE-2021-31166-exploit.svg)

- [https://github.com/c4dr01d/CVE-2021-31166](https://github.com/c4dr01d/CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/c4dr01d/CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/c4dr01d/CVE-2021-31166.svg)

- [https://github.com/bgsilvait/WIn-CVE-2021-31166](https://github.com/bgsilvait/WIn-CVE-2021-31166) :  ![starts](https://img.shields.io/github/stars/bgsilvait/WIn-CVE-2021-31166.svg) ![forks](https://img.shields.io/github/forks/bgsilvait/WIn-CVE-2021-31166.svg)

## CVE-2021-31159
 Zoho ManageEngine ServiceDesk Plus MSP before 10519 is vulnerable to a User Enumeration bug due to improper error-message generation in the Forgot Password functionality, aka SDPMSP-15732.



- [https://github.com/ricardojoserf/CVE-2021-31159](https://github.com/ricardojoserf/CVE-2021-31159) :  ![starts](https://img.shields.io/github/stars/ricardojoserf/CVE-2021-31159.svg) ![forks](https://img.shields.io/github/forks/ricardojoserf/CVE-2021-31159.svg)

## CVE-2021-30860
 An integer overflow was addressed with improved input validation. This issue is fixed in Security Update 2021-005 Catalina, iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6, watchOS 7.6.2. Processing a maliciously crafted PDF may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.



- [https://github.com/Levilutz/CVE-2021-30860](https://github.com/Levilutz/CVE-2021-30860) :  ![starts](https://img.shields.io/github/stars/Levilutz/CVE-2021-30860.svg) ![forks](https://img.shields.io/github/forks/Levilutz/CVE-2021-30860.svg)

## CVE-2021-30858
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.



- [https://github.com/KameleonReloaded/CVEREV3](https://github.com/KameleonReloaded/CVEREV3) :  ![starts](https://img.shields.io/github/stars/KameleonReloaded/CVEREV3.svg) ![forks](https://img.shields.io/github/forks/KameleonReloaded/CVEREV3.svg)

- [https://github.com/Jeromeyoung/ps4_8.00_vuln_poc](https://github.com/Jeromeyoung/ps4_8.00_vuln_poc) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/ps4_8.00_vuln_poc.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/ps4_8.00_vuln_poc.svg)

## CVE-2021-30807
 A memory corruption issue was addressed with improved memory handling. This issue is fixed in macOS Big Sur 11.5.1, iOS 14.7.1 and iPadOS 14.7.1, watchOS 7.6.1. An application may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited.



- [https://github.com/jsherman212/iomfb-exploit](https://github.com/jsherman212/iomfb-exploit) :  ![starts](https://img.shields.io/github/stars/jsherman212/iomfb-exploit.svg) ![forks](https://img.shields.io/github/forks/jsherman212/iomfb-exploit.svg)

- [https://github.com/30440r/gex](https://github.com/30440r/gex) :  ![starts](https://img.shields.io/github/stars/30440r/gex.svg) ![forks](https://img.shields.io/github/forks/30440r/gex.svg)

## CVE-2021-30682
 A logic issue was addressed with improved restrictions. This issue is fixed in tvOS 14.6, iOS 14.6 and iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. A malicious application may be able to leak sensitive user information.



- [https://github.com/threatnix/csp-playground](https://github.com/threatnix/csp-playground) :  ![starts](https://img.shields.io/github/stars/threatnix/csp-playground.svg) ![forks](https://img.shields.io/github/forks/threatnix/csp-playground.svg)

## CVE-2021-30657
 A logic issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.3, Security Update 2021-002 Catalina. A malicious application may bypass Gatekeeper checks. Apple is aware of a report that this issue may have been actively exploited..



- [https://github.com/shubham0d/CVE-2021-30657](https://github.com/shubham0d/CVE-2021-30657) :  ![starts](https://img.shields.io/github/stars/shubham0d/CVE-2021-30657.svg) ![forks](https://img.shields.io/github/forks/shubham0d/CVE-2021-30657.svg)

## CVE-2021-30641
 Apache HTTP Server versions 2.4.39 to 2.4.46 Unexpected matching behavior with 'MergeSlashes OFF'



- [https://github.com/fkm75P8YjLkb/CVE-2021-30641](https://github.com/fkm75P8YjLkb/CVE-2021-30641) :  ![starts](https://img.shields.io/github/stars/fkm75P8YjLkb/CVE-2021-30641.svg) ![forks](https://img.shields.io/github/forks/fkm75P8YjLkb/CVE-2021-30641.svg)

## CVE-2021-30632
 Out of bounds write in V8 in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.



- [https://github.com/Phuong39/PoC-CVE-2021-30632](https://github.com/Phuong39/PoC-CVE-2021-30632) :  ![starts](https://img.shields.io/github/stars/Phuong39/PoC-CVE-2021-30632.svg) ![forks](https://img.shields.io/github/forks/Phuong39/PoC-CVE-2021-30632.svg)

- [https://github.com/CrackerCat/CVE-2021-30632](https://github.com/CrackerCat/CVE-2021-30632) :  ![starts](https://img.shields.io/github/stars/CrackerCat/CVE-2021-30632.svg) ![forks](https://img.shields.io/github/forks/CrackerCat/CVE-2021-30632.svg)

## CVE-2021-30573
 Use after free in GPU in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.



- [https://github.com/onsecuredev/CVE-2021-30573](https://github.com/onsecuredev/CVE-2021-30573) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-30573.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-30573.svg)

- [https://github.com/kh4sh3i/CVE-2021-30573](https://github.com/kh4sh3i/CVE-2021-30573) :  ![starts](https://img.shields.io/github/stars/kh4sh3i/CVE-2021-30573.svg) ![forks](https://img.shields.io/github/forks/kh4sh3i/CVE-2021-30573.svg)

## CVE-2021-30551
 Type confusion in V8 in Google Chrome prior to 91.0.4472.101 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.



- [https://github.com/xmzyshypnc/CVE-2021-30551](https://github.com/xmzyshypnc/CVE-2021-30551) :  ![starts](https://img.shields.io/github/stars/xmzyshypnc/CVE-2021-30551.svg) ![forks](https://img.shields.io/github/forks/xmzyshypnc/CVE-2021-30551.svg)

## CVE-2021-30481
 Valve Steam through 2021-04-10, when a Source engine game is installed, allows remote authenticated users to execute arbitrary code because of a buffer overflow that occurs for a Steam invite after one click.



- [https://github.com/floesen/CVE-2021-30481](https://github.com/floesen/CVE-2021-30481) :  ![starts](https://img.shields.io/github/stars/floesen/CVE-2021-30481.svg) ![forks](https://img.shields.io/github/forks/floesen/CVE-2021-30481.svg)

## CVE-2021-30461
 A remote code execution issue was discovered in the web UI of VoIPmonitor before 24.61. When the recheck option is used, the user-supplied SPOOLDIR value (which might contain PHP code) is injected into config/configuration.php.



- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)

- [https://github.com/Al1ex/CVE-2021-30461](https://github.com/Al1ex/CVE-2021-30461) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-30461.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-30461.svg)

- [https://github.com/Vulnmachines/CVE-2021-30461](https://github.com/Vulnmachines/CVE-2021-30461) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/CVE-2021-30461.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/CVE-2021-30461.svg)

- [https://github.com/daedalus/CVE-2021-30461](https://github.com/daedalus/CVE-2021-30461) :  ![starts](https://img.shields.io/github/stars/daedalus/CVE-2021-30461.svg) ![forks](https://img.shields.io/github/forks/daedalus/CVE-2021-30461.svg)

- [https://github.com/puckiestyle/CVE-2021-30461](https://github.com/puckiestyle/CVE-2021-30461) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-30461.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-30461.svg)

## CVE-2021-30150
 Composr 10.0.36 allows XSS in an XML script.



- [https://github.com/orionhridoy/CVE-2021-30150](https://github.com/orionhridoy/CVE-2021-30150) :  ![starts](https://img.shields.io/github/stars/orionhridoy/CVE-2021-30150.svg) ![forks](https://img.shields.io/github/forks/orionhridoy/CVE-2021-30150.svg)

## CVE-2021-30149
 Composr 10.0.36 allows upload and execution of PHP files.



- [https://github.com/orionhridoy/CVE-2021-30149](https://github.com/orionhridoy/CVE-2021-30149) :  ![starts](https://img.shields.io/github/stars/orionhridoy/CVE-2021-30149.svg) ![forks](https://img.shields.io/github/forks/orionhridoy/CVE-2021-30149.svg)

## CVE-2021-30146
 Seafile 7.0.5 (2019) allows Persistent XSS via the &quot;share of library functionality.&quot;



- [https://github.com/Security-AVS/CVE-2021-30146](https://github.com/Security-AVS/CVE-2021-30146) :  ![starts](https://img.shields.io/github/stars/Security-AVS/CVE-2021-30146.svg) ![forks](https://img.shields.io/github/forks/Security-AVS/CVE-2021-30146.svg)

## CVE-2021-30128
 Apache OFBiz has unsafe deserialization prior to 17.12.07 version



- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)

- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)

- [https://github.com/LioTree/CVE-2021-30128-EXP](https://github.com/LioTree/CVE-2021-30128-EXP) :  ![starts](https://img.shields.io/github/stars/LioTree/CVE-2021-30128-EXP.svg) ![forks](https://img.shields.io/github/forks/LioTree/CVE-2021-30128-EXP.svg)

- [https://github.com/r0ckysec/CVE-2021-30128](https://github.com/r0ckysec/CVE-2021-30128) :  ![starts](https://img.shields.io/github/stars/r0ckysec/CVE-2021-30128.svg) ![forks](https://img.shields.io/github/forks/r0ckysec/CVE-2021-30128.svg)

## CVE-2021-30109
 Froala Editor 3.2.6 is affected by Cross Site Scripting (XSS). Under certain conditions, a base64 crafted string leads to persistent Cross-site scripting (XSS) vulnerability within the hyperlink creation module.



- [https://github.com/Hackdwerg/CVE-2021-30109](https://github.com/Hackdwerg/CVE-2021-30109) :  ![starts](https://img.shields.io/github/stars/Hackdwerg/CVE-2021-30109.svg) ![forks](https://img.shields.io/github/forks/Hackdwerg/CVE-2021-30109.svg)

## CVE-2021-30005
 In JetBrains PyCharm before 2020.3.4, local code execution was possible because of insufficient checks when getting the project from VCS.



- [https://github.com/atorralba/CVE-2021-30005-POC](https://github.com/atorralba/CVE-2021-30005-POC) :  ![starts](https://img.shields.io/github/stars/atorralba/CVE-2021-30005-POC.svg) ![forks](https://img.shields.io/github/forks/atorralba/CVE-2021-30005-POC.svg)

## CVE-2021-29627
 In FreeBSD 13.0-STABLE before n245050, 12.2-STABLE before r369525, 13.0-RC4 before p0, and 12.2-RELEASE before p6, listening socket accept filters implementing the accf_create callback incorrectly freed a process supplied argument string. Additional operations on the socket can lead to a double free or use after free.



- [https://github.com/raymontag/cve-2021-29627](https://github.com/raymontag/cve-2021-29627) :  ![starts](https://img.shields.io/github/stars/raymontag/cve-2021-29627.svg) ![forks](https://img.shields.io/github/forks/raymontag/cve-2021-29627.svg)

## CVE-2021-29505
 XStream is software for serializing Java objects to XML and back again. A vulnerability in XStream versions prior to 1.4.17 may allow a remote attacker has sufficient rights to execute commands of the host only by manipulating the processed input stream. No user who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types is affected. The vulnerability is patched in version 1.4.17.



- [https://github.com/MyBlackManba/CVE-2021-29505](https://github.com/MyBlackManba/CVE-2021-29505) :  ![starts](https://img.shields.io/github/stars/MyBlackManba/CVE-2021-29505.svg) ![forks](https://img.shields.io/github/forks/MyBlackManba/CVE-2021-29505.svg)

## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.



- [https://github.com/motikan2010/CVE-2021-29447](https://github.com/motikan2010/CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/motikan2010/CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/motikan2010/CVE-2021-29447.svg)

- [https://github.com/Vulnmachines/wordpress_cve-2021-29447](https://github.com/Vulnmachines/wordpress_cve-2021-29447) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/wordpress_cve-2021-29447.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/wordpress_cve-2021-29447.svg)

- [https://github.com/dnr6419/CVE-2021-29447](https://github.com/dnr6419/CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/dnr6419/CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/dnr6419/CVE-2021-29447.svg)

- [https://github.com/AssassinUKG/CVE-2021-29447](https://github.com/AssassinUKG/CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/AssassinUKG/CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/AssassinUKG/CVE-2021-29447.svg)

## CVE-2021-29441
 Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, when configured to use authentication (-Dnacos.core.auth.enabled=true) Nacos uses the AuthFilter servlet filter to enforce authentication. This filter has a backdoor that enables Nacos servers to bypass this filter and therefore skip authentication checks. This mechanism relies on the user-agent HTTP header so it can be easily spoofed. This issue may allow any user to carry out any administrative tasks on the Nacos server.



- [https://github.com/hh-hunter/nacos-cve-2021-29441](https://github.com/hh-hunter/nacos-cve-2021-29441) :  ![starts](https://img.shields.io/github/stars/hh-hunter/nacos-cve-2021-29441.svg) ![forks](https://img.shields.io/github/forks/hh-hunter/nacos-cve-2021-29441.svg)

## CVE-2021-29440
 Grav is a file based Web-platform. Twig processing of static pages can be enabled in the front matter by any administrative user allowed to create or edit pages. As the Twig processor runs unsandboxed, this behavior can be used to gain arbitrary code execution and elevate privileges on the instance. The issue was addressed in version 1.7.11.



- [https://github.com/CsEnox/CVE-2021-29440](https://github.com/CsEnox/CVE-2021-29440) :  ![starts](https://img.shields.io/github/stars/CsEnox/CVE-2021-29440.svg) ![forks](https://img.shields.io/github/forks/CsEnox/CVE-2021-29440.svg)

## CVE-2021-29386
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/Umarovm/PowerSchool-Grade-Stealer](https://github.com/Umarovm/PowerSchool-Grade-Stealer) :  ![starts](https://img.shields.io/github/stars/Umarovm/PowerSchool-Grade-Stealer.svg) ![forks](https://img.shields.io/github/forks/Umarovm/PowerSchool-Grade-Stealer.svg)

## CVE-2021-29349
 Mahara 20.10 is affected by Cross Site Request Forgery (CSRF) that allows a remote attacker to remove inbox-mail on the server. The application fails to validate the CSRF token for a POST request. An attacker can craft a module/multirecipientnotification/inbox.php pieform_delete_all_notifications request, which leads to removing all messages from a mailbox.



- [https://github.com/Vulnmachines/CVE-2021-29349](https://github.com/Vulnmachines/CVE-2021-29349) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/CVE-2021-29349.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/CVE-2021-29349.svg)

- [https://github.com/0xBaz/CVE-2021-29349](https://github.com/0xBaz/CVE-2021-29349) :  ![starts](https://img.shields.io/github/stars/0xBaz/CVE-2021-29349.svg) ![forks](https://img.shields.io/github/forks/0xBaz/CVE-2021-29349.svg)

## CVE-2021-29337
 MODAPI.sys in MSI Dragon Center 2.0.104.0 allows low-privileged users to access kernel memory and potentially escalate privileges via a crafted IOCTL 0x9c406104 call. This IOCTL provides the MmMapIoSpace feature for mapping physical memory.



- [https://github.com/rjt-gupta/CVE-2021-29337](https://github.com/rjt-gupta/CVE-2021-29337) :  ![starts](https://img.shields.io/github/stars/rjt-gupta/CVE-2021-29337.svg) ![forks](https://img.shields.io/github/forks/rjt-gupta/CVE-2021-29337.svg)

## CVE-2021-29280
 In TP-Link Wireless N Router WR840N an ARP poisoning attack can cause buffer overflow



- [https://github.com/deadlysnowman3308/upgraded-ARP-Poisoning](https://github.com/deadlysnowman3308/upgraded-ARP-Poisoning) :  ![starts](https://img.shields.io/github/stars/deadlysnowman3308/upgraded-ARP-Poisoning.svg) ![forks](https://img.shields.io/github/forks/deadlysnowman3308/upgraded-ARP-Poisoning.svg)

## CVE-2021-29267
 Sherlock SherlockIM through 2021-03-29 allows Cross Site Scripting (XSS) by leveraging the api/Files/Attachment URI to attack help-desk staff via the chatbot feature.



- [https://github.com/Security-AVS/CVE-2021-29267](https://github.com/Security-AVS/CVE-2021-29267) :  ![starts](https://img.shields.io/github/stars/Security-AVS/CVE-2021-29267.svg) ![forks](https://img.shields.io/github/forks/Security-AVS/CVE-2021-29267.svg)

## CVE-2021-29200
 Apache OFBiz has unsafe deserialization prior to 17.12.07 version An unauthenticated user can perform an RCE attack



- [https://github.com/r0ckysec/CVE-2021-29200](https://github.com/r0ckysec/CVE-2021-29200) :  ![starts](https://img.shields.io/github/stars/r0ckysec/CVE-2021-29200.svg) ![forks](https://img.shields.io/github/forks/r0ckysec/CVE-2021-29200.svg)

## CVE-2021-29156
 ForgeRock OpenAM before 13.5.1 allows LDAP injection via the Webfinger protocol. For example, an unauthenticated attacker can perform character-by-character retrieval of password hashes, or retrieve a session token or a private key.



- [https://github.com/guidepointsecurity/CVE-2021-29156](https://github.com/guidepointsecurity/CVE-2021-29156) :  ![starts](https://img.shields.io/github/stars/guidepointsecurity/CVE-2021-29156.svg) ![forks](https://img.shields.io/github/forks/guidepointsecurity/CVE-2021-29156.svg)

## CVE-2021-29155
 An issue was discovered in the Linux kernel through 5.11.x. kernel/bpf/verifier.c performs undesirable out-of-bounds speculation on pointer arithmetic, leading to side-channel attacks that defeat Spectre mitigations and obtain sensitive information from kernel memory. Specifically, for sequences of pointer arithmetic operations, the pointer modification performed by the first operation is not correctly accounted for when restricting subsequent operations.



- [https://github.com/Kakashiiiiy/CVE-2021-29155](https://github.com/Kakashiiiiy/CVE-2021-29155) :  ![starts](https://img.shields.io/github/stars/Kakashiiiiy/CVE-2021-29155.svg) ![forks](https://img.shields.io/github/forks/Kakashiiiiy/CVE-2021-29155.svg)

## CVE-2021-29003
 Genexis PLATINUM 4410 2.1 P4410-V2-1.28 devices allow remote attackers to execute arbitrary code via shell metacharacters to sys_config_valid.xgi, as demonstrated by the sys_config_valid.xgi?exeshell=%60telnetd%20%26%60 URI.



- [https://github.com/jaysharma786/CVE-2021-29003](https://github.com/jaysharma786/CVE-2021-29003) :  ![starts](https://img.shields.io/github/stars/jaysharma786/CVE-2021-29003.svg) ![forks](https://img.shields.io/github/forks/jaysharma786/CVE-2021-29003.svg)

## CVE-2021-28664
 The Arm Mali GPU kernel driver allows privilege escalation or a denial of service (memory corruption) because an unprivileged user can achieve read/write access to read-only pages. This affects Bifrost r0p0 through r28p0 before r29p0, Valhall r19p0 through r28p0 before r29p0, and Midgard r8p0 through r30p0.



- [https://github.com/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664](https://github.com/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664) :  ![starts](https://img.shields.io/github/stars/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664.svg) ![forks](https://img.shields.io/github/forks/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664.svg)

## CVE-2021-28663
 The Arm Mali GPU kernel driver allows privilege escalation or information disclosure because GPU memory operations are mishandled, leading to a use-after-free. This affects Bifrost r0p0 through r28p0 before r29p0, Valhall r19p0 through r28p0 before r29p0, and Midgard r4p0 through r30p0.



- [https://github.com/lntrx/CVE-2021-28663](https://github.com/lntrx/CVE-2021-28663) :  ![starts](https://img.shields.io/github/stars/lntrx/CVE-2021-28663.svg) ![forks](https://img.shields.io/github/forks/lntrx/CVE-2021-28663.svg)

- [https://github.com/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664](https://github.com/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664) :  ![starts](https://img.shields.io/github/stars/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664.svg) ![forks](https://img.shields.io/github/forks/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664.svg)

## CVE-2021-28482
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-28480, CVE-2021-28481, CVE-2021-28483.



- [https://github.com/Shadow0ps/CVE-2021-28482-Exchange-POC](https://github.com/Shadow0ps/CVE-2021-28482-Exchange-POC) :  ![starts](https://img.shields.io/github/stars/Shadow0ps/CVE-2021-28482-Exchange-POC.svg) ![forks](https://img.shields.io/github/forks/Shadow0ps/CVE-2021-28482-Exchange-POC.svg)

- [https://github.com/KevinWorst/CVE-2021-28482_Exploit](https://github.com/KevinWorst/CVE-2021-28482_Exploit) :  ![starts](https://img.shields.io/github/stars/KevinWorst/CVE-2021-28482_Exploit.svg) ![forks](https://img.shields.io/github/forks/KevinWorst/CVE-2021-28482_Exploit.svg)

## CVE-2021-28480
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-28481, CVE-2021-28482, CVE-2021-28483.



- [https://github.com/ZephrFish/CVE-2021-28480_HoneyPoC3](https://github.com/ZephrFish/CVE-2021-28480_HoneyPoC3) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2021-28480_HoneyPoC3.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2021-28480_HoneyPoC3.svg)

## CVE-2021-28476
 Hyper-V Remote Code Execution Vulnerability



- [https://github.com/0vercl0k/CVE-2021-28476](https://github.com/0vercl0k/CVE-2021-28476) :  ![starts](https://img.shields.io/github/stars/0vercl0k/CVE-2021-28476.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/CVE-2021-28476.svg)

- [https://github.com/bluefrostsecurity/CVE-2021-28476](https://github.com/bluefrostsecurity/CVE-2021-28476) :  ![starts](https://img.shields.io/github/stars/bluefrostsecurity/CVE-2021-28476.svg) ![forks](https://img.shields.io/github/forks/bluefrostsecurity/CVE-2021-28476.svg)

- [https://github.com/LaCeeKa/CVE-2021-28476-tools-env](https://github.com/LaCeeKa/CVE-2021-28476-tools-env) :  ![starts](https://img.shields.io/github/stars/LaCeeKa/CVE-2021-28476-tools-env.svg) ![forks](https://img.shields.io/github/forks/LaCeeKa/CVE-2021-28476-tools-env.svg)

## CVE-2021-28378
 Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.



- [https://github.com/pandatix/CVE-2021-28378](https://github.com/pandatix/CVE-2021-28378) :  ![starts](https://img.shields.io/github/stars/pandatix/CVE-2021-28378.svg) ![forks](https://img.shields.io/github/forks/pandatix/CVE-2021-28378.svg)

## CVE-2021-28312
 Windows NTFS Denial of Service Vulnerability



- [https://github.com/shubham0d/CVE-2021-28312](https://github.com/shubham0d/CVE-2021-28312) :  ![starts](https://img.shields.io/github/stars/shubham0d/CVE-2021-28312.svg) ![forks](https://img.shields.io/github/forks/shubham0d/CVE-2021-28312.svg)

## CVE-2021-28310
 Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-27072.



- [https://github.com/Rafael-Svechinskaya/IOC_for_CVE-2021-28310](https://github.com/Rafael-Svechinskaya/IOC_for_CVE-2021-28310) :  ![starts](https://img.shields.io/github/stars/Rafael-Svechinskaya/IOC_for_CVE-2021-28310.svg) ![forks](https://img.shields.io/github/forks/Rafael-Svechinskaya/IOC_for_CVE-2021-28310.svg)

## CVE-2021-28079
 Jamovi &lt;=1.6.18 is affected by a cross-site scripting (XSS) vulnerability. The column-name is vulnerable to XSS in the ElectronJS Framework. An attacker can make a .omv (Jamovi) document containing a payload. When opened by victim, the payload is triggered.



- [https://github.com/g33xter/CVE-2021-28079](https://github.com/g33xter/CVE-2021-28079) :  ![starts](https://img.shields.io/github/stars/g33xter/CVE-2021-28079.svg) ![forks](https://img.shields.io/github/forks/g33xter/CVE-2021-28079.svg)

## CVE-2021-27965
 The MsIo64.sys driver before 1.1.19.1016 in MSI Dragon Center before 2.0.98.0 has a buffer overflow that allows privilege escalation via a crafted 0x80102040, 0x80102044, 0x80102050, or 0x80102054 IOCTL request.



- [https://github.com/mathisvickie/CVE-2021-27965](https://github.com/mathisvickie/CVE-2021-27965) :  ![starts](https://img.shields.io/github/stars/mathisvickie/CVE-2021-27965.svg) ![forks](https://img.shields.io/github/forks/mathisvickie/CVE-2021-27965.svg)

- [https://github.com/Crystalware/CVE-2021-27965](https://github.com/Crystalware/CVE-2021-27965) :  ![starts](https://img.shields.io/github/stars/Crystalware/CVE-2021-27965.svg) ![forks](https://img.shields.io/github/forks/Crystalware/CVE-2021-27965.svg)

## CVE-2021-27964
 SonLogger before 6.4.1 is affected by Unauthenticated Arbitrary File Upload. An attacker can send a POST request to /Config/SaveUploadedHotspotLogoFile without any authentication or session header. There is no check for the file extension or content of the uploaded file.



- [https://github.com/erberkan/SonLogger-vulns](https://github.com/erberkan/SonLogger-vulns) :  ![starts](https://img.shields.io/github/stars/erberkan/SonLogger-vulns.svg) ![forks](https://img.shields.io/github/forks/erberkan/SonLogger-vulns.svg)

## CVE-2021-27963
 SonLogger before 6.4.1 is affected by user creation with any user permissions profile (e.g., SuperAdmin). An anonymous user can send a POST request to /User/saveUser without any authentication or session header.



- [https://github.com/erberkan/SonLogger-vulns](https://github.com/erberkan/SonLogger-vulns) :  ![starts](https://img.shields.io/github/stars/erberkan/SonLogger-vulns.svg) ![forks](https://img.shields.io/github/forks/erberkan/SonLogger-vulns.svg)

## CVE-2021-27928
 A remote code execution issue was discovered in MariaDB 10.2 before 10.2.37, 10.3 before 10.3.28, 10.4 before 10.4.18, and 10.5 before 10.5.9; Percona Server through 2021-03-03; and the wsrep patch through 2021-03-03 for MySQL. An untrusted search path leads to eval injection, in which a database SUPER user can execute OS commands after modifying wsrep_provider and wsrep_notify_cmd. NOTE: this does not affect an Oracle product.



- [https://github.com/Al1ex/CVE-2021-27928](https://github.com/Al1ex/CVE-2021-27928) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-27928.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-27928.svg)

- [https://github.com/shamo0/CVE-2021-27928-POC](https://github.com/shamo0/CVE-2021-27928-POC) :  ![starts](https://img.shields.io/github/stars/shamo0/CVE-2021-27928-POC.svg) ![forks](https://img.shields.io/github/forks/shamo0/CVE-2021-27928-POC.svg)

## CVE-2021-27905
 The ReplicationHandler (normally registered at &quot;/replication&quot; under a Solr core) in Apache Solr has a &quot;masterUrl&quot; (also &quot;leaderUrl&quot; alias) parameter that is used to designate another ReplicationHandler on another Solr core to replicate index data into the local core. To prevent a SSRF vulnerability, Solr ought to check these parameters against a similar configuration it uses for the &quot;shards&quot; parameter. Prior to this bug getting fixed, it did not. This problem affects essentially all Solr versions prior to it getting fixed in 8.8.2.



- [https://github.com/Henry4E36/Solr-SSRF](https://github.com/Henry4E36/Solr-SSRF) :  ![starts](https://img.shields.io/github/stars/Henry4E36/Solr-SSRF.svg) ![forks](https://img.shields.io/github/forks/Henry4E36/Solr-SSRF.svg)

- [https://github.com/murataydemir/CVE-2021-27905](https://github.com/murataydemir/CVE-2021-27905) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2021-27905.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2021-27905.svg)

- [https://github.com/W2Ning/Solr-SSRF](https://github.com/W2Ning/Solr-SSRF) :  ![starts](https://img.shields.io/github/stars/W2Ning/Solr-SSRF.svg) ![forks](https://img.shields.io/github/forks/W2Ning/Solr-SSRF.svg)

## CVE-2021-27890
 SQL Injection vulnerablity in MyBB before 1.8.26 via theme properties included in theme XML files.



- [https://github.com/xiaopan233/Mybb-XSS_SQL_RCE-POC](https://github.com/xiaopan233/Mybb-XSS_SQL_RCE-POC) :  ![starts](https://img.shields.io/github/stars/xiaopan233/Mybb-XSS_SQL_RCE-POC.svg) ![forks](https://img.shields.io/github/forks/xiaopan233/Mybb-XSS_SQL_RCE-POC.svg)

## CVE-2021-27889
 Cross-site Scripting (XSS) vulnerability in MyBB before 1.8.26 via Nested Auto URL when parsing messages.



- [https://github.com/xiaopan233/Mybb-XSS_SQL_RCE-POC](https://github.com/xiaopan233/Mybb-XSS_SQL_RCE-POC) :  ![starts](https://img.shields.io/github/stars/xiaopan233/Mybb-XSS_SQL_RCE-POC.svg) ![forks](https://img.shields.io/github/forks/xiaopan233/Mybb-XSS_SQL_RCE-POC.svg)

## CVE-2021-27850
 A critical unauthenticated remote code execution vulnerability was found all recent versions of Apache Tapestry. The affected versions include 5.4.5, 5.5.0, 5.6.2 and 5.7.0. The vulnerability I have found is a bypass of the fix for CVE-2019-0195. Recap: Before the fix of CVE-2019-0195 it was possible to download arbitrary class files from the classpath by providing a crafted asset file URL. An attacker was able to download the file `AppModule.class` by requesting the URL `http://localhost:8080/assets/something/services/AppModule.class` which contains a HMAC secret key. The fix for that bug was a blacklist filter that checks if the URL ends with `.class`, `.properties` or `.xml`. Bypass: Unfortunately, the blacklist solution can simply be bypassed by appending a `/` at the end of the URL: `http://localhost:8080/assets/something/services/AppModule.class/` The slash is stripped after the blacklist check and the file `AppModule.class` is loaded into the response. This class usually contains the HMAC secret key which is used to sign serialized Java objects. With the knowledge of that key an attacker can sign a Java gadget chain that leads to RCE (e.g. CommonsBeanUtils1 from ysoserial). Solution for this vulnerability: * For Apache Tapestry 5.4.0 to 5.6.1, upgrade to 5.6.2 or later. * For Apache Tapestry 5.7.0, upgrade to 5.7.1 or later.



- [https://github.com/Ovi3/CVE_2021_27850_POC](https://github.com/Ovi3/CVE_2021_27850_POC) :  ![starts](https://img.shields.io/github/stars/Ovi3/CVE_2021_27850_POC.svg) ![forks](https://img.shields.io/github/forks/Ovi3/CVE_2021_27850_POC.svg)

- [https://github.com/dorkerdevil/CVE-2021-27850_POC](https://github.com/dorkerdevil/CVE-2021-27850_POC) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-27850_POC.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-27850_POC.svg)

## CVE-2021-27651
 In versions 8.2.1 through 8.5.2 of Pega Infinity, the password reset functionality for local accounts can be used to bypass local authentication checks.



- [https://github.com/samwcyo/CVE-2021-27651-PoC](https://github.com/samwcyo/CVE-2021-27651-PoC) :  ![starts](https://img.shields.io/github/stars/samwcyo/CVE-2021-27651-PoC.svg) ![forks](https://img.shields.io/github/forks/samwcyo/CVE-2021-27651-PoC.svg)

- [https://github.com/Vulnmachines/CVE-2021-27651](https://github.com/Vulnmachines/CVE-2021-27651) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/CVE-2021-27651.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/CVE-2021-27651.svg)

- [https://github.com/onsecuredev/CVE-2021-27651](https://github.com/onsecuredev/CVE-2021-27651) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-27651.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-27651.svg)

## CVE-2021-27514
 EyesOfNetwork 5.3-10 uses an integer of between 8 and 10 digits for the session ID, which might be leveraged for brute-force authentication bypass (such as in CVE-2021-27513 exploitation).



- [https://github.com/ArianeBlow/CVE-2021-27513-CVE-2021-27514](https://github.com/ArianeBlow/CVE-2021-27513-CVE-2021-27514) :  ![starts](https://img.shields.io/github/stars/ArianeBlow/CVE-2021-27513-CVE-2021-27514.svg) ![forks](https://img.shields.io/github/forks/ArianeBlow/CVE-2021-27513-CVE-2021-27514.svg)

## CVE-2021-27513
 The module admin_ITSM in EyesOfNetwork 5.3-10 allows remote authenticated users to upload arbitrary .xml.php files because it relies on &quot;le filtre userside.&quot;



- [https://github.com/ArianeBlow/CVE-2021-27513](https://github.com/ArianeBlow/CVE-2021-27513) :  ![starts](https://img.shields.io/github/stars/ArianeBlow/CVE-2021-27513.svg) ![forks](https://img.shields.io/github/forks/ArianeBlow/CVE-2021-27513.svg)

- [https://github.com/ArianeBlow/CVE-2021-27513-CVE-2021-27514](https://github.com/ArianeBlow/CVE-2021-27513-CVE-2021-27514) :  ![starts](https://img.shields.io/github/stars/ArianeBlow/CVE-2021-27513-CVE-2021-27514.svg) ![forks](https://img.shields.io/github/forks/ArianeBlow/CVE-2021-27513-CVE-2021-27514.svg)

## CVE-2021-27404
 Askey RTF8115VW BR_SV_g11.11_RTF_TEF001_V6.54_V014 devices allow injection of a Host HTTP header.



- [https://github.com/bokanrb/CVE-2021-27404](https://github.com/bokanrb/CVE-2021-27404) :  ![starts](https://img.shields.io/github/stars/bokanrb/CVE-2021-27404.svg) ![forks](https://img.shields.io/github/forks/bokanrb/CVE-2021-27404.svg)

## CVE-2021-27403
 Askey RTF8115VW BR_SV_g11.11_RTF_TEF001_V6.54_V014 devices allow cgi-bin/te_acceso_router.cgi curWebPage XSS.



- [https://github.com/bokanrb/CVE-2021-27403](https://github.com/bokanrb/CVE-2021-27403) :  ![starts](https://img.shields.io/github/stars/bokanrb/CVE-2021-27403.svg) ![forks](https://img.shields.io/github/forks/bokanrb/CVE-2021-27403.svg)

## CVE-2021-27342
 An authentication brute-force protection mechanism bypass in telnetd in D-Link Router model DIR-842 firmware version 3.0.2 allows a remote attacker to circumvent the anti-brute-force cool-down delay period via a timing-based side-channel attack



- [https://github.com/guywhataguy/D-Link-CVE-2021-27342-exploit](https://github.com/guywhataguy/D-Link-CVE-2021-27342-exploit) :  ![starts](https://img.shields.io/github/stars/guywhataguy/D-Link-CVE-2021-27342-exploit.svg) ![forks](https://img.shields.io/github/forks/guywhataguy/D-Link-CVE-2021-27342-exploit.svg)

## CVE-2021-27338
 Faraday Edge before 3.7 allows XSS via the network/create/ page and its network name parameter.



- [https://github.com/Pho03niX/CVE-2021-27338](https://github.com/Pho03niX/CVE-2021-27338) :  ![starts](https://img.shields.io/github/stars/Pho03niX/CVE-2021-27338.svg) ![forks](https://img.shields.io/github/forks/Pho03niX/CVE-2021-27338.svg)

## CVE-2021-27328
 Yeastar NeoGate TG400 91.3.0.3 devices are affected by Directory Traversal. An authenticated user can decrypt firmware and can read sensitive information, such as a password or decryption key.



- [https://github.com/SQSamir/CVE-2021-27328](https://github.com/SQSamir/CVE-2021-27328) :  ![starts](https://img.shields.io/github/stars/SQSamir/CVE-2021-27328.svg) ![forks](https://img.shields.io/github/forks/SQSamir/CVE-2021-27328.svg)

## CVE-2021-27246
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link Archer A7 AC1750 1.0.15 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the handling of MAC addresses by the tdpServer endpoint. A crafted TCP message can write stack pointers to the stack. An attacker can leverage this vulnerability to execute code in the context of the root user. Was ZDI-CAN-12306.



- [https://github.com/synacktiv/CVE-2021-27246_Pwn2Own2020](https://github.com/synacktiv/CVE-2021-27246_Pwn2Own2020) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2021-27246_Pwn2Own2020.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2021-27246_Pwn2Own2020.svg)

## CVE-2021-27211
 steghide 0.5.1 relies on a certain 32-bit seed value, which makes it easier for attackers to detect hidden data.



- [https://github.com/b4shfire/stegcrack](https://github.com/b4shfire/stegcrack) :  ![starts](https://img.shields.io/github/stars/b4shfire/stegcrack.svg) ![forks](https://img.shields.io/github/forks/b4shfire/stegcrack.svg)

## CVE-2021-27190
 A Stored Cross Site Scripting(XSS) Vulnerability was discovered in PEEL SHOPPING 9.3.0 and 9.4.0, which are publicly available. The user supplied input containing polyglot payload is echoed back in javascript code in HTML response. This allows an attacker to input malicious JavaScript which can steal cookie, redirect them to other malicious website, etc.



- [https://github.com/anmolksachan/CVE-2021-27190-PEEL-Shopping-cart-9.3.0-Stored-XSS](https://github.com/anmolksachan/CVE-2021-27190-PEEL-Shopping-cart-9.3.0-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/anmolksachan/CVE-2021-27190-PEEL-Shopping-cart-9.3.0-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/anmolksachan/CVE-2021-27190-PEEL-Shopping-cart-9.3.0-Stored-XSS.svg)

## CVE-2021-27188
 The Sovremennye Delovye Tekhnologii FX Aggregator terminal client 1 allows attackers to cause a denial of service (access suspended for five hours) by making five invalid login attempts to a victim's account.



- [https://github.com/jet-pentest/CVE-2021-27188](https://github.com/jet-pentest/CVE-2021-27188) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2021-27188.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2021-27188.svg)

## CVE-2021-27187
 The Sovremennye Delovye Tekhnologii FX Aggregator terminal client 1 stores authentication credentials in cleartext in login.sav when the Save Password box is checked.



- [https://github.com/jet-pentest/CVE-2021-27187](https://github.com/jet-pentest/CVE-2021-27187) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2021-27187.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2021-27187.svg)

## CVE-2021-27183
 An issue was discovered in MDaemon before 20.0.4. Administrators can use Remote Administration to exploit an Arbitrary File Write vulnerability. An attacker is able to create new files in any location of the filesystem, or he may be able to modify existing files. This vulnerability may directly lead to Remote Code Execution.



- [https://github.com/chudyPB/MDaemon-Advisories](https://github.com/chudyPB/MDaemon-Advisories) :  ![starts](https://img.shields.io/github/stars/chudyPB/MDaemon-Advisories.svg) ![forks](https://img.shields.io/github/forks/chudyPB/MDaemon-Advisories.svg)

## CVE-2021-27182
 An issue was discovered in MDaemon before 20.0.4. There is an IFRAME injection vulnerability in Webmail (aka WorldClient). It can be exploited via an email message. It allows an attacker to perform any action with the privileges of the attacked user.



- [https://github.com/chudyPB/MDaemon-Advisories](https://github.com/chudyPB/MDaemon-Advisories) :  ![starts](https://img.shields.io/github/stars/chudyPB/MDaemon-Advisories.svg) ![forks](https://img.shields.io/github/forks/chudyPB/MDaemon-Advisories.svg)

## CVE-2021-27181
 An issue was discovered in MDaemon before 20.0.4. Remote Administration allows an attacker to perform a fixation of the anti-CSRF token. In order to exploit this issue, the user has to click on a malicious URL provided by the attacker and successfully authenticate into the application. Having the value of the anti-CSRF token, the attacker may trick the user into visiting his malicious page and performing any request with the privileges of attacked user.



- [https://github.com/chudyPB/MDaemon-Advisories](https://github.com/chudyPB/MDaemon-Advisories) :  ![starts](https://img.shields.io/github/stars/chudyPB/MDaemon-Advisories.svg) ![forks](https://img.shields.io/github/forks/chudyPB/MDaemon-Advisories.svg)

## CVE-2021-27180
 An issue was discovered in MDaemon before 20.0.4. There is Reflected XSS in Webmail (aka WorldClient). It can be exploited via a GET request. It allows performing any action with the privileges of the attacked user.



- [https://github.com/chudyPB/MDaemon-Advisories](https://github.com/chudyPB/MDaemon-Advisories) :  ![starts](https://img.shields.io/github/stars/chudyPB/MDaemon-Advisories.svg) ![forks](https://img.shields.io/github/forks/chudyPB/MDaemon-Advisories.svg)

## CVE-2021-27065
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27078.



- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)

- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)

- [https://github.com/dwisiswant0/proxylogscan](https://github.com/dwisiswant0/proxylogscan) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/proxylogscan.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/proxylogscan.svg)

- [https://github.com/hosch3n/ProxyVulns](https://github.com/hosch3n/ProxyVulns) :  ![starts](https://img.shields.io/github/stars/hosch3n/ProxyVulns.svg) ![forks](https://img.shields.io/github/forks/hosch3n/ProxyVulns.svg)

- [https://github.com/herwonowr/exprolog](https://github.com/herwonowr/exprolog) :  ![starts](https://img.shields.io/github/stars/herwonowr/exprolog.svg) ![forks](https://img.shields.io/github/forks/herwonowr/exprolog.svg)

- [https://github.com/Udyz/Proxylogon](https://github.com/Udyz/Proxylogon) :  ![starts](https://img.shields.io/github/stars/Udyz/Proxylogon.svg) ![forks](https://img.shields.io/github/forks/Udyz/Proxylogon.svg)

- [https://github.com/p0wershe11/ProxyLogon](https://github.com/p0wershe11/ProxyLogon) :  ![starts](https://img.shields.io/github/stars/p0wershe11/ProxyLogon.svg) ![forks](https://img.shields.io/github/forks/p0wershe11/ProxyLogon.svg)

- [https://github.com/cert-lv/exchange_webshell_detection](https://github.com/cert-lv/exchange_webshell_detection) :  ![starts](https://img.shields.io/github/stars/cert-lv/exchange_webshell_detection.svg) ![forks](https://img.shields.io/github/forks/cert-lv/exchange_webshell_detection.svg)

- [https://github.com/praetorian-inc/proxylogon-exploit](https://github.com/praetorian-inc/proxylogon-exploit) :  ![starts](https://img.shields.io/github/stars/praetorian-inc/proxylogon-exploit.svg) ![forks](https://img.shields.io/github/forks/praetorian-inc/proxylogon-exploit.svg)

- [https://github.com/RickGeex/ProxyLogon](https://github.com/RickGeex/ProxyLogon) :  ![starts](https://img.shields.io/github/stars/RickGeex/ProxyLogon.svg) ![forks](https://img.shields.io/github/forks/RickGeex/ProxyLogon.svg)

- [https://github.com/evilashz/ExchangeSSRFtoRCEExploit](https://github.com/evilashz/ExchangeSSRFtoRCEExploit) :  ![starts](https://img.shields.io/github/stars/evilashz/ExchangeSSRFtoRCEExploit.svg) ![forks](https://img.shields.io/github/forks/evilashz/ExchangeSSRFtoRCEExploit.svg)

- [https://github.com/raheel0x01/CVE-2021-26855](https://github.com/raheel0x01/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/raheel0x01/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/raheel0x01/CVE-2021-26855.svg)

- [https://github.com/adamrpostjr/cve-2021-27065](https://github.com/adamrpostjr/cve-2021-27065) :  ![starts](https://img.shields.io/github/stars/adamrpostjr/cve-2021-27065.svg) ![forks](https://img.shields.io/github/forks/adamrpostjr/cve-2021-27065.svg)

- [https://github.com/sgnls/exchange-0days-202103](https://github.com/sgnls/exchange-0days-202103) :  ![starts](https://img.shields.io/github/stars/sgnls/exchange-0days-202103.svg) ![forks](https://img.shields.io/github/forks/sgnls/exchange-0days-202103.svg)

- [https://github.com/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day](https://github.com/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day) :  ![starts](https://img.shields.io/github/stars/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day.svg) ![forks](https://img.shields.io/github/forks/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day.svg)

- [https://github.com/mekhalleh/exchange_proxylogon](https://github.com/mekhalleh/exchange_proxylogon) :  ![starts](https://img.shields.io/github/stars/mekhalleh/exchange_proxylogon.svg) ![forks](https://img.shields.io/github/forks/mekhalleh/exchange_proxylogon.svg)

- [https://github.com/hictf/CVE-2021-26855-CVE-2021-27065](https://github.com/hictf/CVE-2021-26855-CVE-2021-27065) :  ![starts](https://img.shields.io/github/stars/hictf/CVE-2021-26855-CVE-2021-27065.svg) ![forks](https://img.shields.io/github/forks/hictf/CVE-2021-26855-CVE-2021-27065.svg)

- [https://github.com/DCScoder/Exchange_IOC_Hunter](https://github.com/DCScoder/Exchange_IOC_Hunter) :  ![starts](https://img.shields.io/github/stars/DCScoder/Exchange_IOC_Hunter.svg) ![forks](https://img.shields.io/github/forks/DCScoder/Exchange_IOC_Hunter.svg)

- [https://github.com/cryptolakk/ProxyLogon-Mass-RCE](https://github.com/cryptolakk/ProxyLogon-Mass-RCE) :  ![starts](https://img.shields.io/github/stars/cryptolakk/ProxyLogon-Mass-RCE.svg) ![forks](https://img.shields.io/github/forks/cryptolakk/ProxyLogon-Mass-RCE.svg)

## CVE-2021-26943
 The UX360CA BIOS through 303 on ASUS laptops allow an attacker (with the ring 0 privilege) to overwrite nearly arbitrary physical memory locations, including SMRAM, and execute arbitrary code in the SMM (issue 3 of 3).



- [https://github.com/tandasat/SmmExploit](https://github.com/tandasat/SmmExploit) :  ![starts](https://img.shields.io/github/stars/tandasat/SmmExploit.svg) ![forks](https://img.shields.io/github/forks/tandasat/SmmExploit.svg)

## CVE-2021-26904
 LMA ISIDA Retriever 5.2 allows SQL Injection.



- [https://github.com/Security-AVS/-CVE-2021-26904](https://github.com/Security-AVS/-CVE-2021-26904) :  ![starts](https://img.shields.io/github/stars/Security-AVS/-CVE-2021-26904.svg) ![forks](https://img.shields.io/github/forks/Security-AVS/-CVE-2021-26904.svg)

## CVE-2021-26903
 LMA ISIDA Retriever 5.2 is vulnerable to XSS via query['text'].



- [https://github.com/Security-AVS/CVE-2021-26903](https://github.com/Security-AVS/CVE-2021-26903) :  ![starts](https://img.shields.io/github/stars/Security-AVS/CVE-2021-26903.svg) ![forks](https://img.shields.io/github/forks/Security-AVS/CVE-2021-26903.svg)

## CVE-2021-26885
 Windows WalletService Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-26871.



- [https://github.com/Yang0615777/PocList](https://github.com/Yang0615777/PocList) :  ![starts](https://img.shields.io/github/stars/Yang0615777/PocList.svg) ![forks](https://img.shields.io/github/forks/Yang0615777/PocList.svg)

## CVE-2021-26882
 Remote Access API Elevation of Privilege Vulnerability



- [https://github.com/api0cradle/CVE-2021-26882](https://github.com/api0cradle/CVE-2021-26882) :  ![starts](https://img.shields.io/github/stars/api0cradle/CVE-2021-26882.svg) ![forks](https://img.shields.io/github/forks/api0cradle/CVE-2021-26882.svg)

## CVE-2021-26871
 Windows WalletService Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-26885.



- [https://github.com/robotMD5/CVE-2021-26871_POC](https://github.com/robotMD5/CVE-2021-26871_POC) :  ![starts](https://img.shields.io/github/stars/robotMD5/CVE-2021-26871_POC.svg) ![forks](https://img.shields.io/github/forks/robotMD5/CVE-2021-26871_POC.svg)

## CVE-2021-26868
 Windows Graphics Component Elevation of Privilege Vulnerability



- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)

- [https://github.com/KangD1W2/CVE-2021-26868](https://github.com/KangD1W2/CVE-2021-26868) :  ![starts](https://img.shields.io/github/stars/KangD1W2/CVE-2021-26868.svg) ![forks](https://img.shields.io/github/forks/KangD1W2/CVE-2021-26868.svg)

## CVE-2021-26865
 Windows Container Execution Agent Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-26891.



- [https://github.com/soteria-security/HAFNIUM-IOC](https://github.com/soteria-security/HAFNIUM-IOC) :  ![starts](https://img.shields.io/github/stars/soteria-security/HAFNIUM-IOC.svg) ![forks](https://img.shields.io/github/forks/soteria-security/HAFNIUM-IOC.svg)

- [https://github.com/Yt1g3r/CVE-2021-26855_SSRF](https://github.com/Yt1g3r/CVE-2021-26855_SSRF) :  ![starts](https://img.shields.io/github/stars/Yt1g3r/CVE-2021-26855_SSRF.svg) ![forks](https://img.shields.io/github/forks/Yt1g3r/CVE-2021-26855_SSRF.svg)

## CVE-2021-26858
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26857, CVE-2021-27065, CVE-2021-27078.



- [https://github.com/herwonowr/exprolog](https://github.com/herwonowr/exprolog) :  ![starts](https://img.shields.io/github/stars/herwonowr/exprolog.svg) ![forks](https://img.shields.io/github/forks/herwonowr/exprolog.svg)

- [https://github.com/cert-lv/exchange_webshell_detection](https://github.com/cert-lv/exchange_webshell_detection) :  ![starts](https://img.shields.io/github/stars/cert-lv/exchange_webshell_detection.svg) ![forks](https://img.shields.io/github/forks/cert-lv/exchange_webshell_detection.svg)

- [https://github.com/soteria-security/HAFNIUM-IOC](https://github.com/soteria-security/HAFNIUM-IOC) :  ![starts](https://img.shields.io/github/stars/soteria-security/HAFNIUM-IOC.svg) ![forks](https://img.shields.io/github/forks/soteria-security/HAFNIUM-IOC.svg)

- [https://github.com/sgnls/exchange-0days-202103](https://github.com/sgnls/exchange-0days-202103) :  ![starts](https://img.shields.io/github/stars/sgnls/exchange-0days-202103.svg) ![forks](https://img.shields.io/github/forks/sgnls/exchange-0days-202103.svg)

- [https://github.com/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day](https://github.com/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day) :  ![starts](https://img.shields.io/github/stars/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day.svg) ![forks](https://img.shields.io/github/forks/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day.svg)

- [https://github.com/Yt1g3r/CVE-2021-26855_SSRF](https://github.com/Yt1g3r/CVE-2021-26855_SSRF) :  ![starts](https://img.shields.io/github/stars/Yt1g3r/CVE-2021-26855_SSRF.svg) ![forks](https://img.shields.io/github/forks/Yt1g3r/CVE-2021-26855_SSRF.svg)

- [https://github.com/DCScoder/Exchange_IOC_Hunter](https://github.com/DCScoder/Exchange_IOC_Hunter) :  ![starts](https://img.shields.io/github/stars/DCScoder/Exchange_IOC_Hunter.svg) ![forks](https://img.shields.io/github/forks/DCScoder/Exchange_IOC_Hunter.svg)

## CVE-2021-26857
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.



- [https://github.com/herwonowr/exprolog](https://github.com/herwonowr/exprolog) :  ![starts](https://img.shields.io/github/stars/herwonowr/exprolog.svg) ![forks](https://img.shields.io/github/forks/herwonowr/exprolog.svg)

- [https://github.com/sirpedrotavares/Proxylogon-exploit](https://github.com/sirpedrotavares/Proxylogon-exploit) :  ![starts](https://img.shields.io/github/stars/sirpedrotavares/Proxylogon-exploit.svg) ![forks](https://img.shields.io/github/forks/sirpedrotavares/Proxylogon-exploit.svg)

- [https://github.com/cert-lv/exchange_webshell_detection](https://github.com/cert-lv/exchange_webshell_detection) :  ![starts](https://img.shields.io/github/stars/cert-lv/exchange_webshell_detection.svg) ![forks](https://img.shields.io/github/forks/cert-lv/exchange_webshell_detection.svg)

- [https://github.com/soteria-security/HAFNIUM-IOC](https://github.com/soteria-security/HAFNIUM-IOC) :  ![starts](https://img.shields.io/github/stars/soteria-security/HAFNIUM-IOC.svg) ![forks](https://img.shields.io/github/forks/soteria-security/HAFNIUM-IOC.svg)

- [https://github.com/sgnls/exchange-0days-202103](https://github.com/sgnls/exchange-0days-202103) :  ![starts](https://img.shields.io/github/stars/sgnls/exchange-0days-202103.svg) ![forks](https://img.shields.io/github/forks/sgnls/exchange-0days-202103.svg)

- [https://github.com/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day](https://github.com/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day) :  ![starts](https://img.shields.io/github/stars/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day.svg) ![forks](https://img.shields.io/github/forks/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day.svg)

- [https://github.com/Yt1g3r/CVE-2021-26855_SSRF](https://github.com/Yt1g3r/CVE-2021-26855_SSRF) :  ![starts](https://img.shields.io/github/stars/Yt1g3r/CVE-2021-26855_SSRF.svg) ![forks](https://img.shields.io/github/forks/Yt1g3r/CVE-2021-26855_SSRF.svg)

- [https://github.com/Immersive-Labs-Sec/ProxyLogon](https://github.com/Immersive-Labs-Sec/ProxyLogon) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/ProxyLogon.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/ProxyLogon.svg)

- [https://github.com/DCScoder/Exchange_IOC_Hunter](https://github.com/DCScoder/Exchange_IOC_Hunter) :  ![starts](https://img.shields.io/github/stars/DCScoder/Exchange_IOC_Hunter.svg) ![forks](https://img.shields.io/github/forks/DCScoder/Exchange_IOC_Hunter.svg)

- [https://github.com/cryptolakk/ProxyLogon-Mass-RCE](https://github.com/cryptolakk/ProxyLogon-Mass-RCE) :  ![starts](https://img.shields.io/github/stars/cryptolakk/ProxyLogon-Mass-RCE.svg) ![forks](https://img.shields.io/github/forks/cryptolakk/ProxyLogon-Mass-RCE.svg)

## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.



- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)

- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)

- [https://github.com/Flangvik/SharpProxyLogon](https://github.com/Flangvik/SharpProxyLogon) :  ![starts](https://img.shields.io/github/stars/Flangvik/SharpProxyLogon.svg) ![forks](https://img.shields.io/github/forks/Flangvik/SharpProxyLogon.svg)

- [https://github.com/dwisiswant0/proxylogscan](https://github.com/dwisiswant0/proxylogscan) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/proxylogscan.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/proxylogscan.svg)

- [https://github.com/hosch3n/ProxyVulns](https://github.com/hosch3n/ProxyVulns) :  ![starts](https://img.shields.io/github/stars/hosch3n/ProxyVulns.svg) ![forks](https://img.shields.io/github/forks/hosch3n/ProxyVulns.svg)

- [https://github.com/herwonowr/exprolog](https://github.com/herwonowr/exprolog) :  ![starts](https://img.shields.io/github/stars/herwonowr/exprolog.svg) ![forks](https://img.shields.io/github/forks/herwonowr/exprolog.svg)

- [https://github.com/Udyz/Proxylogon](https://github.com/Udyz/Proxylogon) :  ![starts](https://img.shields.io/github/stars/Udyz/Proxylogon.svg) ![forks](https://img.shields.io/github/forks/Udyz/Proxylogon.svg)

- [https://github.com/charlottelatest/CVE-2021-26855](https://github.com/charlottelatest/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/charlottelatest/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/charlottelatest/CVE-2021-26855.svg)

- [https://github.com/p0wershe11/ProxyLogon](https://github.com/p0wershe11/ProxyLogon) :  ![starts](https://img.shields.io/github/stars/p0wershe11/ProxyLogon.svg) ![forks](https://img.shields.io/github/forks/p0wershe11/ProxyLogon.svg)

- [https://github.com/cert-lv/exchange_webshell_detection](https://github.com/cert-lv/exchange_webshell_detection) :  ![starts](https://img.shields.io/github/stars/cert-lv/exchange_webshell_detection.svg) ![forks](https://img.shields.io/github/forks/cert-lv/exchange_webshell_detection.svg)

- [https://github.com/h4x0r-dz/CVE-2021-26855](https://github.com/h4x0r-dz/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/h4x0r-dz/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/h4x0r-dz/CVE-2021-26855.svg)

- [https://github.com/hackerschoice/CVE-2021-26855](https://github.com/hackerschoice/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/hackerschoice/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/hackerschoice/CVE-2021-26855.svg)

- [https://github.com/alt3kx/CVE-2021-26855_PoC](https://github.com/alt3kx/CVE-2021-26855_PoC) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2021-26855_PoC.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2021-26855_PoC.svg)

- [https://github.com/conjojo/Microsoft_Exchange_Server_SSRF_CVE-2021-26855](https://github.com/conjojo/Microsoft_Exchange_Server_SSRF_CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/conjojo/Microsoft_Exchange_Server_SSRF_CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/conjojo/Microsoft_Exchange_Server_SSRF_CVE-2021-26855.svg)

- [https://github.com/praetorian-inc/proxylogon-exploit](https://github.com/praetorian-inc/proxylogon-exploit) :  ![starts](https://img.shields.io/github/stars/praetorian-inc/proxylogon-exploit.svg) ![forks](https://img.shields.io/github/forks/praetorian-inc/proxylogon-exploit.svg)

- [https://github.com/ZephrFish/Exch-CVE-2021-26855](https://github.com/ZephrFish/Exch-CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/ZephrFish/Exch-CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/Exch-CVE-2021-26855.svg)

- [https://github.com/RickGeex/ProxyLogon](https://github.com/RickGeex/ProxyLogon) :  ![starts](https://img.shields.io/github/stars/RickGeex/ProxyLogon.svg) ![forks](https://img.shields.io/github/forks/RickGeex/ProxyLogon.svg)

- [https://github.com/evilashz/ExchangeSSRFtoRCEExploit](https://github.com/evilashz/ExchangeSSRFtoRCEExploit) :  ![starts](https://img.shields.io/github/stars/evilashz/ExchangeSSRFtoRCEExploit.svg) ![forks](https://img.shields.io/github/forks/evilashz/ExchangeSSRFtoRCEExploit.svg)

- [https://github.com/pussycat0x/CVE-2021-26855-SSRF](https://github.com/pussycat0x/CVE-2021-26855-SSRF) :  ![starts](https://img.shields.io/github/stars/pussycat0x/CVE-2021-26855-SSRF.svg) ![forks](https://img.shields.io/github/forks/pussycat0x/CVE-2021-26855-SSRF.svg)

- [https://github.com/soteria-security/HAFNIUM-IOC](https://github.com/soteria-security/HAFNIUM-IOC) :  ![starts](https://img.shields.io/github/stars/soteria-security/HAFNIUM-IOC.svg) ![forks](https://img.shields.io/github/forks/soteria-security/HAFNIUM-IOC.svg)

- [https://github.com/0xAbdullah/CVE-2021-26855](https://github.com/0xAbdullah/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/0xAbdullah/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/0xAbdullah/CVE-2021-26855.svg)

- [https://github.com/r0ckysec/CVE-2021-26855_Exchange](https://github.com/r0ckysec/CVE-2021-26855_Exchange) :  ![starts](https://img.shields.io/github/stars/r0ckysec/CVE-2021-26855_Exchange.svg) ![forks](https://img.shields.io/github/forks/r0ckysec/CVE-2021-26855_Exchange.svg)

- [https://github.com/raheel0x01/CVE-2021-26855](https://github.com/raheel0x01/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/raheel0x01/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/raheel0x01/CVE-2021-26855.svg)

- [https://github.com/srvaccount/CVE-2021-26855-PoC](https://github.com/srvaccount/CVE-2021-26855-PoC) :  ![starts](https://img.shields.io/github/stars/srvaccount/CVE-2021-26855-PoC.svg) ![forks](https://img.shields.io/github/forks/srvaccount/CVE-2021-26855-PoC.svg)

- [https://github.com/mil1200/ProxyLogon-CVE-2021-26855](https://github.com/mil1200/ProxyLogon-CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/mil1200/ProxyLogon-CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/mil1200/ProxyLogon-CVE-2021-26855.svg)

- [https://github.com/Th3eCrow/CVE-2021-26855-SSRF-Exchange](https://github.com/Th3eCrow/CVE-2021-26855-SSRF-Exchange) :  ![starts](https://img.shields.io/github/stars/Th3eCrow/CVE-2021-26855-SSRF-Exchange.svg) ![forks](https://img.shields.io/github/forks/Th3eCrow/CVE-2021-26855-SSRF-Exchange.svg)

- [https://github.com/Mr-xn/CVE-2021-26855-d](https://github.com/Mr-xn/CVE-2021-26855-d) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2021-26855-d.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2021-26855-d.svg)

- [https://github.com/stressboi/hafnium-exchange-splunk-csvs](https://github.com/stressboi/hafnium-exchange-splunk-csvs) :  ![starts](https://img.shields.io/github/stars/stressboi/hafnium-exchange-splunk-csvs.svg) ![forks](https://img.shields.io/github/forks/stressboi/hafnium-exchange-splunk-csvs.svg)

- [https://github.com/sgnls/exchange-0days-202103](https://github.com/sgnls/exchange-0days-202103) :  ![starts](https://img.shields.io/github/stars/sgnls/exchange-0days-202103.svg) ![forks](https://img.shields.io/github/forks/sgnls/exchange-0days-202103.svg)

- [https://github.com/hakivvi/proxylogon](https://github.com/hakivvi/proxylogon) :  ![starts](https://img.shields.io/github/stars/hakivvi/proxylogon.svg) ![forks](https://img.shields.io/github/forks/hakivvi/proxylogon.svg)

- [https://github.com/WiredPulse/Invoke-HAFNIUMCheck.ps1](https://github.com/WiredPulse/Invoke-HAFNIUMCheck.ps1) :  ![starts](https://img.shields.io/github/stars/WiredPulse/Invoke-HAFNIUMCheck.ps1.svg) ![forks](https://img.shields.io/github/forks/WiredPulse/Invoke-HAFNIUMCheck.ps1.svg)

- [https://github.com/0xmahmoudJo0/Check_Emails_For_CVE_2021_26855](https://github.com/0xmahmoudJo0/Check_Emails_For_CVE_2021_26855) :  ![starts](https://img.shields.io/github/stars/0xmahmoudJo0/Check_Emails_For_CVE_2021_26855.svg) ![forks](https://img.shields.io/github/forks/0xmahmoudJo0/Check_Emails_For_CVE_2021_26855.svg)

- [https://github.com/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day](https://github.com/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day) :  ![starts](https://img.shields.io/github/stars/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day.svg) ![forks](https://img.shields.io/github/forks/SCS-Labs/HAFNIUM-Microsoft-Exchange-0day.svg)

- [https://github.com/Yt1g3r/CVE-2021-26855_SSRF](https://github.com/Yt1g3r/CVE-2021-26855_SSRF) :  ![starts](https://img.shields.io/github/stars/Yt1g3r/CVE-2021-26855_SSRF.svg) ![forks](https://img.shields.io/github/forks/Yt1g3r/CVE-2021-26855_SSRF.svg)

- [https://github.com/shacojx/CVE_2021_26855_SSRF](https://github.com/shacojx/CVE_2021_26855_SSRF) :  ![starts](https://img.shields.io/github/stars/shacojx/CVE_2021_26855_SSRF.svg) ![forks](https://img.shields.io/github/forks/shacojx/CVE_2021_26855_SSRF.svg)

- [https://github.com/achabahe/CVE-2021-26855](https://github.com/achabahe/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/achabahe/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/achabahe/CVE-2021-26855.svg)

- [https://github.com/TaroballzChen/ProxyLogon-CVE-2021-26855-metasploit](https://github.com/TaroballzChen/ProxyLogon-CVE-2021-26855-metasploit) :  ![starts](https://img.shields.io/github/stars/TaroballzChen/ProxyLogon-CVE-2021-26855-metasploit.svg) ![forks](https://img.shields.io/github/forks/TaroballzChen/ProxyLogon-CVE-2021-26855-metasploit.svg)

- [https://github.com/KotSec/CVE-2021-26855-Scanner](https://github.com/KotSec/CVE-2021-26855-Scanner) :  ![starts](https://img.shields.io/github/stars/KotSec/CVE-2021-26855-Scanner.svg) ![forks](https://img.shields.io/github/forks/KotSec/CVE-2021-26855-Scanner.svg)

- [https://github.com/shacojx/CVE-2021-26855-exploit-Exchange](https://github.com/shacojx/CVE-2021-26855-exploit-Exchange) :  ![starts](https://img.shields.io/github/stars/shacojx/CVE-2021-26855-exploit-Exchange.svg) ![forks](https://img.shields.io/github/forks/shacojx/CVE-2021-26855-exploit-Exchange.svg)

- [https://github.com/mekhalleh/exchange_proxylogon](https://github.com/mekhalleh/exchange_proxylogon) :  ![starts](https://img.shields.io/github/stars/mekhalleh/exchange_proxylogon.svg) ![forks](https://img.shields.io/github/forks/mekhalleh/exchange_proxylogon.svg)

- [https://github.com/thau0x01/poc_proxylogon](https://github.com/thau0x01/poc_proxylogon) :  ![starts](https://img.shields.io/github/stars/thau0x01/poc_proxylogon.svg) ![forks](https://img.shields.io/github/forks/thau0x01/poc_proxylogon.svg)

- [https://github.com/shacojx/Scan-Vuln-CVE-2021-26855](https://github.com/shacojx/Scan-Vuln-CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/shacojx/Scan-Vuln-CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/shacojx/Scan-Vuln-CVE-2021-26855.svg)

- [https://github.com/Immersive-Labs-Sec/ProxyLogon](https://github.com/Immersive-Labs-Sec/ProxyLogon) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/ProxyLogon.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/ProxyLogon.svg)

- [https://github.com/SotirisKar/CVE-2021-26855](https://github.com/SotirisKar/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/SotirisKar/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/SotirisKar/CVE-2021-26855.svg)

- [https://github.com/hictf/CVE-2021-26855-CVE-2021-27065](https://github.com/hictf/CVE-2021-26855-CVE-2021-27065) :  ![starts](https://img.shields.io/github/stars/hictf/CVE-2021-26855-CVE-2021-27065.svg) ![forks](https://img.shields.io/github/forks/hictf/CVE-2021-26855-CVE-2021-27065.svg)

- [https://github.com/DCScoder/Exchange_IOC_Hunter](https://github.com/DCScoder/Exchange_IOC_Hunter) :  ![starts](https://img.shields.io/github/stars/DCScoder/Exchange_IOC_Hunter.svg) ![forks](https://img.shields.io/github/forks/DCScoder/Exchange_IOC_Hunter.svg)

- [https://github.com/mauricelambert/ExchangeWeaknessTest](https://github.com/mauricelambert/ExchangeWeaknessTest) :  ![starts](https://img.shields.io/github/stars/mauricelambert/ExchangeWeaknessTest.svg) ![forks](https://img.shields.io/github/forks/mauricelambert/ExchangeWeaknessTest.svg)

- [https://github.com/yaoxiaoangry3/Flangvik](https://github.com/yaoxiaoangry3/Flangvik) :  ![starts](https://img.shields.io/github/stars/yaoxiaoangry3/Flangvik.svg) ![forks](https://img.shields.io/github/forks/yaoxiaoangry3/Flangvik.svg)

- [https://github.com/cryptolakk/ProxyLogon-Mass-RCE](https://github.com/cryptolakk/ProxyLogon-Mass-RCE) :  ![starts](https://img.shields.io/github/stars/cryptolakk/ProxyLogon-Mass-RCE.svg) ![forks](https://img.shields.io/github/forks/cryptolakk/ProxyLogon-Mass-RCE.svg)

## CVE-2021-26832
 Cross Site Scripting (XSS) in the &quot;Reset Password&quot; page form of Priority Enterprise Management System v8.00 allows attackers to execute javascript on behalf of the victim by sending a malicious URL or directing the victim to a malicious site.



- [https://github.com/NagliNagli/CVE-2021-26832](https://github.com/NagliNagli/CVE-2021-26832) :  ![starts](https://img.shields.io/github/stars/NagliNagli/CVE-2021-26832.svg) ![forks](https://img.shields.io/github/forks/NagliNagli/CVE-2021-26832.svg)

## CVE-2021-26828
 OpenPLC ScadaBR through 0.9.1 on Linux and through 1.12.4 on Windows allows remote authenticated users to upload and execute arbitrary JSP files via view_edit.shtm.



- [https://github.com/h3v0x/CVE-2021-26828_ScadaBR_RCE](https://github.com/h3v0x/CVE-2021-26828_ScadaBR_RCE) :  ![starts](https://img.shields.io/github/stars/h3v0x/CVE-2021-26828_ScadaBR_RCE.svg) ![forks](https://img.shields.io/github/forks/h3v0x/CVE-2021-26828_ScadaBR_RCE.svg)

## CVE-2021-26814
 Wazuh API in Wazuh from 4.0.0 to 4.0.3 allows authenticated users to execute arbitrary code with administrative privileges via /manager/files URI. An authenticated user to the service may exploit incomplete input validation on the /manager/files API to inject arbitrary code within the API service script.



- [https://github.com/WickdDavid/CVE-2021-26814](https://github.com/WickdDavid/CVE-2021-26814) :  ![starts](https://img.shields.io/github/stars/WickdDavid/CVE-2021-26814.svg) ![forks](https://img.shields.io/github/forks/WickdDavid/CVE-2021-26814.svg)

- [https://github.com/CYS4srl/CVE-2021-26814](https://github.com/CYS4srl/CVE-2021-26814) :  ![starts](https://img.shields.io/github/stars/CYS4srl/CVE-2021-26814.svg) ![forks](https://img.shields.io/github/forks/CYS4srl/CVE-2021-26814.svg)

- [https://github.com/paolorabbito/Internet-Security-Project---CVE-2021-26814](https://github.com/paolorabbito/Internet-Security-Project---CVE-2021-26814) :  ![starts](https://img.shields.io/github/stars/paolorabbito/Internet-Security-Project---CVE-2021-26814.svg) ![forks](https://img.shields.io/github/forks/paolorabbito/Internet-Security-Project---CVE-2021-26814.svg)

## CVE-2021-26714
 The Enterprise License Manager portal in Mitel MiContact Center Enterprise before 9.4 could allow a user to access restricted files and folders due to insufficient access control. A successful exploit could allow an attacker to view and modify application data via Directory Traversal.



- [https://github.com/PwCNO-CTO/CVE-2021-26714](https://github.com/PwCNO-CTO/CVE-2021-26714) :  ![starts](https://img.shields.io/github/stars/PwCNO-CTO/CVE-2021-26714.svg) ![forks](https://img.shields.io/github/forks/PwCNO-CTO/CVE-2021-26714.svg)

## CVE-2021-26708
 A local privilege escalation was discovered in the Linux kernel before 5.10.13. Multiple race conditions in the AF_VSOCK implementation are caused by wrong locking in net/vmw_vsock/af_vsock.c. The race conditions were implicitly introduced in the commits that added VSOCK multi-transport support.



- [https://github.com/jordan9001/vsock_poc](https://github.com/jordan9001/vsock_poc) :  ![starts](https://img.shields.io/github/stars/jordan9001/vsock_poc.svg) ![forks](https://img.shields.io/github/forks/jordan9001/vsock_poc.svg)

## CVE-2021-26700
 Visual Studio Code npm-script Extension Remote Code Execution Vulnerability



- [https://github.com/jackadamson/CVE-2021-26700](https://github.com/jackadamson/CVE-2021-26700) :  ![starts](https://img.shields.io/github/stars/jackadamson/CVE-2021-26700.svg) ![forks](https://img.shields.io/github/forks/jackadamson/CVE-2021-26700.svg)

## CVE-2021-26691
 In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server could cause a heap overflow



- [https://github.com/fkm75P8YjLkb/CVE-2021-26691](https://github.com/fkm75P8YjLkb/CVE-2021-26691) :  ![starts](https://img.shields.io/github/stars/fkm75P8YjLkb/CVE-2021-26691.svg) ![forks](https://img.shields.io/github/forks/fkm75P8YjLkb/CVE-2021-26691.svg)

## CVE-2021-26690
 Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Cookie header handled by mod_session can cause a NULL pointer dereference and crash, leading to a possible Denial Of Service



- [https://github.com/fkm75P8YjLkb/CVE-2021-26690](https://github.com/fkm75P8YjLkb/CVE-2021-26690) :  ![starts](https://img.shields.io/github/stars/fkm75P8YjLkb/CVE-2021-26690.svg) ![forks](https://img.shields.io/github/forks/fkm75P8YjLkb/CVE-2021-26690.svg)

## CVE-2021-26415
 Windows Installer Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-28440.



- [https://github.com/adenkiewicz/CVE-2021-26415](https://github.com/adenkiewicz/CVE-2021-26415) :  ![starts](https://img.shields.io/github/stars/adenkiewicz/CVE-2021-26415.svg) ![forks](https://img.shields.io/github/forks/adenkiewicz/CVE-2021-26415.svg)

## CVE-2021-26295
 Apache OFBiz has unsafe deserialization prior to 17.12.06. An unauthenticated attacker can use this vulnerability to successfully take over Apache OFBiz.



- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)

- [https://github.com/yumusb/CVE-2021-26295](https://github.com/yumusb/CVE-2021-26295) :  ![starts](https://img.shields.io/github/stars/yumusb/CVE-2021-26295.svg) ![forks](https://img.shields.io/github/forks/yumusb/CVE-2021-26295.svg)

- [https://github.com/r0ckysec/CVE-2021-26295](https://github.com/r0ckysec/CVE-2021-26295) :  ![starts](https://img.shields.io/github/stars/r0ckysec/CVE-2021-26295.svg) ![forks](https://img.shields.io/github/forks/r0ckysec/CVE-2021-26295.svg)

- [https://github.com/S0por/CVE-2021-26295-Apache-OFBiz-EXP](https://github.com/S0por/CVE-2021-26295-Apache-OFBiz-EXP) :  ![starts](https://img.shields.io/github/stars/S0por/CVE-2021-26295-Apache-OFBiz-EXP.svg) ![forks](https://img.shields.io/github/forks/S0por/CVE-2021-26295-Apache-OFBiz-EXP.svg)

- [https://github.com/rakjong/CVE-2021-26295-Apache-OFBiz](https://github.com/rakjong/CVE-2021-26295-Apache-OFBiz) :  ![starts](https://img.shields.io/github/stars/rakjong/CVE-2021-26295-Apache-OFBiz.svg) ![forks](https://img.shields.io/github/forks/rakjong/CVE-2021-26295-Apache-OFBiz.svg)

- [https://github.com/TheTh1nk3r/exp_hub](https://github.com/TheTh1nk3r/exp_hub) :  ![starts](https://img.shields.io/github/stars/TheTh1nk3r/exp_hub.svg) ![forks](https://img.shields.io/github/forks/TheTh1nk3r/exp_hub.svg)

- [https://github.com/yuaneuro/ofbiz-poc](https://github.com/yuaneuro/ofbiz-poc) :  ![starts](https://img.shields.io/github/stars/yuaneuro/ofbiz-poc.svg) ![forks](https://img.shields.io/github/forks/yuaneuro/ofbiz-poc.svg)

- [https://github.com/coolyin001/CVE-2021-26295--](https://github.com/coolyin001/CVE-2021-26295--) :  ![starts](https://img.shields.io/github/stars/coolyin001/CVE-2021-26295--.svg) ![forks](https://img.shields.io/github/forks/coolyin001/CVE-2021-26295--.svg)

## CVE-2021-26294
 An issue was discovered in AfterLogic Aurora through 7.7.9 and WebMail Pro through 7.7.9. They allow directory traversal to read files (such as a data/settings/settings.xml file containing admin panel credentials), as demonstrated by dav/server.php/files/personal/%2e%2e when using the caldav_public_user account (with caldav_public_user as its password).



- [https://github.com/dorkerdevil/CVE-2021-26294](https://github.com/dorkerdevil/CVE-2021-26294) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-26294.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-26294.svg)

## CVE-2021-26121
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/sourceincite/CVE-2021-26121](https://github.com/sourceincite/CVE-2021-26121) :  ![starts](https://img.shields.io/github/stars/sourceincite/CVE-2021-26121.svg) ![forks](https://img.shields.io/github/forks/sourceincite/CVE-2021-26121.svg)

## CVE-2021-26119
 Smarty before 3.1.39 allows a Sandbox Escape because $smarty.template_object can be accessed in sandbox mode.



- [https://github.com/Udyz/CVE-2021-26119](https://github.com/Udyz/CVE-2021-26119) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2021-26119.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2021-26119.svg)

## CVE-2021-26102
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/SleepyCofe/CVE-2021-26102](https://github.com/SleepyCofe/CVE-2021-26102) :  ![starts](https://img.shields.io/github/stars/SleepyCofe/CVE-2021-26102.svg) ![forks](https://img.shields.io/github/forks/SleepyCofe/CVE-2021-26102.svg)

## CVE-2021-26086
 Affected versions of Atlassian Jira Server and Data Center allow remote attackers to read particular files via a path traversal vulnerability in the /WEB-INF/web.xml endpoint. The affected versions are before version 8.5.14, from version 8.6.0 before 8.13.6, and from version 8.14.0 before 8.16.1.



- [https://github.com/ColdFusionX/CVE-2021-26086](https://github.com/ColdFusionX/CVE-2021-26086) :  ![starts](https://img.shields.io/github/stars/ColdFusionX/CVE-2021-26086.svg) ![forks](https://img.shields.io/github/forks/ColdFusionX/CVE-2021-26086.svg)

## CVE-2021-26085
 Affected versions of Atlassian Confluence Server allow remote attackers to view restricted resources via a Pre-Authorization Arbitrary File Read vulnerability in the /s/ endpoint. The affected versions are before version 7.4.10, and from version 7.5.0 before 7.12.3.



- [https://github.com/ColdFusionX/CVE-2021-26085](https://github.com/ColdFusionX/CVE-2021-26085) :  ![starts](https://img.shields.io/github/stars/ColdFusionX/CVE-2021-26085.svg) ![forks](https://img.shields.io/github/forks/ColdFusionX/CVE-2021-26085.svg)

- [https://github.com/zeroc00I/CVE-2021-26085](https://github.com/zeroc00I/CVE-2021-26085) :  ![starts](https://img.shields.io/github/stars/zeroc00I/CVE-2021-26085.svg) ![forks](https://img.shields.io/github/forks/zeroc00I/CVE-2021-26085.svg)

## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.



- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)

- [https://github.com/h3v0x/CVE-2021-26084_Confluence](https://github.com/h3v0x/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/h3v0x/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/h3v0x/CVE-2021-26084_Confluence.svg)

- [https://github.com/r0ckysec/CVE-2021-26084_Confluence](https://github.com/r0ckysec/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/r0ckysec/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/r0ckysec/CVE-2021-26084_Confluence.svg)

- [https://github.com/alt3kx/CVE-2021-26084_PoC](https://github.com/alt3kx/CVE-2021-26084_PoC) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2021-26084_PoC.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2021-26084_PoC.svg)

- [https://github.com/dinhbaouit/CVE-2021-26084](https://github.com/dinhbaouit/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/dinhbaouit/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/dinhbaouit/CVE-2021-26084.svg)

- [https://github.com/0xf4n9x/CVE-2021-26084](https://github.com/0xf4n9x/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2021-26084.svg)

- [https://github.com/Sma11New/PocList](https://github.com/Sma11New/PocList) :  ![starts](https://img.shields.io/github/stars/Sma11New/PocList.svg) ![forks](https://img.shields.io/github/forks/Sma11New/PocList.svg)

- [https://github.com/1ZRR4H/CVE-2021-26084](https://github.com/1ZRR4H/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/1ZRR4H/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/1ZRR4H/CVE-2021-26084.svg)

- [https://github.com/carlosevieira/CVE-2021-26084](https://github.com/carlosevieira/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/carlosevieira/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/carlosevieira/CVE-2021-26084.svg)

- [https://github.com/Udyz/CVE-2021-26084](https://github.com/Udyz/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2021-26084.svg)

- [https://github.com/dorkerdevil/CVE-2021-26084](https://github.com/dorkerdevil/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-26084.svg)

- [https://github.com/Vulnmachines/Confluence_CVE-2021-26084](https://github.com/Vulnmachines/Confluence_CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/Confluence_CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/Confluence_CVE-2021-26084.svg)

- [https://github.com/taythebot/CVE-2021-26084](https://github.com/taythebot/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/taythebot/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/taythebot/CVE-2021-26084.svg)

- [https://github.com/lleavesl/CVE-2021-26084](https://github.com/lleavesl/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/lleavesl/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/lleavesl/CVE-2021-26084.svg)

- [https://github.com/march0s1as/CVE-2021-26084](https://github.com/march0s1as/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/march0s1as/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/march0s1as/CVE-2021-26084.svg)

- [https://github.com/JKme/CVE-2021-26084](https://github.com/JKme/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/JKme/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/JKme/CVE-2021-26084.svg)

- [https://github.com/onsecuredev/CVE-2021-26084](https://github.com/onsecuredev/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-26084.svg)

- [https://github.com/toowoxx/docker-confluence-patched](https://github.com/toowoxx/docker-confluence-patched) :  ![starts](https://img.shields.io/github/stars/toowoxx/docker-confluence-patched.svg) ![forks](https://img.shields.io/github/forks/toowoxx/docker-confluence-patched.svg)

- [https://github.com/ludy-dev/CVE-2021-26084_PoC](https://github.com/ludy-dev/CVE-2021-26084_PoC) :  ![starts](https://img.shields.io/github/stars/ludy-dev/CVE-2021-26084_PoC.svg) ![forks](https://img.shields.io/github/forks/ludy-dev/CVE-2021-26084_PoC.svg)

- [https://github.com/rootsmadi/CVE-2021-26084](https://github.com/rootsmadi/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/rootsmadi/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/rootsmadi/CVE-2021-26084.svg)

- [https://github.com/GlennPegden2/cve-2021-26084-confluence](https://github.com/GlennPegden2/cve-2021-26084-confluence) :  ![starts](https://img.shields.io/github/stars/GlennPegden2/cve-2021-26084-confluence.svg) ![forks](https://img.shields.io/github/forks/GlennPegden2/cve-2021-26084-confluence.svg)

- [https://github.com/Loneyers/CVE-2021-26084](https://github.com/Loneyers/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/Loneyers/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/Loneyers/CVE-2021-26084.svg)

- [https://github.com/p0nymc1/CVE-2021-26084](https://github.com/p0nymc1/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/p0nymc1/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/p0nymc1/CVE-2021-26084.svg)

- [https://github.com/Jun-5heng/CVE-2021-26084](https://github.com/Jun-5heng/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/Jun-5heng/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/Jun-5heng/CVE-2021-26084.svg)

- [https://github.com/nizarbamida/CVE-2021-26084-patch-](https://github.com/nizarbamida/CVE-2021-26084-patch-) :  ![starts](https://img.shields.io/github/stars/nizarbamida/CVE-2021-26084-patch-.svg) ![forks](https://img.shields.io/github/forks/nizarbamida/CVE-2021-26084-patch-.svg)

- [https://github.com/BeRserKerSec/CVE-2021-26084-Nuclei-template](https://github.com/BeRserKerSec/CVE-2021-26084-Nuclei-template) :  ![starts](https://img.shields.io/github/stars/BeRserKerSec/CVE-2021-26084-Nuclei-template.svg) ![forks](https://img.shields.io/github/forks/BeRserKerSec/CVE-2021-26084-Nuclei-template.svg)

- [https://github.com/z0edff0x3d/CVE-2021-26084-Confluence-OGNL](https://github.com/z0edff0x3d/CVE-2021-26084-Confluence-OGNL) :  ![starts](https://img.shields.io/github/stars/z0edff0x3d/CVE-2021-26084-Confluence-OGNL.svg) ![forks](https://img.shields.io/github/forks/z0edff0x3d/CVE-2021-26084-Confluence-OGNL.svg)

- [https://github.com/b1gw00d/CVE-2021-26084](https://github.com/b1gw00d/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/b1gw00d/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/b1gw00d/CVE-2021-26084.svg)

- [https://github.com/Xc1Ym/cve_2021_26084](https://github.com/Xc1Ym/cve_2021_26084) :  ![starts](https://img.shields.io/github/stars/Xc1Ym/cve_2021_26084.svg) ![forks](https://img.shields.io/github/forks/Xc1Ym/cve_2021_26084.svg)

- [https://github.com/dock0d1/CVE-2021-26084_Confluence](https://github.com/dock0d1/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/dock0d1/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/dock0d1/CVE-2021-26084_Confluence.svg)

- [https://github.com/wdjcy/CVE-2021-26084](https://github.com/wdjcy/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/wdjcy/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/wdjcy/CVE-2021-26084.svg)

- [https://github.com/smallpiggy/cve-2021-26084-confluence](https://github.com/smallpiggy/cve-2021-26084-confluence) :  ![starts](https://img.shields.io/github/stars/smallpiggy/cve-2021-26084-confluence.svg) ![forks](https://img.shields.io/github/forks/smallpiggy/cve-2021-26084-confluence.svg)

- [https://github.com/maskerTUI/CVE-2021-26084](https://github.com/maskerTUI/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/maskerTUI/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/maskerTUI/CVE-2021-26084.svg)

- [https://github.com/mr-r3bot/Confluence-CVE-2021-26084](https://github.com/mr-r3bot/Confluence-CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/mr-r3bot/Confluence-CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/mr-r3bot/Confluence-CVE-2021-26084.svg)

- [https://github.com/wolf1892/confluence-rce-poc](https://github.com/wolf1892/confluence-rce-poc) :  ![starts](https://img.shields.io/github/stars/wolf1892/confluence-rce-poc.svg) ![forks](https://img.shields.io/github/forks/wolf1892/confluence-rce-poc.svg)

- [https://github.com/Osyanina/westone-CVE-2021-26084-scanner](https://github.com/Osyanina/westone-CVE-2021-26084-scanner) :  ![starts](https://img.shields.io/github/stars/Osyanina/westone-CVE-2021-26084-scanner.svg) ![forks](https://img.shields.io/github/forks/Osyanina/westone-CVE-2021-26084-scanner.svg)

- [https://github.com/bcdannyboy/CVE-2021-26084_GoPOC](https://github.com/bcdannyboy/CVE-2021-26084_GoPOC) :  ![starts](https://img.shields.io/github/stars/bcdannyboy/CVE-2021-26084_GoPOC.svg) ![forks](https://img.shields.io/github/forks/bcdannyboy/CVE-2021-26084_GoPOC.svg)

- [https://github.com/quesodipesto/conflucheck](https://github.com/quesodipesto/conflucheck) :  ![starts](https://img.shields.io/github/stars/quesodipesto/conflucheck.svg) ![forks](https://img.shields.io/github/forks/quesodipesto/conflucheck.svg)

## CVE-2021-25791
 Multiple stored cross site scripting (XSS) vulnerabilities in the &quot;Update Profile&quot; module of Online Doctor Appointment System 1.0 allows authenticated attackers to execute arbitrary web scripts or HTML via crafted payloads in the First Name, Last Name, and Address text fields.



- [https://github.com/MrCraniums/CVE-2021-25791-Multiple-Stored-XSS](https://github.com/MrCraniums/CVE-2021-25791-Multiple-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/MrCraniums/CVE-2021-25791-Multiple-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/MrCraniums/CVE-2021-25791-Multiple-Stored-XSS.svg)

## CVE-2021-25790
 Multiple stored cross site scripting (XSS) vulnerabilities in the &quot;Register&quot; module of House Rental and Property Listing 1.0 allows authenticated attackers to execute arbitrary web scripts or HTML via crafted payloads in all text fields except for Phone Number and Alternate Phone Number.



- [https://github.com/MrCraniums/CVE-2021-25790-Multiple-Stored-XSS](https://github.com/MrCraniums/CVE-2021-25790-Multiple-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/MrCraniums/CVE-2021-25790-Multiple-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/MrCraniums/CVE-2021-25790-Multiple-Stored-XSS.svg)

## CVE-2021-25735
 A security issue was discovered in kube-apiserver that could allow node updates to bypass a Validating Admission Webhook. Clusters are only affected by this vulnerability if they run a Validating Admission Webhook for Nodes that denies admission based at least partially on the old state of the Node object. Validating Admission Webhook does not observe some previous fields.



- [https://github.com/darryk10/CVE-2021-25735](https://github.com/darryk10/CVE-2021-25735) :  ![starts](https://img.shields.io/github/stars/darryk10/CVE-2021-25735.svg) ![forks](https://img.shields.io/github/forks/darryk10/CVE-2021-25735.svg)

## CVE-2021-25681
 ** UNSUPPORTED WHEN ASSIGNED ** AdTran Personal Phone Manager 10.8.1 software is vulnerable to an issue that allows for exfiltration of data over DNS. This could allow for exposed AdTran Personal Phone Manager web servers to be used as DNS redirectors to tunnel arbitrary data over DNS. NOTE: The affected appliances NetVanta 7060 and NetVanta 7100 are considered End of Life and as such this issue will not be patched.



- [https://github.com/3ndG4me/AdTran-Personal-Phone-Manager-Vulns](https://github.com/3ndG4me/AdTran-Personal-Phone-Manager-Vulns) :  ![starts](https://img.shields.io/github/stars/3ndG4me/AdTran-Personal-Phone-Manager-Vulns.svg) ![forks](https://img.shields.io/github/forks/3ndG4me/AdTran-Personal-Phone-Manager-Vulns.svg)

## CVE-2021-25680
 ** UNSUPPORTED WHEN ASSIGNED ** The AdTran Personal Phone Manager software is vulnerable to multiple reflected cross-site scripting (XSS) issues. These issues impact at minimum versions 10.8.1 and below but potentially impact later versions as well since they have not previously been disclosed. Only version 10.8.1 was able to be confirmed during primary research. NOTE: The affected appliances NetVanta 7060 and NetVanta 7100 are considered End of Life and as such this issue will not be patched.



- [https://github.com/3ndG4me/AdTran-Personal-Phone-Manager-Vulns](https://github.com/3ndG4me/AdTran-Personal-Phone-Manager-Vulns) :  ![starts](https://img.shields.io/github/stars/3ndG4me/AdTran-Personal-Phone-Manager-Vulns.svg) ![forks](https://img.shields.io/github/forks/3ndG4me/AdTran-Personal-Phone-Manager-Vulns.svg)

## CVE-2021-25679
 ** UNSUPPORTED WHEN ASSIGNED ** The AdTran Personal Phone Manager software is vulnerable to an authenticated stored cross-site scripting (XSS) issues. These issues impact at minimum versions 10.8.1 and below but potentially impact later versions as well since they have not previously been disclosed. Only version 10.8.1 was able to be confirmed during primary research. NOTE: The affected appliances NetVanta 7060 and NetVanta 7100 are considered End of Life and as such this issue will not be patched.



- [https://github.com/3ndG4me/AdTran-Personal-Phone-Manager-Vulns](https://github.com/3ndG4me/AdTran-Personal-Phone-Manager-Vulns) :  ![starts](https://img.shields.io/github/stars/3ndG4me/AdTran-Personal-Phone-Manager-Vulns.svg) ![forks](https://img.shields.io/github/forks/3ndG4me/AdTran-Personal-Phone-Manager-Vulns.svg)

## CVE-2021-25646
 Apache Druid includes the ability to execute user-provided JavaScript code embedded in various types of requests. This functionality is intended for use in high-trust environments, and is disabled by default. However, in Druid 0.20.0 and earlier, it is possible for an authenticated user to send a specially-crafted request that forces Druid to run user-provided JavaScript code for that request, regardless of server configuration. This can be leveraged to execute code on the target machine with the privileges of the Druid server process.



- [https://github.com/Yang0615777/PocList](https://github.com/Yang0615777/PocList) :  ![starts](https://img.shields.io/github/stars/Yang0615777/PocList.svg) ![forks](https://img.shields.io/github/forks/Yang0615777/PocList.svg)

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)

- [https://github.com/yaunsky/cve-2021-25646](https://github.com/yaunsky/cve-2021-25646) :  ![starts](https://img.shields.io/github/stars/yaunsky/cve-2021-25646.svg) ![forks](https://img.shields.io/github/forks/yaunsky/cve-2021-25646.svg)

- [https://github.com/Vulnmachines/Apache-Druid-CVE-2021-25646](https://github.com/Vulnmachines/Apache-Druid-CVE-2021-25646) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/Apache-Druid-CVE-2021-25646.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/Apache-Druid-CVE-2021-25646.svg)

- [https://github.com/givemefivw/CVE-2021-25646](https://github.com/givemefivw/CVE-2021-25646) :  ![starts](https://img.shields.io/github/stars/givemefivw/CVE-2021-25646.svg) ![forks](https://img.shields.io/github/forks/givemefivw/CVE-2021-25646.svg)

- [https://github.com/lp008/CVE-2021-25646](https://github.com/lp008/CVE-2021-25646) :  ![starts](https://img.shields.io/github/stars/lp008/CVE-2021-25646.svg) ![forks](https://img.shields.io/github/forks/lp008/CVE-2021-25646.svg)

- [https://github.com/AirEvan/CVE-2021-25646-GUI](https://github.com/AirEvan/CVE-2021-25646-GUI) :  ![starts](https://img.shields.io/github/stars/AirEvan/CVE-2021-25646-GUI.svg) ![forks](https://img.shields.io/github/forks/AirEvan/CVE-2021-25646-GUI.svg)

- [https://github.com/j2ekim/CVE-2021-25646](https://github.com/j2ekim/CVE-2021-25646) :  ![starts](https://img.shields.io/github/stars/j2ekim/CVE-2021-25646.svg) ![forks](https://img.shields.io/github/forks/j2ekim/CVE-2021-25646.svg)

## CVE-2021-25641
 Each Apache Dubbo server will set a serialization id to tell the clients which serialization protocol it is working on. But for Dubbo versions before 2.7.8 or 2.6.9, an attacker can choose which serialization id the Provider will use by tampering with the byte preamble flags, aka, not following the server's instruction. This means that if a weak deserializer such as the Kryo and FST are somehow in code scope (e.g. if Kryo is somehow a part of a dependency), a remote unauthenticated attacker can tell the Provider to use the weak deserializer, and then proceed to exploit it.



- [https://github.com/Dor-Tumarkin/CVE-2021-25641-Proof-of-Concept](https://github.com/Dor-Tumarkin/CVE-2021-25641-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/Dor-Tumarkin/CVE-2021-25641-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/Dor-Tumarkin/CVE-2021-25641-Proof-of-Concept.svg)

## CVE-2021-25374
 An improper authorization vulnerability in Samsung Members &quot;samsungrewards&quot; scheme for deeplink in versions 2.4.83.9 in Android O(8.1) and below, and 3.9.00.9 in Android P(9.0) and above allows remote attackers to access a user data related with Samsung Account.



- [https://github.com/FSecureLABS/CVE-2021-25374_Samsung-Account-Access](https://github.com/FSecureLABS/CVE-2021-25374_Samsung-Account-Access) :  ![starts](https://img.shields.io/github/stars/FSecureLABS/CVE-2021-25374_Samsung-Account-Access.svg) ![forks](https://img.shields.io/github/forks/FSecureLABS/CVE-2021-25374_Samsung-Account-Access.svg)

## CVE-2021-25282
 An issue was discovered in through SaltStack Salt before 3002.5. The salt.wheel.pillar_roots.write method is vulnerable to directory traversal.



- [https://github.com/Immersive-Labs-Sec/CVE-2021-25281](https://github.com/Immersive-Labs-Sec/CVE-2021-25281) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/CVE-2021-25281.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/CVE-2021-25281.svg)

## CVE-2021-25281
 An issue was discovered in through SaltStack Salt before 3002.5. salt-api does not honor eauth credentials for the wheel_async client. Thus, an attacker can remotely run any wheel modules on the master.



- [https://github.com/Immersive-Labs-Sec/CVE-2021-25281](https://github.com/Immersive-Labs-Sec/CVE-2021-25281) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/CVE-2021-25281.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/CVE-2021-25281.svg)

- [https://github.com/SkyBulk/CVE-2021-25281](https://github.com/SkyBulk/CVE-2021-25281) :  ![starts](https://img.shields.io/github/stars/SkyBulk/CVE-2021-25281.svg) ![forks](https://img.shields.io/github/forks/SkyBulk/CVE-2021-25281.svg)

## CVE-2021-25251
 The Trend Micro Security 2020 and 2021 families of consumer products are vulnerable to a code injection vulnerability which could allow an attacker to disable the program's password protection and disable protection. An attacker must already have administrator privileges on the machine to exploit this vulnerability.



- [https://github.com/Parasect-Team/for-trendmciro](https://github.com/Parasect-Team/for-trendmciro) :  ![starts](https://img.shields.io/github/stars/Parasect-Team/for-trendmciro.svg) ![forks](https://img.shields.io/github/forks/Parasect-Team/for-trendmciro.svg)

## CVE-2021-25162
 A remote execution of arbitrary commands vulnerability was discovered in some Aruba Instant Access Point (IAP) products in version(s): Aruba Instant 6.4.x: 6.4.4.8-4.2.4.17 and below; Aruba Instant 6.5.x: 6.5.4.18 and below; Aruba Instant 8.3.x: 8.3.0.14 and below; Aruba Instant 8.5.x: 8.5.0.11 and below; Aruba Instant 8.6.x: 8.6.0.7 and below; Aruba Instant 8.7.x: 8.7.1.1 and below. Aruba has released patches for Aruba Instant that address this security vulnerability.



- [https://github.com/twentybel0w/CVE-2021-25162](https://github.com/twentybel0w/CVE-2021-25162) :  ![starts](https://img.shields.io/github/stars/twentybel0w/CVE-2021-25162.svg) ![forks](https://img.shields.io/github/forks/twentybel0w/CVE-2021-25162.svg)

## CVE-2021-24884
 The Formidable Form Builder WordPress plugin before 4.09.05 allows to inject certain HTML Tags like &lt;audio&gt;,&lt;video&gt;,&lt;img&gt;,&lt;a&gt; and&lt;button&gt;.This could allow an unauthenticated, remote attacker to exploit a HTML-injection byinjecting a malicous link. The HTML-injection may trick authenticated users to follow the link. If the Link gets clicked, Javascript code can be executed. The vulnerability is due to insufficient sanitization of the &quot;data-frmverify&quot; tag for links in the web-based entry inspection page of affected systems. A successful exploitation incomibantion with CSRF could allow the attacker to perform arbitrary actions on an affected system with the privileges of the user. These actions include stealing the users account by changing their password or allowing attackers to submit their own code through an authenticated user resulting in Remote Code Execution. If an authenticated user who is able to edit Wordpress PHP Code in any kind, clicks the malicious link, PHP code can be edited.



- [https://github.com/S1lkys/CVE-2021-24884](https://github.com/S1lkys/CVE-2021-24884) :  ![starts](https://img.shields.io/github/stars/S1lkys/CVE-2021-24884.svg) ![forks](https://img.shields.io/github/forks/S1lkys/CVE-2021-24884.svg)

## CVE-2021-24807
 The Support Board WordPress plugin before 3.3.5 allows Authenticated (Agent+) users to perform Cross-Site Scripting attacks by placing a payload in the notes field, when an administrator or any authenticated user go to the chat the XSS will be automatically executed.



- [https://github.com/itsjeffersonli/CVE-2021-24807](https://github.com/itsjeffersonli/CVE-2021-24807) :  ![starts](https://img.shields.io/github/stars/itsjeffersonli/CVE-2021-24807.svg) ![forks](https://img.shields.io/github/forks/itsjeffersonli/CVE-2021-24807.svg)

## CVE-2021-24741
 The Support Board WordPress plugin before 3.3.4 does not escape multiple POST parameters (such as status_code, department, user_id, conversation_id, conversation_status_code, and recipient_id) before using them in SQL statements, leading to SQL injections which are exploitable by unauthenticated users.



- [https://github.com/itsjeffersonli/CVE-2021-24741](https://github.com/itsjeffersonli/CVE-2021-24741) :  ![starts](https://img.shields.io/github/stars/itsjeffersonli/CVE-2021-24741.svg) ![forks](https://img.shields.io/github/forks/itsjeffersonli/CVE-2021-24741.svg)

## CVE-2021-24563
 The Frontend Uploader WordPress plugin through 1.3.2 does not prevent HTML files from being uploaded via its form, allowing unauthenticated user to upload a malicious HTML file containing JavaScript for example, which will be triggered when someone access the file directly



- [https://github.com/V35HR4J/CVE-2021-24563](https://github.com/V35HR4J/CVE-2021-24563) :  ![starts](https://img.shields.io/github/stars/V35HR4J/CVE-2021-24563.svg) ![forks](https://img.shields.io/github/forks/V35HR4J/CVE-2021-24563.svg)

## CVE-2021-24545
 The WP HTML Author Bio WordPress plugin through 1.2.0 does not sanitise the HTML allowed in the Bio of users, allowing them to use malicious JavaScript code, which will be executed when anyone visit a post in the frontend made by such user. As a result, user with a role as low as author could perform Cross-Site Scripting attacks against users, which could potentially lead to privilege escalation when an admin view the related post/s.



- [https://github.com/V35HR4J/CVE-2021-24545](https://github.com/V35HR4J/CVE-2021-24545) :  ![starts](https://img.shields.io/github/stars/V35HR4J/CVE-2021-24545.svg) ![forks](https://img.shields.io/github/forks/V35HR4J/CVE-2021-24545.svg)

- [https://github.com/dnr6419/CVE-2021-24545](https://github.com/dnr6419/CVE-2021-24545) :  ![starts](https://img.shields.io/github/stars/dnr6419/CVE-2021-24545.svg) ![forks](https://img.shields.io/github/forks/dnr6419/CVE-2021-24545.svg)

## CVE-2021-24499
 The Workreap WordPress theme before 2.2.2 AJAX actions workreap_award_temp_file_uploader and workreap_temp_file_uploader did not perform nonce checks, or validate that the request is from a valid user in any other way. The endpoints allowed for uploading arbitrary files to the uploads/workreap-temp directory. Uploaded files were neither sanitized nor validated, allowing an unauthenticated visitor to upload executable code such as php scripts.



- [https://github.com/RyouYoo/CVE-2021-24499](https://github.com/RyouYoo/CVE-2021-24499) :  ![starts](https://img.shields.io/github/stars/RyouYoo/CVE-2021-24499.svg) ![forks](https://img.shields.io/github/forks/RyouYoo/CVE-2021-24499.svg)

- [https://github.com/hh-hunter/cve-2021-24499](https://github.com/hh-hunter/cve-2021-24499) :  ![starts](https://img.shields.io/github/stars/hh-hunter/cve-2021-24499.svg) ![forks](https://img.shields.io/github/forks/hh-hunter/cve-2021-24499.svg)

## CVE-2021-24347
 The SP Project &amp; Document Manager WordPress plugin before 4.22 allows users to upload files, however, the plugin attempts to prevent php and other similar files that could be executed on the server from being uploaded by checking the file extension. It was discovered that php files could still be uploaded by changing the file extension's case, for example, from &quot;php&quot; to &quot;pHP&quot;.



- [https://github.com/huydoppa/CVE-2021-24347-](https://github.com/huydoppa/CVE-2021-24347-) :  ![starts](https://img.shields.io/github/stars/huydoppa/CVE-2021-24347-.svg) ![forks](https://img.shields.io/github/forks/huydoppa/CVE-2021-24347-.svg)

## CVE-2021-24155
 The WordPress Backup and Migrate Plugin &#8211; Backup Guard WordPress plugin before 1.6.0 did not ensure that the imported files are of the SGBP format and extension, allowing high privilege users (admin+) to upload arbitrary files, including PHP ones, leading to RCE.



- [https://github.com/0dayNinja/CVE-2021-24155.rb](https://github.com/0dayNinja/CVE-2021-24155.rb) :  ![starts](https://img.shields.io/github/stars/0dayNinja/CVE-2021-24155.rb.svg) ![forks](https://img.shields.io/github/forks/0dayNinja/CVE-2021-24155.rb.svg)

## CVE-2021-24145
 Arbitrary file upload in the Modern Events Calendar Lite WordPress plugin, versions before 5.16.5, did not properly check the imported file, allowing PHP ones to be uploaded by administrator by using the 'text/csv' content-type in the request.



- [https://github.com/dnr6419/CVE-2021-24145](https://github.com/dnr6419/CVE-2021-24145) :  ![starts](https://img.shields.io/github/stars/dnr6419/CVE-2021-24145.svg) ![forks](https://img.shields.io/github/forks/dnr6419/CVE-2021-24145.svg)

## CVE-2021-24098
 Windows Console Driver Denial of Service Vulnerability



- [https://github.com/waleedassar/CVE-2021-24098](https://github.com/waleedassar/CVE-2021-24098) :  ![starts](https://img.shields.io/github/stars/waleedassar/CVE-2021-24098.svg) ![forks](https://img.shields.io/github/forks/waleedassar/CVE-2021-24098.svg)

## CVE-2021-24096
 Windows Kernel Elevation of Privilege Vulnerability



- [https://github.com/FunPhishing/CVE-2021-24096](https://github.com/FunPhishing/CVE-2021-24096) :  ![starts](https://img.shields.io/github/stars/FunPhishing/CVE-2021-24096.svg) ![forks](https://img.shields.io/github/forks/FunPhishing/CVE-2021-24096.svg)

## CVE-2021-24086
 Windows TCP/IP Denial of Service Vulnerability



- [https://github.com/0vercl0k/CVE-2021-24086](https://github.com/0vercl0k/CVE-2021-24086) :  ![starts](https://img.shields.io/github/stars/0vercl0k/CVE-2021-24086.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/CVE-2021-24086.svg)

- [https://github.com/lisinan988/CVE-2021-24086-exp](https://github.com/lisinan988/CVE-2021-24086-exp) :  ![starts](https://img.shields.io/github/stars/lisinan988/CVE-2021-24086-exp.svg) ![forks](https://img.shields.io/github/forks/lisinan988/CVE-2021-24086-exp.svg)

## CVE-2021-24085
 Microsoft Exchange Server Spoofing Vulnerability This CVE ID is unique from CVE-2021-1730.



- [https://github.com/sourceincite/CVE-2021-24085](https://github.com/sourceincite/CVE-2021-24085) :  ![starts](https://img.shields.io/github/stars/sourceincite/CVE-2021-24085.svg) ![forks](https://img.shields.io/github/forks/sourceincite/CVE-2021-24085.svg)

## CVE-2021-24084
 Windows Mobile Device Management Information Disclosure Vulnerability



- [https://github.com/exploitblizzard/WindowsMDM-LPE-0Day](https://github.com/exploitblizzard/WindowsMDM-LPE-0Day) :  ![starts](https://img.shields.io/github/stars/exploitblizzard/WindowsMDM-LPE-0Day.svg) ![forks](https://img.shields.io/github/forks/exploitblizzard/WindowsMDM-LPE-0Day.svg)

- [https://github.com/ohnonoyesyes/CVE-2021-24084](https://github.com/ohnonoyesyes/CVE-2021-24084) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2021-24084.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2021-24084.svg)

## CVE-2021-24027
 A cache configuration issue prior to WhatsApp for Android v2.21.4.18 and WhatsApp Business for Android v2.21.4.18 may have allowed a third party with access to the device&#8217;s external storage to read cached TLS material.



- [https://github.com/CENSUS/whatsapp-mitd-mitm](https://github.com/CENSUS/whatsapp-mitd-mitm) :  ![starts](https://img.shields.io/github/stars/CENSUS/whatsapp-mitd-mitm.svg) ![forks](https://img.shields.io/github/forks/CENSUS/whatsapp-mitd-mitm.svg)

## CVE-2021-23758
 All versions of package ajaxpro.2 are vulnerable to Deserialization of Untrusted Data due to the possibility of deserialization of arbitrary .NET classes, which can be abused to gain remote code execution.



- [https://github.com/numanturle/CVE-2021-23758-POC](https://github.com/numanturle/CVE-2021-23758-POC) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2021-23758-POC.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2021-23758-POC.svg)

## CVE-2021-23410
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.



- [https://github.com/azu/msgpack-CVE-2021-23410-test](https://github.com/azu/msgpack-CVE-2021-23410-test) :  ![starts](https://img.shields.io/github/stars/azu/msgpack-CVE-2021-23410-test.svg) ![forks](https://img.shields.io/github/forks/azu/msgpack-CVE-2021-23410-test.svg)

## CVE-2021-23383
 The package handlebars before 4.7.7 are vulnerable to Prototype Pollution when selecting certain compiling options to compile templates coming from an untrusted source.



- [https://github.com/dn9uy3n/Check-CVE-2021-23383](https://github.com/dn9uy3n/Check-CVE-2021-23383) :  ![starts](https://img.shields.io/github/stars/dn9uy3n/Check-CVE-2021-23383.svg) ![forks](https://img.shields.io/github/forks/dn9uy3n/Check-CVE-2021-23383.svg)

## CVE-2021-23132
 An issue was discovered in Joomla! 3.0.0 through 3.9.24. com_media allowed paths that are not intended for image uploads



- [https://github.com/HoangKien1020/CVE-2021-23132](https://github.com/HoangKien1020/CVE-2021-23132) :  ![starts](https://img.shields.io/github/stars/HoangKien1020/CVE-2021-23132.svg) ![forks](https://img.shields.io/github/forks/HoangKien1020/CVE-2021-23132.svg)

- [https://github.com/CyberCommands/CVE2021-23132](https://github.com/CyberCommands/CVE2021-23132) :  ![starts](https://img.shields.io/github/stars/CyberCommands/CVE2021-23132.svg) ![forks](https://img.shields.io/github/forks/CyberCommands/CVE2021-23132.svg)

## CVE-2021-23017
 A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server to cause 1-byte memory overwrite, resulting in worker process crash or potential other impact.



- [https://github.com/niandy/nginx-patch](https://github.com/niandy/nginx-patch) :  ![starts](https://img.shields.io/github/stars/niandy/nginx-patch.svg) ![forks](https://img.shields.io/github/forks/niandy/nginx-patch.svg)

## CVE-2021-22986
 On BIG-IP versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x before 14.1.4, 13.1.x before 13.1.3.6, and 12.1.x before 12.1.5.3 amd BIG-IQ 7.1.0.x before 7.1.0.3 and 7.0.0.x before 7.0.0.2, the iControl REST interface has an unauthenticated remote command execution vulnerability. Note: Software versions which have reached End of Software Development (EoSD) are not evaluated.



- [https://github.com/Yang0615777/PocList](https://github.com/Yang0615777/PocList) :  ![starts](https://img.shields.io/github/stars/Yang0615777/PocList.svg) ![forks](https://img.shields.io/github/forks/Yang0615777/PocList.svg)

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)

- [https://github.com/Al1ex/CVE-2021-22986](https://github.com/Al1ex/CVE-2021-22986) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-22986.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-22986.svg)

- [https://github.com/dorkerdevil/CVE-2021-22986-Poc](https://github.com/dorkerdevil/CVE-2021-22986-Poc) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-22986-Poc.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-22986-Poc.svg)

- [https://github.com/S1xHcL/f5_rce_poc](https://github.com/S1xHcL/f5_rce_poc) :  ![starts](https://img.shields.io/github/stars/S1xHcL/f5_rce_poc.svg) ![forks](https://img.shields.io/github/forks/S1xHcL/f5_rce_poc.svg)

- [https://github.com/Udyz/CVE-2021-22986-SSRF2RCE](https://github.com/Udyz/CVE-2021-22986-SSRF2RCE) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2021-22986-SSRF2RCE.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2021-22986-SSRF2RCE.svg)

- [https://github.com/yaunsky/CVE-202122986-EXP](https://github.com/yaunsky/CVE-202122986-EXP) :  ![starts](https://img.shields.io/github/stars/yaunsky/CVE-202122986-EXP.svg) ![forks](https://img.shields.io/github/forks/yaunsky/CVE-202122986-EXP.svg)

- [https://github.com/Tas9er/CVE-2021-22986](https://github.com/Tas9er/CVE-2021-22986) :  ![starts](https://img.shields.io/github/stars/Tas9er/CVE-2021-22986.svg) ![forks](https://img.shields.io/github/forks/Tas9er/CVE-2021-22986.svg)

- [https://github.com/safesword/F5_RCE](https://github.com/safesword/F5_RCE) :  ![starts](https://img.shields.io/github/stars/safesword/F5_RCE.svg) ![forks](https://img.shields.io/github/forks/safesword/F5_RCE.svg)

- [https://github.com/ZephrFish/CVE-2021-22986_Check](https://github.com/ZephrFish/CVE-2021-22986_Check) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2021-22986_Check.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2021-22986_Check.svg)

- [https://github.com/adminwaf/CVE-2021-22986](https://github.com/adminwaf/CVE-2021-22986) :  ![starts](https://img.shields.io/github/stars/adminwaf/CVE-2021-22986.svg) ![forks](https://img.shields.io/github/forks/adminwaf/CVE-2021-22986.svg)

- [https://github.com/dotslashed/CVE-2021-22986](https://github.com/dotslashed/CVE-2021-22986) :  ![starts](https://img.shields.io/github/stars/dotslashed/CVE-2021-22986.svg) ![forks](https://img.shields.io/github/forks/dotslashed/CVE-2021-22986.svg)

- [https://github.com/adminwaf/CVE-2021-229861](https://github.com/adminwaf/CVE-2021-229861) :  ![starts](https://img.shields.io/github/stars/adminwaf/CVE-2021-229861.svg) ![forks](https://img.shields.io/github/forks/adminwaf/CVE-2021-229861.svg)

- [https://github.com/Osyanina/westone-CVE-2021-22986-scanner](https://github.com/Osyanina/westone-CVE-2021-22986-scanner) :  ![starts](https://img.shields.io/github/stars/Osyanina/westone-CVE-2021-22986-scanner.svg) ![forks](https://img.shields.io/github/forks/Osyanina/westone-CVE-2021-22986-scanner.svg)

## CVE-2021-22941
 Improper Access Control in Citrix ShareFile storage zones controller before 5.11.20 may allow an unauthenticated attacker to remotely compromise the storage zones controller.



- [https://github.com/hoavt184/CVE-2021-22941](https://github.com/hoavt184/CVE-2021-22941) :  ![starts](https://img.shields.io/github/stars/hoavt184/CVE-2021-22941.svg) ![forks](https://img.shields.io/github/forks/hoavt184/CVE-2021-22941.svg)

## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 &amp; 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.



- [https://github.com/CsEnox/CVE-2021-22911](https://github.com/CsEnox/CVE-2021-22911) :  ![starts](https://img.shields.io/github/stars/CsEnox/CVE-2021-22911.svg) ![forks](https://img.shields.io/github/forks/CsEnox/CVE-2021-22911.svg)

- [https://github.com/optionalCTF/Rocket.Chat-Automated-Account-Takeover-RCE-CVE-2021-22911](https://github.com/optionalCTF/Rocket.Chat-Automated-Account-Takeover-RCE-CVE-2021-22911) :  ![starts](https://img.shields.io/github/stars/optionalCTF/Rocket.Chat-Automated-Account-Takeover-RCE-CVE-2021-22911.svg) ![forks](https://img.shields.io/github/forks/optionalCTF/Rocket.Chat-Automated-Account-Takeover-RCE-CVE-2021-22911.svg)

- [https://github.com/jayngng/CVE-2021-22911](https://github.com/jayngng/CVE-2021-22911) :  ![starts](https://img.shields.io/github/stars/jayngng/CVE-2021-22911.svg) ![forks](https://img.shields.io/github/forks/jayngng/CVE-2021-22911.svg)

## CVE-2021-22893
 Pulse Connect Secure 9.0R3/9.1R1 and higher is vulnerable to an authentication bypass vulnerability exposed by the Windows File Share Browser and Pulse Secure Collaboration features of Pulse Connect Secure that can allow an unauthenticated user to perform remote arbitrary code execution on the Pulse Connect Secure gateway. This vulnerability has been exploited in the wild.



- [https://github.com/ZephrFish/CVE-2021-22893_HoneyPoC2](https://github.com/ZephrFish/CVE-2021-22893_HoneyPoC2) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2021-22893_HoneyPoC2.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2021-22893_HoneyPoC2.svg)

- [https://github.com/Mad-robot/CVE-2021-22893](https://github.com/Mad-robot/CVE-2021-22893) :  ![starts](https://img.shields.io/github/stars/Mad-robot/CVE-2021-22893.svg) ![forks](https://img.shields.io/github/forks/Mad-robot/CVE-2021-22893.svg)

- [https://github.com/onsecuredev/CVE-2021-22893](https://github.com/onsecuredev/CVE-2021-22893) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-22893.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-22893.svg)

## CVE-2021-22555
 A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c. This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name space



- [https://github.com/cgwalters/container-cve-2021-22555](https://github.com/cgwalters/container-cve-2021-22555) :  ![starts](https://img.shields.io/github/stars/cgwalters/container-cve-2021-22555.svg) ![forks](https://img.shields.io/github/forks/cgwalters/container-cve-2021-22555.svg)

- [https://github.com/JoneyJunior/cve-2021-22555](https://github.com/JoneyJunior/cve-2021-22555) :  ![starts](https://img.shields.io/github/stars/JoneyJunior/cve-2021-22555.svg) ![forks](https://img.shields.io/github/forks/JoneyJunior/cve-2021-22555.svg)

- [https://github.com/xyjl-ly/CVE-2021-22555-Exploit](https://github.com/xyjl-ly/CVE-2021-22555-Exploit) :  ![starts](https://img.shields.io/github/stars/xyjl-ly/CVE-2021-22555-Exploit.svg) ![forks](https://img.shields.io/github/forks/xyjl-ly/CVE-2021-22555-Exploit.svg)

- [https://github.com/daletoniris/CVE-2021-22555-esc-priv](https://github.com/daletoniris/CVE-2021-22555-esc-priv) :  ![starts](https://img.shields.io/github/stars/daletoniris/CVE-2021-22555-esc-priv.svg) ![forks](https://img.shields.io/github/forks/daletoniris/CVE-2021-22555-esc-priv.svg)

## CVE-2021-22214
 When requests to the internal network for webhooks are enabled, a server-side request forgery vulnerability in GitLab CE/EE affecting all versions starting from 10.5 was possible to exploit for an unauthenticated attacker even on a GitLab instance where registration is limited



- [https://github.com/r0ckysec/CVE-2021-22214](https://github.com/r0ckysec/CVE-2021-22214) :  ![starts](https://img.shields.io/github/stars/r0ckysec/CVE-2021-22214.svg) ![forks](https://img.shields.io/github/forks/r0ckysec/CVE-2021-22214.svg)

- [https://github.com/antx-code/CVE-2021-22214](https://github.com/antx-code/CVE-2021-22214) :  ![starts](https://img.shields.io/github/stars/antx-code/CVE-2021-22214.svg) ![forks](https://img.shields.io/github/forks/antx-code/CVE-2021-22214.svg)

- [https://github.com/Vulnmachines/gitlab-cve-2021-22214](https://github.com/Vulnmachines/gitlab-cve-2021-22214) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/gitlab-cve-2021-22214.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/gitlab-cve-2021-22214.svg)

## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.



- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)

- [https://github.com/mr-r3bot/Gitlab-CVE-2021-22205](https://github.com/mr-r3bot/Gitlab-CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/mr-r3bot/Gitlab-CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/mr-r3bot/Gitlab-CVE-2021-22205.svg)

- [https://github.com/Al1ex/CVE-2021-22205](https://github.com/Al1ex/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-22205.svg)

- [https://github.com/inspiringz/CVE-2021-22205](https://github.com/inspiringz/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/inspiringz/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/inspiringz/CVE-2021-22205.svg)

- [https://github.com/XTeam-Wing/CVE-2021-22205](https://github.com/XTeam-Wing/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/XTeam-Wing/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/XTeam-Wing/CVE-2021-22205.svg)

- [https://github.com/r0eXpeR/CVE-2021-22205](https://github.com/r0eXpeR/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/r0eXpeR/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/r0eXpeR/CVE-2021-22205.svg)

- [https://github.com/Seals6/CVE-2021-22205](https://github.com/Seals6/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/Seals6/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/Seals6/CVE-2021-22205.svg)

- [https://github.com/whwlsfb/CVE-2021-22205](https://github.com/whwlsfb/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/whwlsfb/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/whwlsfb/CVE-2021-22205.svg)

- [https://github.com/c0okB/CVE-2021-22205](https://github.com/c0okB/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/c0okB/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/c0okB/CVE-2021-22205.svg)

- [https://github.com/faisalfs10x/GitLab-CVE-2021-22205-scanner](https://github.com/faisalfs10x/GitLab-CVE-2021-22205-scanner) :  ![starts](https://img.shields.io/github/stars/faisalfs10x/GitLab-CVE-2021-22205-scanner.svg) ![forks](https://img.shields.io/github/forks/faisalfs10x/GitLab-CVE-2021-22205-scanner.svg)

- [https://github.com/shang159/CVE-2021-22205-getshell](https://github.com/shang159/CVE-2021-22205-getshell) :  ![starts](https://img.shields.io/github/stars/shang159/CVE-2021-22205-getshell.svg) ![forks](https://img.shields.io/github/forks/shang159/CVE-2021-22205-getshell.svg)

- [https://github.com/ahmad4fifz/CVE-2021-22205](https://github.com/ahmad4fifz/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/ahmad4fifz/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/ahmad4fifz/CVE-2021-22205.svg)

- [https://github.com/antx-code/CVE-2021-22205](https://github.com/antx-code/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/antx-code/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/antx-code/CVE-2021-22205.svg)

- [https://github.com/pizza-power/Golang-CVE-2021-22205-POC](https://github.com/pizza-power/Golang-CVE-2021-22205-POC) :  ![starts](https://img.shields.io/github/stars/pizza-power/Golang-CVE-2021-22205-POC.svg) ![forks](https://img.shields.io/github/forks/pizza-power/Golang-CVE-2021-22205-POC.svg)

- [https://github.com/findneo/GitLab-preauth-RCE_CVE-2021-22205](https://github.com/findneo/GitLab-preauth-RCE_CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/findneo/GitLab-preauth-RCE_CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/findneo/GitLab-preauth-RCE_CVE-2021-22205.svg)

- [https://github.com/runsel/GitLab-CVE-2021-22205-](https://github.com/runsel/GitLab-CVE-2021-22205-) :  ![starts](https://img.shields.io/github/stars/runsel/GitLab-CVE-2021-22205-.svg) ![forks](https://img.shields.io/github/forks/runsel/GitLab-CVE-2021-22205-.svg)

- [https://github.com/X1pe0/Automated-Gitlab-RCE](https://github.com/X1pe0/Automated-Gitlab-RCE) :  ![starts](https://img.shields.io/github/stars/X1pe0/Automated-Gitlab-RCE.svg) ![forks](https://img.shields.io/github/forks/X1pe0/Automated-Gitlab-RCE.svg)

- [https://github.com/devdanqtuan/CVE-2021-22205](https://github.com/devdanqtuan/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/devdanqtuan/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/devdanqtuan/CVE-2021-22205.svg)

- [https://github.com/AkBanner/CVE-2021-22205](https://github.com/AkBanner/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/AkBanner/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/AkBanner/CVE-2021-22205.svg)

- [https://github.com/hh-hunter/cve-2021-22205](https://github.com/hh-hunter/cve-2021-22205) :  ![starts](https://img.shields.io/github/stars/hh-hunter/cve-2021-22205.svg) ![forks](https://img.shields.io/github/forks/hh-hunter/cve-2021-22205.svg)

- [https://github.com/Qclover/Gitlab_RCE_CVE_2021_22205](https://github.com/Qclover/Gitlab_RCE_CVE_2021_22205) :  ![starts](https://img.shields.io/github/stars/Qclover/Gitlab_RCE_CVE_2021_22205.svg) ![forks](https://img.shields.io/github/forks/Qclover/Gitlab_RCE_CVE_2021_22205.svg)

## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image



- [https://github.com/convisolabs/CVE-2021-22204-exiftool](https://github.com/convisolabs/CVE-2021-22204-exiftool) :  ![starts](https://img.shields.io/github/stars/convisolabs/CVE-2021-22204-exiftool.svg) ![forks](https://img.shields.io/github/forks/convisolabs/CVE-2021-22204-exiftool.svg)

- [https://github.com/se162xg/CVE-2021-22204](https://github.com/se162xg/CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/se162xg/CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/se162xg/CVE-2021-22204.svg)

- [https://github.com/PenTestical/CVE-2021-22204](https://github.com/PenTestical/CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/PenTestical/CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/PenTestical/CVE-2021-22204.svg)

- [https://github.com/bilkoh/POC-CVE-2021-22204](https://github.com/bilkoh/POC-CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/bilkoh/POC-CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/bilkoh/POC-CVE-2021-22204.svg)

- [https://github.com/AssassinUKG/CVE-2021-22204](https://github.com/AssassinUKG/CVE-2021-22204) :  ![starts](https://img.shields.io/github/stars/AssassinUKG/CVE-2021-22204.svg) ![forks](https://img.shields.io/github/forks/AssassinUKG/CVE-2021-22204.svg)

- [https://github.com/Konstantinos-Papanagnou/CMSpit](https://github.com/Konstantinos-Papanagnou/CMSpit) :  ![starts](https://img.shields.io/github/stars/Konstantinos-Papanagnou/CMSpit.svg) ![forks](https://img.shields.io/github/forks/Konstantinos-Papanagnou/CMSpit.svg)

- [https://github.com/ph-arm/CVE-2021-22204-Gitlab](https://github.com/ph-arm/CVE-2021-22204-Gitlab) :  ![starts](https://img.shields.io/github/stars/ph-arm/CVE-2021-22204-Gitlab.svg) ![forks](https://img.shields.io/github/forks/ph-arm/CVE-2021-22204-Gitlab.svg)

- [https://github.com/Asaad27/CVE-2021-22204-RSE](https://github.com/Asaad27/CVE-2021-22204-RSE) :  ![starts](https://img.shields.io/github/stars/Asaad27/CVE-2021-22204-RSE.svg) ![forks](https://img.shields.io/github/forks/Asaad27/CVE-2021-22204-RSE.svg)

## CVE-2021-22201
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.9. A specially crafted import file could read files on the server.



- [https://github.com/exp1orer/CVE-2021-22201](https://github.com/exp1orer/CVE-2021-22201) :  ![starts](https://img.shields.io/github/stars/exp1orer/CVE-2021-22201.svg) ![forks](https://img.shields.io/github/forks/exp1orer/CVE-2021-22201.svg)

## CVE-2021-22192
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.2 allowing unauthorized authenticated users to execute arbitrary code on the server.



- [https://github.com/lyy289065406/CVE-2021-22192](https://github.com/lyy289065406/CVE-2021-22192) :  ![starts](https://img.shields.io/github/stars/lyy289065406/CVE-2021-22192.svg) ![forks](https://img.shields.io/github/forks/lyy289065406/CVE-2021-22192.svg)

- [https://github.com/PetrusViet/Gitlab-RCE](https://github.com/PetrusViet/Gitlab-RCE) :  ![starts](https://img.shields.io/github/stars/PetrusViet/Gitlab-RCE.svg) ![forks](https://img.shields.io/github/forks/PetrusViet/Gitlab-RCE.svg)

## CVE-2021-22146
 All versions of Elastic Cloud Enterprise has the Elasticsearch &#8220;anonymous&#8221; user enabled by default in deployed clusters. While in the default setting the anonymous user has no permissions and is unable to successfully query any Elasticsearch APIs, an attacker could leverage the anonymous user to gain insight into certain details of a deployed cluster.



- [https://github.com/magichk/cve-2021-22146](https://github.com/magichk/cve-2021-22146) :  ![starts](https://img.shields.io/github/stars/magichk/cve-2021-22146.svg) ![forks](https://img.shields.io/github/forks/magichk/cve-2021-22146.svg)

## CVE-2021-22123
 An OS command injection vulnerability in FortiWeb's management interface 6.3.7 and below, 6.2.3 and below, 6.1.x, 6.0.x, 5.9.x may allow a remote authenticated attacker to execute arbitrary commands on the system via the SAML server configuration page.



- [https://github.com/murataydemir/CVE-2021-22123](https://github.com/murataydemir/CVE-2021-22123) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2021-22123.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2021-22123.svg)

## CVE-2021-22119
 Spring Security versions 5.5.x prior to 5.5.1, 5.4.x prior to 5.4.7, 5.3.x prior to 5.3.10 and 5.2.x prior to 5.2.11 are susceptible to a Denial-of-Service (DoS) attack via the initiation of the Authorization Request in an OAuth 2.0 Client Web and WebFlux application. A malicious user or attacker can send multiple requests initiating the Authorization Request for the Authorization Code Grant, which has the potential of exhausting system resources using a single session or multiple sessions.



- [https://github.com/mari6274/oauth-client-exploit](https://github.com/mari6274/oauth-client-exploit) :  ![starts](https://img.shields.io/github/stars/mari6274/oauth-client-exploit.svg) ![forks](https://img.shields.io/github/forks/mari6274/oauth-client-exploit.svg)

## CVE-2021-22053
 Applications using both `spring-cloud-netflix-hystrix-dashboard` and `spring-boot-starter-thymeleaf` expose a way to execute code submitted within the request URI path during the resolution of view templates. When a request is made at `/hystrix/monitor;[user-provided data]`, the path elements following `hystrix/monitor` are being evaluated as SpringEL expressions, which can lead to code execution.



- [https://github.com/SecCoder-Security-Lab/spring-cloud-netflix-hystrix-dashboard-cve-2021-22053](https://github.com/SecCoder-Security-Lab/spring-cloud-netflix-hystrix-dashboard-cve-2021-22053) :  ![starts](https://img.shields.io/github/stars/SecCoder-Security-Lab/spring-cloud-netflix-hystrix-dashboard-cve-2021-22053.svg) ![forks](https://img.shields.io/github/forks/SecCoder-Security-Lab/spring-cloud-netflix-hystrix-dashboard-cve-2021-22053.svg)

- [https://github.com/Vulnmachines/CVE-2021-22053](https://github.com/Vulnmachines/CVE-2021-22053) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/CVE-2021-22053.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/CVE-2021-22053.svg)

## CVE-2021-22015
 The vCenter Server contains multiple local privilege escalation vulnerabilities due to improper permissions of files and directories. An authenticated local user with non-administrative privilege may exploit these issues to elevate their privileges to root on vCenter Server Appliance.



- [https://github.com/PenteraIO/vScalation-CVE-2021-22015](https://github.com/PenteraIO/vScalation-CVE-2021-22015) :  ![starts](https://img.shields.io/github/stars/PenteraIO/vScalation-CVE-2021-22015.svg) ![forks](https://img.shields.io/github/forks/PenteraIO/vScalation-CVE-2021-22015.svg)

## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.



- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)

- [https://github.com/r0ckysec/CVE-2021-22005](https://github.com/r0ckysec/CVE-2021-22005) :  ![starts](https://img.shields.io/github/stars/r0ckysec/CVE-2021-22005.svg) ![forks](https://img.shields.io/github/forks/r0ckysec/CVE-2021-22005.svg)

- [https://github.com/TaroballzChen/CVE-2021-22005-metasploit](https://github.com/TaroballzChen/CVE-2021-22005-metasploit) :  ![starts](https://img.shields.io/github/stars/TaroballzChen/CVE-2021-22005-metasploit.svg) ![forks](https://img.shields.io/github/forks/TaroballzChen/CVE-2021-22005-metasploit.svg)

- [https://github.com/rwincey/CVE-2021-22005](https://github.com/rwincey/CVE-2021-22005) :  ![starts](https://img.shields.io/github/stars/rwincey/CVE-2021-22005.svg) ![forks](https://img.shields.io/github/forks/rwincey/CVE-2021-22005.svg)

- [https://github.com/5gstudent/CVE-2021-22005-](https://github.com/5gstudent/CVE-2021-22005-) :  ![starts](https://img.shields.io/github/stars/5gstudent/CVE-2021-22005-.svg) ![forks](https://img.shields.io/github/forks/5gstudent/CVE-2021-22005-.svg)

- [https://github.com/1ZRR4H/CVE-2021-22005](https://github.com/1ZRR4H/CVE-2021-22005) :  ![starts](https://img.shields.io/github/stars/1ZRR4H/CVE-2021-22005.svg) ![forks](https://img.shields.io/github/forks/1ZRR4H/CVE-2021-22005.svg)

- [https://github.com/X1pe0/VMWare-CVE-Check](https://github.com/X1pe0/VMWare-CVE-Check) :  ![starts](https://img.shields.io/github/stars/X1pe0/VMWare-CVE-Check.svg) ![forks](https://img.shields.io/github/forks/X1pe0/VMWare-CVE-Check.svg)

- [https://github.com/TheTh1nk3r/exp_hub](https://github.com/TheTh1nk3r/exp_hub) :  ![starts](https://img.shields.io/github/stars/TheTh1nk3r/exp_hub.svg) ![forks](https://img.shields.io/github/forks/TheTh1nk3r/exp_hub.svg)

- [https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-22005-scanning-activity](https://github.com/pisut4152/Sigma-Rule-for-CVE-2021-22005-scanning-activity) :  ![starts](https://img.shields.io/github/stars/pisut4152/Sigma-Rule-for-CVE-2021-22005-scanning-activity.svg) ![forks](https://img.shields.io/github/forks/pisut4152/Sigma-Rule-for-CVE-2021-22005-scanning-activity.svg)

- [https://github.com/RedTeamExp/CVE-2021-22005_PoC](https://github.com/RedTeamExp/CVE-2021-22005_PoC) :  ![starts](https://img.shields.io/github/stars/RedTeamExp/CVE-2021-22005_PoC.svg) ![forks](https://img.shields.io/github/forks/RedTeamExp/CVE-2021-22005_PoC.svg)

- [https://github.com/Jun-5heng/CVE-2021-22005](https://github.com/Jun-5heng/CVE-2021-22005) :  ![starts](https://img.shields.io/github/stars/Jun-5heng/CVE-2021-22005.svg) ![forks](https://img.shields.io/github/forks/Jun-5heng/CVE-2021-22005.svg)

- [https://github.com/TiagoSergio/CVE-2021-22005](https://github.com/TiagoSergio/CVE-2021-22005) :  ![starts](https://img.shields.io/github/stars/TiagoSergio/CVE-2021-22005.svg) ![forks](https://img.shields.io/github/forks/TiagoSergio/CVE-2021-22005.svg)

- [https://github.com/shmilylty/cve-2021-22005-exp](https://github.com/shmilylty/cve-2021-22005-exp) :  ![starts](https://img.shields.io/github/stars/shmilylty/cve-2021-22005-exp.svg) ![forks](https://img.shields.io/github/forks/shmilylty/cve-2021-22005-exp.svg)

## CVE-2021-21985
 The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.



- [https://github.com/r0ckysec/CVE-2021-21985](https://github.com/r0ckysec/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/r0ckysec/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/r0ckysec/CVE-2021-21985.svg)

- [https://github.com/alt3kx/CVE-2021-21985_PoC](https://github.com/alt3kx/CVE-2021-21985_PoC) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2021-21985_PoC.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2021-21985_PoC.svg)

- [https://github.com/xnianq/cve-2021-21985_exp](https://github.com/xnianq/cve-2021-21985_exp) :  ![starts](https://img.shields.io/github/stars/xnianq/cve-2021-21985_exp.svg) ![forks](https://img.shields.io/github/forks/xnianq/cve-2021-21985_exp.svg)

- [https://github.com/testanull/Project_CVE-2021-21985_PoC](https://github.com/testanull/Project_CVE-2021-21985_PoC) :  ![starts](https://img.shields.io/github/stars/testanull/Project_CVE-2021-21985_PoC.svg) ![forks](https://img.shields.io/github/forks/testanull/Project_CVE-2021-21985_PoC.svg)

- [https://github.com/sknux/CVE-2021-21985_PoC](https://github.com/sknux/CVE-2021-21985_PoC) :  ![starts](https://img.shields.io/github/stars/sknux/CVE-2021-21985_PoC.svg) ![forks](https://img.shields.io/github/forks/sknux/CVE-2021-21985_PoC.svg)

- [https://github.com/daedalus/CVE-2021-21985](https://github.com/daedalus/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/daedalus/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/daedalus/CVE-2021-21985.svg)

- [https://github.com/onSec-fr/CVE-2021-21985-Checker](https://github.com/onSec-fr/CVE-2021-21985-Checker) :  ![starts](https://img.shields.io/github/stars/onSec-fr/CVE-2021-21985-Checker.svg) ![forks](https://img.shields.io/github/forks/onSec-fr/CVE-2021-21985-Checker.svg)

- [https://github.com/bigbroke/CVE-2021-21985](https://github.com/bigbroke/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/bigbroke/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/bigbroke/CVE-2021-21985.svg)

- [https://github.com/mauricelambert/CVE-2021-21985](https://github.com/mauricelambert/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/mauricelambert/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/mauricelambert/CVE-2021-21985.svg)

- [https://github.com/aristosMiliaressis/CVE-2021-21985](https://github.com/aristosMiliaressis/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/aristosMiliaressis/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/aristosMiliaressis/CVE-2021-21985.svg)

- [https://github.com/haiclover/CVE-2021-21985](https://github.com/haiclover/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/haiclover/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/haiclover/CVE-2021-21985.svg)

## CVE-2021-21983
 Arbitrary file write vulnerability in vRealize Operations Manager API (CVE-2021-21983) prior to 8.4 may allow an authenticated malicious actor with network access to the vRealize Operations Manager API can write files to arbitrary locations on the underlying photon operating system.



- [https://github.com/rabidwh0re/REALITY_SMASHER](https://github.com/rabidwh0re/REALITY_SMASHER) :  ![starts](https://img.shields.io/github/stars/rabidwh0re/REALITY_SMASHER.svg) ![forks](https://img.shields.io/github/forks/rabidwh0re/REALITY_SMASHER.svg)

## CVE-2021-21980
 The vSphere Web Client (FLEX/Flash) contains an unauthorized arbitrary file read vulnerability. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to gain access to sensitive information.



- [https://github.com/Osyanina/westone-CVE-2021-21980-scanner](https://github.com/Osyanina/westone-CVE-2021-21980-scanner) :  ![starts](https://img.shields.io/github/stars/Osyanina/westone-CVE-2021-21980-scanner.svg) ![forks](https://img.shields.io/github/forks/Osyanina/westone-CVE-2021-21980-scanner.svg)

## CVE-2021-21978
 VMware View Planner 4.x prior to 4.6 Security Patch 1 contains a remote code execution vulnerability. Improper input validation and lack of authorization leading to arbitrary file upload in logupload web application. An unauthorized attacker with network access to View Planner Harness could upload and execute a specially crafted file leading to remote code execution within the logupload container.



- [https://github.com/skytina/CVE-2021-21978](https://github.com/skytina/CVE-2021-21978) :  ![starts](https://img.shields.io/github/stars/skytina/CVE-2021-21978.svg) ![forks](https://img.shields.io/github/forks/skytina/CVE-2021-21978.svg)

- [https://github.com/GreyOrder/CVE-2021-21978](https://github.com/GreyOrder/CVE-2021-21978) :  ![starts](https://img.shields.io/github/stars/GreyOrder/CVE-2021-21978.svg) ![forks](https://img.shields.io/github/forks/GreyOrder/CVE-2021-21978.svg)

- [https://github.com/me1ons/CVE-2021-21978](https://github.com/me1ons/CVE-2021-21978) :  ![starts](https://img.shields.io/github/stars/me1ons/CVE-2021-21978.svg) ![forks](https://img.shields.io/github/forks/me1ons/CVE-2021-21978.svg)

## CVE-2021-21975
 Server Side Request Forgery in vRealize Operations Manager API (CVE-2021-21975) prior to 8.4 may allow a malicious actor with network access to the vRealize Operations Manager API can perform a Server Side Request Forgery attack to steal administrative credentials.



- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)

- [https://github.com/rabidwh0re/REALITY_SMASHER](https://github.com/rabidwh0re/REALITY_SMASHER) :  ![starts](https://img.shields.io/github/stars/rabidwh0re/REALITY_SMASHER.svg) ![forks](https://img.shields.io/github/forks/rabidwh0re/REALITY_SMASHER.svg)

- [https://github.com/GuayoyoCyber/CVE-2021-21975](https://github.com/GuayoyoCyber/CVE-2021-21975) :  ![starts](https://img.shields.io/github/stars/GuayoyoCyber/CVE-2021-21975.svg) ![forks](https://img.shields.io/github/forks/GuayoyoCyber/CVE-2021-21975.svg)

- [https://github.com/Henry4E36/VMWare-vRealize-SSRF](https://github.com/Henry4E36/VMWare-vRealize-SSRF) :  ![starts](https://img.shields.io/github/stars/Henry4E36/VMWare-vRealize-SSRF.svg) ![forks](https://img.shields.io/github/forks/Henry4E36/VMWare-vRealize-SSRF.svg)

- [https://github.com/Al1ex/CVE-2021-21975](https://github.com/Al1ex/CVE-2021-21975) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-21975.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-21975.svg)

- [https://github.com/Vulnmachines/VMWare-CVE-2021-21975](https://github.com/Vulnmachines/VMWare-CVE-2021-21975) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/VMWare-CVE-2021-21975.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/VMWare-CVE-2021-21975.svg)

- [https://github.com/TheTh1nk3r/exp_hub](https://github.com/TheTh1nk3r/exp_hub) :  ![starts](https://img.shields.io/github/stars/TheTh1nk3r/exp_hub.svg) ![forks](https://img.shields.io/github/forks/TheTh1nk3r/exp_hub.svg)

- [https://github.com/dorkerdevil/CVE-2021-21975](https://github.com/dorkerdevil/CVE-2021-21975) :  ![starts](https://img.shields.io/github/stars/dorkerdevil/CVE-2021-21975.svg) ![forks](https://img.shields.io/github/forks/dorkerdevil/CVE-2021-21975.svg)

- [https://github.com/murataydemir/CVE-2021-21975](https://github.com/murataydemir/CVE-2021-21975) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2021-21975.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2021-21975.svg)

- [https://github.com/CyberCommands/CVE2021-21975](https://github.com/CyberCommands/CVE2021-21975) :  ![starts](https://img.shields.io/github/stars/CyberCommands/CVE2021-21975.svg) ![forks](https://img.shields.io/github/forks/CyberCommands/CVE2021-21975.svg)

## CVE-2021-21974
 OpenSLP as used in ESXi (7.0 before ESXi70U1c-17325551, 6.7 before ESXi670-202102401-SG, 6.5 before ESXi650-202102101-SG) has a heap-overflow vulnerability. A malicious actor residing within the same network segment as ESXi who has access to port 427 may be able to trigger the heap-overflow issue in OpenSLP service resulting in remote code execution.



- [https://github.com/Shadow0ps/CVE-2021-21974](https://github.com/Shadow0ps/CVE-2021-21974) :  ![starts](https://img.shields.io/github/stars/Shadow0ps/CVE-2021-21974.svg) ![forks](https://img.shields.io/github/forks/Shadow0ps/CVE-2021-21974.svg)

## CVE-2021-21973
 The vSphere Client (HTML5) contains an SSRF (Server Side Request Forgery) vulnerability due to improper validation of URLs in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue by sending a POST request to vCenter Server plugin leading to information disclosure. This affects: VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).



- [https://github.com/freakanonymous/CVE-2021-21973-Automateme](https://github.com/freakanonymous/CVE-2021-21973-Automateme) :  ![starts](https://img.shields.io/github/stars/freakanonymous/CVE-2021-21973-Automateme.svg) ![forks](https://img.shields.io/github/forks/freakanonymous/CVE-2021-21973-Automateme.svg)

## CVE-2021-21972
 The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).



- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)

- [https://github.com/NS-Sp4ce/CVE-2021-21972](https://github.com/NS-Sp4ce/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/NS-Sp4ce/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/NS-Sp4ce/CVE-2021-21972.svg)

- [https://github.com/horizon3ai/CVE-2021-21972](https://github.com/horizon3ai/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2021-21972.svg)

- [https://github.com/QmF0c3UK/CVE-2021-21972-vCenter-6.5-7.0-RCE-POC](https://github.com/QmF0c3UK/CVE-2021-21972-vCenter-6.5-7.0-RCE-POC) :  ![starts](https://img.shields.io/github/stars/QmF0c3UK/CVE-2021-21972-vCenter-6.5-7.0-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/QmF0c3UK/CVE-2021-21972-vCenter-6.5-7.0-RCE-POC.svg)

- [https://github.com/psc4re/NSE-scripts](https://github.com/psc4re/NSE-scripts) :  ![starts](https://img.shields.io/github/stars/psc4re/NSE-scripts.svg) ![forks](https://img.shields.io/github/forks/psc4re/NSE-scripts.svg)

- [https://github.com/alt3kx/CVE-2021-21972](https://github.com/alt3kx/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2021-21972.svg)

- [https://github.com/milo2012/CVE-2021-21972](https://github.com/milo2012/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/milo2012/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/milo2012/CVE-2021-21972.svg)

- [https://github.com/GuayoyoCyber/CVE-2021-21972](https://github.com/GuayoyoCyber/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/GuayoyoCyber/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/GuayoyoCyber/CVE-2021-21972.svg)

- [https://github.com/conjojo/VMware_vCenter_UNAuthorized_RCE_CVE-2021-21972](https://github.com/conjojo/VMware_vCenter_UNAuthorized_RCE_CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/conjojo/VMware_vCenter_UNAuthorized_RCE_CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/conjojo/VMware_vCenter_UNAuthorized_RCE_CVE-2021-21972.svg)

- [https://github.com/TaroballzChen/CVE-2021-21972](https://github.com/TaroballzChen/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/TaroballzChen/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/TaroballzChen/CVE-2021-21972.svg)

- [https://github.com/onsecuredev/CVE-2021-21972](https://github.com/onsecuredev/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-21972.svg)

- [https://github.com/yaunsky/CVE-2021-21972](https://github.com/yaunsky/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/yaunsky/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/yaunsky/CVE-2021-21972.svg)

- [https://github.com/B1anda0/CVE-2021-21972](https://github.com/B1anda0/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/B1anda0/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/B1anda0/CVE-2021-21972.svg)

- [https://github.com/Udyz/CVE-2021-21972](https://github.com/Udyz/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2021-21972.svg)

- [https://github.com/ByZain/CVE-2021-21972](https://github.com/ByZain/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/ByZain/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/ByZain/CVE-2021-21972.svg)

- [https://github.com/Ma1Dong/vcenter_rce](https://github.com/Ma1Dong/vcenter_rce) :  ![starts](https://img.shields.io/github/stars/Ma1Dong/vcenter_rce.svg) ![forks](https://img.shields.io/github/forks/Ma1Dong/vcenter_rce.svg)

- [https://github.com/renini/CVE-2021-21972](https://github.com/renini/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/renini/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/renini/CVE-2021-21972.svg)

- [https://github.com/haiclover/CVE-2021-21972](https://github.com/haiclover/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/haiclover/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/haiclover/CVE-2021-21972.svg)

- [https://github.com/murataydemir/CVE-2021-21972](https://github.com/murataydemir/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2021-21972.svg)

- [https://github.com/L-pin/CVE-2021-21972](https://github.com/L-pin/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/L-pin/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/L-pin/CVE-2021-21972.svg)

- [https://github.com/pettyhacks/vSphereyeeter](https://github.com/pettyhacks/vSphereyeeter) :  ![starts](https://img.shields.io/github/stars/pettyhacks/vSphereyeeter.svg) ![forks](https://img.shields.io/github/forks/pettyhacks/vSphereyeeter.svg)

- [https://github.com/Osyanina/westone-CVE-2021-21972-scanner](https://github.com/Osyanina/westone-CVE-2021-21972-scanner) :  ![starts](https://img.shields.io/github/stars/Osyanina/westone-CVE-2021-21972-scanner.svg) ![forks](https://img.shields.io/github/forks/Osyanina/westone-CVE-2021-21972-scanner.svg)

- [https://github.com/d3sh1n/cve-2021-21972](https://github.com/d3sh1n/cve-2021-21972) :  ![starts](https://img.shields.io/github/stars/d3sh1n/cve-2021-21972.svg) ![forks](https://img.shields.io/github/forks/d3sh1n/cve-2021-21972.svg)

- [https://github.com/DougCarroll/CVE_2021_21972](https://github.com/DougCarroll/CVE_2021_21972) :  ![starts](https://img.shields.io/github/stars/DougCarroll/CVE_2021_21972.svg) ![forks](https://img.shields.io/github/forks/DougCarroll/CVE_2021_21972.svg)

- [https://github.com/stevenp322/cve-2021-21972](https://github.com/stevenp322/cve-2021-21972) :  ![starts](https://img.shields.io/github/stars/stevenp322/cve-2021-21972.svg) ![forks](https://img.shields.io/github/forks/stevenp322/cve-2021-21972.svg)

- [https://github.com/password520/CVE-2021-21972](https://github.com/password520/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/password520/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/password520/CVE-2021-21972.svg)

- [https://github.com/robwillisinfo/VMware_vCenter_CVE-2021-21972](https://github.com/robwillisinfo/VMware_vCenter_CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/robwillisinfo/VMware_vCenter_CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/robwillisinfo/VMware_vCenter_CVE-2021-21972.svg)

- [https://github.com/JMousqueton/Detect-CVE-2021-21972](https://github.com/JMousqueton/Detect-CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/JMousqueton/Detect-CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/JMousqueton/Detect-CVE-2021-21972.svg)

## CVE-2021-21551
 Dell dbutil_2_3.sys driver contains an insufficient access control vulnerability which may lead to escalation of privileges, denial of service, or information disclosure. Local authenticated user access is required.



- [https://github.com/waldo-irc/CVE-2021-21551](https://github.com/waldo-irc/CVE-2021-21551) :  ![starts](https://img.shields.io/github/stars/waldo-irc/CVE-2021-21551.svg) ![forks](https://img.shields.io/github/forks/waldo-irc/CVE-2021-21551.svg)

- [https://github.com/mathisvickie/CVE-2021-21551](https://github.com/mathisvickie/CVE-2021-21551) :  ![starts](https://img.shields.io/github/stars/mathisvickie/CVE-2021-21551.svg) ![forks](https://img.shields.io/github/forks/mathisvickie/CVE-2021-21551.svg)

- [https://github.com/ihack4falafel/Dell-Driver-EoP-CVE-2021-21551](https://github.com/ihack4falafel/Dell-Driver-EoP-CVE-2021-21551) :  ![starts](https://img.shields.io/github/stars/ihack4falafel/Dell-Driver-EoP-CVE-2021-21551.svg) ![forks](https://img.shields.io/github/forks/ihack4falafel/Dell-Driver-EoP-CVE-2021-21551.svg)

- [https://github.com/ch3rn0byl/CVE-2021-21551](https://github.com/ch3rn0byl/CVE-2021-21551) :  ![starts](https://img.shields.io/github/stars/ch3rn0byl/CVE-2021-21551.svg) ![forks](https://img.shields.io/github/forks/ch3rn0byl/CVE-2021-21551.svg)

- [https://github.com/mzakocs/CVE-2021-21551-POC](https://github.com/mzakocs/CVE-2021-21551-POC) :  ![starts](https://img.shields.io/github/stars/mzakocs/CVE-2021-21551-POC.svg) ![forks](https://img.shields.io/github/forks/mzakocs/CVE-2021-21551-POC.svg)

- [https://github.com/arnaudluti/PS-CVE-2021-21551](https://github.com/arnaudluti/PS-CVE-2021-21551) :  ![starts](https://img.shields.io/github/stars/arnaudluti/PS-CVE-2021-21551.svg) ![forks](https://img.shields.io/github/forks/arnaudluti/PS-CVE-2021-21551.svg)

- [https://github.com/Kinsiinoo/PoshDellDBUtil](https://github.com/Kinsiinoo/PoshDellDBUtil) :  ![starts](https://img.shields.io/github/stars/Kinsiinoo/PoshDellDBUtil.svg) ![forks](https://img.shields.io/github/forks/Kinsiinoo/PoshDellDBUtil.svg)

## CVE-2021-21425
 Grav Admin Plugin is an HTML user interface that provides a way to configure Grav and create and modify pages. In versions 1.10.7 and earlier, an unauthenticated user can execute some methods of administrator controller without needing any credentials. Particular method execution will result in arbitrary YAML file creation or content change of existing YAML files on the system. Successfully exploitation of that vulnerability results in configuration changes, such as general site information change, custom scheduler job definition, etc. Due to the nature of the vulnerability, an adversary can change some part of the webpage, or hijack an administrator account, or execute operating system command under the context of the web-server user. This vulnerability is fixed in version 1.10.8. Blocking access to the `/admin` path from untrusted sources can be applied as a workaround.



- [https://github.com/CsEnox/CVE-2021-21425](https://github.com/CsEnox/CVE-2021-21425) :  ![starts](https://img.shields.io/github/stars/CsEnox/CVE-2021-21425.svg) ![forks](https://img.shields.io/github/forks/CsEnox/CVE-2021-21425.svg)

## CVE-2021-21402
 Jellyfin is a Free Software Media System. In Jellyfin before version 10.7.1, with certain endpoints, well crafted requests will allow arbitrary file read from a Jellyfin server's file system. This issue is more prevalent when Windows is used as the host OS. Servers that are exposed to the public Internet are potentially at risk. This is fixed in version 10.7.1. As a workaround, users may be able to restrict some access by enforcing strict security permissions on their filesystem, however, it is recommended to update as soon as possible.



- [https://github.com/MzzdToT/CVE-2021-21402](https://github.com/MzzdToT/CVE-2021-21402) :  ![starts](https://img.shields.io/github/stars/MzzdToT/CVE-2021-21402.svg) ![forks](https://img.shields.io/github/forks/MzzdToT/CVE-2021-21402.svg)

- [https://github.com/jiaocoll/CVE-2021-21402-Jellyfin](https://github.com/jiaocoll/CVE-2021-21402-Jellyfin) :  ![starts](https://img.shields.io/github/stars/jiaocoll/CVE-2021-21402-Jellyfin.svg) ![forks](https://img.shields.io/github/forks/jiaocoll/CVE-2021-21402-Jellyfin.svg)

- [https://github.com/somatrasss/CVE-2021-21402](https://github.com/somatrasss/CVE-2021-21402) :  ![starts](https://img.shields.io/github/stars/somatrasss/CVE-2021-21402.svg) ![forks](https://img.shields.io/github/forks/somatrasss/CVE-2021-21402.svg)

- [https://github.com/givemefivw/CVE-2021-21402](https://github.com/givemefivw/CVE-2021-21402) :  ![starts](https://img.shields.io/github/stars/givemefivw/CVE-2021-21402.svg) ![forks](https://img.shields.io/github/forks/givemefivw/CVE-2021-21402.svg)

## CVE-2021-21349
 XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16, there is a vulnerability which may allow a remote attacker to request data from internal resources that are not publicly available only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.



- [https://github.com/s-index/poc-list](https://github.com/s-index/poc-list) :  ![starts](https://img.shields.io/github/stars/s-index/poc-list.svg) ![forks](https://img.shields.io/github/forks/s-index/poc-list.svg)

- [https://github.com/s-index/CVE-2021-21349](https://github.com/s-index/CVE-2021-21349) :  ![starts](https://img.shields.io/github/stars/s-index/CVE-2021-21349.svg) ![forks](https://img.shields.io/github/forks/s-index/CVE-2021-21349.svg)

## CVE-2021-21341
 XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16, there is vulnerability which may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU type or parallel execution of such a payload resulting in a denial of service only by manipulating the processed input stream. No user is affected who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.



- [https://github.com/s-index/poc-list](https://github.com/s-index/poc-list) :  ![starts](https://img.shields.io/github/stars/s-index/poc-list.svg) ![forks](https://img.shields.io/github/forks/s-index/poc-list.svg)

- [https://github.com/s-index/CVE-2021-21341](https://github.com/s-index/CVE-2021-21341) :  ![starts](https://img.shields.io/github/stars/s-index/CVE-2021-21341.svg) ![forks](https://img.shields.io/github/forks/s-index/CVE-2021-21341.svg)

## CVE-2021-21315
 The System Information Library for Node.JS (npm package &quot;systeminformation&quot;) is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected.



- [https://github.com/ForbiddenProgrammer/CVE-2021-21315-PoC](https://github.com/ForbiddenProgrammer/CVE-2021-21315-PoC) :  ![starts](https://img.shields.io/github/stars/ForbiddenProgrammer/CVE-2021-21315-PoC.svg) ![forks](https://img.shields.io/github/forks/ForbiddenProgrammer/CVE-2021-21315-PoC.svg)

- [https://github.com/alikarimi999/CVE-2021-21315](https://github.com/alikarimi999/CVE-2021-21315) :  ![starts](https://img.shields.io/github/stars/alikarimi999/CVE-2021-21315.svg) ![forks](https://img.shields.io/github/forks/alikarimi999/CVE-2021-21315.svg)

- [https://github.com/cherrera0001/CVE-2021-21315v2](https://github.com/cherrera0001/CVE-2021-21315v2) :  ![starts](https://img.shields.io/github/stars/cherrera0001/CVE-2021-21315v2.svg) ![forks](https://img.shields.io/github/forks/cherrera0001/CVE-2021-21315v2.svg)

- [https://github.com/Ki11i0n4ir3/CVE-2021-21315](https://github.com/Ki11i0n4ir3/CVE-2021-21315) :  ![starts](https://img.shields.io/github/stars/Ki11i0n4ir3/CVE-2021-21315.svg) ![forks](https://img.shields.io/github/forks/Ki11i0n4ir3/CVE-2021-21315.svg)

- [https://github.com/MazX0p/CVE-2021-21315-exploit](https://github.com/MazX0p/CVE-2021-21315-exploit) :  ![starts](https://img.shields.io/github/stars/MazX0p/CVE-2021-21315-exploit.svg) ![forks](https://img.shields.io/github/forks/MazX0p/CVE-2021-21315-exploit.svg)

- [https://github.com/xMohamed0/CVE-2021-21315-POC](https://github.com/xMohamed0/CVE-2021-21315-POC) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-21315-POC.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-21315-POC.svg)

## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.



- [https://github.com/Maskhe/CVE-2021-21300](https://github.com/Maskhe/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/Maskhe/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/Maskhe/CVE-2021-21300.svg)

- [https://github.com/AlkenePan/CVE-2021-21300](https://github.com/AlkenePan/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/AlkenePan/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/AlkenePan/CVE-2021-21300.svg)

- [https://github.com/tao-sun2/CVE-2021-21300](https://github.com/tao-sun2/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/tao-sun2/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/tao-sun2/CVE-2021-21300.svg)

- [https://github.com/danshuizhangyu/CVE-2021-21300](https://github.com/danshuizhangyu/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/danshuizhangyu/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/danshuizhangyu/CVE-2021-21300.svg)

- [https://github.com/0ahu/CVE-2021-21300](https://github.com/0ahu/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/0ahu/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/0ahu/CVE-2021-21300.svg)

- [https://github.com/Kirill89/CVE-2021-21300](https://github.com/Kirill89/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/Kirill89/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/Kirill89/CVE-2021-21300.svg)

- [https://github.com/ETOCheney/cve-2021-21300](https://github.com/ETOCheney/cve-2021-21300) :  ![starts](https://img.shields.io/github/stars/ETOCheney/cve-2021-21300.svg) ![forks](https://img.shields.io/github/forks/ETOCheney/cve-2021-21300.svg)

- [https://github.com/Faisal78123/CVE-2021-21300](https://github.com/Faisal78123/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/Faisal78123/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/Faisal78123/CVE-2021-21300.svg)

- [https://github.com/erranfenech/CVE-2021-21300](https://github.com/erranfenech/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/erranfenech/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/erranfenech/CVE-2021-21300.svg)

- [https://github.com/fengzhouc/CVE-2021-21300](https://github.com/fengzhouc/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/fengzhouc/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/fengzhouc/CVE-2021-21300.svg)

- [https://github.com/1uanWu/CVE-2021-21300](https://github.com/1uanWu/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/1uanWu/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/1uanWu/CVE-2021-21300.svg)

- [https://github.com/xiaofeihahah/CVE-2021-21300](https://github.com/xiaofeihahah/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/xiaofeihahah/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/xiaofeihahah/CVE-2021-21300.svg)

## CVE-2021-21234
 spring-boot-actuator-logview in a library that adds a simple logfile viewer as spring boot actuator endpoint. It is maven package &quot;eu.hinsch:spring-boot-actuator-logview&quot;. In spring-boot-actuator-logview before version 0.2.13 there is a directory traversal vulnerability. The nature of this library is to expose a log file directory via admin (spring boot actuator) HTTP endpoints. Both the filename to view and a base folder (relative to the logging folder root) can be specified via request parameters. While the filename parameter was checked to prevent directory traversal exploits (so that `filename=../somefile` would not work), the base folder parameter was not sufficiently checked, so that `filename=somefile&amp;base=../` could access a file outside the logging base directory). The vulnerability has been patched in release 0.2.13. Any users of 0.2.12 should be able to update without any issues as there are no other changes in that release. There is no workaround to fix the vulnerability other than updating or removing the dependency. However, removing read access of the user the application is run with to any directory not required for running the application can limit the impact. Additionally, access to the logview endpoint can be limited by deploying the application behind a reverse proxy.



- [https://github.com/xiaojiangxl/CVE-2021-21234](https://github.com/xiaojiangxl/CVE-2021-21234) :  ![starts](https://img.shields.io/github/stars/xiaojiangxl/CVE-2021-21234.svg) ![forks](https://img.shields.io/github/forks/xiaojiangxl/CVE-2021-21234.svg)

- [https://github.com/PwCNO-CTO/CVE-2021-21234](https://github.com/PwCNO-CTO/CVE-2021-21234) :  ![starts](https://img.shields.io/github/stars/PwCNO-CTO/CVE-2021-21234.svg) ![forks](https://img.shields.io/github/forks/PwCNO-CTO/CVE-2021-21234.svg)

## CVE-2021-21224
 Type confusion in V8 in Google Chrome prior to 90.0.4430.85 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.



- [https://github.com/ohnonoyesyes/CVE-2021-21224](https://github.com/ohnonoyesyes/CVE-2021-21224) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2021-21224.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2021-21224.svg)

## CVE-2021-21220
 Insufficient validation of untrusted input in V8 in Google Chrome prior to 89.0.4389.128 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.



- [https://github.com/security-dbg/CVE-2021-21220](https://github.com/security-dbg/CVE-2021-21220) :  ![starts](https://img.shields.io/github/stars/security-dbg/CVE-2021-21220.svg) ![forks](https://img.shields.io/github/forks/security-dbg/CVE-2021-21220.svg)

## CVE-2021-21148
 Heap buffer overflow in V8 in Google Chrome prior to 88.0.4324.150 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.



- [https://github.com/Grayhaxor/CVE-2021-21148](https://github.com/Grayhaxor/CVE-2021-21148) :  ![starts](https://img.shields.io/github/stars/Grayhaxor/CVE-2021-21148.svg) ![forks](https://img.shields.io/github/forks/Grayhaxor/CVE-2021-21148.svg)

## CVE-2021-21123
 Insufficient data validation in File System API in Google Chrome prior to 88.0.4324.96 allowed a remote attacker to bypass filesystem restrictions via a crafted HTML page.



- [https://github.com/Puliczek/CVE-2021-21123-PoC-Google-Chrome](https://github.com/Puliczek/CVE-2021-21123-PoC-Google-Chrome) :  ![starts](https://img.shields.io/github/stars/Puliczek/CVE-2021-21123-PoC-Google-Chrome.svg) ![forks](https://img.shields.io/github/forks/Puliczek/CVE-2021-21123-PoC-Google-Chrome.svg)

## CVE-2021-21110
 Use after free in safe browsing in Google Chrome prior to 87.0.4280.141 allowed a remote attacker to potentially perform a sandbox escape via a crafted HTML page.



- [https://github.com/Gh0st0ne/CVE-2021-21110](https://github.com/Gh0st0ne/CVE-2021-21110) :  ![starts](https://img.shields.io/github/stars/Gh0st0ne/CVE-2021-21110.svg) ![forks](https://img.shields.io/github/forks/Gh0st0ne/CVE-2021-21110.svg)

## CVE-2021-21086
 Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and 2017.011.30188 (and earlier) are affected by an Out-of-bounds Write vulnerability in the CoolType library. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/infobyte/Exploit-CVE-2021-21086](https://github.com/infobyte/Exploit-CVE-2021-21086) :  ![starts](https://img.shields.io/github/stars/infobyte/Exploit-CVE-2021-21086.svg) ![forks](https://img.shields.io/github/forks/infobyte/Exploit-CVE-2021-21086.svg)

## CVE-2021-21042
 Acrobat Reader DC versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and 2017.011.30188 (and earlier) are affected by an Out-of-bounds Read vulnerability that could lead to arbitrary disclosure of information in the memory stack. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/NattiSamson/CVE-2021-21042](https://github.com/NattiSamson/CVE-2021-21042) :  ![starts](https://img.shields.io/github/stars/NattiSamson/CVE-2021-21042.svg) ![forks](https://img.shields.io/github/forks/NattiSamson/CVE-2021-21042.svg)

- [https://github.com/r1l4-i3pur1l4/CVE-2021-21042](https://github.com/r1l4-i3pur1l4/CVE-2021-21042) :  ![starts](https://img.shields.io/github/stars/r1l4-i3pur1l4/CVE-2021-21042.svg) ![forks](https://img.shields.io/github/forks/r1l4-i3pur1l4/CVE-2021-21042.svg)

## CVE-2021-21017
 Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and 2017.011.30188 (and earlier) are affected by a heap-based buffer overflow vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/ZeusBox/CVE-2021-21017](https://github.com/ZeusBox/CVE-2021-21017) :  ![starts](https://img.shields.io/github/stars/ZeusBox/CVE-2021-21017.svg) ![forks](https://img.shields.io/github/forks/ZeusBox/CVE-2021-21017.svg)

## CVE-2021-21014
 Magento versions 2.4.1 (and earlier), 2.4.0-p1 (and earlier) and 2.3.6 (and earlier) are vulnerable to a file upload restriction bypass. Successful exploitation could lead to arbitrary code execution by an authenticated attacker. Access to the admin console is required for successful exploitation.



- [https://github.com/HoangKien1020/CVE-2021-21014](https://github.com/HoangKien1020/CVE-2021-21014) :  ![starts](https://img.shields.io/github/stars/HoangKien1020/CVE-2021-21014.svg) ![forks](https://img.shields.io/github/forks/HoangKien1020/CVE-2021-21014.svg)

## CVE-2021-20837
 Movable Type 7 r.5002 and earlier (Movable Type 7 Series), Movable Type 6.8.2 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.5002 and earlier (Movable Type Advanced 7 Series), Movable Type Advanced 6.8.2 and earlier (Movable Type Advanced 6 Series), Movable Type Premium 1.46 and earlier, and Movable Type Premium Advanced 1.46 and earlier allow remote attackers to execute arbitrary OS commands via unspecified vectors. Note that all versions of Movable Type 4.0 or later including unsupported (End-of-Life, EOL) versions are also affected by this vulnerability.



- [https://github.com/onsecuredev/CVE-2021-20837](https://github.com/onsecuredev/CVE-2021-20837) :  ![starts](https://img.shields.io/github/stars/onsecuredev/CVE-2021-20837.svg) ![forks](https://img.shields.io/github/forks/onsecuredev/CVE-2021-20837.svg)

- [https://github.com/ghost-nemesis/cve-2021-20837-poc](https://github.com/ghost-nemesis/cve-2021-20837-poc) :  ![starts](https://img.shields.io/github/stars/ghost-nemesis/cve-2021-20837-poc.svg) ![forks](https://img.shields.io/github/forks/ghost-nemesis/cve-2021-20837-poc.svg)

- [https://github.com/ohnonoyesyes/CVE-2021-20837](https://github.com/ohnonoyesyes/CVE-2021-20837) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2021-20837.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2021-20837.svg)

- [https://github.com/Cosemz/CVE-2021-20837](https://github.com/Cosemz/CVE-2021-20837) :  ![starts](https://img.shields.io/github/stars/Cosemz/CVE-2021-20837.svg) ![forks](https://img.shields.io/github/forks/Cosemz/CVE-2021-20837.svg)

## CVE-2021-20717
 Cross-site scripting vulnerability in EC-CUBE 4.0.0 to 4.0.5 allows a remote attacker to inject a specially crafted script in the specific input field of the EC web site which is created using EC-CUBE. As a result, it may lead to an arbitrary script execution on the administrator's web browser.



- [https://github.com/s-index/poc-list](https://github.com/s-index/poc-list) :  ![starts](https://img.shields.io/github/stars/s-index/poc-list.svg) ![forks](https://img.shields.io/github/forks/s-index/poc-list.svg)

- [https://github.com/s-index/CVE-2021-20717](https://github.com/s-index/CVE-2021-20717) :  ![starts](https://img.shields.io/github/stars/s-index/CVE-2021-20717.svg) ![forks](https://img.shields.io/github/forks/s-index/CVE-2021-20717.svg)

## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.



- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)

- [https://github.com/cckuailong/log4shell_1.x](https://github.com/cckuailong/log4shell_1.x) :  ![starts](https://img.shields.io/github/stars/cckuailong/log4shell_1.x.svg) ![forks](https://img.shields.io/github/forks/cckuailong/log4shell_1.x.svg)

- [https://github.com/TheInterception/Log4J-Simulation-Tool](https://github.com/TheInterception/Log4J-Simulation-Tool) :  ![starts](https://img.shields.io/github/stars/TheInterception/Log4J-Simulation-Tool.svg) ![forks](https://img.shields.io/github/forks/TheInterception/Log4J-Simulation-Tool.svg)

## CVE-2021-3708
 D-Link router DSL-2750U with firmware vME1.16 or prior versions is vulnerable to OS command injection. An unauthenticated attacker on the local network may exploit this, with CVE-2021-3707, to execute any OS commands on the vulnerable device.



- [https://github.com/HadiMed/firmware-analysis](https://github.com/HadiMed/firmware-analysis) :  ![starts](https://img.shields.io/github/stars/HadiMed/firmware-analysis.svg) ![forks](https://img.shields.io/github/forks/HadiMed/firmware-analysis.svg)

## CVE-2021-3707
 D-Link router DSL-2750U with firmware vME1.16 or prior versions is vulnerable to unauthorized configuration modification. An unauthenticated attacker on the local network may exploit this, with CVE-2021-3708, to execute any OS commands on the vulnerable device.



- [https://github.com/HadiMed/firmware-analysis](https://github.com/HadiMed/firmware-analysis) :  ![starts](https://img.shields.io/github/stars/HadiMed/firmware-analysis.svg) ![forks](https://img.shields.io/github/forks/HadiMed/firmware-analysis.svg)

## CVE-2021-3679
 A lack of CPU resource in the Linux kernel tracing module functionality in versions prior to 5.14-rc3 was found in the way user uses trace ring buffer in a specific way. Only privileged local users (with CAP_SYS_ADMIN capability) could use this flaw to starve the resources causing denial of service.



- [https://github.com/aegistudio/RingBufferDetonator](https://github.com/aegistudio/RingBufferDetonator) :  ![starts](https://img.shields.io/github/stars/aegistudio/RingBufferDetonator.svg) ![forks](https://img.shields.io/github/forks/aegistudio/RingBufferDetonator.svg)

## CVE-2021-3625
 Buffer overflow in Zephyr USB DFU DNLOAD. Zephyr versions &gt;= v2.5.0 contain Heap-based Buffer Overflow (CWE-122). For more information, see https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-c3gr-hgvr-f363



- [https://github.com/szymonh/zephyr_cve-2021-3625](https://github.com/szymonh/zephyr_cve-2021-3625) :  ![starts](https://img.shields.io/github/stars/szymonh/zephyr_cve-2021-3625.svg) ![forks](https://img.shields.io/github/forks/szymonh/zephyr_cve-2021-3625.svg)

## CVE-2021-3572
 A flaw was found in python-pip in the way it handled Unicode separators in git references. A remote attacker could possibly use this issue to install a different revision on a repository. The highest threat from this vulnerability is to data integrity. This is fixed in python-pip version 21.1.



- [https://github.com/frenzymadness/CVE-2021-3572](https://github.com/frenzymadness/CVE-2021-3572) :  ![starts](https://img.shields.io/github/stars/frenzymadness/CVE-2021-3572.svg) ![forks](https://img.shields.io/github/forks/frenzymadness/CVE-2021-3572.svg)

## CVE-2021-3560
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/liamg/traitor](https://github.com/liamg/traitor) :  ![starts](https://img.shields.io/github/stars/liamg/traitor.svg) ![forks](https://img.shields.io/github/forks/liamg/traitor.svg)

- [https://github.com/swapravo/polkadots](https://github.com/swapravo/polkadots) :  ![starts](https://img.shields.io/github/stars/swapravo/polkadots.svg) ![forks](https://img.shields.io/github/forks/swapravo/polkadots.svg)

- [https://github.com/Almorabea/Polkit-exploit](https://github.com/Almorabea/Polkit-exploit) :  ![starts](https://img.shields.io/github/stars/Almorabea/Polkit-exploit.svg) ![forks](https://img.shields.io/github/forks/Almorabea/Polkit-exploit.svg)

- [https://github.com/hakivvi/CVE-2021-3560](https://github.com/hakivvi/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/hakivvi/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/hakivvi/CVE-2021-3560.svg)

- [https://github.com/0dayNinja/CVE-2021-3560](https://github.com/0dayNinja/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/0dayNinja/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/0dayNinja/CVE-2021-3560.svg)

- [https://github.com/oxagast/oxasploits](https://github.com/oxagast/oxasploits) :  ![starts](https://img.shields.io/github/stars/oxagast/oxasploits.svg) ![forks](https://img.shields.io/github/forks/oxagast/oxasploits.svg)

- [https://github.com/aancw/polkit-auto-exploit](https://github.com/aancw/polkit-auto-exploit) :  ![starts](https://img.shields.io/github/stars/aancw/polkit-auto-exploit.svg) ![forks](https://img.shields.io/github/forks/aancw/polkit-auto-exploit.svg)

- [https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation) :  ![starts](https://img.shields.io/github/stars/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation.svg) ![forks](https://img.shields.io/github/forks/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation.svg)

- [https://github.com/BizarreLove/CVE-2021-3560](https://github.com/BizarreLove/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/BizarreLove/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/BizarreLove/CVE-2021-3560.svg)

- [https://github.com/LeoBreaker1411/CVE-2021-3560](https://github.com/LeoBreaker1411/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/LeoBreaker1411/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/LeoBreaker1411/CVE-2021-3560.svg)

- [https://github.com/curtishoughton/CVE-2021-3560](https://github.com/curtishoughton/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/curtishoughton/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/curtishoughton/CVE-2021-3560.svg)

- [https://github.com/AssassinUKG/Polkit-CVE-2021-3560](https://github.com/AssassinUKG/Polkit-CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/AssassinUKG/Polkit-CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/AssassinUKG/Polkit-CVE-2021-3560.svg)

- [https://github.com/mr-nobody20/CVE-2021-3560](https://github.com/mr-nobody20/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/mr-nobody20/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/mr-nobody20/CVE-2021-3560.svg)

- [https://github.com/iSTARLabs/CVE-2021-3560_PoC](https://github.com/iSTARLabs/CVE-2021-3560_PoC) :  ![starts](https://img.shields.io/github/stars/iSTARLabs/CVE-2021-3560_PoC.svg) ![forks](https://img.shields.io/github/forks/iSTARLabs/CVE-2021-3560_PoC.svg)

## CVE-2021-3516
 There's a flaw in libxml2's xmllint in versions before 2.9.11. An attacker who is able to submit a crafted file to be processed by xmllint could trigger a use-after-free. The greatest impact of this flaw is to confidentiality, integrity, and availability.



- [https://github.com/fkm75P8YjLkb/CVE-2021-3516](https://github.com/fkm75P8YjLkb/CVE-2021-3516) :  ![starts](https://img.shields.io/github/stars/fkm75P8YjLkb/CVE-2021-3516.svg) ![forks](https://img.shields.io/github/forks/fkm75P8YjLkb/CVE-2021-3516.svg)

## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.



- [https://github.com/briskets/CVE-2021-3493](https://github.com/briskets/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/briskets/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/briskets/CVE-2021-3493.svg)

- [https://github.com/inspiringz/CVE-2021-3493](https://github.com/inspiringz/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/inspiringz/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/inspiringz/CVE-2021-3493.svg)

- [https://github.com/oneoy/CVE-2021-3493](https://github.com/oneoy/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/oneoy/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/oneoy/CVE-2021-3493.svg)

- [https://github.com/AmIAHuman/OverlayFS-CVE-2021-3493](https://github.com/AmIAHuman/OverlayFS-CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/AmIAHuman/OverlayFS-CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/AmIAHuman/OverlayFS-CVE-2021-3493.svg)

- [https://github.com/Ishan3011/CVE-2021-3493](https://github.com/Ishan3011/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/Ishan3011/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/Ishan3011/CVE-2021-3493.svg)

- [https://github.com/cerodah/overlayFS-CVE-2021-3493](https://github.com/cerodah/overlayFS-CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/cerodah/overlayFS-CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/cerodah/overlayFS-CVE-2021-3493.svg)

- [https://github.com/derek-turing/CVE-2021-3493](https://github.com/derek-turing/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/derek-turing/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/derek-turing/CVE-2021-3493.svg)

- [https://github.com/Abdennour-py/CVE-2021-3493](https://github.com/Abdennour-py/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/Abdennour-py/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/Abdennour-py/CVE-2021-3493.svg)

- [https://github.com/puckiestyle/CVE-2021-3493](https://github.com/puckiestyle/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-3493.svg)

## CVE-2021-3492
 Shiftfs, an out-of-tree stacking file system included in Ubuntu Linux kernels, did not properly handle faults occurring during copy_from_user() correctly. These could lead to either a double-free situation or memory not being freed at all. An attacker could use this to cause a denial of service (kernel memory exhaustion) or gain privileges via executing arbitrary code. AKA ZDI-CAN-13562.



- [https://github.com/synacktiv/CVE-2021-3492](https://github.com/synacktiv/CVE-2021-3492) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2021-3492.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2021-3492.svg)

## CVE-2021-3490
 The eBPF ALU32 bounds tracking for bitwise ops (AND, OR and XOR) in the Linux kernel did not properly update 32-bit bounds, which could be turned into out of bounds reads and writes in the Linux kernel and therefore, arbitrary code execution. This issue was fixed via commit 049c4e13714e (&quot;bpf: Fix alu32 const subreg bound tracking on bitwise operations&quot;) (v5.13-rc4) and backported to the stable kernels in v5.12.4, v5.11.21, and v5.10.37. The AND/OR issues were introduced by commit 3f50f132d840 (&quot;bpf: Verifier, do explicit ALU32 bounds tracking&quot;) (5.7-rc1) and the XOR variant was introduced by 2921c90d4718 (&quot;bpf:Fix a verifier failure with xor&quot;) ( 5.10-rc1).



- [https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490](https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490) :  ![starts](https://img.shields.io/github/stars/chompie1337/Linux_LPE_eBPF_CVE-2021-3490.svg) ![forks](https://img.shields.io/github/forks/chompie1337/Linux_LPE_eBPF_CVE-2021-3490.svg)

## CVE-2021-3449
 An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j).



- [https://github.com/terorie/cve-2021-3449](https://github.com/terorie/cve-2021-3449) :  ![starts](https://img.shields.io/github/stars/terorie/cve-2021-3449.svg) ![forks](https://img.shields.io/github/forks/terorie/cve-2021-3449.svg)

## CVE-2021-3441
 A potential security vulnerability has been identified for the HP OfficeJet 7110 Wide Format ePrinter that enables Cross-Site Scripting (XSS).



- [https://github.com/tcbutler320/CVE-2021-3441-check](https://github.com/tcbutler320/CVE-2021-3441-check) :  ![starts](https://img.shields.io/github/stars/tcbutler320/CVE-2021-3441-check.svg) ![forks](https://img.shields.io/github/forks/tcbutler320/CVE-2021-3441-check.svg)

## CVE-2021-3438
 A potential buffer overflow in the software drivers for certain HP LaserJet products and Samsung product printers could lead to an escalation of privilege.



- [https://github.com/Crystalware/CVE-2021-3438](https://github.com/Crystalware/CVE-2021-3438) :  ![starts](https://img.shields.io/github/stars/Crystalware/CVE-2021-3438.svg) ![forks](https://img.shields.io/github/forks/Crystalware/CVE-2021-3438.svg)

- [https://github.com/TobiasS1402/CVE-2021-3438](https://github.com/TobiasS1402/CVE-2021-3438) :  ![starts](https://img.shields.io/github/stars/TobiasS1402/CVE-2021-3438.svg) ![forks](https://img.shields.io/github/forks/TobiasS1402/CVE-2021-3438.svg)

## CVE-2021-3395
 A cross-site scripting (XSS) vulnerability in Pryaniki 6.44.3 allows remote authenticated users to upload an arbitrary file. The JavaScript code will execute when someone visits the attachment.



- [https://github.com/jet-pentest/CVE-2021-3395](https://github.com/jet-pentest/CVE-2021-3395) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2021-3395.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2021-3395.svg)

## CVE-2021-3378
 FortiLogger 4.4.2.2 is affected by Arbitrary File Upload by sending a &quot;Content-Type: image/png&quot; header to Config/SaveUploadedHotspotLogoFile and then visiting Assets/temp/hotspot/img/logohotspot.asp.



- [https://github.com/erberkan/fortilogger_arbitrary_fileupload](https://github.com/erberkan/fortilogger_arbitrary_fileupload) :  ![starts](https://img.shields.io/github/stars/erberkan/fortilogger_arbitrary_fileupload.svg) ![forks](https://img.shields.io/github/forks/erberkan/fortilogger_arbitrary_fileupload.svg)

## CVE-2021-3360
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/tcbutler320/CVE-2021-3360](https://github.com/tcbutler320/CVE-2021-3360) :  ![starts](https://img.shields.io/github/stars/tcbutler320/CVE-2021-3360.svg) ![forks](https://img.shields.io/github/forks/tcbutler320/CVE-2021-3360.svg)

## CVE-2021-3345
 _gcry_md_block_write in cipher/hash-common.c in Libgcrypt version 1.9.0 has a heap-based buffer overflow when the digest final function sets a large count value. It is recommended to upgrade to 1.9.1 or later.



- [https://github.com/MLGRadish/CVE-2021-3345](https://github.com/MLGRadish/CVE-2021-3345) :  ![starts](https://img.shields.io/github/stars/MLGRadish/CVE-2021-3345.svg) ![forks](https://img.shields.io/github/forks/MLGRadish/CVE-2021-3345.svg)

## CVE-2021-3317
 KLog Server through 2.4.1 allows authenticated command injection. async.php calls shell_exec() on the original value of the source parameter.



- [https://github.com/Al1ex/CVE-2021-3317](https://github.com/Al1ex/CVE-2021-3317) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-3317.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-3317.svg)

## CVE-2021-3310
 Western Digital My Cloud OS 5 devices before 5.10.122 mishandle Symbolic Link Following on SMB and AFP shares. This can lead to code execution and information disclosure (by reading local files).



- [https://github.com/piffd0s/CVE-2021-3310](https://github.com/piffd0s/CVE-2021-3310) :  ![starts](https://img.shields.io/github/stars/piffd0s/CVE-2021-3310.svg) ![forks](https://img.shields.io/github/forks/piffd0s/CVE-2021-3310.svg)

## CVE-2021-3291
 Zen Cart 1.5.7b allows admins to execute arbitrary OS commands by inspecting an HTML radio input element (within the modules edit page) and inserting a command.



- [https://github.com/ImHades101/CVE-2021-3291](https://github.com/ImHades101/CVE-2021-3291) :  ![starts](https://img.shields.io/github/stars/ImHades101/CVE-2021-3291.svg) ![forks](https://img.shields.io/github/forks/ImHades101/CVE-2021-3291.svg)

## CVE-2021-3281
 In Django 2.2 before 2.2.18, 3.0 before 3.0.12, and 3.1 before 3.1.6, the django.utils.archive.extract method (used by &quot;startapp --template&quot; and &quot;startproject --template&quot;) allows directory traversal via an archive with absolute paths or relative paths with dot segments.



- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)

- [https://github.com/lwzSoviet/CVE-2021-3281](https://github.com/lwzSoviet/CVE-2021-3281) :  ![starts](https://img.shields.io/github/stars/lwzSoviet/CVE-2021-3281.svg) ![forks](https://img.shields.io/github/forks/lwzSoviet/CVE-2021-3281.svg)

## CVE-2021-3229
 Denial of service in ASUSWRT ASUS RT-AX3000 firmware versions 3.0.0.4.384_10177 and earlier versions allows an attacker to disrupt the use of device setup services via continuous login error.



- [https://github.com/fullbbadda1208/CVE-2021-3229](https://github.com/fullbbadda1208/CVE-2021-3229) :  ![starts](https://img.shields.io/github/stars/fullbbadda1208/CVE-2021-3229.svg) ![forks](https://img.shields.io/github/forks/fullbbadda1208/CVE-2021-3229.svg)

## CVE-2021-3165
 SmartAgent 3.1.0 allows a ViewOnly attacker to create a SuperUser account via the /#/CampaignManager/users URI.



- [https://github.com/orionhridoy/CVE-2021-3165](https://github.com/orionhridoy/CVE-2021-3165) :  ![starts](https://img.shields.io/github/stars/orionhridoy/CVE-2021-3165.svg) ![forks](https://img.shields.io/github/forks/orionhridoy/CVE-2021-3165.svg)

## CVE-2021-3164
 ChurchRota 2.6.4 is vulnerable to authenticated remote code execution. The user does not need to have file upload permission in order to upload and execute an arbitrary file via a POST request to resources.php.



- [https://github.com/rmccarth/cve-2021-3164](https://github.com/rmccarth/cve-2021-3164) :  ![starts](https://img.shields.io/github/stars/rmccarth/cve-2021-3164.svg) ![forks](https://img.shields.io/github/forks/rmccarth/cve-2021-3164.svg)

## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.



- [https://github.com/blasty/CVE-2021-3156](https://github.com/blasty/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/blasty/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/blasty/CVE-2021-3156.svg)

- [https://github.com/stong/CVE-2021-3156](https://github.com/stong/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/stong/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/stong/CVE-2021-3156.svg)

- [https://github.com/worawit/CVE-2021-3156](https://github.com/worawit/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/worawit/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/worawit/CVE-2021-3156.svg)

- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)

- [https://github.com/Rvn0xsy/CVE-2021-3156-plus](https://github.com/Rvn0xsy/CVE-2021-3156-plus) :  ![starts](https://img.shields.io/github/stars/Rvn0xsy/CVE-2021-3156-plus.svg) ![forks](https://img.shields.io/github/forks/Rvn0xsy/CVE-2021-3156-plus.svg)

- [https://github.com/LiveOverflow/pwnedit](https://github.com/LiveOverflow/pwnedit) :  ![starts](https://img.shields.io/github/stars/LiveOverflow/pwnedit.svg) ![forks](https://img.shields.io/github/forks/LiveOverflow/pwnedit.svg)

- [https://github.com/reverse-ex/CVE-2021-3156](https://github.com/reverse-ex/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/reverse-ex/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/reverse-ex/CVE-2021-3156.svg)

- [https://github.com/CptGibbon/CVE-2021-3156](https://github.com/CptGibbon/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/CptGibbon/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/CptGibbon/CVE-2021-3156.svg)

- [https://github.com/mbcrump/CVE-2021-3156](https://github.com/mbcrump/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/mbcrump/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/mbcrump/CVE-2021-3156.svg)

- [https://github.com/0xdevil/CVE-2021-3156](https://github.com/0xdevil/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/0xdevil/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/0xdevil/CVE-2021-3156.svg)

- [https://github.com/mr-r3b00t/CVE-2021-3156](https://github.com/mr-r3b00t/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2021-3156.svg)

- [https://github.com/kernelzeroday/CVE-2021-3156-Baron-Samedit](https://github.com/kernelzeroday/CVE-2021-3156-Baron-Samedit) :  ![starts](https://img.shields.io/github/stars/kernelzeroday/CVE-2021-3156-Baron-Samedit.svg) ![forks](https://img.shields.io/github/forks/kernelzeroday/CVE-2021-3156-Baron-Samedit.svg)

- [https://github.com/jm33-m0/CVE-2021-3156](https://github.com/jm33-m0/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/jm33-m0/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/jm33-m0/CVE-2021-3156.svg)

- [https://github.com/teamtopkarl/CVE-2021-3156](https://github.com/teamtopkarl/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/teamtopkarl/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/teamtopkarl/CVE-2021-3156.svg)

- [https://github.com/apogiatzis/docker-CVE-2021-3156](https://github.com/apogiatzis/docker-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/apogiatzis/docker-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/apogiatzis/docker-CVE-2021-3156.svg)

- [https://github.com/yaunsky/cve-2021-3156](https://github.com/yaunsky/cve-2021-3156) :  ![starts](https://img.shields.io/github/stars/yaunsky/cve-2021-3156.svg) ![forks](https://img.shields.io/github/forks/yaunsky/cve-2021-3156.svg)

- [https://github.com/dinhbaouit/CVE-2021-3156](https://github.com/dinhbaouit/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/dinhbaouit/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/dinhbaouit/CVE-2021-3156.svg)

- [https://github.com/baka9moe/CVE-2021-3156-Exp](https://github.com/baka9moe/CVE-2021-3156-Exp) :  ![starts](https://img.shields.io/github/stars/baka9moe/CVE-2021-3156-Exp.svg) ![forks](https://img.shields.io/github/forks/baka9moe/CVE-2021-3156-Exp.svg)

- [https://github.com/elbee-cyber/CVE-2021-3156-PATCHER](https://github.com/elbee-cyber/CVE-2021-3156-PATCHER) :  ![starts](https://img.shields.io/github/stars/elbee-cyber/CVE-2021-3156-PATCHER.svg) ![forks](https://img.shields.io/github/forks/elbee-cyber/CVE-2021-3156-PATCHER.svg)

- [https://github.com/JureGrinffin/CVE-2021-3156](https://github.com/JureGrinffin/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/JureGrinffin/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/JureGrinffin/CVE-2021-3156.svg)

- [https://github.com/Q4n/CVE-2021-3156](https://github.com/Q4n/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Q4n/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Q4n/CVE-2021-3156.svg)

- [https://github.com/ph4ntonn/CVE-2021-3156](https://github.com/ph4ntonn/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/ph4ntonn/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/ph4ntonn/CVE-2021-3156.svg)

- [https://github.com/kal1gh0st/CVE-2021-3156](https://github.com/kal1gh0st/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/kal1gh0st/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/kal1gh0st/CVE-2021-3156.svg)

- [https://github.com/lmol/CVE-2021-3156](https://github.com/lmol/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/lmol/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/lmol/CVE-2021-3156.svg)

- [https://github.com/1N53C/CVE-2021-3156-PoC](https://github.com/1N53C/CVE-2021-3156-PoC) :  ![starts](https://img.shields.io/github/stars/1N53C/CVE-2021-3156-PoC.svg) ![forks](https://img.shields.io/github/forks/1N53C/CVE-2021-3156-PoC.svg)

- [https://github.com/musergi/CVE-2021-3156](https://github.com/musergi/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/musergi/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/musergi/CVE-2021-3156.svg)

- [https://github.com/H4ckForJob/cve-2021-3156](https://github.com/H4ckForJob/cve-2021-3156) :  ![starts](https://img.shields.io/github/stars/H4ckForJob/cve-2021-3156.svg) ![forks](https://img.shields.io/github/forks/H4ckForJob/cve-2021-3156.svg)

- [https://github.com/donghyunlee00/CVE-2021-3156](https://github.com/donghyunlee00/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/donghyunlee00/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/donghyunlee00/CVE-2021-3156.svg)

- [https://github.com/Nokialinux/CVE-2021-3156](https://github.com/Nokialinux/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Nokialinux/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Nokialinux/CVE-2021-3156.svg)

- [https://github.com/oneoy/CVE-2021-3156](https://github.com/oneoy/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/oneoy/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/oneoy/CVE-2021-3156.svg)

- [https://github.com/SantiagoSerrao/ScannerCVE-2021-3156](https://github.com/SantiagoSerrao/ScannerCVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/SantiagoSerrao/ScannerCVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/SantiagoSerrao/ScannerCVE-2021-3156.svg)

- [https://github.com/binw2018/CVE-2021-3156-SCRIPT](https://github.com/binw2018/CVE-2021-3156-SCRIPT) :  ![starts](https://img.shields.io/github/stars/binw2018/CVE-2021-3156-SCRIPT.svg) ![forks](https://img.shields.io/github/forks/binw2018/CVE-2021-3156-SCRIPT.svg)

- [https://github.com/0x7183/CVE-2021-3156](https://github.com/0x7183/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/0x7183/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/0x7183/CVE-2021-3156.svg)

- [https://github.com/nobodyatall648/CVE-2021-3156](https://github.com/nobodyatall648/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/nobodyatall648/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/nobodyatall648/CVE-2021-3156.svg)

- [https://github.com/TheFlash2k/CVE-2021-3156](https://github.com/TheFlash2k/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/TheFlash2k/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/TheFlash2k/CVE-2021-3156.svg)

- [https://github.com/redhawkeye/sudo-exploit](https://github.com/redhawkeye/sudo-exploit) :  ![starts](https://img.shields.io/github/stars/redhawkeye/sudo-exploit.svg) ![forks](https://img.shields.io/github/forks/redhawkeye/sudo-exploit.svg)

- [https://github.com/AbdullahRizwan101/Baron-Samedit](https://github.com/AbdullahRizwan101/Baron-Samedit) :  ![starts](https://img.shields.io/github/stars/AbdullahRizwan101/Baron-Samedit.svg) ![forks](https://img.shields.io/github/forks/AbdullahRizwan101/Baron-Samedit.svg)

- [https://github.com/usr2r00t/patches](https://github.com/usr2r00t/patches) :  ![starts](https://img.shields.io/github/stars/usr2r00t/patches.svg) ![forks](https://img.shields.io/github/forks/usr2r00t/patches.svg)

- [https://github.com/ymrsmns/CVE-2021-3156](https://github.com/ymrsmns/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/ymrsmns/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/ymrsmns/CVE-2021-3156.svg)

- [https://github.com/Jauler/cve2021-3156-sudo-heap-overflow](https://github.com/Jauler/cve2021-3156-sudo-heap-overflow) :  ![starts](https://img.shields.io/github/stars/Jauler/cve2021-3156-sudo-heap-overflow.svg) ![forks](https://img.shields.io/github/forks/Jauler/cve2021-3156-sudo-heap-overflow.svg)

- [https://github.com/Bubleh21/CVE-2021-3156](https://github.com/Bubleh21/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Bubleh21/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Bubleh21/CVE-2021-3156.svg)

- [https://github.com/freeFV/CVE-2021-3156](https://github.com/freeFV/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/freeFV/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/freeFV/CVE-2021-3156.svg)

- [https://github.com/password520/CVE-2021-3156](https://github.com/password520/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/password520/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/password520/CVE-2021-3156.svg)

- [https://github.com/cdeletre/Serpentiel-CVE-2021-3156](https://github.com/cdeletre/Serpentiel-CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/cdeletre/Serpentiel-CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/cdeletre/Serpentiel-CVE-2021-3156.svg)

- [https://github.com/Y3A/CVE-2021-3156](https://github.com/Y3A/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Y3A/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Y3A/CVE-2021-3156.svg)

- [https://github.com/capturingcats/CVE-2021-3156](https://github.com/capturingcats/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/capturingcats/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/capturingcats/CVE-2021-3156.svg)

- [https://github.com/nexcess/sudo_cve-2021-3156](https://github.com/nexcess/sudo_cve-2021-3156) :  ![starts](https://img.shields.io/github/stars/nexcess/sudo_cve-2021-3156.svg) ![forks](https://img.shields.io/github/forks/nexcess/sudo_cve-2021-3156.svg)

- [https://github.com/Exodusro/CVE-2021-3156](https://github.com/Exodusro/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Exodusro/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Exodusro/CVE-2021-3156.svg)

- [https://github.com/voidlsd/CVE-2021-3156](https://github.com/voidlsd/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/voidlsd/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/voidlsd/CVE-2021-3156.svg)

- [https://github.com/gmldbd94/cve-2021-3156](https://github.com/gmldbd94/cve-2021-3156) :  ![starts](https://img.shields.io/github/stars/gmldbd94/cve-2021-3156.svg) ![forks](https://img.shields.io/github/forks/gmldbd94/cve-2021-3156.svg)

- [https://github.com/d3c3ptic0n/CVE-2021-3156](https://github.com/d3c3ptic0n/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/d3c3ptic0n/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/d3c3ptic0n/CVE-2021-3156.svg)

- [https://github.com/Ashish-dawani/CVE-2021-3156-Patch](https://github.com/Ashish-dawani/CVE-2021-3156-Patch) :  ![starts](https://img.shields.io/github/stars/Ashish-dawani/CVE-2021-3156-Patch.svg) ![forks](https://img.shields.io/github/forks/Ashish-dawani/CVE-2021-3156-Patch.svg)

- [https://github.com/CyberCommands/CVE-2021-3156](https://github.com/CyberCommands/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/CyberCommands/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/CyberCommands/CVE-2021-3156.svg)

- [https://github.com/leterts/CVE-2021-3156-sudo-raising](https://github.com/leterts/CVE-2021-3156-sudo-raising) :  ![starts](https://img.shields.io/github/stars/leterts/CVE-2021-3156-sudo-raising.svg) ![forks](https://img.shields.io/github/forks/leterts/CVE-2021-3156-sudo-raising.svg)

- [https://github.com/ajtech-hue/CVE-2021-3156-Mitigation-ShellScript-Build](https://github.com/ajtech-hue/CVE-2021-3156-Mitigation-ShellScript-Build) :  ![starts](https://img.shields.io/github/stars/ajtech-hue/CVE-2021-3156-Mitigation-ShellScript-Build.svg) ![forks](https://img.shields.io/github/forks/ajtech-hue/CVE-2021-3156-Mitigation-ShellScript-Build.svg)

- [https://github.com/r3k4t/how-to-solve-sudo-heap-based-bufferoverflow-vulnerability](https://github.com/r3k4t/how-to-solve-sudo-heap-based-bufferoverflow-vulnerability) :  ![starts](https://img.shields.io/github/stars/r3k4t/how-to-solve-sudo-heap-based-bufferoverflow-vulnerability.svg) ![forks](https://img.shields.io/github/forks/r3k4t/how-to-solve-sudo-heap-based-bufferoverflow-vulnerability.svg)

- [https://github.com/perlun/sudo-1.8.3p1-patched](https://github.com/perlun/sudo-1.8.3p1-patched) :  ![starts](https://img.shields.io/github/stars/perlun/sudo-1.8.3p1-patched.svg) ![forks](https://img.shields.io/github/forks/perlun/sudo-1.8.3p1-patched.svg)

- [https://github.com/TheSerialiZator/CTF-2021](https://github.com/TheSerialiZator/CTF-2021) :  ![starts](https://img.shields.io/github/stars/TheSerialiZator/CTF-2021.svg) ![forks](https://img.shields.io/github/forks/TheSerialiZator/CTF-2021.svg)

## CVE-2021-3138
 In Discourse 2.7.0 through beta1, a rate-limit bypass leads to a bypass of the 2FA requirement for certain forms.



- [https://github.com/Mesh3l911/CVE-2021-3138](https://github.com/Mesh3l911/CVE-2021-3138) :  ![starts](https://img.shields.io/github/stars/Mesh3l911/CVE-2021-3138.svg) ![forks](https://img.shields.io/github/forks/Mesh3l911/CVE-2021-3138.svg)

## CVE-2021-3131
 The Web server in 1C:Enterprise 8 before 8.3.17.1851 sends base64 encoded credentials in the creds URL parameter.



- [https://github.com/jet-pentest/CVE-2021-3131](https://github.com/jet-pentest/CVE-2021-3131) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2021-3131.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2021-3131.svg)

## CVE-2021-3130
 Within the Open-AudIT up to version 3.5.3 application, the web interface hides SSH secrets, Windows passwords, and SNMP strings from users using HTML 'password field' obfuscation. By using Developer tools or similar, it is possible to change the obfuscation so that the credentials are visible.



- [https://github.com/jet-pentest/CVE-2021-3130](https://github.com/jet-pentest/CVE-2021-3130) :  ![starts](https://img.shields.io/github/stars/jet-pentest/CVE-2021-3130.svg) ![forks](https://img.shields.io/github/forks/jet-pentest/CVE-2021-3130.svg)

## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.



- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)

- [https://github.com/ambionics/laravel-exploits](https://github.com/ambionics/laravel-exploits) :  ![starts](https://img.shields.io/github/stars/ambionics/laravel-exploits.svg) ![forks](https://img.shields.io/github/forks/ambionics/laravel-exploits.svg)

- [https://github.com/SNCKER/CVE-2021-3129](https://github.com/SNCKER/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/SNCKER/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/SNCKER/CVE-2021-3129.svg)

- [https://github.com/zhzyker/CVE-2021-3129](https://github.com/zhzyker/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/zhzyker/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/zhzyker/CVE-2021-3129.svg)

- [https://github.com/nth347/CVE-2021-3129_exploit](https://github.com/nth347/CVE-2021-3129_exploit) :  ![starts](https://img.shields.io/github/stars/nth347/CVE-2021-3129_exploit.svg) ![forks](https://img.shields.io/github/forks/nth347/CVE-2021-3129_exploit.svg)

- [https://github.com/SecPros-Team/laravel-CVE-2021-3129-EXP](https://github.com/SecPros-Team/laravel-CVE-2021-3129-EXP) :  ![starts](https://img.shields.io/github/stars/SecPros-Team/laravel-CVE-2021-3129-EXP.svg) ![forks](https://img.shields.io/github/forks/SecPros-Team/laravel-CVE-2021-3129-EXP.svg)

- [https://github.com/crisprss/Laravel_CVE-2021-3129_EXP](https://github.com/crisprss/Laravel_CVE-2021-3129_EXP) :  ![starts](https://img.shields.io/github/stars/crisprss/Laravel_CVE-2021-3129_EXP.svg) ![forks](https://img.shields.io/github/forks/crisprss/Laravel_CVE-2021-3129_EXP.svg)

- [https://github.com/knqyf263/CVE-2021-3129](https://github.com/knqyf263/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2021-3129.svg)

- [https://github.com/simonlee-hello/CVE-2021-3129](https://github.com/simonlee-hello/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/simonlee-hello/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/simonlee-hello/CVE-2021-3129.svg)

- [https://github.com/FunPhishing/Laravel-8.4.2-rce-CVE-2021-3129](https://github.com/FunPhishing/Laravel-8.4.2-rce-CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/FunPhishing/Laravel-8.4.2-rce-CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/FunPhishing/Laravel-8.4.2-rce-CVE-2021-3129.svg)

- [https://github.com/1111one/laravel-CVE-2021-3129-EXP](https://github.com/1111one/laravel-CVE-2021-3129-EXP) :  ![starts](https://img.shields.io/github/stars/1111one/laravel-CVE-2021-3129-EXP.svg) ![forks](https://img.shields.io/github/forks/1111one/laravel-CVE-2021-3129-EXP.svg)

- [https://github.com/Erikten/CVE-2021-3129](https://github.com/Erikten/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/Erikten/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/Erikten/CVE-2021-3129.svg)

## CVE-2021-3122
 CMCAgent in NCR Command Center Agent 16.3 on Aloha POS/BOH servers permits the submission of a runCommand parameter (within an XML document sent to port 8089) that enables the remote, unauthenticated execution of an arbitrary command as SYSTEM, as exploited in the wild in 2020 and/or 2021. NOTE: the vendor's position is that exploitation occurs only on devices with a certain &quot;misconfiguration.&quot;



- [https://github.com/roughb8722/CVE-2021-3122-Details](https://github.com/roughb8722/CVE-2021-3122-Details) :  ![starts](https://img.shields.io/github/stars/roughb8722/CVE-2021-3122-Details.svg) ![forks](https://img.shields.io/github/forks/roughb8722/CVE-2021-3122-Details.svg)

## CVE-2021-3019
 ffay lanproxy 0.1 allows Directory Traversal to read /../conf/config.properties to obtain credentials for a connection to the intranet.



- [https://github.com/0xf4n9x/CVE-2021-3019](https://github.com/0xf4n9x/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2021-3019.svg)

- [https://github.com/B1anda0/CVE-2021-3019](https://github.com/B1anda0/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/B1anda0/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/B1anda0/CVE-2021-3019.svg)

- [https://github.com/liuxu54898/CVE-2021-3019](https://github.com/liuxu54898/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/liuxu54898/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/liuxu54898/CVE-2021-3019.svg)

- [https://github.com/murataydemir/CVE-2021-3019](https://github.com/murataydemir/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2021-3019.svg)

- [https://github.com/givemefivw/CVE-2021-3019](https://github.com/givemefivw/CVE-2021-3019) :  ![starts](https://img.shields.io/github/stars/givemefivw/CVE-2021-3019.svg) ![forks](https://img.shields.io/github/forks/givemefivw/CVE-2021-3019.svg)

- [https://github.com/qiezi-maozi/CVE-2021-3019-Lanproxy](https://github.com/qiezi-maozi/CVE-2021-3019-Lanproxy) :  ![starts](https://img.shields.io/github/stars/qiezi-maozi/CVE-2021-3019-Lanproxy.svg) ![forks](https://img.shields.io/github/forks/qiezi-maozi/CVE-2021-3019-Lanproxy.svg)

- [https://github.com/Aoyuh/cve-2021-3019](https://github.com/Aoyuh/cve-2021-3019) :  ![starts](https://img.shields.io/github/stars/Aoyuh/cve-2021-3019.svg) ![forks](https://img.shields.io/github/forks/Aoyuh/cve-2021-3019.svg)

## CVE-2021-3007
 ** DISPUTED ** Laminas Project laminas-http before 2.14.2, and Zend Framework 3.0.0, has a deserialization vulnerability that can lead to remote code execution if the content is controllable, related to the __destruct method of the Zend\Http\Response\Stream class in Stream.php. NOTE: Zend Framework is no longer supported by the maintainer. NOTE: the laminas-http vendor considers this a &quot;vulnerability in the PHP language itself&quot; but has added certain type checking as a way to prevent exploitation in (unrecommended) use cases where attacker-supplied data can be deserialized.



- [https://github.com/Vulnmachines/ZF3_CVE-2021-3007](https://github.com/Vulnmachines/ZF3_CVE-2021-3007) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/ZF3_CVE-2021-3007.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/ZF3_CVE-2021-3007.svg)

## CVE-2021-2471
 Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions that are affected are 8.0.26 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Connectors. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all MySQL Connectors accessible data and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Connectors. CVSS 3.1 Base Score 5.9 (Confidentiality and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:H).



- [https://github.com/SecCoder-Security-Lab/jdbc-sqlxml-xxe](https://github.com/SecCoder-Security-Lab/jdbc-sqlxml-xxe) :  ![starts](https://img.shields.io/github/stars/SecCoder-Security-Lab/jdbc-sqlxml-xxe.svg) ![forks](https://img.shields.io/github/forks/SecCoder-Security-Lab/jdbc-sqlxml-xxe.svg)

- [https://github.com/cckuailong/CVE-2021-2471](https://github.com/cckuailong/CVE-2021-2471) :  ![starts](https://img.shields.io/github/stars/cckuailong/CVE-2021-2471.svg) ![forks](https://img.shields.io/github/forks/cckuailong/CVE-2021-2471.svg)

- [https://github.com/DrunkenShells/CVE-2021-2471](https://github.com/DrunkenShells/CVE-2021-2471) :  ![starts](https://img.shields.io/github/stars/DrunkenShells/CVE-2021-2471.svg) ![forks](https://img.shields.io/github/forks/DrunkenShells/CVE-2021-2471.svg)

## CVE-2021-2456
 Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Fusion Middleware (component: Analytics Web General). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this vulnerability can result in takeover of Oracle Business Intelligence Enterprise Edition. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/peterjson31337/CVE-2021-2456](https://github.com/peterjson31337/CVE-2021-2456) :  ![starts](https://img.shields.io/github/stars/peterjson31337/CVE-2021-2456.svg) ![forks](https://img.shields.io/github/forks/peterjson31337/CVE-2021-2456.svg)

## CVE-2021-2394
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/lz2y/CVE-2021-2394](https://github.com/lz2y/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/lz2y/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/lz2y/CVE-2021-2394.svg)

- [https://github.com/freeide/CVE-2021-2394](https://github.com/freeide/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/freeide/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/freeide/CVE-2021-2394.svg)

- [https://github.com/BabyTeam1024/CVE-2021-2394](https://github.com/BabyTeam1024/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/BabyTeam1024/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/BabyTeam1024/CVE-2021-2394.svg)

- [https://github.com/fasanhlieu/CVE-2021-2394](https://github.com/fasanhlieu/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/fasanhlieu/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/fasanhlieu/CVE-2021-2394.svg)

## CVE-2021-2302
 Vulnerability in the Oracle Platform Security for Java product of Oracle Fusion Middleware (component: OPSS). Supported versions that are affected are 11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Platform Security for Java. Successful attacks of this vulnerability can result in takeover of Oracle Platform Security for Java. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/quynhle7821/CVE-2021-2302](https://github.com/quynhle7821/CVE-2021-2302) :  ![starts](https://img.shields.io/github/stars/quynhle7821/CVE-2021-2302.svg) ![forks](https://img.shields.io/github/forks/quynhle7821/CVE-2021-2302.svg)

## CVE-2021-2173
 Vulnerability in the Recovery component of Oracle Database Server. Supported versions that are affected are 12.1.0.2, 12.2.0.1, 18c and 19c. Easily exploitable vulnerability allows high privileged attacker having DBA Level Account privilege with network access via Oracle Net to compromise Recovery. While the vulnerability is in Recovery, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Recovery accessible data. CVSS 3.1 Base Score 4.1 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:N).



- [https://github.com/emad-almousa/CVE-2021-2173](https://github.com/emad-almousa/CVE-2021-2173) :  ![starts](https://img.shields.io/github/stars/emad-almousa/CVE-2021-2173.svg) ![forks](https://img.shields.io/github/forks/emad-almousa/CVE-2021-2173.svg)

## CVE-2021-2119
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.0 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N).



- [https://github.com/Sauercloud/RWCTF21-VirtualBox-61-escape](https://github.com/Sauercloud/RWCTF21-VirtualBox-61-escape) :  ![starts](https://img.shields.io/github/stars/Sauercloud/RWCTF21-VirtualBox-61-escape.svg) ![forks](https://img.shields.io/github/forks/Sauercloud/RWCTF21-VirtualBox-61-escape.svg)

## CVE-2021-2109
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/Yang0615777/PocList](https://github.com/Yang0615777/PocList) :  ![starts](https://img.shields.io/github/stars/Yang0615777/PocList.svg) ![forks](https://img.shields.io/github/forks/Yang0615777/PocList.svg)

- [https://github.com/Al1ex/CVE-2021-2109](https://github.com/Al1ex/CVE-2021-2109) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-2109.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-2109.svg)

- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)

- [https://github.com/rabbitsafe/CVE-2021-2109](https://github.com/rabbitsafe/CVE-2021-2109) :  ![starts](https://img.shields.io/github/stars/rabbitsafe/CVE-2021-2109.svg) ![forks](https://img.shields.io/github/forks/rabbitsafe/CVE-2021-2109.svg)

- [https://github.com/yuaneuro/CVE-2021-2109_poc](https://github.com/yuaneuro/CVE-2021-2109_poc) :  ![starts](https://img.shields.io/github/stars/yuaneuro/CVE-2021-2109_poc.svg) ![forks](https://img.shields.io/github/forks/yuaneuro/CVE-2021-2109_poc.svg)

- [https://github.com/dinosn/CVE-2021-2109](https://github.com/dinosn/CVE-2021-2109) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2021-2109.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2021-2109.svg)

## CVE-2021-2108
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). The supported version that is affected is 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)

## CVE-2021-2075
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Samples). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)

## CVE-2021-2064
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). The supported version that is affected is 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)

## CVE-2021-2047
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)

## CVE-2021-2021
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/TheCryingGame/CVE-2021-2021good](https://github.com/TheCryingGame/CVE-2021-2021good) :  ![starts](https://img.shields.io/github/stars/TheCryingGame/CVE-2021-2021good.svg) ![forks](https://img.shields.io/github/forks/TheCryingGame/CVE-2021-2021good.svg)

## CVE-2021-1994
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Services). Supported versions that are affected are 10.3.6.0.0 and 12.1.3.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/somatrasss/weblogic2021](https://github.com/somatrasss/weblogic2021) :  ![starts](https://img.shields.io/github/stars/somatrasss/weblogic2021.svg) ![forks](https://img.shields.io/github/forks/somatrasss/weblogic2021.svg)

## CVE-2021-1906
 Improper handling of address deregistration on failure can lead to new GPU address allocation failure. in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice &amp; Music, Snapdragon Wearables



- [https://github.com/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664](https://github.com/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664) :  ![starts](https://img.shields.io/github/stars/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664.svg) ![forks](https://img.shields.io/github/forks/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664.svg)

## CVE-2021-1905
 Possible use after free due to improper handling of memory mapping of multiple processes simultaneously. in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice &amp; Music, Snapdragon Wearables



- [https://github.com/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664](https://github.com/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664) :  ![starts](https://img.shields.io/github/stars/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664.svg) ![forks](https://img.shields.io/github/forks/TAKIANFIF/CVE-2021-1905-CVE-2021-1906-CVE-2021-28663-CVE-2021-28664.svg)

## CVE-2021-1782
 A race condition was addressed with improved locking. This issue is fixed in macOS Big Sur 11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, watchOS 7.3, tvOS 14.4, iOS 14.4 and iPadOS 14.4. A malicious application may be able to elevate privileges. Apple is aware of a report that this issue may have been actively exploited..



- [https://github.com/synacktiv/CVE-2021-1782](https://github.com/synacktiv/CVE-2021-1782) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2021-1782.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2021-1782.svg)

## CVE-2021-1748
 A validation issue was addressed with improved input sanitization. This issue is fixed in tvOS 14.4, watchOS 7.3, iOS 14.4 and iPadOS 14.4. Processing a maliciously crafted URL may lead to arbitrary javascript code execution.



- [https://github.com/ChiChou/mistune-patch-backport](https://github.com/ChiChou/mistune-patch-backport) :  ![starts](https://img.shields.io/github/stars/ChiChou/mistune-patch-backport.svg) ![forks](https://img.shields.io/github/forks/ChiChou/mistune-patch-backport.svg)

- [https://github.com/Ivanhoe76zzzz/itmsBlock](https://github.com/Ivanhoe76zzzz/itmsBlock) :  ![starts](https://img.shields.io/github/stars/Ivanhoe76zzzz/itmsBlock.svg) ![forks](https://img.shields.io/github/forks/Ivanhoe76zzzz/itmsBlock.svg)

## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-1698.



- [https://github.com/Ascotbe/Kernelhub](https://github.com/Ascotbe/Kernelhub) :  ![starts](https://img.shields.io/github/stars/Ascotbe/Kernelhub.svg) ![forks](https://img.shields.io/github/forks/Ascotbe/Kernelhub.svg)

- [https://github.com/KaLendsi/CVE-2021-1732-Exploit](https://github.com/KaLendsi/CVE-2021-1732-Exploit) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2021-1732-Exploit.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2021-1732-Exploit.svg)

- [https://github.com/Al1ex/WindowsElevation](https://github.com/Al1ex/WindowsElevation) :  ![starts](https://img.shields.io/github/stars/Al1ex/WindowsElevation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/WindowsElevation.svg)

- [https://github.com/Pai-Po/CVE-2021-1732](https://github.com/Pai-Po/CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/Pai-Po/CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/Pai-Po/CVE-2021-1732.svg)

- [https://github.com/k-k-k-k-k/CVE-2021-1732](https://github.com/k-k-k-k-k/CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/k-k-k-k-k/CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/k-k-k-k-k/CVE-2021-1732.svg)

- [https://github.com/exploitblizzard/Windows-Privilege-Escalation-CVE-2021-1732](https://github.com/exploitblizzard/Windows-Privilege-Escalation-CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/exploitblizzard/Windows-Privilege-Escalation-CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/exploitblizzard/Windows-Privilege-Escalation-CVE-2021-1732.svg)

- [https://github.com/linuxdy/CVE-2021-1732_exp](https://github.com/linuxdy/CVE-2021-1732_exp) :  ![starts](https://img.shields.io/github/stars/linuxdy/CVE-2021-1732_exp.svg) ![forks](https://img.shields.io/github/forks/linuxdy/CVE-2021-1732_exp.svg)

- [https://github.com/jessica0f0116/cve_2021_1732](https://github.com/jessica0f0116/cve_2021_1732) :  ![starts](https://img.shields.io/github/stars/jessica0f0116/cve_2021_1732.svg) ![forks](https://img.shields.io/github/forks/jessica0f0116/cve_2021_1732.svg)

- [https://github.com/oneoy/CVE-2021-1732-Exploit](https://github.com/oneoy/CVE-2021-1732-Exploit) :  ![starts](https://img.shields.io/github/stars/oneoy/CVE-2021-1732-Exploit.svg) ![forks](https://img.shields.io/github/forks/oneoy/CVE-2021-1732-Exploit.svg)

- [https://github.com/BeneficialCode/CVE-2021-1732](https://github.com/BeneficialCode/CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/BeneficialCode/CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/BeneficialCode/CVE-2021-1732.svg)

## CVE-2021-1727
 Windows Installer Elevation of Privilege Vulnerability



- [https://github.com/klinix5/CVE-2021-1727](https://github.com/klinix5/CVE-2021-1727) :  ![starts](https://img.shields.io/github/stars/klinix5/CVE-2021-1727.svg) ![forks](https://img.shields.io/github/forks/klinix5/CVE-2021-1727.svg)

## CVE-2021-1699
 Windows (modem.sys) Information Disclosure Vulnerability



- [https://github.com/waleedassar/CVE-2021-1699](https://github.com/waleedassar/CVE-2021-1699) :  ![starts](https://img.shields.io/github/stars/waleedassar/CVE-2021-1699.svg) ![forks](https://img.shields.io/github/forks/waleedassar/CVE-2021-1699.svg)

## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability



- [https://github.com/cube0x0/CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/cube0x0/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/cube0x0/CVE-2021-1675.svg)

- [https://github.com/calebstewart/CVE-2021-1675](https://github.com/calebstewart/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/calebstewart/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/calebstewart/CVE-2021-1675.svg)

- [https://github.com/hlldz/CVE-2021-1675-LPE](https://github.com/hlldz/CVE-2021-1675-LPE) :  ![starts](https://img.shields.io/github/stars/hlldz/CVE-2021-1675-LPE.svg) ![forks](https://img.shields.io/github/forks/hlldz/CVE-2021-1675-LPE.svg)

- [https://github.com/BeetleChunks/SpoolSploit](https://github.com/BeetleChunks/SpoolSploit) :  ![starts](https://img.shields.io/github/stars/BeetleChunks/SpoolSploit.svg) ![forks](https://img.shields.io/github/forks/BeetleChunks/SpoolSploit.svg)

- [https://github.com/LaresLLC/CVE-2021-1675](https://github.com/LaresLLC/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/LaresLLC/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/LaresLLC/CVE-2021-1675.svg)

- [https://github.com/mstxq17/CVE-2021-1675_RDL_LPE](https://github.com/mstxq17/CVE-2021-1675_RDL_LPE) :  ![starts](https://img.shields.io/github/stars/mstxq17/CVE-2021-1675_RDL_LPE.svg) ![forks](https://img.shields.io/github/forks/mstxq17/CVE-2021-1675_RDL_LPE.svg)

- [https://github.com/ly4k/PrintNightmare](https://github.com/ly4k/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/ly4k/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/ly4k/PrintNightmare.svg)

- [https://github.com/sailay1996/PrintNightmare-LPE](https://github.com/sailay1996/PrintNightmare-LPE) :  ![starts](https://img.shields.io/github/stars/sailay1996/PrintNightmare-LPE.svg) ![forks](https://img.shields.io/github/forks/sailay1996/PrintNightmare-LPE.svg)

- [https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527](https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/nemo-wq/PrintNightmare-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/nemo-wq/PrintNightmare-CVE-2021-34527.svg)

- [https://github.com/evilashz/CVE-2021-1675-LPE-EXP](https://github.com/evilashz/CVE-2021-1675-LPE-EXP) :  ![starts](https://img.shields.io/github/stars/evilashz/CVE-2021-1675-LPE-EXP.svg) ![forks](https://img.shields.io/github/forks/evilashz/CVE-2021-1675-LPE-EXP.svg)

- [https://github.com/JumpsecLabs/PrintNightmare](https://github.com/JumpsecLabs/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/JumpsecLabs/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/JumpsecLabs/PrintNightmare.svg)

- [https://github.com/k8gege/cve-2021-1675](https://github.com/k8gege/cve-2021-1675) :  ![starts](https://img.shields.io/github/stars/k8gege/cve-2021-1675.svg) ![forks](https://img.shields.io/github/forks/k8gege/cve-2021-1675.svg)

- [https://github.com/cybersecurityworks553/CVE-2021-1675_PrintNightMare](https://github.com/cybersecurityworks553/CVE-2021-1675_PrintNightMare) :  ![starts](https://img.shields.io/github/stars/cybersecurityworks553/CVE-2021-1675_PrintNightMare.svg) ![forks](https://img.shields.io/github/forks/cybersecurityworks553/CVE-2021-1675_PrintNightMare.svg)

- [https://github.com/fumamatar/NimNightmare](https://github.com/fumamatar/NimNightmare) :  ![starts](https://img.shields.io/github/stars/fumamatar/NimNightmare.svg) ![forks](https://img.shields.io/github/forks/fumamatar/NimNightmare.svg)

- [https://github.com/Leonidus0x10/CVE-2021-1675-SCANNER](https://github.com/Leonidus0x10/CVE-2021-1675-SCANNER) :  ![starts](https://img.shields.io/github/stars/Leonidus0x10/CVE-2021-1675-SCANNER.svg) ![forks](https://img.shields.io/github/forks/Leonidus0x10/CVE-2021-1675-SCANNER.svg)

- [https://github.com/corelight/CVE-2021-1675](https://github.com/corelight/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/corelight/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/corelight/CVE-2021-1675.svg)

- [https://github.com/CnOxx1/CVE-2021-34527-1675](https://github.com/CnOxx1/CVE-2021-34527-1675) :  ![starts](https://img.shields.io/github/stars/CnOxx1/CVE-2021-34527-1675.svg) ![forks](https://img.shields.io/github/forks/CnOxx1/CVE-2021-34527-1675.svg)

- [https://github.com/exploitblizzard/PrintNightmare-CVE-2021-1675](https://github.com/exploitblizzard/PrintNightmare-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/exploitblizzard/PrintNightmare-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/exploitblizzard/PrintNightmare-CVE-2021-1675.svg)

- [https://github.com/thomasgeens/CVE-2021-1675](https://github.com/thomasgeens/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/thomasgeens/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/thomasgeens/CVE-2021-1675.svg)

- [https://github.com/kondah/patch-cve-2021-1675](https://github.com/kondah/patch-cve-2021-1675) :  ![starts](https://img.shields.io/github/stars/kondah/patch-cve-2021-1675.svg) ![forks](https://img.shields.io/github/forks/kondah/patch-cve-2021-1675.svg)

- [https://github.com/ozergoker/PrintNightmare](https://github.com/ozergoker/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/ozergoker/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/ozergoker/PrintNightmare.svg)

- [https://github.com/Wra7h/SharpPN](https://github.com/Wra7h/SharpPN) :  ![starts](https://img.shields.io/github/stars/Wra7h/SharpPN.svg) ![forks](https://img.shields.io/github/forks/Wra7h/SharpPN.svg)

- [https://github.com/bartimus-primed/CVE-2021-1675-Yara](https://github.com/bartimus-primed/CVE-2021-1675-Yara) :  ![starts](https://img.shields.io/github/stars/bartimus-primed/CVE-2021-1675-Yara.svg) ![forks](https://img.shields.io/github/forks/bartimus-primed/CVE-2021-1675-Yara.svg)

- [https://github.com/killtr0/CVE-2021-1675-PrintNightmare](https://github.com/killtr0/CVE-2021-1675-PrintNightmare) :  ![starts](https://img.shields.io/github/stars/killtr0/CVE-2021-1675-PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/killtr0/CVE-2021-1675-PrintNightmare.svg)

- [https://github.com/Tomparte/PrintNightmare](https://github.com/Tomparte/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/Tomparte/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/Tomparte/PrintNightmare.svg)

- [https://github.com/puckiestyle/CVE-2021-1675](https://github.com/puckiestyle/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-1675.svg)

- [https://github.com/tanarchytan/CVE-2021-1675](https://github.com/tanarchytan/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/tanarchytan/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/tanarchytan/CVE-2021-1675.svg)

- [https://github.com/yu2u/CVE-2021-1675](https://github.com/yu2u/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/yu2u/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/yu2u/CVE-2021-1675.svg)

- [https://github.com/kougyokugentou/CVE-2021-1675](https://github.com/kougyokugentou/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/kougyokugentou/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/kougyokugentou/CVE-2021-1675.svg)

- [https://github.com/Winter3un/CVE-2021-1675](https://github.com/Winter3un/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/Winter3un/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/Winter3un/CVE-2021-1675.svg)

- [https://github.com/hahaleyile/my-CVE-2021-1675](https://github.com/hahaleyile/my-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/hahaleyile/my-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/hahaleyile/my-CVE-2021-1675.svg)

- [https://github.com/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare](https://github.com/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare) :  ![starts](https://img.shields.io/github/stars/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/OppressionBreedsResistance/CVE-2021-1675-PrintNightmare.svg)

- [https://github.com/edsonjt81/CVE-2021-1675](https://github.com/edsonjt81/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/edsonjt81/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/edsonjt81/CVE-2021-1675.svg)

- [https://github.com/ptter23/CVE-2021-1675](https://github.com/ptter23/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/ptter23/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/ptter23/CVE-2021-1675.svg)

- [https://github.com/thalpius/Microsoft-CVE-2021-1675](https://github.com/thalpius/Microsoft-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/thalpius/Microsoft-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/thalpius/Microsoft-CVE-2021-1675.svg)

- [https://github.com/initconf/cve-2021-1675-printnightmare](https://github.com/initconf/cve-2021-1675-printnightmare) :  ![starts](https://img.shields.io/github/stars/initconf/cve-2021-1675-printnightmare.svg) ![forks](https://img.shields.io/github/forks/initconf/cve-2021-1675-printnightmare.svg)

- [https://github.com/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery](https://github.com/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery) :  ![starts](https://img.shields.io/github/stars/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery.svg) ![forks](https://img.shields.io/github/forks/mrezqi/CVE-2021-1675_CarbonBlack_HuntingQuery.svg)

- [https://github.com/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527](https://github.com/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/galoget/PrintNightmare-CVE-2021-1675-CVE-2021-34527.svg)

- [https://github.com/gohrenberg/CVE-2021-1675-Mitigation-For-Systems-That-Need-Spooler](https://github.com/gohrenberg/CVE-2021-1675-Mitigation-For-Systems-That-Need-Spooler) :  ![starts](https://img.shields.io/github/stars/gohrenberg/CVE-2021-1675-Mitigation-For-Systems-That-Need-Spooler.svg) ![forks](https://img.shields.io/github/forks/gohrenberg/CVE-2021-1675-Mitigation-For-Systems-That-Need-Spooler.svg)

- [https://github.com/NickSanzotta/zeroscan](https://github.com/NickSanzotta/zeroscan) :  ![starts](https://img.shields.io/github/stars/NickSanzotta/zeroscan.svg) ![forks](https://img.shields.io/github/forks/NickSanzotta/zeroscan.svg)

- [https://github.com/zha0/Microsoft-CVE-2021-1675](https://github.com/zha0/Microsoft-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/zha0/Microsoft-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/zha0/Microsoft-CVE-2021-1675.svg)

- [https://github.com/DenizSe/CVE-2021-34527](https://github.com/DenizSe/CVE-2021-34527) :  ![starts](https://img.shields.io/github/stars/DenizSe/CVE-2021-34527.svg) ![forks](https://img.shields.io/github/forks/DenizSe/CVE-2021-34527.svg)

- [https://github.com/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R.](https://github.com/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R.) :  ![starts](https://img.shields.io/github/stars/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R..svg) ![forks](https://img.shields.io/github/forks/Sirius-RJ/FullstackAcademy-Printernightmare-writeup-2105-E.C.A.R..svg)

## CVE-2021-1656
 TPM Device Driver Information Disclosure Vulnerability



- [https://github.com/waleedassar/CVE-2021-1656](https://github.com/waleedassar/CVE-2021-1656) :  ![starts](https://img.shields.io/github/stars/waleedassar/CVE-2021-1656.svg) ![forks](https://img.shields.io/github/forks/waleedassar/CVE-2021-1656.svg)

## CVE-2021-1647
 Microsoft Defender Remote Code Execution Vulnerability



- [https://github.com/dmlgzs/cve-2021-1647](https://github.com/dmlgzs/cve-2021-1647) :  ![starts](https://img.shields.io/github/stars/dmlgzs/cve-2021-1647.svg) ![forks](https://img.shields.io/github/forks/dmlgzs/cve-2021-1647.svg)

## CVE-2021-1499
 A vulnerability in the web-based management interface of Cisco HyperFlex HX Data Platform could allow an unauthenticated, remote attacker to upload files to an affected device. This vulnerability is due to missing authentication for the upload function. An attacker could exploit this vulnerability by sending a specific HTTP request to an affected device. A successful exploit could allow the attacker to upload files to the affected device with the permissions of the tomcat8 user.



- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)

## CVE-2021-1498
 Multiple vulnerabilities in the web-based management interface of Cisco HyperFlex HX could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device. For more information about these vulnerabilities, see the Details section of this advisory.



- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)

## CVE-2021-1480
 Multiple vulnerabilities in Cisco SD-WAN vManage Software could allow an unauthenticated, remote attacker to execute arbitrary code or allow an authenticated, local attacker to gain escalated privileges on an affected system. For more information about these vulnerabilities, see the Details section of this advisory.



- [https://github.com/xmco/sdwan-cve-2021-1480](https://github.com/xmco/sdwan-cve-2021-1480) :  ![starts](https://img.shields.io/github/stars/xmco/sdwan-cve-2021-1480.svg) ![forks](https://img.shields.io/github/forks/xmco/sdwan-cve-2021-1480.svg)

## CVE-2021-1234
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/zoukba0014/cve-2021-123456](https://github.com/zoukba0014/cve-2021-123456) :  ![starts](https://img.shields.io/github/stars/zoukba0014/cve-2021-123456.svg) ![forks](https://img.shields.io/github/forks/zoukba0014/cve-2021-123456.svg)

## CVE-2021-1112
 NVIDIA Linux kernel distributions contain a vulnerability in nvmap, where a null pointer dereference may lead to complete denial of service.



- [https://github.com/chenanu123/cve-2021-11123](https://github.com/chenanu123/cve-2021-11123) :  ![starts](https://img.shields.io/github/stars/chenanu123/cve-2021-11123.svg) ![forks](https://img.shields.io/github/forks/chenanu123/cve-2021-11123.svg)

## CVE-2021-1056
 NVIDIA GPU Display Driver for Linux, all versions, contains a vulnerability in the kernel mode layer (nvidia.ko) in which it does not completely honor operating system file system permissions to provide GPU device-level isolation, which may lead to denial of service or information disclosure.



- [https://github.com/pokerfaceSad/CVE-2021-1056](https://github.com/pokerfaceSad/CVE-2021-1056) :  ![starts](https://img.shields.io/github/stars/pokerfaceSad/CVE-2021-1056.svg) ![forks](https://img.shields.io/github/forks/pokerfaceSad/CVE-2021-1056.svg)

## CVE-2021-1008
 In addSubInfo of SubscriptionController.java, there is a possible way to force the user to make a factory reset due to a logic error in the code. This could lead to local denial of service with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12Android ID: A-197327688



- [https://github.com/xiaoyun-1/CVE-2021-10086](https://github.com/xiaoyun-1/CVE-2021-10086) :  ![starts](https://img.shields.io/github/stars/xiaoyun-1/CVE-2021-10086.svg) ![forks](https://img.shields.io/github/forks/xiaoyun-1/CVE-2021-10086.svg)
