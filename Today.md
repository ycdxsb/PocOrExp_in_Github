# Update 2021-12-11
## CVE-2021-44228
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jas502n/Log4j2-CVE-2021-44228](https://github.com/jas502n/Log4j2-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/jas502n/Log4j2-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/jas502n/Log4j2-CVE-2021-44228.svg)
- [https://github.com/jacobtread/L4J-Vuln-Patch](https://github.com/jacobtread/L4J-Vuln-Patch) :  ![starts](https://img.shields.io/github/stars/jacobtread/L4J-Vuln-Patch.svg) ![forks](https://img.shields.io/github/forks/jacobtread/L4J-Vuln-Patch.svg)
- [https://github.com/Glease/Healer](https://github.com/Glease/Healer) :  ![starts](https://img.shields.io/github/stars/Glease/Healer.svg) ![forks](https://img.shields.io/github/forks/Glease/Healer.svg)
- [https://github.com/UltraVanilla/LogJackFix](https://github.com/UltraVanilla/LogJackFix) :  ![starts](https://img.shields.io/github/stars/UltraVanilla/LogJackFix.svg) ![forks](https://img.shields.io/github/forks/UltraVanilla/LogJackFix.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools](https://github.com/Anonymous-ghost/AttackWebFrameworkTools) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools.svg)
- [https://github.com/z3n70/CVE-2021-43798](https://github.com/z3n70/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/z3n70/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/z3n70/CVE-2021-43798.svg)
- [https://github.com/fanygit/Grafana-CVE-2021-43798Exp](https://github.com/fanygit/Grafana-CVE-2021-43798Exp) :  ![starts](https://img.shields.io/github/stars/fanygit/Grafana-CVE-2021-43798Exp.svg) ![forks](https://img.shields.io/github/forks/fanygit/Grafana-CVE-2021-43798Exp.svg)
- [https://github.com/culprits/Grafana_POC-CVE-2021-43798](https://github.com/culprits/Grafana_POC-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/culprits/Grafana_POC-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/culprits/Grafana_POC-CVE-2021-43798.svg)
- [https://github.com/julesbozouklian/CVE-2021-43798](https://github.com/julesbozouklian/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/julesbozouklian/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/julesbozouklian/CVE-2021-43798.svg)


## CVE-2021-27928
 A remote code execution issue was discovered in MariaDB 10.2 before 10.2.37, 10.3 before 10.3.28, 10.4 before 10.4.18, and 10.5 before 10.5.9; Percona Server through 2021-03-03; and the wsrep patch through 2021-03-03 for MySQL. An untrusted search path leads to eval injection, in which a database SUPER user can execute OS commands after modifying wsrep_provider and wsrep_notify_cmd. NOTE: this does not affect an Oracle product.

- [https://github.com/shamo0/CVE-2021-27928-POC](https://github.com/shamo0/CVE-2021-27928-POC) :  ![starts](https://img.shields.io/github/stars/shamo0/CVE-2021-27928-POC.svg) ![forks](https://img.shields.io/github/forks/shamo0/CVE-2021-27928-POC.svg)


## CVE-2021-26102
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/SleepyCofe/CVE-2021-26102](https://github.com/SleepyCofe/CVE-2021-26102) :  ![starts](https://img.shields.io/github/stars/SleepyCofe/CVE-2021-26102.svg) ![forks](https://img.shields.io/github/forks/SleepyCofe/CVE-2021-26102.svg)


## CVE-2019-19609
 The Strapi framework before 3.0.0-beta.17.8 is vulnerable to Remote Code Execution in the Install and Uninstall Plugin components of the Admin panel, because it does not sanitize the plugin name, and attackers can inject arbitrary shell commands to be executed by the execa function.

- [https://github.com/RamPanic/CVE-2019-19609-EXPLOIT](https://github.com/RamPanic/CVE-2019-19609-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/RamPanic/CVE-2019-19609-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/RamPanic/CVE-2019-19609-EXPLOIT.svg)


## CVE-2019-18276
 An issue was discovered in disable_priv_mode in shell.c in GNU Bash through 5.0 patch 11. By default, if Bash is run with its effective UID not equal to its real UID, it will drop privileges by setting its effective UID to its real UID. However, it does so incorrectly. On Linux and other systems that support &quot;saved UID&quot; functionality, the saved UID is not dropped. An attacker with command execution in the shell can use &quot;enable -f&quot; for runtime loading of a new builtin, which can be a shared object that calls setuid() and therefore regains privileges. However, binaries running with an effective UID of 0 are unaffected.

- [https://github.com/M-ensimag/CVE-2019-18276](https://github.com/M-ensimag/CVE-2019-18276) :  ![starts](https://img.shields.io/github/stars/M-ensimag/CVE-2019-18276.svg) ![forks](https://img.shields.io/github/forks/M-ensimag/CVE-2019-18276.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/Marbocatcat/46635.py](https://github.com/Marbocatcat/46635.py) :  ![starts](https://img.shields.io/github/stars/Marbocatcat/46635.py.svg) ![forks](https://img.shields.io/github/forks/Marbocatcat/46635.py.svg)


## CVE-2018-1207
 Dell EMC iDRAC7/iDRAC8, versions prior to 2.52.52.52, contain CGI injection vulnerability which could be used to execute remote code. A remote unauthenticated attacker may potentially be able to use CGI variables to execute remote code.

- [https://github.com/mgargiullo/cve-2018-1207](https://github.com/mgargiullo/cve-2018-1207) :  ![starts](https://img.shields.io/github/stars/mgargiullo/cve-2018-1207.svg) ![forks](https://img.shields.io/github/forks/mgargiullo/cve-2018-1207.svg)


## CVE-2017-9097
 In Anti-Web through 3.8.7, as used on NetBiter FGW200 devices through 3.21.2, WS100 devices through 3.30.5, EC150 devices through 1.40.0, WS200 devices through 3.30.4, EC250 devices through 1.40.0, and other products, an LFI vulnerability allows a remote attacker to read or modify files through a path traversal technique, as demonstrated by reading the password file, or using the template parameter to cgi-bin/write.cgi to write to an arbitrary file.

- [https://github.com/MDudek-ICS/AntiWeb_testing-Suite](https://github.com/MDudek-ICS/AntiWeb_testing-Suite) :  ![starts](https://img.shields.io/github/stars/MDudek-ICS/AntiWeb_testing-Suite.svg) ![forks](https://img.shields.io/github/forks/MDudek-ICS/AntiWeb_testing-Suite.svg)


## CVE-2012-2982
 file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.

- [https://github.com/R00tendo/CVE-2012-2982](https://github.com/R00tendo/CVE-2012-2982) :  ![starts](https://img.shields.io/github/stars/R00tendo/CVE-2012-2982.svg) ![forks](https://img.shields.io/github/forks/R00tendo/CVE-2012-2982.svg)

