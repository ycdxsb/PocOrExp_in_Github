# Update 2023-09-15
## CVE-2023-42362
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Mr-n0b3dy/CVE-2023-42362](https://github.com/Mr-n0b3dy/CVE-2023-42362) :  ![starts](https://img.shields.io/github/stars/Mr-n0b3dy/CVE-2023-42362.svg) ![forks](https://img.shields.io/github/forks/Mr-n0b3dy/CVE-2023-42362.svg)


## CVE-2023-4863
 Heap buffer overflow in WebP in Google Chrome prior to 116.0.5845.187 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/suhipek/CVE-2023-4863](https://github.com/suhipek/CVE-2023-4863) :  ![starts](https://img.shields.io/github/stars/suhipek/CVE-2023-4863.svg) ![forks](https://img.shields.io/github/forks/suhipek/CVE-2023-4863.svg)


## CVE-2023-3244
 The Comments Like Dislike plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the restore_settings function called via an AJAX action in versions up to, and including, 1.1.9. This makes it possible for authenticated attackers with minimal permissions, such as a subscriber, to reset the plugin's settings. NOTE: After attempting to contact the developer with no response, and reporting this to the WordPress plugin's team 30 days ago we are disclosing this issue as it still is not updated.

- [https://github.com/drnull03/POC-CVE-2023-3244](https://github.com/drnull03/POC-CVE-2023-3244) :  ![starts](https://img.shields.io/github/stars/drnull03/POC-CVE-2023-3244.svg) ![forks](https://img.shields.io/github/forks/drnull03/POC-CVE-2023-3244.svg)


## CVE-2022-32862
 This issue was addressed with improved data protection. This issue is fixed in macOS Big Sur 11.7.1, macOS Ventura 13, macOS Monterey 12.6.1. An app with root privileges may be able to access private information.

- [https://github.com/rohitc33/CVE-2022-32862](https://github.com/rohitc33/CVE-2022-32862) :  ![starts](https://img.shields.io/github/stars/rohitc33/CVE-2022-32862.svg) ![forks](https://img.shields.io/github/forks/rohitc33/CVE-2022-32862.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/AbdulRKB/Follina](https://github.com/AbdulRKB/Follina) :  ![starts](https://img.shields.io/github/stars/AbdulRKB/Follina.svg) ![forks](https://img.shields.io/github/forks/AbdulRKB/Follina.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/f0ng/log4j2burpscanner](https://github.com/f0ng/log4j2burpscanner) :  ![starts](https://img.shields.io/github/stars/f0ng/log4j2burpscanner.svg) ![forks](https://img.shields.io/github/forks/f0ng/log4j2burpscanner.svg)
- [https://github.com/giterlizzi/nmap-log4shell](https://github.com/giterlizzi/nmap-log4shell) :  ![starts](https://img.shields.io/github/stars/giterlizzi/nmap-log4shell.svg) ![forks](https://img.shields.io/github/forks/giterlizzi/nmap-log4shell.svg)
- [https://github.com/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab](https://github.com/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab) :  ![starts](https://img.shields.io/github/stars/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab.svg) ![forks](https://img.shields.io/github/forks/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab.svg)
- [https://github.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228](https://github.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228.svg)
- [https://github.com/Hydragyrum/evil-rmi-server](https://github.com/Hydragyrum/evil-rmi-server) :  ![starts](https://img.shields.io/github/stars/Hydragyrum/evil-rmi-server.svg) ![forks](https://img.shields.io/github/forks/Hydragyrum/evil-rmi-server.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/blasty/CVE-2021-41773](https://github.com/blasty/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/blasty/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/blasty/CVE-2021-41773.svg)
- [https://github.com/iilegacyyii/PoC-CVE-2021-41773](https://github.com/iilegacyyii/PoC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/iilegacyyii/PoC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/iilegacyyii/PoC-CVE-2021-41773.svg)
- [https://github.com/noflowpls/CVE-2021-41773](https://github.com/noflowpls/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/noflowpls/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/noflowpls/CVE-2021-41773.svg)
- [https://github.com/LudovicPatho/CVE-2021-41773](https://github.com/LudovicPatho/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LudovicPatho/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LudovicPatho/CVE-2021-41773.svg)
- [https://github.com/i6c/MASS_CVE-2021-41773](https://github.com/i6c/MASS_CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/i6c/MASS_CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/i6c/MASS_CVE-2021-41773.svg)
- [https://github.com/lopqto/CVE-2021-41773_Honeypot](https://github.com/lopqto/CVE-2021-41773_Honeypot) :  ![starts](https://img.shields.io/github/stars/lopqto/CVE-2021-41773_Honeypot.svg) ![forks](https://img.shields.io/github/forks/lopqto/CVE-2021-41773_Honeypot.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)
- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)
- [https://github.com/DoTuan1/Reserch-CVE-2021-41773](https://github.com/DoTuan1/Reserch-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/DoTuan1/Reserch-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/DoTuan1/Reserch-CVE-2021-41773.svg)
- [https://github.com/mightysai1997/CVE-2021-41773-i-](https://github.com/mightysai1997/CVE-2021-41773-i-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-i-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-i-.svg)


## CVE-2021-30190
 CODESYS V2 Web-Server before 1.1.9.20 has Improper Access Control.

- [https://github.com/AbdulRKB/Follina](https://github.com/AbdulRKB/Follina) :  ![starts](https://img.shields.io/github/stars/AbdulRKB/Follina.svg) ![forks](https://img.shields.io/github/forks/AbdulRKB/Follina.svg)


## CVE-2020-9934
 An issue existed in the handling of environment variables. This issue was addressed with improved validation. This issue is fixed in iOS 13.6 and iPadOS 13.6, macOS Catalina 10.15.6. A local user may be able to view sensitive user information.

- [https://github.com/mattshockl/CVE-2020-9934](https://github.com/mattshockl/CVE-2020-9934) :  ![starts](https://img.shields.io/github/stars/mattshockl/CVE-2020-9934.svg) ![forks](https://img.shields.io/github/forks/mattshockl/CVE-2020-9934.svg)


## CVE-2019-8341
 ** DISPUTED ** An issue was discovered in Jinja2 2.10. The from_string function is prone to Server Side Template Injection (SSTI) where it takes the &quot;source&quot; parameter as a template object, renders it, and then returns it. The attacker can exploit it with {{INJECTION COMMANDS}} in a URI. NOTE: The maintainer and multiple third parties believe that this vulnerability isn't valid because users shouldn't use untrusted templates without sandboxing.

- [https://github.com/adindrabkin/llama_facts](https://github.com/adindrabkin/llama_facts) :  ![starts](https://img.shields.io/github/stars/adindrabkin/llama_facts.svg) ![forks](https://img.shields.io/github/forks/adindrabkin/llama_facts.svg)


## CVE-2018-1000861
 A code execution vulnerability exists in the Stapler web framework used by Jenkins 2.153 and earlier, LTS 2.138.3 and earlier in stapler/core/src/main/java/org/kohsuke/stapler/MetaClass.java that allows attackers to invoke some methods on Java objects by accessing crafted URLs that were not intended to be invoked this way.

- [https://github.com/smokeintheshell/CVE-2018-1000861](https://github.com/smokeintheshell/CVE-2018-1000861) :  ![starts](https://img.shields.io/github/stars/smokeintheshell/CVE-2018-1000861.svg) ![forks](https://img.shields.io/github/forks/smokeintheshell/CVE-2018-1000861.svg)


## CVE-2017-9805
 The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.

- [https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805](https://github.com/Lone-Ranger/apache-struts-pwn_CVE-2017-9805) :  ![starts](https://img.shields.io/github/stars/Lone-Ranger/apache-struts-pwn_CVE-2017-9805.svg) ![forks](https://img.shields.io/github/forks/Lone-Ranger/apache-struts-pwn_CVE-2017-9805.svg)


## CVE-2017-5689
 An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).

- [https://github.com/TheWay-hue/CVE-2017-5689-Checker](https://github.com/TheWay-hue/CVE-2017-5689-Checker) :  ![starts](https://img.shields.io/github/stars/TheWay-hue/CVE-2017-5689-Checker.svg) ![forks](https://img.shields.io/github/forks/TheWay-hue/CVE-2017-5689-Checker.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/0xTabun/CVE-2014-6271](https://github.com/0xTabun/CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/0xTabun/CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/0xTabun/CVE-2014-6271.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the &quot;username map script&quot; smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/0xTabun/CVE-2007-2447](https://github.com/0xTabun/CVE-2007-2447) :  ![starts](https://img.shields.io/github/stars/0xTabun/CVE-2007-2447.svg) ![forks](https://img.shields.io/github/forks/0xTabun/CVE-2007-2447.svg)

