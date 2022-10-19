# Update 2022-10-19
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/SeanWrightSec/CVE-2022-42889-PoC](https://github.com/SeanWrightSec/CVE-2022-42889-PoC) :  ![starts](https://img.shields.io/github/stars/SeanWrightSec/CVE-2022-42889-PoC.svg) ![forks](https://img.shields.io/github/forks/SeanWrightSec/CVE-2022-42889-PoC.svg)
- [https://github.com/standb/CVE-2022-42889](https://github.com/standb/CVE-2022-42889) :  ![starts](https://img.shields.io/github/stars/standb/CVE-2022-42889.svg) ![forks](https://img.shields.io/github/forks/standb/CVE-2022-42889.svg)
- [https://github.com/pr0n3d/CVE-2022-42889-MASS-RCE](https://github.com/pr0n3d/CVE-2022-42889-MASS-RCE) :  ![starts](https://img.shields.io/github/stars/pr0n3d/CVE-2022-42889-MASS-RCE.svg) ![forks](https://img.shields.io/github/forks/pr0n3d/CVE-2022-42889-MASS-RCE.svg)


## CVE-2022-41082
 Microsoft Exchange Server Remote Code Execution Vulnerability.

- [https://github.com/backcr4t/CVE-2022-41082-RCE](https://github.com/backcr4t/CVE-2022-41082-RCE) :  ![starts](https://img.shields.io/github/stars/backcr4t/CVE-2022-41082-RCE.svg) ![forks](https://img.shields.io/github/forks/backcr4t/CVE-2022-41082-RCE.svg)


## CVE-2022-41040
 Microsoft Exchange Server Elevation of Privilege Vulnerability.

- [https://github.com/backcr4t/CVE-2022-41082-RCE](https://github.com/backcr4t/CVE-2022-41082-RCE) :  ![starts](https://img.shields.io/github/stars/backcr4t/CVE-2022-41082-RCE.svg) ![forks](https://img.shields.io/github/forks/backcr4t/CVE-2022-41082-RCE.svg)


## CVE-2022-40684
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jsongmax/Fortinet-CVE-2022-40684](https://github.com/jsongmax/Fortinet-CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/jsongmax/Fortinet-CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/jsongmax/Fortinet-CVE-2022-40684.svg)
- [https://github.com/mohamedbenchikh/FortiPWN](https://github.com/mohamedbenchikh/FortiPWN) :  ![starts](https://img.shields.io/github/stars/mohamedbenchikh/FortiPWN.svg) ![forks](https://img.shields.io/github/forks/mohamedbenchikh/FortiPWN.svg)
- [https://github.com/puckiestyle/CVE-2022-40684](https://github.com/puckiestyle/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2022-40684.svg)


## CVE-2022-39197
 An XSS (Cross Site Scripting) vulnerability was found in HelpSystems Cobalt Strike through 4.7 that allowed a remote attacker to execute HTML on the Cobalt Strike teamserver. To exploit the vulnerability, one must first inspect a Cobalt Strike payload, and then modify the username field in the payload (or create a new payload with the extracted information and then modify that username field to be malformed).

- [https://github.com/its-arun/CVE-2022-39197](https://github.com/its-arun/CVE-2022-39197) :  ![starts](https://img.shields.io/github/stars/its-arun/CVE-2022-39197.svg) ![forks](https://img.shields.io/github/forks/its-arun/CVE-2022-39197.svg)
- [https://github.com/PyterSmithDarkGhost/CVE-2022-39197-POC](https://github.com/PyterSmithDarkGhost/CVE-2022-39197-POC) :  ![starts](https://img.shields.io/github/stars/PyterSmithDarkGhost/CVE-2022-39197-POC.svg) ![forks](https://img.shields.io/github/forks/PyterSmithDarkGhost/CVE-2022-39197-POC.svg)


## CVE-2022-36067
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. In versions prior to version 3.9.11, a threat actor can bypass the sandbox protections to gain remote code execution rights on the host running the sandbox. This vulnerability was patched in the release of version 3.9.11 of vm2. There are no known workarounds.

- [https://github.com/backcr4t/CVE-2022-36067-MASS-RCE](https://github.com/backcr4t/CVE-2022-36067-MASS-RCE) :  ![starts](https://img.shields.io/github/stars/backcr4t/CVE-2022-36067-MASS-RCE.svg) ![forks](https://img.shields.io/github/forks/backcr4t/CVE-2022-36067-MASS-RCE.svg)


## CVE-2022-33980
 Apache Commons Configuration performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.configuration2.interpol.Lookup that performs the interpolation. Starting with version 2.4 and continuing through 2.7, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Configuration 2.8.0, which disables the problematic interpolators by default.

- [https://github.com/sammwyy/CVE-2022-33980-POC](https://github.com/sammwyy/CVE-2022-33980-POC) :  ![starts](https://img.shields.io/github/stars/sammwyy/CVE-2022-33980-POC.svg) ![forks](https://img.shields.io/github/forks/sammwyy/CVE-2022-33980-POC.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/xanszZZ/ATLASSIAN-Confluence_rce](https://github.com/xanszZZ/ATLASSIAN-Confluence_rce) :  ![starts](https://img.shields.io/github/stars/xanszZZ/ATLASSIAN-Confluence_rce.svg) ![forks](https://img.shields.io/github/forks/xanszZZ/ATLASSIAN-Confluence_rce.svg)


## CVE-2022-24990
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jsongmax/terraMaster-CVE-2022-24990](https://github.com/jsongmax/terraMaster-CVE-2022-24990) :  ![starts](https://img.shields.io/github/stars/jsongmax/terraMaster-CVE-2022-24990.svg) ![forks](https://img.shields.io/github/forks/jsongmax/terraMaster-CVE-2022-24990.svg)


## CVE-2022-21882
 Win32k Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21887.

- [https://github.com/jessica0f0116/cve_2022_21882-cve_2021_1732](https://github.com/jessica0f0116/cve_2022_21882-cve_2021_1732) :  ![starts](https://img.shields.io/github/stars/jessica0f0116/cve_2022_21882-cve_2021_1732.svg) ![forks](https://img.shields.io/github/forks/jessica0f0116/cve_2022_21882-cve_2021_1732.svg)


## CVE-2022-3236
 A code injection vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v19.0 MR1 and older.

- [https://github.com/n0npro/CVE-2022-3236-MASS-RCE](https://github.com/n0npro/CVE-2022-3236-MASS-RCE) :  ![starts](https://img.shields.io/github/stars/n0npro/CVE-2022-3236-MASS-RCE.svg) ![forks](https://img.shields.io/github/forks/n0npro/CVE-2022-3236-MASS-RCE.svg)


## CVE-2022-0824
 Improper Access Control to Remote Code Execution in GitHub repository webmin/webmin prior to 1.990.

- [https://github.com/pizza-power/golang-webmin-CVE-2022-0824-revshell](https://github.com/pizza-power/golang-webmin-CVE-2022-0824-revshell) :  ![starts](https://img.shields.io/github/stars/pizza-power/golang-webmin-CVE-2022-0824-revshell.svg) ![forks](https://img.shields.io/github/forks/pizza-power/golang-webmin-CVE-2022-0824-revshell.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/defhacks/cve-2021-4034](https://github.com/defhacks/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/defhacks/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/defhacks/cve-2021-4034.svg)
- [https://github.com/k4u5h41/CVE-2021-4034](https://github.com/k4u5h41/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/k4u5h41/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/k4u5h41/CVE-2021-4034.svg)


## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-1698.

- [https://github.com/jessica0f0116/cve_2022_21882-cve_2021_1732](https://github.com/jessica0f0116/cve_2022_21882-cve_2021_1732) :  ![starts](https://img.shields.io/github/stars/jessica0f0116/cve_2022_21882-cve_2021_1732.svg) ![forks](https://img.shields.io/github/forks/jessica0f0116/cve_2022_21882-cve_2021_1732.svg)


## CVE-2014-3704
 The expandArguments function in the database abstraction API in Drupal core 7.x before 7.32 does not properly construct prepared statements, which allows remote attackers to conduct SQL injection attacks via an array containing crafted keys.

- [https://github.com/AleDiBen/Drupalgeddon](https://github.com/AleDiBen/Drupalgeddon) :  ![starts](https://img.shields.io/github/stars/AleDiBen/Drupalgeddon.svg) ![forks](https://img.shields.io/github/forks/AleDiBen/Drupalgeddon.svg)

