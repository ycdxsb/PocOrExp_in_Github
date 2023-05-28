# Update 2023-05-28
## CVE-2023-33617
 An OS Command Injection vulnerability in Parks Fiberlink 210 firmware version V2.1.14_X000 was found via the /boaform/admin/formPing target_addr parameter.

- [https://github.com/tucommenceapousser/CVE-2023-33617](https://github.com/tucommenceapousser/CVE-2023-33617) :  ![starts](https://img.shields.io/github/stars/tucommenceapousser/CVE-2023-33617.svg) ![forks](https://img.shields.io/github/forks/tucommenceapousser/CVE-2023-33617.svg)
- [https://github.com/Chocapikk/CVE-2023-33617](https://github.com/Chocapikk/CVE-2023-33617) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2023-33617.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2023-33617.svg)


## CVE-2023-32243
 Improper Authentication vulnerability in WPDeveloper Essential Addons for Elementor allows Privilege Escalation. This issue affects Essential Addons for Elementor: from 5.4.0 through 5.7.1.

- [https://github.com/hheeyywweellccoommee/Mass-CVE-2023-32243-kcpqa](https://github.com/hheeyywweellccoommee/Mass-CVE-2023-32243-kcpqa) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/Mass-CVE-2023-32243-kcpqa.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/Mass-CVE-2023-32243-kcpqa.svg)


## CVE-2023-31047
 In Django 3.2 before 3.2.19, 4.x before 4.1.9, and 4.2 before 4.2.1, it was possible to bypass validation when using one form field to upload multiple files. This multiple upload has never been supported by forms.FileField or forms.ImageField (only the last uploaded file was validated). However, Django's &quot;Uploading multiple files&quot; documentation suggested otherwise.

- [https://github.com/hheeyywweellccoommee/Django_rce-nwvba](https://github.com/hheeyywweellccoommee/Django_rce-nwvba) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/Django_rce-nwvba.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/Django_rce-nwvba.svg)


## CVE-2023-30212
 OURPHP &lt;= 7.2.0 is vulnerale to Cross Site Scripting (XSS) via /client/manage/ourphp_out.php.

- [https://github.com/libas7994/CVE-2023-30212](https://github.com/libas7994/CVE-2023-30212) :  ![starts](https://img.shields.io/github/stars/libas7994/CVE-2023-30212.svg) ![forks](https://img.shields.io/github/forks/libas7994/CVE-2023-30212.svg)
- [https://github.com/mallutrojan/CVE-2023-30212-Lab](https://github.com/mallutrojan/CVE-2023-30212-Lab) :  ![starts](https://img.shields.io/github/stars/mallutrojan/CVE-2023-30212-Lab.svg) ![forks](https://img.shields.io/github/forks/mallutrojan/CVE-2023-30212-Lab.svg)
- [https://github.com/Anandhu990/CVE-2023-30212-iab](https://github.com/Anandhu990/CVE-2023-30212-iab) :  ![starts](https://img.shields.io/github/stars/Anandhu990/CVE-2023-30212-iab.svg) ![forks](https://img.shields.io/github/forks/Anandhu990/CVE-2023-30212-iab.svg)
- [https://github.com/Anandhu990/CVE-2023-30212_lab](https://github.com/Anandhu990/CVE-2023-30212_lab) :  ![starts](https://img.shields.io/github/stars/Anandhu990/CVE-2023-30212_lab.svg) ![forks](https://img.shields.io/github/forks/Anandhu990/CVE-2023-30212_lab.svg)
- [https://github.com/Anandhu990/r-CVE-2023-30212-lab](https://github.com/Anandhu990/r-CVE-2023-30212-lab) :  ![starts](https://img.shields.io/github/stars/Anandhu990/r-CVE-2023-30212-lab.svg) ![forks](https://img.shields.io/github/forks/Anandhu990/r-CVE-2023-30212-lab.svg)
- [https://github.com/Anandhu990/r-CVE-2023-30212--lab](https://github.com/Anandhu990/r-CVE-2023-30212--lab) :  ![starts](https://img.shields.io/github/stars/Anandhu990/r-CVE-2023-30212--lab.svg) ![forks](https://img.shields.io/github/forks/Anandhu990/r-CVE-2023-30212--lab.svg)
- [https://github.com/libasmon/Vulnerable-Docker-Environment-CVE-2023-30212](https://github.com/libasmon/Vulnerable-Docker-Environment-CVE-2023-30212) :  ![starts](https://img.shields.io/github/stars/libasmon/Vulnerable-Docker-Environment-CVE-2023-30212.svg) ![forks](https://img.shields.io/github/forks/libasmon/Vulnerable-Docker-Environment-CVE-2023-30212.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/cryxnet/CVE-2022-42889-RCE](https://github.com/cryxnet/CVE-2022-42889-RCE) :  ![starts](https://img.shields.io/github/stars/cryxnet/CVE-2022-42889-RCE.svg) ![forks](https://img.shields.io/github/forks/cryxnet/CVE-2022-42889-RCE.svg)
- [https://github.com/stavrosgns/Text4ShellPayloads](https://github.com/stavrosgns/Text4ShellPayloads) :  ![starts](https://img.shields.io/github/stars/stavrosgns/Text4ShellPayloads.svg) ![forks](https://img.shields.io/github/forks/stavrosgns/Text4ShellPayloads.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/Le1a/CVE-2022-22947](https://github.com/Le1a/CVE-2022-22947) :  ![starts](https://img.shields.io/github/stars/Le1a/CVE-2022-22947.svg) ![forks](https://img.shields.io/github/forks/Le1a/CVE-2022-22947.svg)


## CVE-2022-1119
 The Simple File List WordPress plugin is vulnerable to Arbitrary File Download via the eeFile parameter found in the ~/includes/ee-downloader.php file due to missing controls which makes it possible unauthenticated attackers to supply a path to a file that will subsequently be downloaded, in versions up to and including 3.2.7.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2021-22005
 The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

- [https://github.com/mamba-2021/EXP-POC](https://github.com/mamba-2021/EXP-POC) :  ![starts](https://img.shields.io/github/stars/mamba-2021/EXP-POC.svg) ![forks](https://img.shields.io/github/forks/mamba-2021/EXP-POC.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/itsmetraw/CVE-2021-4034](https://github.com/itsmetraw/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/itsmetraw/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/itsmetraw/CVE-2021-4034.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/Ajomix/CVE-2020-0796-POC](https://github.com/Ajomix/CVE-2020-0796-POC) :  ![starts](https://img.shields.io/github/stars/Ajomix/CVE-2020-0796-POC.svg) ![forks](https://img.shields.io/github/forks/Ajomix/CVE-2020-0796-POC.svg)
- [https://github.com/hheeyywweellccoommee/CVE-2020-0796-VCS-mzecv](https://github.com/hheeyywweellccoommee/CVE-2020-0796-VCS-mzecv) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2020-0796-VCS-mzecv.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2020-0796-VCS-mzecv.svg)


## CVE-2018-1270
 Spring Framework, versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported versions, allow applications to expose STOMP over WebSocket endpoints with a simple, in-memory STOMP broker through the spring-messaging module. A malicious user (or attacker) can craft a message to the broker that can lead to a remote code execution attack.

- [https://github.com/tafamace/CVE-2018-1270](https://github.com/tafamace/CVE-2018-1270) :  ![starts](https://img.shields.io/github/stars/tafamace/CVE-2018-1270.svg) ![forks](https://img.shields.io/github/forks/tafamace/CVE-2018-1270.svg)

