# Update 2023-11-14
## CVE-2023-47119
 Discourse is an open source platform for community discussion. Prior to version 3.1.3 of the `stable` branch and version 3.2.0.beta3 of the `beta` and `tests-passed` branches, some links can inject arbitrary HTML tags when rendered through our Onebox engine. The issue is patched in version 3.1.3 of the `stable` branch and version 3.2.0.beta3 of the `beta` and `tests-passed` branches. There are no known workarounds.

- [https://github.com/BaadMaro/CVE-2023-47119](https://github.com/BaadMaro/CVE-2023-47119) :  ![starts](https://img.shields.io/github/stars/BaadMaro/CVE-2023-47119.svg) ![forks](https://img.shields.io/github/forks/BaadMaro/CVE-2023-47119.svg)


## CVE-2023-46604
 The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client or the broker (respectively) to instantiate any class on the classpath. Users are recommended to upgrade both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 which fixes this issue.

- [https://github.com/LiritoShawshark/CVE-2023-46604_ActiveMQ_RCE_Recurrence](https://github.com/LiritoShawshark/CVE-2023-46604_ActiveMQ_RCE_Recurrence) :  ![starts](https://img.shields.io/github/stars/LiritoShawshark/CVE-2023-46604_ActiveMQ_RCE_Recurrence.svg) ![forks](https://img.shields.io/github/forks/LiritoShawshark/CVE-2023-46604_ActiveMQ_RCE_Recurrence.svg)
- [https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell](https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell) :  ![starts](https://img.shields.io/github/stars/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell.svg) ![forks](https://img.shields.io/github/forks/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell.svg)


## CVE-2023-34096
 Thruk is a multibackend monitoring webinterface which currently supports Naemon, Icinga, Shinken and Nagios as backends. In versions 3.06 and prior, the file `panorama.pm` is vulnerable to a Path Traversal vulnerability which allows an attacker to upload a file to any folder which has write permissions on the affected system. The parameter location is not filtered, validated or sanitized and it accepts any kind of characters. For a path traversal attack, the only characters required were the dot (`.`) and the slash (`/`). A fix is available in version 3.06.2.

- [https://github.com/galoget/Thruk-CVE-2023-34096](https://github.com/galoget/Thruk-CVE-2023-34096) :  ![starts](https://img.shields.io/github/stars/galoget/Thruk-CVE-2023-34096.svg) ![forks](https://img.shields.io/github/forks/galoget/Thruk-CVE-2023-34096.svg)


## CVE-2023-3640
 A possible unauthorized memory access flaw was found in the Linux kernel's cpu_entry_area mapping of X86 CPU data to memory, where a user may guess the location of exception stacks or other important data. Based on the previous CVE-2023-0597, the 'Randomize per-cpu entry area' feature was implemented in /arch/x86/mm/cpu_entry_area.c, which works through the init_cea_offsets() function when KASLR is enabled. However, despite this feature, there is still a risk of per-cpu entry area leaks. This issue could allow a local user to gain access to some important data with memory in an expected location and potentially escalate their privileges on the system.

- [https://github.com/pray77/CVE-2023-3640](https://github.com/pray77/CVE-2023-3640) :  ![starts](https://img.shields.io/github/stars/pray77/CVE-2023-3640.svg) ![forks](https://img.shields.io/github/forks/pray77/CVE-2023-3640.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.

- [https://github.com/Pasch0/WSO2RCE](https://github.com/Pasch0/WSO2RCE) :  ![starts](https://img.shields.io/github/stars/Pasch0/WSO2RCE.svg) ![forks](https://img.shields.io/github/forks/Pasch0/WSO2RCE.svg)


## CVE-2022-24706
 In Apache CouchDB prior to 3.2.2, an attacker can access an improperly secured default installation without authenticating and gain admin privileges. The CouchDB documentation has always made recommendations for properly securing an installation, including recommending using a firewall in front of all CouchDB installations.

- [https://github.com/superzerosec/CVE-2022-24706](https://github.com/superzerosec/CVE-2022-24706) :  ![starts](https://img.shields.io/github/stars/superzerosec/CVE-2022-24706.svg) ![forks](https://img.shields.io/github/forks/superzerosec/CVE-2022-24706.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/LucasPDiniz/CVE-2022-22965](https://github.com/LucasPDiniz/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2022-22965.svg)


## CVE-2021-46422
 Telesquare SDT-CW3B1 1.1.0 is affected by an OS command injection vulnerability that allows a remote attacker to execute OS commands without any authentication.

- [https://github.com/Chocapikk/CVE-2021-46422](https://github.com/Chocapikk/CVE-2021-46422) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2021-46422.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2021-46422.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-36356
 KRAMER VIAware through August 2021 allows remote attackers to execute arbitrary code because ajaxPages/writeBrowseFilePathAjax.php accepts arbitrary executable pathnames (even though browseSystemFiles.php is no longer reachable via the GUI). NOTE: this issue exists because of an incomplete fix for CVE-2019-17124.

- [https://github.com/Chocapikk/CVE-2021-35064](https://github.com/Chocapikk/CVE-2021-35064) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2021-35064.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2021-35064.svg)


## CVE-2021-35064
 KramerAV VIAWare, all tested versions, allow privilege escalation through misconfiguration of sudo. Sudoers permits running of multiple dangerous commands, including unzip, systemctl and dpkg.

- [https://github.com/Chocapikk/CVE-2021-35064](https://github.com/Chocapikk/CVE-2021-35064) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2021-35064.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2021-35064.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/PwnFunction/CVE-2021-4034](https://github.com/PwnFunction/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/PwnFunction/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/PwnFunction/CVE-2021-4034.svg)
- [https://github.com/ryaagard/CVE-2021-4034](https://github.com/ryaagard/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ryaagard/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ryaagard/CVE-2021-4034.svg)
- [https://github.com/Al1ex/CVE-2021-4034](https://github.com/Al1ex/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-4034.svg)
- [https://github.com/hackingyseguridad/CVE-2021-4034](https://github.com/hackingyseguridad/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/CVE-2021-4034.svg)
- [https://github.com/sentryCyberSec/sentryCyberSec.github.io](https://github.com/sentryCyberSec/sentryCyberSec.github.io) :  ![starts](https://img.shields.io/github/stars/sentryCyberSec/sentryCyberSec.github.io.svg) ![forks](https://img.shields.io/github/forks/sentryCyberSec/sentryCyberSec.github.io.svg)
- [https://github.com/ch4rum/CVE-2021-4034](https://github.com/ch4rum/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ch4rum/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ch4rum/CVE-2021-4034.svg)
- [https://github.com/ayypril/CVE-2021-4034](https://github.com/ayypril/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ayypril/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ayypril/CVE-2021-4034.svg)
- [https://github.com/jcatala/f_poc_cve-2021-4034](https://github.com/jcatala/f_poc_cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/jcatala/f_poc_cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/jcatala/f_poc_cve-2021-4034.svg)


## CVE-2019-19492
 FreeSWITCH 1.6.10 through 1.10.1 has a default password in event_socket.conf.xml.

- [https://github.com/Chocapikk/CVE-2019-19492](https://github.com/Chocapikk/CVE-2019-19492) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2019-19492.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2019-19492.svg)


## CVE-2018-25031
 Swagger UI before 4.1.3 could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions.

- [https://github.com/wrkk112/CVE-2018-25031](https://github.com/wrkk112/CVE-2018-25031) :  ![starts](https://img.shields.io/github/stars/wrkk112/CVE-2018-25031.svg) ![forks](https://img.shields.io/github/forks/wrkk112/CVE-2018-25031.svg)


## CVE-2017-9805
 The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.

- [https://github.com/luc10/struts-rce-cve-2017-9805](https://github.com/luc10/struts-rce-cve-2017-9805) :  ![starts](https://img.shields.io/github/stars/luc10/struts-rce-cve-2017-9805.svg) ![forks](https://img.shields.io/github/forks/luc10/struts-rce-cve-2017-9805.svg)
- [https://github.com/wifido/CVE-2017-9805-Exploit](https://github.com/wifido/CVE-2017-9805-Exploit) :  ![starts](https://img.shields.io/github/stars/wifido/CVE-2017-9805-Exploit.svg) ![forks](https://img.shields.io/github/forks/wifido/CVE-2017-9805-Exploit.svg)

