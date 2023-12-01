# Update 2023-12-01
## CVE-2023-49103
 An issue was discovered in ownCloud owncloud/graphapi 0.2.x before 0.2.1 and 0.3.x before 0.3.1. The graphapi app relies on a third-party GetPhpInfo.php library that provides a URL. When this URL is accessed, it reveals the configuration details of the PHP environment (phpinfo). This information includes all the environment variables of the webserver. In containerized deployments, these environment variables may include sensitive data such as the ownCloud admin password, mail server credentials, and license key. Simply disabling the graphapi app does not eliminate the vulnerability. Additionally, phpinfo exposes various other potentially sensitive configuration details that could be exploited by an attacker to gather information about the system. Therefore, even if ownCloud is not running in a containerized environment, this vulnerability should still be a cause for concern. Note that Docker containers from before February 2023 are not vulnerable to the credential disclosure.

- [https://github.com/ditekshen/ansible-cve-2023-49103](https://github.com/ditekshen/ansible-cve-2023-49103) :  ![starts](https://img.shields.io/github/stars/ditekshen/ansible-cve-2023-49103.svg) ![forks](https://img.shields.io/github/forks/ditekshen/ansible-cve-2023-49103.svg)


## CVE-2023-48984
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/l00neyhacker/CVE-2023-48984](https://github.com/l00neyhacker/CVE-2023-48984) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-48984.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-48984.svg)


## CVE-2023-47840
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/RandomRobbieBF/CVE-2023-47840](https://github.com/RandomRobbieBF/CVE-2023-47840) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2023-47840.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2023-47840.svg)


## CVE-2023-47184
 Auth. (admin+) Stored Cross-Site Scripting (XSS) vulnerability in Proper Fraction LLC. Admin Bar &amp; Dashboard Access Control plugin &lt;= 1.2.8 versions.

- [https://github.com/cont1nuum/CVE-2023-47184](https://github.com/cont1nuum/CVE-2023-47184) :  ![starts](https://img.shields.io/github/stars/cont1nuum/CVE-2023-47184.svg) ![forks](https://img.shields.io/github/forks/cont1nuum/CVE-2023-47184.svg)


## CVE-2023-46604
 The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client or the broker (respectively) to instantiate any class on the classpath. Users are recommended to upgrade both brokers and clients to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 which fixes this issue.

- [https://github.com/tomasmussi-mulesoft/activemq-cve-2023-46604](https://github.com/tomasmussi-mulesoft/activemq-cve-2023-46604) :  ![starts](https://img.shields.io/github/stars/tomasmussi-mulesoft/activemq-cve-2023-46604.svg) ![forks](https://img.shields.io/github/forks/tomasmussi-mulesoft/activemq-cve-2023-46604.svg)


## CVE-2023-26025
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ka7ana/CVE-2023-36025](https://github.com/ka7ana/CVE-2023-36025) :  ![starts](https://img.shields.io/github/stars/ka7ana/CVE-2023-36025.svg) ![forks](https://img.shields.io/github/forks/ka7ana/CVE-2023-36025.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/Ly0kha/Joomla-CVE-2023-23752-Exploit-Script](https://github.com/Ly0kha/Joomla-CVE-2023-23752-Exploit-Script) :  ![starts](https://img.shields.io/github/stars/Ly0kha/Joomla-CVE-2023-23752-Exploit-Script.svg) ![forks](https://img.shields.io/github/forks/Ly0kha/Joomla-CVE-2023-23752-Exploit-Script.svg)


## CVE-2023-20944
 In run of ChooseTypeAndAccountActivity.java, there is a possible escalation of privilege due to unsafe deserialization. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-244154558

- [https://github.com/nidhi7598/frameworks_base_AOSP_06_r22_core_CVE-2023-20944](https://github.com/nidhi7598/frameworks_base_AOSP_06_r22_core_CVE-2023-20944) :  ![starts](https://img.shields.io/github/stars/nidhi7598/frameworks_base_AOSP_06_r22_core_CVE-2023-20944.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/frameworks_base_AOSP_06_r22_core_CVE-2023-20944.svg)


## CVE-2023-20921
 In onPackageRemoved of AccessibilityManagerService.java, there is a possibility to automatically grant accessibility services due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-243378132

- [https://github.com/Trinadh465/frameworks_base_android-6.0.1_r22_CVE-2023-20921](https://github.com/Trinadh465/frameworks_base_android-6.0.1_r22_CVE-2023-20921) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_base_android-6.0.1_r22_CVE-2023-20921.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_base_android-6.0.1_r22_CVE-2023-20921.svg)


## CVE-2023-4357
 Insufficient validation of untrusted input in XML in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to bypass file access restrictions via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/sunu11/chrome-CVE-2023-4357](https://github.com/sunu11/chrome-CVE-2023-4357) :  ![starts](https://img.shields.io/github/stars/sunu11/chrome-CVE-2023-4357.svg) ![forks](https://img.shields.io/github/forks/sunu11/chrome-CVE-2023-4357.svg)


## CVE-2023-0157
 The All-In-One Security (AIOS) WordPress plugin before 5.1.5 does not escape the content of log files before outputting it to the plugin admin page, allowing an authorized user (admin+) to plant bogus log files containing malicious JavaScript code that will be executed in the context of any administrator visiting this page.

- [https://github.com/b0marek/CVE-2023-0157](https://github.com/b0marek/CVE-2023-0157) :  ![starts](https://img.shields.io/github/stars/b0marek/CVE-2023-0157.svg) ![forks](https://img.shields.io/github/forks/b0marek/CVE-2023-0157.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/securekomodo/text4shell-scan](https://github.com/securekomodo/text4shell-scan) :  ![starts](https://img.shields.io/github/stars/securekomodo/text4shell-scan.svg) ![forks](https://img.shields.io/github/forks/securekomodo/text4shell-scan.svg)
- [https://github.com/SeanWrightSec/CVE-2022-42889-PoC](https://github.com/SeanWrightSec/CVE-2022-42889-PoC) :  ![starts](https://img.shields.io/github/stars/SeanWrightSec/CVE-2022-42889-PoC.svg) ![forks](https://img.shields.io/github/forks/SeanWrightSec/CVE-2022-42889-PoC.svg)
- [https://github.com/gokul-ramesh/text4shell-exploit](https://github.com/gokul-ramesh/text4shell-exploit) :  ![starts](https://img.shields.io/github/stars/gokul-ramesh/text4shell-exploit.svg) ![forks](https://img.shields.io/github/forks/gokul-ramesh/text4shell-exploit.svg)


## CVE-2022-1609
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/w4r3s/cve-2022-1609-exploit](https://github.com/w4r3s/cve-2022-1609-exploit) :  ![starts](https://img.shields.io/github/stars/w4r3s/cve-2022-1609-exploit.svg) ![forks](https://img.shields.io/github/forks/w4r3s/cve-2022-1609-exploit.svg)


## CVE-2021-42342
 An issue was discovered in GoAhead 4.x and 5.x before 5.1.5. In the file upload filter, user form variables can be passed to CGI scripts without being prefixed with the CGI prefix. This permits tunneling untrusted environment variables into vulnerable CGI scripts.

- [https://github.com/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-](https://github.com/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-) :  ![starts](https://img.shields.io/github/stars/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-.svg) ![forks](https://img.shields.io/github/forks/kimusan/goahead-webserver-pre-5.1.5-RCE-PoC-CVE-2021-42342-.svg)


## CVE-2021-4154
 A use-after-free flaw was found in cgroup1_parse_param in kernel/cgroup/cgroup-v1.c in the Linux kernel's cgroup v1 parser. A local attacker with a user privilege could cause a privilege escalation by exploiting the fsconfig syscall parameter leading to a container breakout and a denial of service on the system.

- [https://github.com/veritas501/CVE-2021-4154](https://github.com/veritas501/CVE-2021-4154) :  ![starts](https://img.shields.io/github/stars/veritas501/CVE-2021-4154.svg) ![forks](https://img.shields.io/github/forks/veritas501/CVE-2021-4154.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/SNCKER/CVE-2021-3129](https://github.com/SNCKER/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/SNCKER/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/SNCKER/CVE-2021-3129.svg)
- [https://github.com/keyuan15/CVE-2021-3129](https://github.com/keyuan15/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/keyuan15/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/keyuan15/CVE-2021-3129.svg)


## CVE-2020-13405
 userfiles/modules/users/controller/controller.php in Microweber before 1.1.20 allows an unauthenticated user to disclose the users database via a /modules/ POST request.

- [https://github.com/mrnazu/CVE-2020-13405](https://github.com/mrnazu/CVE-2020-13405) :  ![starts](https://img.shields.io/github/stars/mrnazu/CVE-2020-13405.svg) ![forks](https://img.shields.io/github/forks/mrnazu/CVE-2020-13405.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/BjarneVerschorre/CVE-2019-9053](https://github.com/BjarneVerschorre/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/BjarneVerschorre/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/BjarneVerschorre/CVE-2019-9053.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/b3d3c/poc-cve-2019-5736](https://github.com/b3d3c/poc-cve-2019-5736) :  ![starts](https://img.shields.io/github/stars/b3d3c/poc-cve-2019-5736.svg) ![forks](https://img.shields.io/github/forks/b3d3c/poc-cve-2019-5736.svg)


## CVE-2019-2017
 In rw_t2t_handle_tlv_detect_rsp of rw_t2t_ndef.cc, there is a possible out-of-bound write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-7.0 Android-7.1.1 Android-7.1.2 Android-8.0 Android-8.1 Android-9Android ID: A-121035711

- [https://github.com/grmono/CVE2019-2017_POC](https://github.com/grmono/CVE2019-2017_POC) :  ![starts](https://img.shields.io/github/stars/grmono/CVE2019-2017_POC.svg) ![forks](https://img.shields.io/github/forks/grmono/CVE2019-2017_POC.svg)

