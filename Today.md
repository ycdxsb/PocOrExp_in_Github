# Update 2022-04-14
## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/Omaraitbenhaddi/-Spring4Shell-CVE-2022-22965-](https://github.com/Omaraitbenhaddi/-Spring4Shell-CVE-2022-22965-) :  ![starts](https://img.shields.io/github/stars/Omaraitbenhaddi/-Spring4Shell-CVE-2022-22965-.svg) ![forks](https://img.shields.io/github/forks/Omaraitbenhaddi/-Spring4Shell-CVE-2022-22965-.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/hktalent/spring-spel-0day-poc](https://github.com/hktalent/spring-spel-0day-poc) :  ![starts](https://img.shields.io/github/stars/hktalent/spring-spel-0day-poc.svg) ![forks](https://img.shields.io/github/forks/hktalent/spring-spel-0day-poc.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/chaosec2021/CVE-2022-22954-VMware-RCE](https://github.com/chaosec2021/CVE-2022-22954-VMware-RCE) :  ![starts](https://img.shields.io/github/stars/chaosec2021/CVE-2022-22954-VMware-RCE.svg) ![forks](https://img.shields.io/github/forks/chaosec2021/CVE-2022-22954-VMware-RCE.svg)
- [https://github.com/DrorDvash/CVE-2022-22954_VMware_PoC](https://github.com/DrorDvash/CVE-2022-22954_VMware_PoC) :  ![starts](https://img.shields.io/github/stars/DrorDvash/CVE-2022-22954_VMware_PoC.svg) ![forks](https://img.shields.io/github/forks/DrorDvash/CVE-2022-22954_VMware_PoC.svg)
- [https://github.com/lucksec/VMware-CVE-2022-22954](https://github.com/lucksec/VMware-CVE-2022-22954) :  ![starts](https://img.shields.io/github/stars/lucksec/VMware-CVE-2022-22954.svg) ![forks](https://img.shields.io/github/forks/lucksec/VMware-CVE-2022-22954.svg)
- [https://github.com/MSeymenD/CVE-2022-22954-Testi](https://github.com/MSeymenD/CVE-2022-22954-Testi) :  ![starts](https://img.shields.io/github/stars/MSeymenD/CVE-2022-22954-Testi.svg) ![forks](https://img.shields.io/github/forks/MSeymenD/CVE-2022-22954-Testi.svg)
- [https://github.com/axingde/CVE-2022-22954-POC](https://github.com/axingde/CVE-2022-22954-POC) :  ![starts](https://img.shields.io/github/stars/axingde/CVE-2022-22954-POC.svg) ![forks](https://img.shields.io/github/forks/axingde/CVE-2022-22954-POC.svg)
- [https://github.com/mumu2020629/-CVE-2022-22954-scanner](https://github.com/mumu2020629/-CVE-2022-22954-scanner) :  ![starts](https://img.shields.io/github/stars/mumu2020629/-CVE-2022-22954-scanner.svg) ![forks](https://img.shields.io/github/forks/mumu2020629/-CVE-2022-22954-scanner.svg)
- [https://github.com/west-wind/Threat-Hunting-With-Splunk](https://github.com/west-wind/Threat-Hunting-With-Splunk) :  ![starts](https://img.shields.io/github/stars/west-wind/Threat-Hunting-With-Splunk.svg) ![forks](https://img.shields.io/github/forks/west-wind/Threat-Hunting-With-Splunk.svg)


## CVE-2022-1175
 Improper neutralization of user input in GitLab CE/EE versions 14.4 before 14.7.7, all versions starting from 14.8 before 14.8.5, all versions starting from 14.9 before 14.9.2 allowed an attacker to exploit XSS by injecting HTML in notes.

- [https://github.com/Greenwolf/CVE-2022-1175](https://github.com/Greenwolf/CVE-2022-1175) :  ![starts](https://img.shields.io/github/stars/Greenwolf/CVE-2022-1175.svg) ![forks](https://img.shields.io/github/forks/Greenwolf/CVE-2022-1175.svg)


## CVE-2022-1162
 A hardcoded password was set for accounts registered using an OmniAuth provider (e.g. OAuth, LDAP, SAML) in GitLab CE/EE versions 14.7 prior to 14.7.7, 14.8 prior to 14.8.5, and 14.9 prior to 14.9.2 allowing attackers to potentially take over accounts

- [https://github.com/Greenwolf/CVE-2022-1162](https://github.com/Greenwolf/CVE-2022-1162) :  ![starts](https://img.shields.io/github/stars/Greenwolf/CVE-2022-1162.svg) ![forks](https://img.shields.io/github/forks/Greenwolf/CVE-2022-1162.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Chocapikk/CVE-2021-41773](https://github.com/Chocapikk/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2021-41773.svg)
- [https://github.com/pirenga/CVE-2021-41773](https://github.com/pirenga/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/pirenga/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/pirenga/CVE-2021-41773.svg)


## CVE-2021-0688
 In lockNow of PhoneWindowManager.java, there is a possible lock screen bypass due to a race condition. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-8.1 Android-9Android ID: A-161149543

- [https://github.com/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0688](https://github.com/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0688) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0688.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/frameworks_base_AOSP10_r33_CVE-2021-0688.svg)


## CVE-2021-0600
 In onCreate of DeviceAdminAdd.java, there is a possible way to mislead a user to activate a device admin app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-8.1 Android-9 Android-10 Android-11Android ID: A-179042963

- [https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0600](https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0600) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0600.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0600.svg)


## CVE-2021-0506
 In ActivityPicker.java, there is a possible bypass of user interaction in intent resolution due to a tapjacking/overlay attack. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-8.1 Android-9Android ID: A-181962311

- [https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0506](https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0506) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0506.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0506.svg)


## CVE-2020-0188
 In onCreatePermissionRequest of SettingsSliceProvider.java, there is a possible permissions bypass due to a PendingIntent error. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-147355897

- [https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0188](https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0188) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0188.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0188.svg)


## CVE-2018-8120
 An elevation of privilege vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot; This affects Windows Server 2008, Windows 7, Windows Server 2008 R2. This CVE ID is unique from CVE-2018-8124, CVE-2018-8164, CVE-2018-8166.

- [https://github.com/EVOL4/CVE-2018-8120](https://github.com/EVOL4/CVE-2018-8120) :  ![starts](https://img.shields.io/github/stars/EVOL4/CVE-2018-8120.svg) ![forks](https://img.shields.io/github/forks/EVOL4/CVE-2018-8120.svg)
- [https://github.com/StartZYP/CVE-2018-8120](https://github.com/StartZYP/CVE-2018-8120) :  ![starts](https://img.shields.io/github/stars/StartZYP/CVE-2018-8120.svg) ![forks](https://img.shields.io/github/forks/StartZYP/CVE-2018-8120.svg)

