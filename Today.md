# Update 2022-05-28
## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/trhacknon/CVE-2022-29464-mass](https://github.com/trhacknon/CVE-2022-29464-mass) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2022-29464-mass.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2022-29464-mass.svg)
- [https://github.com/Chocapikk/CVE-2022-29464](https://github.com/Chocapikk/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2022-29464.svg)


## CVE-2022-22972
 VMware Workspace ONE Access, Identity Manager and vRealize Automation contain an authentication bypass vulnerability affecting local domain users. A malicious actor with network access to the UI may be able to obtain administrative access without the need to authenticate.

- [https://github.com/horizon3ai/CVE-2022-22972](https://github.com/horizon3ai/CVE-2022-22972) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2022-22972.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2022-22972.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/gog1071/Spring4Shell-CVE-2022-22965](https://github.com/gog1071/Spring4Shell-CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/gog1071/Spring4Shell-CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/gog1071/Spring4Shell-CVE-2022-22965.svg)


## CVE-2021-38639
 Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-36975.

- [https://github.com/DarkSprings/CVE-2021-38639](https://github.com/DarkSprings/CVE-2021-38639) :  ![starts](https://img.shields.io/github/stars/DarkSprings/CVE-2021-38639.svg) ![forks](https://img.shields.io/github/forks/DarkSprings/CVE-2021-38639.svg)


## CVE-2021-31728
 Incorrect access control in zam64.sys, zam32.sys in MalwareFox AntiMalware 2.74.0.150 allows a non-privileged process to open a handle to \.\ZemanaAntiMalware, register itself with the driver by sending IOCTL 0x80002010, allocate executable memory using a flaw in IOCTL 0x80002040, install a hook with IOCTL 0x80002044 and execute the executable memory using this hook with IOCTL 0x80002014 or 0x80002018, this exposes ring 0 code execution in the context of the driver allowing the non-privileged process to elevate privileges.

- [https://github.com/irql0/CVE-2021-31728](https://github.com/irql0/CVE-2021-31728) :  ![starts](https://img.shields.io/github/stars/irql0/CVE-2021-31728.svg) ![forks](https://img.shields.io/github/forks/irql0/CVE-2021-31728.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/ejlevin99/CVE---2020---1350](https://github.com/ejlevin99/CVE---2020---1350) :  ![starts](https://img.shields.io/github/stars/ejlevin99/CVE---2020---1350.svg) ![forks](https://img.shields.io/github/forks/ejlevin99/CVE---2020---1350.svg)


## CVE-2018-25031
 Swagger UI before 4.1.3 could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions.

- [https://github.com/afine-com/CVE-2018-25031](https://github.com/afine-com/CVE-2018-25031) :  ![starts](https://img.shields.io/github/stars/afine-com/CVE-2018-25031.svg) ![forks](https://img.shields.io/github/forks/afine-com/CVE-2018-25031.svg)


## CVE-2018-17456
 Git before 2.14.5, 2.15.x before 2.15.3, 2.16.x before 2.16.5, 2.17.x before 2.17.2, 2.18.x before 2.18.1, and 2.19.x before 2.19.1 allows remote code execution during processing of a recursive &quot;git clone&quot; of a superproject if a .gitmodules file has a URL field beginning with a '-' character.

- [https://github.com/jiahuiLeee/test](https://github.com/jiahuiLeee/test) :  ![starts](https://img.shields.io/github/stars/jiahuiLeee/test.svg) ![forks](https://img.shields.io/github/forks/jiahuiLeee/test.svg)


## CVE-2017-9947
 A vulnerability has been identified in Siemens APOGEE PXC and TALON TC BACnet Automation Controllers in all versions &lt;V3.5. A directory traversal vulnerability could allow a remote attacker with network access to the integrated web server (80/tcp and 443/tcp) to obtain information on the structure of the file system of the affected devices.

- [https://github.com/RoseSecurity/APOLOGEE](https://github.com/RoseSecurity/APOLOGEE) :  ![starts](https://img.shields.io/github/stars/RoseSecurity/APOLOGEE.svg) ![forks](https://img.shields.io/github/forks/RoseSecurity/APOLOGEE.svg)


## CVE-2017-6516
 A Local Privilege Escalation Vulnerability in MagniComp's Sysinfo before 10-H64 for Linux and UNIX platforms could allow a local attacker to gain elevated privileges. Parts of SysInfo require setuid-to-root access in order to access restricted system files and make restricted kernel calls. This access could be exploited by a local attacker to gain a root shell prompt using the right combination of environment variables and command line arguments.

- [https://github.com/Rubytox/CVE-2017-6516-mcsiwrapper-](https://github.com/Rubytox/CVE-2017-6516-mcsiwrapper-) :  ![starts](https://img.shields.io/github/stars/Rubytox/CVE-2017-6516-mcsiwrapper-.svg) ![forks](https://img.shields.io/github/forks/Rubytox/CVE-2017-6516-mcsiwrapper-.svg)


## CVE-2017-1635
 IBM Tivoli Monitoring V6 6.2.2.x could allow a remote attacker to execute arbitrary code on the system, caused by a use-after-free error. A remote attacker could exploit this vulnerability to execute arbitrary code on the system or cause the application to crash. IBM X-Force ID: 133243.

- [https://github.com/emcalv/tivoli-poc](https://github.com/emcalv/tivoli-poc) :  ![starts](https://img.shields.io/github/stars/emcalv/tivoli-poc.svg) ![forks](https://img.shields.io/github/forks/emcalv/tivoli-poc.svg)


## CVE-2016-3510
 Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.3.6.0, 12.1.3.0, and 12.2.1.0 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to WLS Core Components, a different vulnerability than CVE-2016-3586.

- [https://github.com/minhangxiaohui/Weblogic_direct_T3_Rces](https://github.com/minhangxiaohui/Weblogic_direct_T3_Rces) :  ![starts](https://img.shields.io/github/stars/minhangxiaohui/Weblogic_direct_T3_Rces.svg) ![forks](https://img.shields.io/github/forks/minhangxiaohui/Weblogic_direct_T3_Rces.svg)


## CVE-2016-0638
 Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.3.6, 12.1.2, 12.1.3, and 12.2.1 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to Java Messaging Service.

- [https://github.com/minhangxiaohui/Weblogic_direct_T3_Rces](https://github.com/minhangxiaohui/Weblogic_direct_T3_Rces) :  ![starts](https://img.shields.io/github/stars/minhangxiaohui/Weblogic_direct_T3_Rces.svg) ![forks](https://img.shields.io/github/forks/minhangxiaohui/Weblogic_direct_T3_Rces.svg)


## CVE-2015-4852
 The WLS Security component in Oracle WebLogic Server 10.3.6.0, 12.1.2.0, 12.1.3.0, and 12.2.1.0 allows remote attackers to execute arbitrary commands via a crafted serialized Java object in T3 protocol traffic to TCP port 7001, related to oracle_common/modules/com.bea.core.apache.commons.collections.jar. NOTE: the scope of this CVE is limited to the WebLogic Server product.

- [https://github.com/minhangxiaohui/Weblogic_direct_T3_Rces](https://github.com/minhangxiaohui/Weblogic_direct_T3_Rces) :  ![starts](https://img.shields.io/github/stars/minhangxiaohui/Weblogic_direct_T3_Rces.svg) ![forks](https://img.shields.io/github/forks/minhangxiaohui/Weblogic_direct_T3_Rces.svg)


## CVE-2003-0222
 Stack-based buffer overflow in Oracle Net Services for Oracle Database Server 9i release 2 and earlier allows attackers to execute arbitrary code via a &quot;CREATE DATABASE LINK&quot; query containing a connect string with a long USING parameter.

- [https://github.com/phamthanhsang280477/CVE-2003-0222](https://github.com/phamthanhsang280477/CVE-2003-0222) :  ![starts](https://img.shields.io/github/stars/phamthanhsang280477/CVE-2003-0222.svg) ![forks](https://img.shields.io/github/forks/phamthanhsang280477/CVE-2003-0222.svg)

