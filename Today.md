# Update 2024-04-13
## CVE-2024-28255
 OpenMetadata is a unified platform for discovery, observability, and governance powered by a central metadata repository, in-depth lineage, and seamless team collaboration. The `JwtFilter` handles the API authentication by requiring and verifying JWT tokens. When a new request comes in, the request's path is checked against this list. When the request's path contains any of the excluded endpoints the filter returns without validating the JWT. Unfortunately, an attacker may use Path Parameters to make any path contain any arbitrary strings. For example, a request to `GET /api/v1;v1%2fusers%2flogin/events/subscriptions/validation/condition/111` will match the excluded endpoint condition and therefore will be processed with no JWT validation allowing an attacker to bypass the authentication mechanism and reach any arbitrary endpoint, including the ones listed above that lead to arbitrary SpEL expression injection. This bypass will not work when the endpoint uses the `SecurityContext.getUserPrincipal()` since it will return `null` and will throw an NPE. This issue may lead to authentication bypass and has been addressed in version 1.2.4. Users are advised to upgrade. There are no known workarounds for this vulnerability. This issue is also tracked as `GHSL-2023-237`.

- [https://github.com/YongYe-Security/CVE-2024-28255](https://github.com/YongYe-Security/CVE-2024-28255) :  ![starts](https://img.shields.io/github/stars/YongYe-Security/CVE-2024-28255.svg) ![forks](https://img.shields.io/github/forks/YongYe-Security/CVE-2024-28255.svg)


## CVE-2024-24576
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/foxoman/CVE-2024-24576-PoC---Nim](https://github.com/foxoman/CVE-2024-24576-PoC---Nim) :  ![starts](https://img.shields.io/github/stars/foxoman/CVE-2024-24576-PoC---Nim.svg) ![forks](https://img.shields.io/github/forks/foxoman/CVE-2024-24576-PoC---Nim.svg)


## CVE-2024-2389
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/adhikara13/CVE-2024-2389](https://github.com/adhikara13/CVE-2024-2389) :  ![starts](https://img.shields.io/github/stars/adhikara13/CVE-2024-2389.svg) ![forks](https://img.shields.io/github/forks/adhikara13/CVE-2024-2389.svg)


## CVE-2023-45503
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ally-petitt/CVE-2023-45503](https://github.com/ally-petitt/CVE-2023-45503) :  ![starts](https://img.shields.io/github/stars/ally-petitt/CVE-2023-45503.svg) ![forks](https://img.shields.io/github/forks/ally-petitt/CVE-2023-45503.svg)


## CVE-2023-34960
 A command injection vulnerability in the wsConvertPpt component of Chamilo v1.11.* up to v1.11.18 allows attackers to execute arbitrary commands via a SOAP API call with a crafted PowerPoint name.

- [https://github.com/YongYe-Security/CVE-2023-34960](https://github.com/YongYe-Security/CVE-2023-34960) :  ![starts](https://img.shields.io/github/stars/YongYe-Security/CVE-2023-34960.svg) ![forks](https://img.shields.io/github/forks/YongYe-Security/CVE-2023-34960.svg)


## CVE-2023-32629
 Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels

- [https://github.com/xS9NTX/CVE-2023-32629-CVE-2023-2640-Ubuntu-Privilege-Escalation-POC](https://github.com/xS9NTX/CVE-2023-32629-CVE-2023-2640-Ubuntu-Privilege-Escalation-POC) :  ![starts](https://img.shields.io/github/stars/xS9NTX/CVE-2023-32629-CVE-2023-2640-Ubuntu-Privilege-Escalation-POC.svg) ![forks](https://img.shields.io/github/forks/xS9NTX/CVE-2023-32629-CVE-2023-2640-Ubuntu-Privilege-Escalation-POC.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/0xWhoami35/CVE-2023-23752](https://github.com/0xWhoami35/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/0xWhoami35/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/0xWhoami35/CVE-2023-23752.svg)


## CVE-2023-6319
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/illixion/root-my-webos-tv](https://github.com/illixion/root-my-webos-tv) :  ![starts](https://img.shields.io/github/stars/illixion/root-my-webos-tv.svg) ![forks](https://img.shields.io/github/forks/illixion/root-my-webos-tv.svg)


## CVE-2023-3824
 In PHP version 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length checking may lead to a stack buffer overflow, leading potentially to memory corruption or RCE.

- [https://github.com/NewLockBit/CVE-2023-3824-PHP-to-RCE](https://github.com/NewLockBit/CVE-2023-3824-PHP-to-RCE) :  ![starts](https://img.shields.io/github/stars/NewLockBit/CVE-2023-3824-PHP-to-RCE.svg) ![forks](https://img.shields.io/github/forks/NewLockBit/CVE-2023-3824-PHP-to-RCE.svg)
- [https://github.com/jhonnybonny/CVE-2023-3824](https://github.com/jhonnybonny/CVE-2023-3824) :  ![starts](https://img.shields.io/github/stars/jhonnybonny/CVE-2023-3824.svg) ![forks](https://img.shields.io/github/forks/jhonnybonny/CVE-2023-3824.svg)
- [https://github.com/NewLockBit/Research-of-CVE-2023-3824-NCA-Lockbit](https://github.com/NewLockBit/Research-of-CVE-2023-3824-NCA-Lockbit) :  ![starts](https://img.shields.io/github/stars/NewLockBit/Research-of-CVE-2023-3824-NCA-Lockbit.svg) ![forks](https://img.shields.io/github/forks/NewLockBit/Research-of-CVE-2023-3824-NCA-Lockbit.svg)
- [https://github.com/StayBeautiful-collab/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK](https://github.com/StayBeautiful-collab/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK) :  ![starts](https://img.shields.io/github/stars/StayBeautiful-collab/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK.svg) ![forks](https://img.shields.io/github/forks/StayBeautiful-collab/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK.svg)


## CVE-2023-2640
 On Ubuntu kernels carrying both c914c0e27eb0 and &quot;UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs&quot;, an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks.

- [https://github.com/xS9NTX/CVE-2023-32629-CVE-2023-2640-Ubuntu-Privilege-Escalation-POC](https://github.com/xS9NTX/CVE-2023-32629-CVE-2023-2640-Ubuntu-Privilege-Escalation-POC) :  ![starts](https://img.shields.io/github/stars/xS9NTX/CVE-2023-32629-CVE-2023-2640-Ubuntu-Privilege-Escalation-POC.svg) ![forks](https://img.shields.io/github/forks/xS9NTX/CVE-2023-32629-CVE-2023-2640-Ubuntu-Privilege-Escalation-POC.svg)


## CVE-2022-26377
 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.53 and prior versions.

- [https://github.com/watchtowrlabs/ibm-qradar-ajp_smuggling_CVE-2022-26377_poc](https://github.com/watchtowrlabs/ibm-qradar-ajp_smuggling_CVE-2022-26377_poc) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/ibm-qradar-ajp_smuggling_CVE-2022-26377_poc.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/ibm-qradar-ajp_smuggling_CVE-2022-26377_poc.svg)


## CVE-2021-34527
 &lt;p&gt;A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.&lt;/p&gt; &lt;p&gt;UPDATE July 7, 2021: The security update for Windows Server 2012, Windows Server 2016 and Windows 10, Version 1607 have been released. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. If you are unable to install these updates, see the FAQ and Workaround sections in this CVE for information on how to help protect your system from this vulnerability.&lt;/p&gt; &lt;p&gt;In addition to installing the updates, in order to secure your system, you must confirm that the following registry settings are set to 0 (zero) or are not defined (&lt;strong&gt;Note&lt;/strong&gt;: These registry keys do not exist by default, and therefore are already at the secure setting.), also that your Group Policy setting are correct (see FAQ):&lt;/p&gt; &lt;ul&gt; &lt;li&gt;HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint&lt;/li&gt; &lt;li&gt;NoWarningNoElevationOnInstall = 0 (DWORD) or not defined (default setting)&lt;/li&gt; &lt;li&gt;UpdatePromptSettings = 0 (DWORD) or not defined (default setting)&lt;/li&gt; &lt;/ul&gt; &lt;p&gt;&lt;strong&gt;Having NoWarningNoElevationOnInstall set to 1 makes your system vulnerable by design.&lt;/strong&gt;&lt;/p&gt; &lt;p&gt;UPDATE July 6, 2021: Microsoft has completed the investigation and has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. If you are unable to install these updates, see the FAQ and Workaround sections in this CVE for information on how to help protect your system from this vulnerability. See also &lt;a href=&quot;https://support.microsoft.com/topic/31b91c02-05bc-4ada-a7ea-183b129578a7&quot;&gt;KB5005010: Restricting installation of new printer drivers after applying the July 6, 2021 updates&lt;/a&gt;.&lt;/p&gt; &lt;p&gt;Note that the security updates released on and after July 6, 2021 contain protections for CVE-2021-1675 and the additional remote code execution exploit in the Windows Print Spooler service known as &#8220;PrintNightmare&#8221;, documented in CVE-2021-34527.&lt;/p&gt;

- [https://github.com/thomas-lauer/PrintNightmare](https://github.com/thomas-lauer/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/thomas-lauer/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/thomas-lauer/PrintNightmare.svg)


## CVE-2021-21985
 The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.

- [https://github.com/haidv35/CVE-2021-21985](https://github.com/haidv35/CVE-2021-21985) :  ![starts](https://img.shields.io/github/stars/haidv35/CVE-2021-21985.svg) ![forks](https://img.shields.io/github/forks/haidv35/CVE-2021-21985.svg)


## CVE-2021-21972
 The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

- [https://github.com/haidv35/CVE-2021-21972](https://github.com/haidv35/CVE-2021-21972) :  ![starts](https://img.shields.io/github/stars/haidv35/CVE-2021-21972.svg) ![forks](https://img.shields.io/github/forks/haidv35/CVE-2021-21972.svg)

