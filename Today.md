# Update 2025-02-11
## CVE-2025-23369
 An improper verification of cryptographic signature vulnerability was identified in GitHub Enterprise Server that allowed signature spoofing for unauthorized internal users.  Instances not utilizing SAML single sign-on or where the attacker is not already an existing user were not impacted. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.12.14, 3.13.10, 3.14.7, 3.15.2, and 3.16.0. This vulnerability was reported via the GitHub Bug Bounty program.

- [https://github.com/Arian91/CVE-2025-23369_SAML_bypass](https://github.com/Arian91/CVE-2025-23369_SAML_bypass) :  ![starts](https://img.shields.io/github/stars/Arian91/CVE-2025-23369_SAML_bypass.svg) ![forks](https://img.shields.io/github/forks/Arian91/CVE-2025-23369_SAML_bypass.svg)


## CVE-2024-55591
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

- [https://github.com/0x7556/CVE-2024-55591](https://github.com/0x7556/CVE-2024-55591) :  ![starts](https://img.shields.io/github/stars/0x7556/CVE-2024-55591.svg) ![forks](https://img.shields.io/github/forks/0x7556/CVE-2024-55591.svg)


## CVE-2024-44542
 SQL Injection vulnerability in todesk v.1.1 allows a remote attacker to execute arbitrary code via the /todesk.com/news.html parameter.

- [https://github.com/sshipanoo/CVE-2024-44542](https://github.com/sshipanoo/CVE-2024-44542) :  ![starts](https://img.shields.io/github/stars/sshipanoo/CVE-2024-44542.svg) ![forks](https://img.shields.io/github/forks/sshipanoo/CVE-2024-44542.svg)


## CVE-2024-39119
 idccms v1.35 was discovered to contain a Cross-Site Request Forgery (CSRF) via admin/info_deal.php?mudi=rev&nohrefStr=close.

- [https://github.com/phtcloud-dev/CVE-2024-39199](https://github.com/phtcloud-dev/CVE-2024-39199) :  ![starts](https://img.shields.io/github/stars/phtcloud-dev/CVE-2024-39199.svg) ![forks](https://img.shields.io/github/forks/phtcloud-dev/CVE-2024-39199.svg)


## CVE-2024-36401
Versions 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/wellwornele/CVE-2024-36401](https://github.com/wellwornele/CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/wellwornele/CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/wellwornele/CVE-2024-36401.svg)


## CVE-2024-3919
 The OpenPGP Form Encryption for WordPress plugin before 1.5.1 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/phtcloud-dev/CVE-2024-39199](https://github.com/phtcloud-dev/CVE-2024-39199) :  ![starts](https://img.shields.io/github/stars/phtcloud-dev/CVE-2024-39199.svg) ![forks](https://img.shields.io/github/forks/phtcloud-dev/CVE-2024-39199.svg)


## CVE-2022-31692
 Spring Security, versions 5.7 prior to 5.7.5 and 5.6 prior to 5.6.9 could be susceptible to authorization rules bypass via forward or include dispatcher types. Specifically, an application is vulnerable when all of the following are true: The application expects that Spring Security applies security to forward and include dispatcher types. The application uses the AuthorizationFilter either manually or via the authorizeHttpRequests() method. The application configures the FilterChainProxy to apply to forward and/or include requests (e.g. spring.security.filter.dispatcher-types = request, error, async, forward, include). The application may forward or include the request to a higher privilege-secured endpoint.The application configures Spring Security to apply to every dispatcher type via authorizeHttpRequests().shouldFilterAllDispatcherTypes(true)

- [https://github.com/blipzip/cve-2022-31692](https://github.com/blipzip/cve-2022-31692) :  ![starts](https://img.shields.io/github/stars/blipzip/cve-2022-31692.svg) ![forks](https://img.shields.io/github/forks/blipzip/cve-2022-31692.svg)


## CVE-2022-31691
 Spring Tools 4 for Eclipse version 4.16.0 and below as well as VSCode extensions such as Spring Boot Tools, Concourse CI Pipeline Editor, Bosh Editor and Cloudfoundry Manifest YML Support version 1.39.0 and below all use Snakeyaml library for YAML editing support. This library allows for some special syntax in the YAML that under certain circumstances allows for potentially harmful remote code execution by the attacker.

- [https://github.com/blipzip/CVE-2022-31691](https://github.com/blipzip/CVE-2022-31691) :  ![starts](https://img.shields.io/github/stars/blipzip/CVE-2022-31691.svg) ![forks](https://img.shields.io/github/forks/blipzip/CVE-2022-31691.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/RogelioPumajulca/CVE-2022-0847](https://github.com/RogelioPumajulca/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/RogelioPumajulca/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/RogelioPumajulca/CVE-2022-0847.svg)


## CVE-2021-41277
 Metabase is an open source data analytics platform. In affected versions a security issue has been discovered with the custom GeoJSON map (`admin-settings-maps-custom maps-add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded. This issue is fixed in a new maintenance release (0.40.5 and 1.40.5), and any subsequent release after that. If you’re unable to upgrade immediately, you can mitigate this by including rules in your reverse proxy or load balancer or WAF to provide a validation filter before the application.

- [https://github.com/grey-master-a/Metabase_Nmap_Script](https://github.com/grey-master-a/Metabase_Nmap_Script) :  ![starts](https://img.shields.io/github/stars/grey-master-a/Metabase_Nmap_Script.svg) ![forks](https://img.shields.io/github/forks/grey-master-a/Metabase_Nmap_Script.svg)


## CVE-2021-21425
 Grav Admin Plugin is an HTML user interface that provides a way to configure Grav and create and modify pages. In versions 1.10.7 and earlier, an unauthenticated user can execute some methods of administrator controller without needing any credentials. Particular method execution will result in arbitrary YAML file creation or content change of existing YAML files on the system. Successfully exploitation of that vulnerability results in configuration changes, such as general site information change, custom scheduler job definition, etc. Due to the nature of the vulnerability, an adversary can change some part of the webpage, or hijack an administrator account, or execute operating system command under the context of the web-server user. This vulnerability is fixed in version 1.10.8. Blocking access to the `/admin` path from untrusted sources can be applied as a workaround.

- [https://github.com/grey-master-a/GravCMS_Nmap_Script](https://github.com/grey-master-a/GravCMS_Nmap_Script) :  ![starts](https://img.shields.io/github/stars/grey-master-a/GravCMS_Nmap_Script.svg) ![forks](https://img.shields.io/github/forks/grey-master-a/GravCMS_Nmap_Script.svg)


## CVE-2020-29607
 A file upload restriction bypass vulnerability in Pluck CMS before 4.7.13 allows an admin privileged user to gain access in the host through the "manage files" functionality, which may result in remote code execution.

- [https://github.com/Alienfader/CVE-2020-29607](https://github.com/Alienfader/CVE-2020-29607) :  ![starts](https://img.shields.io/github/stars/Alienfader/CVE-2020-29607.svg) ![forks](https://img.shields.io/github/forks/Alienfader/CVE-2020-29607.svg)


## CVE-2019-18935
 Progress Telerik UI for ASP.NET AJAX through 2019.3.1023 contains a .NET deserialization vulnerability in the RadAsyncUpload function. This is exploitable when the encryption keys are known due to the presence of CVE-2017-11317 or CVE-2017-11357, or other means. Exploitation can result in remote code execution. (As of 2020.1.114, a default setting prevents the exploit. In 2019.3.1023, but not earlier versions, a non-default setting can prevent exploitation.)

- [https://github.com/MorphyKutay/TelerikVulnCheck](https://github.com/MorphyKutay/TelerikVulnCheck) :  ![starts](https://img.shields.io/github/stars/MorphyKutay/TelerikVulnCheck.svg) ![forks](https://img.shields.io/github/forks/MorphyKutay/TelerikVulnCheck.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/OmarV4066/SSHEnumKL](https://github.com/OmarV4066/SSHEnumKL) :  ![starts](https://img.shields.io/github/stars/OmarV4066/SSHEnumKL.svg) ![forks](https://img.shields.io/github/forks/OmarV4066/SSHEnumKL.svg)


## CVE-2017-16894
 In Laravel framework through 5.5.21, remote attackers can obtain sensitive information (such as externally usable passwords) via a direct request for the /.env URI. NOTE: this CVE is only about Laravel framework's writeNewEnvironmentFileWith function in src/Illuminate/Foundation/Console/KeyGenerateCommand.php, which uses file_put_contents without restricting the .env permissions. The .env filename is not used exclusively by Laravel framework.

- [https://github.com/ibnurusdianto/CVE-2017-16894](https://github.com/ibnurusdianto/CVE-2017-16894) :  ![starts](https://img.shields.io/github/stars/ibnurusdianto/CVE-2017-16894.svg) ![forks](https://img.shields.io/github/forks/ibnurusdianto/CVE-2017-16894.svg)


## CVE-2014-4210
 Unspecified vulnerability in the Oracle WebLogic Server component in Oracle Fusion Middleware 10.0.2.0 and 10.3.6.0 allows remote attackers to affect confidentiality via vectors related to WLS - Web Services.

- [https://github.com/ZorvithonLeo/Exploit-CVE-2014-4210-](https://github.com/ZorvithonLeo/Exploit-CVE-2014-4210-) :  ![starts](https://img.shields.io/github/stars/ZorvithonLeo/Exploit-CVE-2014-4210-.svg) ![forks](https://img.shields.io/github/forks/ZorvithonLeo/Exploit-CVE-2014-4210-.svg)

