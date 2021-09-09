# Update 2021-09-09
## CVE-2021-40153
 squashfs_opendir in unsquash-1.c in Squashfs-Tools 4.5 stores the filename in the directory entry; this is then used by unsquashfs to create the new file during the unsquash. The filename is not validated for traversal outside of the destination directory, and thus allows writing to locations outside of the destination.

- [https://github.com/AlAIAL90/CVE-2021-40153](https://github.com/AlAIAL90/CVE-2021-40153) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-40153.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-40153.svg)


## CVE-2021-39371
 An XML external entity (XXE) injection in PyWPS before 4.5.0 allows an attacker to view files on the application server filesystem by assigning a path to the entity. OWSLib 0.24.1 may also be affected.

- [https://github.com/AlAIAL90/CVE-2021-39371](https://github.com/AlAIAL90/CVE-2021-39371) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-39371.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-39371.svg)


## CVE-2021-39115
 Affected versions of Atlassian Jira Service Management Server and Data Center allow remote attackers with &quot;Jira Administrators&quot; access to execute arbitrary Java code or run arbitrary system commands via a Server_Side Template Injection vulnerability in the Email Template feature. The affected versions are before version 4.13.9, and from version 4.14.0 before 4.18.0.

- [https://github.com/PetrusViet/CVE-2021-39115](https://github.com/PetrusViet/CVE-2021-39115) :  ![starts](https://img.shields.io/github/stars/PetrusViet/CVE-2021-39115.svg) ![forks](https://img.shields.io/github/forks/PetrusViet/CVE-2021-39115.svg)


## CVE-2021-38699
 TastyIgniter 3.0.7 allows XSS via /account, /reservation, /admin/dashboard, and /admin/system_logs.

- [https://github.com/Justin-1993/CVE-2021-38699](https://github.com/Justin-1993/CVE-2021-38699) :  ![starts](https://img.shields.io/github/stars/Justin-1993/CVE-2021-38699.svg) ![forks](https://img.shields.io/github/forks/Justin-1993/CVE-2021-38699.svg)


## CVE-2021-38173
 Btrbk before 0.31.2 allows command execution because of the mishandling of remote hosts filtering SSH commands using ssh_filter_btrbk.sh in authorized_keys.

- [https://github.com/AlAIAL90/CVE-2021-38173](https://github.com/AlAIAL90/CVE-2021-38173) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-38173.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-38173.svg)


## CVE-2021-36949
 Microsoft Azure Active Directory Connect Authentication Bypass Vulnerability

- [https://github.com/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability](https://github.com/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability) :  ![starts](https://img.shields.io/github/stars/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability.svg) ![forks](https://img.shields.io/github/forks/Maxwitat/Check-AAD-Connect-for-CVE-2021-36949-vulnerability.svg)


## CVE-2021-34523
 Microsoft Exchange Server Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-33768, CVE-2021-34470.

- [https://github.com/horizon3ai/proxyshell](https://github.com/horizon3ai/proxyshell) :  ![starts](https://img.shields.io/github/stars/horizon3ai/proxyshell.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/proxyshell.svg)


## CVE-2021-34473
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.

- [https://github.com/horizon3ai/proxyshell](https://github.com/horizon3ai/proxyshell) :  ![starts](https://img.shields.io/github/stars/horizon3ai/proxyshell.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/proxyshell.svg)


## CVE-2021-33560
 Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encryption because it lacks exponent blinding to address a side-channel attack against mpi_powm, and the window size is not chosen appropriately. This, for example, affects use of ElGamal in OpenPGP.

- [https://github.com/AlAIAL90/CVE-2021-33560](https://github.com/AlAIAL90/CVE-2021-33560) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-33560.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-33560.svg)


## CVE-2021-31207
 Microsoft Exchange Server Security Feature Bypass Vulnerability

- [https://github.com/horizon3ai/proxyshell](https://github.com/horizon3ai/proxyshell) :  ![starts](https://img.shields.io/github/stars/horizon3ai/proxyshell.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/proxyshell.svg)


## CVE-2021-29484
 Ghost is a Node.js CMS. An unused endpoint added during the development of 4.0.0 has left sites vulnerable to untrusted users gaining access to Ghost Admin. Attackers can gain access by getting logged in users to click a link containing malicious code. Users do not need to enter credentials and may not know they've visited a malicious site. Ghost(Pro) has already been patched. We can find no evidence that the issue was exploited on Ghost(Pro) prior to the patch being added. Self-hosters are impacted if running Ghost a version between 4.0.0 and 4.3.2. Immediate action should be taken to secure your site. The issue has been fixed in 4.3.3, all 4.x sites should upgrade as soon as possible. As the endpoint is unused, the patch simply removes it. As a workaround blocking access to /ghost/preview can also mitigate the issue.

- [https://github.com/AlAIAL90/CVE-2021-29484](https://github.com/AlAIAL90/CVE-2021-29484) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-29484.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-29484.svg)


## CVE-2021-28700
 xen/arm: No memory limit for dom0less domUs The dom0less feature allows an administrator to create multiple unprivileged domains directly from Xen. Unfortunately, the memory limit from them is not set. This allow a domain to allocate memory beyond what an administrator originally configured.

- [https://github.com/AlAIAL90/CVE-2021-28700](https://github.com/AlAIAL90/CVE-2021-28700) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28700.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28700.svg)


## CVE-2021-28476
 Hyper-V Remote Code Execution Vulnerability

- [https://github.com/sh4m2hwz/CVE-2021-28476-tools-env](https://github.com/sh4m2hwz/CVE-2021-28476-tools-env) :  ![starts](https://img.shields.io/github/stars/sh4m2hwz/CVE-2021-28476-tools-env.svg) ![forks](https://img.shields.io/github/forks/sh4m2hwz/CVE-2021-28476-tools-env.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/GlennPegden2/cve-2021-26084-confluence](https://github.com/GlennPegden2/cve-2021-26084-confluence) :  ![starts](https://img.shields.io/github/stars/GlennPegden2/cve-2021-26084-confluence.svg) ![forks](https://img.shields.io/github/forks/GlennPegden2/cve-2021-26084-confluence.svg)


## CVE-2021-21409
 Netty is an open-source, asynchronous event-driven network application framework for rapid development of maintainable high performance protocol servers &amp; clients. In Netty (io.netty:netty-codec-http2) before version 4.1.61.Final there is a vulnerability that enables request smuggling. The content-length header is not correctly validated if the request only uses a single Http2HeaderFrame with the endStream set to to true. This could lead to request smuggling if the request is proxied to a remote peer and translated to HTTP/1.1. This is a followup of GHSA-wm47-8v5p-wjpj/CVE-2021-21295 which did miss to fix this one case. This was fixed as part of 4.1.61.Final.

- [https://github.com/AlAIAL90/CVE-2021-21409](https://github.com/AlAIAL90/CVE-2021-21409) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21409.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21409.svg)


## CVE-2021-21315
 The System Information Library for Node.JS (npm package &quot;systeminformation&quot;) is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected.

- [https://github.com/alikarimi999/CVE-2021-21315](https://github.com/alikarimi999/CVE-2021-21315) :  ![starts](https://img.shields.io/github/stars/alikarimi999/CVE-2021-21315.svg) ![forks](https://img.shields.io/github/forks/alikarimi999/CVE-2021-21315.svg)


## CVE-2021-21295
 Netty is an open-source, asynchronous event-driven network application framework for rapid development of maintainable high performance protocol servers &amp; clients. In Netty (io.netty:netty-codec-http2) before version 4.1.60.Final there is a vulnerability that enables request smuggling. If a Content-Length header is present in the original HTTP/2 request, the field is not validated by `Http2MultiplexHandler` as it is propagated up. This is fine as long as the request is not proxied through as HTTP/1.1. If the request comes in as an HTTP/2 stream, gets converted into the HTTP/1.1 domain objects (`HttpRequest`, `HttpContent`, etc.) via `Http2StreamFrameToHttpObjectCodec `and then sent up to the child channel's pipeline and proxied through a remote peer as HTTP/1.1 this may result in request smuggling. In a proxy case, users may assume the content-length is validated somehow, which is not the case. If the request is forwarded to a backend channel that is a HTTP/1.1 connection, the Content-Length now has meaning and needs to be checked. An attacker can smuggle requests inside the body as it gets downgraded from HTTP/2 to HTTP/1.1. For an example attack refer to the linked GitHub Advisory. Users are only affected if all of this is true: `HTTP2MultiplexCodec` or `Http2FrameCodec` is used, `Http2StreamFrameToHttpObjectCodec` is used to convert to HTTP/1.1 objects, and these HTTP/1.1 objects are forwarded to another remote peer. This has been patched in 4.1.60.Final As a workaround, the user can do the validation by themselves by implementing a custom `ChannelInboundHandler` that is put in the `ChannelPipeline` behind `Http2StreamFrameToHttpObjectCodec`.

- [https://github.com/AlAIAL90/CVE-2021-21409](https://github.com/AlAIAL90/CVE-2021-21409) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21409.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21409.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/Kleptocratic/CVE-2021-3156](https://github.com/Kleptocratic/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Kleptocratic/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Kleptocratic/CVE-2021-3156.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/jptr218/ghostcat](https://github.com/jptr218/ghostcat) :  ![starts](https://img.shields.io/github/stars/jptr218/ghostcat.svg) ![forks](https://img.shields.io/github/forks/jptr218/ghostcat.svg)


## CVE-2019-10172
 A flaw was found in org.codehaus.jackson:jackson-mapper-asl:1.9.x libraries. XML external entity vulnerabilities similar CVE-2016-3720 also affects codehaus jackson-mapper-asl libraries but in different classes.

- [https://github.com/AlAIAL90/CVE-2019-10172](https://github.com/AlAIAL90/CVE-2019-10172) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2019-10172.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2019-10172.svg)


## CVE-2019-5096
 An exploitable code execution vulnerability exists in the processing of multi-part/form-data requests within the base GoAhead web server application in versions v5.0.1, v.4.1.1 and v3.6.5. A specially crafted HTTP request can lead to a use-after-free condition during the processing of this request that can be used to corrupt heap structures that could lead to full code execution. The request can be unauthenticated in the form of GET or POST requests, and does not require the requested resource to exist on the server.

- [https://github.com/ianxtianxt/CVE-2019-5096-GoAhead-Web-Server-Dos-Exploit](https://github.com/ianxtianxt/CVE-2019-5096-GoAhead-Web-Server-Dos-Exploit) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/CVE-2019-5096-GoAhead-Web-Server-Dos-Exploit.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/CVE-2019-5096-GoAhead-Web-Server-Dos-Exploit.svg)


## CVE-2018-14729
 The database backup feature in upload/source/admincp/admincp_db.php in Discuz! 2.5 and 3.4 allows remote attackers to execute arbitrary PHP code.

- [https://github.com/FoolMitAh/CVE-2018-14729](https://github.com/FoolMitAh/CVE-2018-14729) :  ![starts](https://img.shields.io/github/stars/FoolMitAh/CVE-2018-14729.svg) ![forks](https://img.shields.io/github/forks/FoolMitAh/CVE-2018-14729.svg)


## CVE-2016-3720
 XML external entity (XXE) vulnerability in XmlMapper in the Data format extension for Jackson (aka jackson-dataformat-xml) allows attackers to have unspecified impact via unknown vectors.

- [https://github.com/AlAIAL90/CVE-2019-10172](https://github.com/AlAIAL90/CVE-2019-10172) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2019-10172.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2019-10172.svg)

