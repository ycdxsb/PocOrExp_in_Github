# Update 2021-09-03
## CVE-2021-40352
 OpenEMR 6.0.0 has a pnotes_print.php?noteid= Insecure Direct Object Reference vulnerability via which an attacker can read the messages of all users.

- [https://github.com/allenenosh/CVE-2021-40352](https://github.com/allenenosh/CVE-2021-40352) :  ![starts](https://img.shields.io/github/stars/allenenosh/CVE-2021-40352.svg) ![forks](https://img.shields.io/github/forks/allenenosh/CVE-2021-40352.svg)


## CVE-2021-40145
 ** DISPUTED ** gdImageGd2Ptr in gd_gd2.c in the GD Graphics Library (aka LibGD) through 2.3.2 has a double free. NOTE: the vendor's position is &quot;The GD2 image format is a proprietary image format of libgd. It has to be regarded as being obsolete, and should only be used for development and testing purposes.&quot;

- [https://github.com/AlAIAL90/CVE-2021-40145](https://github.com/AlAIAL90/CVE-2021-40145) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-40145.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-40145.svg)


## CVE-2021-39159
 BinderHub is a kubernetes-based cloud service that allows users to share reproducible interactive computing environments from code repositories. In affected versions a remote code execution vulnerability has been identified in BinderHub, where providing BinderHub with maliciously crafted input could execute code in the BinderHub context, with the potential to egress credentials of the BinderHub deployment, including JupyterHub API tokens, kubernetes service accounts, and docker registry credentials. This may provide the ability to manipulate images and other user created pods in the deployment, with the potential to escalate to the host depending on the underlying kubernetes configuration. Users are advised to update to version 0.2.0-n653. If users are unable to update they may disable the git repo provider by specifying the `BinderHub.repo_providers` as a workaround.

- [https://github.com/AlAIAL90/CVE-2021-39159](https://github.com/AlAIAL90/CVE-2021-39159) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-39159.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-39159.svg)


## CVE-2021-39138
 Parse Server is an open source backend that can be deployed to any infrastructure that can run Node.js. Developers can use the REST API to signup users and also allow users to login anonymously. Prior to version 4.5.1, when an anonymous user is first signed up using REST, the server creates session incorrectly. Particularly, the `authProvider` field in `_Session` class under `createdWith` shows the user logged in creating a password. If a developer later depends on the `createdWith` field to provide a different level of access between a password user and anonymous user, the server incorrectly classified the session type as being created with a `password`. The server does not currently use `createdWith` to make decisions about internal functions, so if a developer is not using `createdWith` directly, they are not affected. The vulnerability only affects users who depend on `createdWith` by using it directly. The issue is patched in Parse Server version 4.5.1. As a workaround, do not use the `createdWith` Session field to make decisions if one allows anonymous login.

- [https://github.com/AlAIAL90/CVE-2021-39138](https://github.com/AlAIAL90/CVE-2021-39138) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-39138.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-39138.svg)


## CVE-2021-37749
 MapService.svc in Hexagon GeoMedia WebMap 2020 before Update 2 (aka 16.6.2.66) allows blind SQL Injection via the Id (within sourceItems) parameter to the GetMap method.

- [https://github.com/AlAIAL90/CVE-2021-37749](https://github.com/AlAIAL90/CVE-2021-37749) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-37749.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-37749.svg)


## CVE-2021-36934
 Windows Elevation of Privilege Vulnerability

- [https://github.com/AlAIAL90/CVE-2021-36934](https://github.com/AlAIAL90/CVE-2021-36934) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-36934.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-36934.svg)


## CVE-2021-36931
 Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-36928.

- [https://github.com/AlAIAL90/CVE-2021-36928](https://github.com/AlAIAL90/CVE-2021-36928) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-36928.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-36928.svg)


## CVE-2021-36928
 Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-36931.

- [https://github.com/AlAIAL90/CVE-2021-36928](https://github.com/AlAIAL90/CVE-2021-36928) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-36928.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-36928.svg)


## CVE-2021-36359
 OrbiTeam BSCW Classic before 7.4.3 allows exportpdf authenticated remote code execution (RCE) via XML tag injection because reportlab\platypus\paraparser.py (reached via bscw.cgi op=_editfolder.EditFolder) calls eval on attacker-supplied Python code. This is fixed in 5.0.12, 5.1.10, 5.2.4, 7.3.3, and 7.4.3.

- [https://github.com/AlAIAL90/CVE-2021-36359](https://github.com/AlAIAL90/CVE-2021-36359) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-36359.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-36359.svg)


## CVE-2021-35940
 An out-of-bounds array read in the apr_time_exp*() functions was fixed in the Apache Portable Runtime 1.6.3 release (CVE-2017-12613). The fix for this issue was not carried forward to the APR 1.7.x branch, and hence version 1.7.0 regressed compared to 1.6.3 and is vulnerable to the same issue.

- [https://github.com/AlAIAL90/CVE-2021-35940](https://github.com/AlAIAL90/CVE-2021-35940) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-35940.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-35940.svg)


## CVE-2021-35042
 Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL injection if order_by is untrusted input from a client of a web application.

- [https://github.com/mrlihd/CVE-2021-35042](https://github.com/mrlihd/CVE-2021-35042) :  ![starts](https://img.shields.io/github/stars/mrlihd/CVE-2021-35042.svg) ![forks](https://img.shields.io/github/forks/mrlihd/CVE-2021-35042.svg)


## CVE-2021-34429
 For Eclipse Jetty versions 9.4.37-9.4.42, 10.0.1-10.0.5 &amp; 11.0.1-11.0.5, URIs can be crafted using some encoded characters to access the content of the WEB-INF directory and/or bypass some security constraints. This is a variation of the vulnerability reported in CVE-2021-28164/GHSA-v7ff-8wcx-gmc5.

- [https://github.com/AlAIAL90/CVE-2021-34429](https://github.com/AlAIAL90/CVE-2021-34429) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-34429.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-34429.svg)


## CVE-2021-33909
 fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an unprivileged user, aka CID-8cae8cd89f05.

- [https://github.com/ChrisTheCoolHut/CVE-2021-33909](https://github.com/ChrisTheCoolHut/CVE-2021-33909) :  ![starts](https://img.shields.io/github/stars/ChrisTheCoolHut/CVE-2021-33909.svg) ![forks](https://img.shields.io/github/forks/ChrisTheCoolHut/CVE-2021-33909.svg)


## CVE-2021-33831
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/lanmarc77/CVE-2021-33831](https://github.com/lanmarc77/CVE-2021-33831) :  ![starts](https://img.shields.io/github/stars/lanmarc77/CVE-2021-33831.svg) ![forks](https://img.shields.io/github/forks/lanmarc77/CVE-2021-33831.svg)


## CVE-2021-33015
 Cscape (All Versions prior to 9.90 SP5) lacks proper validation of user-supplied data when parsing project files. This could lead to an out-of-bounds write via an uninitialized pointer. An attacker could leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/AlAIAL90/CVE-2021-33015](https://github.com/AlAIAL90/CVE-2021-33015) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-33015.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-33015.svg)


## CVE-2021-32995
 Cscape (All Versions prior to 9.90 SP5) lacks proper validation of user-supplied data when parsing project files. This could lead to an out-of-bounds write. An attacker could leverage this vulnerability to execute code in the context of the current process.

- [https://github.com/AlAIAL90/CVE-2021-32995](https://github.com/AlAIAL90/CVE-2021-32995) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-32995.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-32995.svg)


## CVE-2021-32778
 Envoy is an open source L7 proxy and communication bus designed for large modern service oriented architectures. In affected versions envoy&#8217;s procedure for resetting a HTTP/2 stream has O(N^2) complexity, leading to high CPU utilization when a large number of streams are reset. Deployments are susceptible to Denial of Service when Envoy is configured with high limit on H/2 concurrent streams. An attacker wishing to exploit this vulnerability would require a client opening and closing a large number of H/2 streams. Envoy versions 1.19.1, 1.18.4, 1.17.4, 1.16.5 contain fixes to reduce time complexity of resetting HTTP/2 streams. As a workaround users may limit the number of simultaneous HTTP/2 dreams for upstream and downstream peers to a low number, i.e. 100.

- [https://github.com/AlAIAL90/CVE-2021-32778](https://github.com/AlAIAL90/CVE-2021-32778) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-32778.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-32778.svg)


## CVE-2021-32777
 Envoy is an open source L7 proxy and communication bus designed for large modern service oriented architectures. In affected versions when ext-authz extension is sending request headers to the external authorization service it must merge multiple value headers according to the HTTP spec. However, only the last header value is sent. This may allow specifically crafted requests to bypass authorization. Attackers may be able to escalate privileges when using ext-authz extension or back end service that uses multiple value headers for authorization. A specifically constructed request may be delivered by an untrusted downstream peer in the presence of ext-authz extension. Envoy versions 1.19.1, 1.18.4, 1.17.4, 1.16.5 contain fixes to the ext-authz extension to correctly merge multiple request header values, when sending request for authorization.

- [https://github.com/AlAIAL90/CVE-2021-32777](https://github.com/AlAIAL90/CVE-2021-32777) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-32777.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-32777.svg)


## CVE-2021-31989
 A user with permission to log on to the machine hosting the AXIS Device Manager client could under certain conditions extract a memory dump from the built-in Windows Task Manager application. The memory dump may potentially contain credentials of connected Axis devices.

- [https://github.com/AlAIAL90/CVE-2021-31989](https://github.com/AlAIAL90/CVE-2021-31989) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-31989.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-31989.svg)


## CVE-2021-28699
 inadequate grant-v2 status frames array bounds check The v2 grant table interface separates grant attributes from grant status. That is, when operating in this mode, a guest has two tables. As a result, guests also need to be able to retrieve the addresses that the new status tracking table can be accessed through. For 32-bit guests on x86, translation of requests has to occur because the interface structure layouts commonly differ between 32- and 64-bit. The translation of the request to obtain the frame numbers of the grant status table involves translating the resulting array of frame numbers. Since the space used to carry out the translation is limited, the translation layer tells the core function the capacity of the array within translation space. Unfortunately the core function then only enforces array bounds to be below 8 times the specified value, and would write past the available space if enough frame numbers needed storing.

- [https://github.com/AlAIAL90/CVE-2021-28699](https://github.com/AlAIAL90/CVE-2021-28699) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28699.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28699.svg)


## CVE-2021-28698
 long running loops in grant table handling In order to properly monitor resource use, Xen maintains information on the grant mappings a domain may create to map grants offered by other domains. In the process of carrying out certain actions, Xen would iterate over all such entries, including ones which aren't in use anymore and some which may have been created but never used. If the number of entries for a given domain is large enough, this iterating of the entire table may tie up a CPU for too long, starving other domains or causing issues in the hypervisor itself. Note that a domain may map its own grants, i.e. there is no need for multiple domains to be involved here. A pair of &quot;cooperating&quot; guests may, however, cause the effects to be more severe.

- [https://github.com/AlAIAL90/CVE-2021-28698](https://github.com/AlAIAL90/CVE-2021-28698) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28698.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28698.svg)


## CVE-2021-28697
 grant table v2 status pages may remain accessible after de-allocation Guest get permitted access to certain Xen-owned pages of memory. The majority of such pages remain allocated / associated with a guest for its entire lifetime. Grant table v2 status pages, however, get de-allocated when a guest switched (back) from v2 to v1. The freeing of such pages requires that the hypervisor know where in the guest these pages were mapped. The hypervisor tracks only one use within guest space, but racing requests from the guest to insert mappings of these pages may result in any of them to become mapped in multiple locations. Upon switching back from v2 to v1, the guest would then retain access to a page that was freed and perhaps re-used for other purposes.

- [https://github.com/AlAIAL90/CVE-2021-28697](https://github.com/AlAIAL90/CVE-2021-28697) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28697.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28697.svg)


## CVE-2021-28696
 IOMMU page mapping issues on x86 T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Both AMD and Intel allow ACPI tables to specify regions of memory which should be left untranslated, which typically means these addresses should pass the translation phase unaltered. While these are typically device specific ACPI properties, they can also be specified to apply to a range of devices, or even all devices. On all systems with such regions Xen failed to prevent guests from undoing/replacing such mappings (CVE-2021-28694). On AMD systems, where a discontinuous range is specified by firmware, the supposedly-excluded middle range will also be identity-mapped (CVE-2021-28695). Further, on AMD systems, upon de-assigment of a physical device from a guest, the identity mappings would be left in place, allowing a guest continued access to ranges of memory which it shouldn't have access to anymore (CVE-2021-28696).

- [https://github.com/AlAIAL90/CVE-2021-28696](https://github.com/AlAIAL90/CVE-2021-28696) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28696.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28696.svg)
- [https://github.com/AlAIAL90/CVE-2021-28694](https://github.com/AlAIAL90/CVE-2021-28694) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28694.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28694.svg)
- [https://github.com/AlAIAL90/CVE-2021-28695](https://github.com/AlAIAL90/CVE-2021-28695) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28695.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28695.svg)


## CVE-2021-28695
 IOMMU page mapping issues on x86 T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Both AMD and Intel allow ACPI tables to specify regions of memory which should be left untranslated, which typically means these addresses should pass the translation phase unaltered. While these are typically device specific ACPI properties, they can also be specified to apply to a range of devices, or even all devices. On all systems with such regions Xen failed to prevent guests from undoing/replacing such mappings (CVE-2021-28694). On AMD systems, where a discontinuous range is specified by firmware, the supposedly-excluded middle range will also be identity-mapped (CVE-2021-28695). Further, on AMD systems, upon de-assigment of a physical device from a guest, the identity mappings would be left in place, allowing a guest continued access to ranges of memory which it shouldn't have access to anymore (CVE-2021-28696).

- [https://github.com/AlAIAL90/CVE-2021-28695](https://github.com/AlAIAL90/CVE-2021-28695) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28695.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28695.svg)
- [https://github.com/AlAIAL90/CVE-2021-28696](https://github.com/AlAIAL90/CVE-2021-28696) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28696.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28696.svg)
- [https://github.com/AlAIAL90/CVE-2021-28694](https://github.com/AlAIAL90/CVE-2021-28694) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28694.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28694.svg)


## CVE-2021-28694
 IOMMU page mapping issues on x86 T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Both AMD and Intel allow ACPI tables to specify regions of memory which should be left untranslated, which typically means these addresses should pass the translation phase unaltered. While these are typically device specific ACPI properties, they can also be specified to apply to a range of devices, or even all devices. On all systems with such regions Xen failed to prevent guests from undoing/replacing such mappings (CVE-2021-28694). On AMD systems, where a discontinuous range is specified by firmware, the supposedly-excluded middle range will also be identity-mapped (CVE-2021-28695). Further, on AMD systems, upon de-assigment of a physical device from a guest, the identity mappings would be left in place, allowing a guest continued access to ranges of memory which it shouldn't have access to anymore (CVE-2021-28696).

- [https://github.com/AlAIAL90/CVE-2021-28694](https://github.com/AlAIAL90/CVE-2021-28694) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28694.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28694.svg)
- [https://github.com/AlAIAL90/CVE-2021-28696](https://github.com/AlAIAL90/CVE-2021-28696) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28696.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28696.svg)
- [https://github.com/AlAIAL90/CVE-2021-28695](https://github.com/AlAIAL90/CVE-2021-28695) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28695.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28695.svg)


## CVE-2021-28164
 In Eclipse Jetty 9.4.37.v20210219 to 9.4.38.v20210224, the default compliance mode allows requests with URIs that contain %2e or %2e%2e segments to access protected resources within the WEB-INF directory. For example a request to /context/%2e/WEB-INF/web.xml can retrieve the web.xml file. This can reveal sensitive information regarding the implementation of a web application.

- [https://github.com/AlAIAL90/CVE-2021-28164](https://github.com/AlAIAL90/CVE-2021-28164) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-28164.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-28164.svg)
- [https://github.com/AlAIAL90/CVE-2021-34429](https://github.com/AlAIAL90/CVE-2021-34429) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-34429.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-34429.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an authenticated user, and in some instances an unauthenticated user, to execute arbitrary code on a Confluence Server or Data Center instance. The vulnerable endpoints can be accessed by a non-administrator user or unauthenticated user if &#8216;Allow people to sign up to create their account&#8217; is enabled. To check whether this is enabled go to COG &gt; User Management &gt; User Signup Options. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/h3v0x/CVE-2021-26084_Confluence](https://github.com/h3v0x/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/h3v0x/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/h3v0x/CVE-2021-26084_Confluence.svg)
- [https://github.com/FanqXu/CVE-2021-26084](https://github.com/FanqXu/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/FanqXu/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/FanqXu/CVE-2021-26084.svg)
- [https://github.com/tangxiaofeng7/CVE-2021-26084](https://github.com/tangxiaofeng7/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/tangxiaofeng7/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/tangxiaofeng7/CVE-2021-26084.svg)
- [https://github.com/r0ckysec/CVE-2021-26084_Confluence](https://github.com/r0ckysec/CVE-2021-26084_Confluence) :  ![starts](https://img.shields.io/github/stars/r0ckysec/CVE-2021-26084_Confluence.svg) ![forks](https://img.shields.io/github/forks/r0ckysec/CVE-2021-26084_Confluence.svg)
- [https://github.com/Udyz/CVE-2021-26084](https://github.com/Udyz/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2021-26084.svg)
- [https://github.com/Vulnmachines/Confluence_CVE-2021-26084](https://github.com/Vulnmachines/Confluence_CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/Confluence_CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/Confluence_CVE-2021-26084.svg)
- [https://github.com/smallpiggy/cve-2021-26084-confluence](https://github.com/smallpiggy/cve-2021-26084-confluence) :  ![starts](https://img.shields.io/github/stars/smallpiggy/cve-2021-26084-confluence.svg) ![forks](https://img.shields.io/github/forks/smallpiggy/cve-2021-26084-confluence.svg)
- [https://github.com/taythebot/CVE-2021-26084](https://github.com/taythebot/CVE-2021-26084) :  ![starts](https://img.shields.io/github/stars/taythebot/CVE-2021-26084.svg) ![forks](https://img.shields.io/github/forks/taythebot/CVE-2021-26084.svg)
- [https://github.com/Osyanina/westone-CVE-2021-26084-scanner](https://github.com/Osyanina/westone-CVE-2021-26084-scanner) :  ![starts](https://img.shields.io/github/stars/Osyanina/westone-CVE-2021-26084-scanner.svg) ![forks](https://img.shields.io/github/forks/Osyanina/westone-CVE-2021-26084-scanner.svg)
- [https://github.com/bcdannyboy/CVE-2021-26084_GoPOC](https://github.com/bcdannyboy/CVE-2021-26084_GoPOC) :  ![starts](https://img.shields.io/github/stars/bcdannyboy/CVE-2021-26084_GoPOC.svg) ![forks](https://img.shields.io/github/forks/bcdannyboy/CVE-2021-26084_GoPOC.svg)


## CVE-2021-23434
 This affects the package object-path before 0.11.6. A type confusion vulnerability can lead to a bypass of CVE-2020-15256 when the path components used in the path parameter are arrays. In particular, the condition currentPath === '__proto__' returns false if currentPath is ['__proto__']. This is because the === operator returns always false when the type of the operands is different.

- [https://github.com/AlAIAL90/CVE-2021-23434](https://github.com/AlAIAL90/CVE-2021-23434) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-23434.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-23434.svg)


## CVE-2021-21853
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow due to unchecked addition arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21853](https://github.com/AlAIAL90/CVE-2021-21853) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21853.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21853.svg)


## CVE-2021-21850
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow when the library encounters an atom using the &#8220;trun&#8221; FOURCC code due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21850](https://github.com/AlAIAL90/CVE-2021-21850) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21850.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21850.svg)


## CVE-2021-21849
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow when the library encounters an atom using the &#8220;tfra&#8221; FOURCC code due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21849](https://github.com/AlAIAL90/CVE-2021-21849) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21849.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21849.svg)


## CVE-2021-21848
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. The library will actually reuse the parser for atoms with the &#8220;stsz&#8221; FOURCC code when parsing atoms that use the &#8220;stz2&#8221; FOURCC code and can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21848](https://github.com/AlAIAL90/CVE-2021-21848) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21848.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21848.svg)


## CVE-2021-21847
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input in &#8220;stts&#8221; decoder can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21847](https://github.com/AlAIAL90/CVE-2021-21847) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21847.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21847.svg)


## CVE-2021-21846
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input in &#8220;stsz&#8221; decoder can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21846](https://github.com/AlAIAL90/CVE-2021-21846) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21846.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21846.svg)


## CVE-2021-21845
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input in &#8220;stsc&#8221; decoder can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21845](https://github.com/AlAIAL90/CVE-2021-21845) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21845.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21845.svg)


## CVE-2021-21844
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input when encountering an atom using the &#8220;stco&#8221; FOURCC code, can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21844](https://github.com/AlAIAL90/CVE-2021-21844) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21844.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21844.svg)


## CVE-2021-21843
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. After validating the number of ranges, at [41] the library will multiply the count by the size of the GF_SubsegmentRangeInfo structure. On a 32-bit platform, this multiplication can result in an integer overflow causing the space of the array being allocated to be less than expected. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21843](https://github.com/AlAIAL90/CVE-2021-21843) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21843.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21843.svg)


## CVE-2021-21842
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow when processing an atom using the 'ssix' FOURCC code, due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21842](https://github.com/AlAIAL90/CVE-2021-21842) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21842.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21842.svg)


## CVE-2021-21841
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input when reading an atom using the 'sbgp' FOURCC code can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21841](https://github.com/AlAIAL90/CVE-2021-21841) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21841.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21841.svg)


## CVE-2021-21840
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input used to process an atom using the &#8220;saio&#8221; FOURCC code cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21840](https://github.com/AlAIAL90/CVE-2021-21840) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21840.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21840.svg)


## CVE-2021-21839
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21839](https://github.com/AlAIAL90/CVE-2021-21839) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21839.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21839.svg)


## CVE-2021-21838
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21838](https://github.com/AlAIAL90/CVE-2021-21838) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21838.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21838.svg)


## CVE-2021-21837
 Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21837](https://github.com/AlAIAL90/CVE-2021-21837) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21837.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21837.svg)


## CVE-2021-21836
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input using the &#8220;ctts&#8221; FOURCC code can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21836](https://github.com/AlAIAL90/CVE-2021-21836) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21836.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21836.svg)


## CVE-2021-21834
 An exploitable integer overflow vulnerability exists within the MPEG-4 decoding functionality of the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input when decoding the atom for the &#8220;co64&#8221; FOURCC can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.

- [https://github.com/AlAIAL90/CVE-2021-21834](https://github.com/AlAIAL90/CVE-2021-21834) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-21834.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-21834.svg)


## CVE-2021-20815
 Cross-site scripting vulnerability in Edit Boilerplate screen of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type 6.8.0 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), Movable Type Premium 1.44 and earlier, and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AlAIAL90/CVE-2021-20815](https://github.com/AlAIAL90/CVE-2021-20815) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-20815.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-20815.svg)


## CVE-2021-20814
 Cross-site scripting vulnerability in Setting screen of ContentType Information Widget Plugin of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), and Movable Type Premium 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AlAIAL90/CVE-2021-20814](https://github.com/AlAIAL90/CVE-2021-20814) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-20814.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-20814.svg)


## CVE-2021-20813
 Cross-site scripting vulnerability in Edit screen of Content Data of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series) and Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series)) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AlAIAL90/CVE-2021-20813](https://github.com/AlAIAL90/CVE-2021-20813) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-20813.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-20813.svg)


## CVE-2021-20812
 Cross-site scripting vulnerability in Setting screen of Server Sync of Movable Type (Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series) and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AlAIAL90/CVE-2021-20812](https://github.com/AlAIAL90/CVE-2021-20812) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-20812.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-20812.svg)


## CVE-2021-20811
 Cross-site scripting vulnerability in List of Assets screen of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type 6.8.0 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), Movable Type Premium 1.44 and earlier, and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AlAIAL90/CVE-2021-20811](https://github.com/AlAIAL90/CVE-2021-20811) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-20811.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-20811.svg)


## CVE-2021-20810
 Cross-site scripting vulnerability in Website Management screen of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type 6.8.0 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), Movable Type Premium 1.44 and earlier, and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AlAIAL90/CVE-2021-20810](https://github.com/AlAIAL90/CVE-2021-20810) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-20810.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-20810.svg)


## CVE-2021-20809
 Cross-site scripting vulnerability in Create screens of Entry, Page, and Content Type of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type 6.8.0 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), Movable Type Premium 1.44 and earlier, and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AlAIAL90/CVE-2021-20809](https://github.com/AlAIAL90/CVE-2021-20809) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-20809.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-20809.svg)


## CVE-2021-20808
 Cross-site scripting vulnerability in Search screen of Movable Type (Movable Type 7 r.4903 and earlier (Movable Type 7 Series), Movable Type 6.8.0 and earlier (Movable Type 6 Series), Movable Type Advanced 7 r.4903 and earlier (Movable Type Advanced 7 Series), Movable Type Premium 1.44 and earlier, and Movable Type Premium Advanced 1.44 and earlier) allows remote attackers to inject arbitrary script or HTML via unspecified vectors.

- [https://github.com/AlAIAL90/CVE-2021-20808](https://github.com/AlAIAL90/CVE-2021-20808) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-20808.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-20808.svg)


## CVE-2021-20793
 Untrusted search path vulnerability in the installer of Sony Audio USB Driver V1.10 and prior and the installer of HAP Music Transfer Ver.1.3.0 and prior allows an attacker to gain privileges and execute arbitrary code via a Trojan horse DLL in an unspecified directory.

- [https://github.com/AlAIAL90/CVE-2021-20793](https://github.com/AlAIAL90/CVE-2021-20793) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-20793.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-20793.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/mstxq17/CVE-2021-1675_RDL_LPE](https://github.com/mstxq17/CVE-2021-1675_RDL_LPE) :  ![starts](https://img.shields.io/github/stars/mstxq17/CVE-2021-1675_RDL_LPE.svg) ![forks](https://img.shields.io/github/forks/mstxq17/CVE-2021-1675_RDL_LPE.svg)


## CVE-2021-0114
 Insecure default variable initialization for the Intel BSSA DFT feature may allow a privileged user to potentially enable an escalation of privilege via local access.

- [https://github.com/AlAIAL90/CVE-2021-0114](https://github.com/AlAIAL90/CVE-2021-0114) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-0114.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-0114.svg)


## CVE-2020-19822
 A remote code execution (RCE) vulnerability in template_user.php of ZZCMS version 2018 allows attackers to execute arbitrary PHP code via the &quot;ml&quot; and &quot;title&quot; parameters.

- [https://github.com/AlAIAL90/CVE-2020-19822](https://github.com/AlAIAL90/CVE-2020-19822) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-19822.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-19822.svg)


## CVE-2020-18913
 EARCLINK ESPCMS-P8 was discovered to contain a SQL injection vulnerability in the espcms_web/Search.php component via the attr_array parameter. This vulnerability allows attackers to access sensitive database information.

- [https://github.com/AlAIAL90/CVE-2020-18913](https://github.com/AlAIAL90/CVE-2020-18913) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2020-18913.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2020-18913.svg)


## CVE-2020-15256
 A prototype pollution vulnerability has been found in `object-path` &lt;= 0.11.4 affecting the `set()` method. The vulnerability is limited to the `includeInheritedProps` mode (if version &gt;= 0.11.0 is used), which has to be explicitly enabled by creating a new instance of `object-path` and setting the option `includeInheritedProps: true`, or by using the default `withInheritedProps` instance. The default operating mode is not affected by the vulnerability if version &gt;= 0.11.0 is used. Any usage of `set()` in versions &lt; 0.11.0 is vulnerable. The issue is fixed in object-path version 0.11.5 As a workaround, don't use the `includeInheritedProps: true` options or the `withInheritedProps` instance if using a version &gt;= 0.11.0.

- [https://github.com/AlAIAL90/CVE-2021-23434](https://github.com/AlAIAL90/CVE-2021-23434) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-23434.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-23434.svg)


## CVE-2020-8515
 DrayTek Vigor2960 1.3.1_Beta, Vigor3900 1.4.4_Beta, and Vigor300B 1.3.3_Beta, 1.4.2.1_Beta, and 1.4.4_Beta devices allow remote code execution as root (without authentication) via shell metacharacters to the cgi-bin/mainfunction.cgi URI. This issue has been fixed in Vigor3900/2960/300B v1.5.1.

- [https://github.com/darrenmartyn/CVE-2020-8515](https://github.com/darrenmartyn/CVE-2020-8515) :  ![starts](https://img.shields.io/github/stars/darrenmartyn/CVE-2020-8515.svg) ![forks](https://img.shields.io/github/forks/darrenmartyn/CVE-2020-8515.svg)


## CVE-2020-7471
 Django 1.11 before 1.11.28, 2.2 before 2.2.10, and 3.0 before 3.0.3 allows SQL Injection if untrusted data is used as a StringAgg delimiter (e.g., in Django applications that offer downloads of data as a series of rows with a user-specified column delimiter). By passing a suitably crafted delimiter to a contrib.postgres.aggregates.StringAgg instance, it was possible to break escaping and inject malicious SQL.

- [https://github.com/mrlihd/CVE-2020-7471](https://github.com/mrlihd/CVE-2020-7471) :  ![starts](https://img.shields.io/github/stars/mrlihd/CVE-2020-7471.svg) ![forks](https://img.shields.io/github/forks/mrlihd/CVE-2020-7471.svg)


## CVE-2019-17571
 Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget when listening to untrusted network traffic for log data. This affects Log4j versions up to 1.2 up to 1.2.17.

- [https://github.com/AlAIAL90/CVE-2019-17571](https://github.com/AlAIAL90/CVE-2019-17571) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2019-17571.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2019-17571.svg)


## CVE-2017-17058
 ** DISPUTED ** The WooCommerce plugin through 3.x for WordPress has a Directory Traversal Vulnerability via a /wp-content/plugins/woocommerce/templates/emails/plain/ URI, which accesses a parent directory. NOTE: a software maintainer indicates that Directory Traversal is not possible because all of the template files have &quot;if (!defined('ABSPATH')) {exit;}&quot; code.

- [https://github.com/fu2x2000/CVE-2017-17058-woo_exploit](https://github.com/fu2x2000/CVE-2017-17058-woo_exploit) :  ![starts](https://img.shields.io/github/stars/fu2x2000/CVE-2017-17058-woo_exploit.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/CVE-2017-17058-woo_exploit.svg)


## CVE-2017-12613
 When apr_time_exp*() or apr_os_exp_time*() functions are invoked with an invalid month field value in Apache Portable Runtime APR 1.6.2 and prior, out of bounds memory may be accessed in converting this value to an apr_time_exp_t value, potentially revealing the contents of a different static heap value or resulting in program termination, and may represent an information disclosure or denial of service vulnerability to applications which call these APR functions with unvalidated external input.

- [https://github.com/AlAIAL90/CVE-2021-35940](https://github.com/AlAIAL90/CVE-2021-35940) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2021-35940.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2021-35940.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit](https://github.com/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit) :  ![starts](https://img.shields.io/github/stars/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit.svg)


## CVE-2016-1828
 The kernel in Apple iOS before 9.3.2, OS X before 10.11.5, tvOS before 9.2.1, and watchOS before 2.2.1 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app, a different vulnerability than CVE-2016-1827, CVE-2016-1829, and CVE-2016-1830.

- [https://github.com/bazad/rootsh](https://github.com/bazad/rootsh) :  ![starts](https://img.shields.io/github/stars/bazad/rootsh.svg) ![forks](https://img.shields.io/github/forks/bazad/rootsh.svg)


## CVE-2016-1234
 Stack-based buffer overflow in the glob implementation in GNU C Library (aka glibc) before 2.24, when GLOB_ALTDIRFUNC is used, allows context-dependent attackers to cause a denial of service (crash) via a long name.

- [https://github.com/AlAIAL90/CVE-2016-1234](https://github.com/AlAIAL90/CVE-2016-1234) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2016-1234.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2016-1234.svg)


## CVE-2015-6612
 libmedia in Android before 5.1.1 LMY48X and 6.0 before 2015-11-01 allows attackers to gain privileges via a crafted application, aka internal bug 23540426.

- [https://github.com/secmob/CVE-2015-6612](https://github.com/secmob/CVE-2015-6612) :  ![starts](https://img.shields.io/github/stars/secmob/CVE-2015-6612.svg) ![forks](https://img.shields.io/github/forks/secmob/CVE-2015-6612.svg)


## CVE-2015-0235
 Heap-based buffer overflow in the __nss_hostname_digits_dots function in glibc 2.2, and other 2.x versions before 2.18, allows context-dependent attackers to execute arbitrary code via vectors related to the (1) gethostbyname or (2) gethostbyname2 function, aka &quot;GHOST.&quot;

- [https://github.com/AlAIAL90/CVE-2015-0235](https://github.com/AlAIAL90/CVE-2015-0235) :  ![starts](https://img.shields.io/github/stars/AlAIAL90/CVE-2015-0235.svg) ![forks](https://img.shields.io/github/forks/AlAIAL90/CVE-2015-0235.svg)

