# Update 2022-02-05
## CVE-2022-21882
 Win32k Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2022-21887.

- [https://github.com/L4ys/CVE-2022-21882](https://github.com/L4ys/CVE-2022-21882) :  ![starts](https://img.shields.io/github/stars/L4ys/CVE-2022-21882.svg) ![forks](https://img.shields.io/github/forks/L4ys/CVE-2022-21882.svg)
- [https://github.com/jessica0f0116/cve_2022_21882](https://github.com/jessica0f0116/cve_2022_21882) :  ![starts](https://img.shields.io/github/stars/jessica0f0116/cve_2022_21882.svg) ![forks](https://img.shields.io/github/forks/jessica0f0116/cve_2022_21882.svg)


## CVE-2021-45901
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/9lyph/CVE-2021-45901](https://github.com/9lyph/CVE-2021-45901) :  ![starts](https://img.shields.io/github/stars/9lyph/CVE-2021-45901.svg) ![forks](https://img.shields.io/github/forks/9lyph/CVE-2021-45901.svg)


## CVE-2021-43848
 h2o is an open source http server. In code prior to the `8c0eca3` commit h2o may attempt to access uninitialized memory. When receiving QUIC frames in certain order, HTTP/3 server-side implementation of h2o can be misguided to treat uninitialized memory as HTTP/3 frames that have been received. When h2o is used as a reverse proxy, an attacker can abuse this vulnerability to send internal state of h2o to backend servers controlled by the attacker or third party. Also, if there is an HTTP endpoint that reflects the traffic sent from the client, an attacker can use that reflector to obtain internal state of h2o. This internal state includes traffic of other connections in unencrypted form and TLS session tickets. This vulnerability exists in h2o server with HTTP/3 support, between commit 93af138 and d1f0f65. None of the released versions of h2o are affected by this vulnerability. There are no known workarounds. Users of unreleased versions of h2o using HTTP/3 are advised to upgrade immediately.

- [https://github.com/neex/hui2ochko](https://github.com/neex/hui2ochko) :  ![starts](https://img.shields.io/github/stars/neex/hui2ochko.svg) ![forks](https://img.shields.io/github/forks/neex/hui2ochko.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/jas9reet/CVE-2021-42013-LAB](https://github.com/jas9reet/CVE-2021-42013-LAB) :  ![starts](https://img.shields.io/github/stars/jas9reet/CVE-2021-42013-LAB.svg) ![forks](https://img.shields.io/github/forks/jas9reet/CVE-2021-42013-LAB.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Ph4nt0mh4x0r/auto-CVE-2021-4034](https://github.com/Ph4nt0mh4x0r/auto-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Ph4nt0mh4x0r/auto-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Ph4nt0mh4x0r/auto-CVE-2021-4034.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/b1cat/CVE_2020_1938_ajp_poc](https://github.com/b1cat/CVE_2020_1938_ajp_poc) :  ![starts](https://img.shields.io/github/stars/b1cat/CVE_2020_1938_ajp_poc.svg) ![forks](https://img.shields.io/github/forks/b1cat/CVE_2020_1938_ajp_poc.svg)
- [https://github.com/haerin7427/CVE_2020_1938](https://github.com/haerin7427/CVE_2020_1938) :  ![starts](https://img.shields.io/github/stars/haerin7427/CVE_2020_1938.svg) ![forks](https://img.shields.io/github/forks/haerin7427/CVE_2020_1938.svg)


## CVE-2006-3392
 Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using &quot;..%01&quot; sequences, which bypass the removal of &quot;../&quot; sequences before bytes such as &quot;%01&quot; are removed from the filename.  NOTE: This is a different issue than CVE-2006-3274.

- [https://github.com/xen00rw/CVE-2006-3392](https://github.com/xen00rw/CVE-2006-3392) :  ![starts](https://img.shields.io/github/stars/xen00rw/CVE-2006-3392.svg) ![forks](https://img.shields.io/github/forks/xen00rw/CVE-2006-3392.svg)

