# Update 2022-02-23
## CVE-2022-24112
 An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.

- [https://github.com/shakeman8/CVE-2022-24112](https://github.com/shakeman8/CVE-2022-24112) :  ![starts](https://img.shields.io/github/stars/shakeman8/CVE-2022-24112.svg) ![forks](https://img.shields.io/github/forks/shakeman8/CVE-2022-24112.svg)


## CVE-2022-23131
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).

- [https://github.com/L0ading-x/cve-2022-23131](https://github.com/L0ading-x/cve-2022-23131) :  ![starts](https://img.shields.io/github/stars/L0ading-x/cve-2022-23131.svg) ![forks](https://img.shields.io/github/forks/L0ading-x/cve-2022-23131.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/coconut20/CVE-2022-21907-RCE-POC](https://github.com/coconut20/CVE-2022-21907-RCE-POC) :  ![starts](https://img.shields.io/github/stars/coconut20/CVE-2022-21907-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/coconut20/CVE-2022-21907-RCE-POC.svg)


## CVE-2021-45008
 Plesk CMS 18.0.37 is affected by an insecure permissions vulnerability that allows privilege Escalation from user to admin rights.

- [https://github.com/AS4mir/CVE-2021-45008](https://github.com/AS4mir/CVE-2021-45008) :  ![starts](https://img.shields.io/github/stars/AS4mir/CVE-2021-45008.svg) ![forks](https://img.shields.io/github/forks/AS4mir/CVE-2021-45008.svg)


## CVE-2021-34863
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of D-Link DAP-2020 1.01rc001 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the handling of the var:page parameter provided to the webproc endpoint. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-13271.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-34862
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of D-Link DAP-2020 1.01rc001 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the handling of the var:menu parameter provided to the webproc endpoint. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-13270.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-34861
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of D-Link DAP-2020 1.01rc001 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the webproc endpoint, which listens on TCP port 80 by default. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-12104.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-34860
 This vulnerability allows network-adjacent attackers to disclose sensitive information on affected installations of D-Link DAP-2020 1.01rc001 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the handling of the getpage parameter provided to the webproc endpoint. The issue results from the lack of proper validation of a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to disclose information in the context of root. Was ZDI-CAN-12103.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-34730
 A vulnerability in the Universal Plug-and-Play (UPnP) service of Cisco Small Business RV110W, RV130, RV130W, and RV215W Routers could allow an unauthenticated, remote attacker to execute arbitrary code or cause an affected device to restart unexpectedly, resulting in a denial of service (DoS) condition. This vulnerability is due to improper validation of incoming UPnP traffic. An attacker could exploit this vulnerability by sending a crafted UPnP request to an affected device. A successful exploit could allow the attacker to execute arbitrary code as the root user on the underlying operating system or cause the device to reload, resulting in a DoS condition. Cisco has not released software updates that address this vulnerability.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-33045
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-33044
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-28797
 A stack-based buffer overflow vulnerability has been reported to affect QNAP NAS devices running Surveillance Station. If exploited, this vulnerability allows attackers to execute arbitrary code. QNAP have already fixed this vulnerability in the following versions: Surveillance Station 5.1.5.4.3 (and later) for ARM CPU NAS (64bit OS) and x86 CPU NAS (64bit OS) Surveillance Station 5.1.5.3.3 (and later) for ARM CPU NAS (32bit OS) and x86 CPU NAS (32bit OS)

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-27965
 The MsIo64.sys driver before 1.1.19.1016 in MSI Dragon Center before 2.0.98.0 has a buffer overflow that allows privilege escalation via a crafted 0x80102040, 0x80102044, 0x80102050, or 0x80102054 IOCTL request.

- [https://github.com/Leo-Security/CVE-2021-27965-Win10-20H2-x64](https://github.com/Leo-Security/CVE-2021-27965-Win10-20H2-x64) :  ![starts](https://img.shields.io/github/stars/Leo-Security/CVE-2021-27965-Win10-20H2-x64.svg) ![forks](https://img.shields.io/github/forks/Leo-Security/CVE-2021-27965-Win10-20H2-x64.svg)


## CVE-2021-27250
 This vulnerability allows network-adjacent attackers to disclose sensitive information on affected installations of D-Link DAP-2020 v1.01rc001 Wi-Fi access points. Authentication is not required to exploit this vulnerability. The specific flaw exists within the processing of CGI scripts. When parsing the errorpage request parameter, the process does not properly validate a user-supplied path prior to using it in file operations. An attacker can leverage this vulnerability to disclose stored credentials, leading to further compromise. Was ZDI-CAN-11856.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-27249
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of D-Link DAP-2020 v1.01rc001 Wi-Fi access points. Authentication is not required to exploit this vulnerability. The specific flaw exists within the processing of CGI scripts. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-11369.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-27248
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of D-Link DAP-2020 v1.01rc001 Wi-Fi access points. Authentication is not required to exploit this vulnerability. The specific flaw exists within the processing of CGI scripts. When parsing the getpage parameter, the process does not properly validate the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-10932.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/tuhin81/CVE-2021-22204-exiftool](https://github.com/tuhin81/CVE-2021-22204-exiftool) :  ![starts](https://img.shields.io/github/stars/tuhin81/CVE-2021-22204-exiftool.svg) ![forks](https://img.shields.io/github/forks/tuhin81/CVE-2021-22204-exiftool.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Tanmay-N/CVE-2021-4034](https://github.com/Tanmay-N/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Tanmay-N/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Tanmay-N/CVE-2021-4034.svg)
- [https://github.com/chenaotian/CVE-2022-0185](https://github.com/chenaotian/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2022-0185.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/Nosferatuvjr/Vivald0x6f](https://github.com/Nosferatuvjr/Vivald0x6f) :  ![starts](https://img.shields.io/github/stars/Nosferatuvjr/Vivald0x6f.svg) ![forks](https://img.shields.io/github/forks/Nosferatuvjr/Vivald0x6f.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/mtthwstffrd/calebstewart-CVE-2021-1675](https://github.com/mtthwstffrd/calebstewart-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/mtthwstffrd/calebstewart-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/mtthwstffrd/calebstewart-CVE-2021-1675.svg)
- [https://github.com/mtthwstffrd/cube0x0-CVE-2021-1675](https://github.com/mtthwstffrd/cube0x0-CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/mtthwstffrd/cube0x0-CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/mtthwstffrd/cube0x0-CVE-2021-1675.svg)


## CVE-2020-35785
 NETGEAR DGN2200v1 devices before v1.0.0.60 mishandle HTTPd authentication (aka PSV-2020-0363, PSV-2020-0364, and PSV-2020-0365).

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2020-8205
 The uppy npm package &lt; 1.13.2 and &lt; 2.0.0-alpha.5 is vulnerable to a Server-Side Request Forgery (SSRF) vulnerability, which allows an attacker to scan local or external networks or otherwise interact with internal systems.

- [https://github.com/ossf-cve-benchmark/CVE-2020-8205](https://github.com/ossf-cve-benchmark/CVE-2020-8205) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2020-8205.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2020-8205.svg)


## CVE-2020-2501
 A stack-based buffer overflow vulnerability has been reported to affect QNAP NAS devices running Surveillance Station. If exploited, this vulnerability allows attackers to execute arbitrary code. QNAP have already fixed this vulnerability in the following versions: Surveillance Station 5.1.5.4.3 (and later) for ARM CPU NAS (64bit OS) and x86 CPU NAS (64bit OS) Surveillance Station 5.1.5.3.3 (and later) for ARM CPU NAS (32bit OS) and x86 CPU NAS (32bit OS)

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/mtthwstffrd/dirkjanm-CVE-2020-1472](https://github.com/mtthwstffrd/dirkjanm-CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/mtthwstffrd/dirkjanm-CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/mtthwstffrd/dirkjanm-CVE-2020-1472.svg)
- [https://github.com/mtthwstffrd/SecuraBV-CVE-2020-1472](https://github.com/mtthwstffrd/SecuraBV-CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/mtthwstffrd/SecuraBV-CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/mtthwstffrd/SecuraBV-CVE-2020-1472.svg)


## CVE-2019-7406
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2016-3116
 CRLF injection vulnerability in Dropbear SSH before 2016.72 allows remote authenticated users to bypass intended shell-command restrictions via crafted X11 forwarding data.

- [https://github.com/mxypoo/CVE-2016-3116-DropbearSSH](https://github.com/mxypoo/CVE-2016-3116-DropbearSSH) :  ![starts](https://img.shields.io/github/stars/mxypoo/CVE-2016-3116-DropbearSSH.svg) ![forks](https://img.shields.io/github/forks/mxypoo/CVE-2016-3116-DropbearSSH.svg)

