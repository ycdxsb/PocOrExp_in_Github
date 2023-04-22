# Update 2023-04-22
## CVE-2023-25234
 Tenda AC500 V2.0.1.9(1307) is vulnerable to Buffer Overflow in function fromAddressNat via parameters entrys and mitInterface.

- [https://github.com/FzBacon/CVE-2023-25234_Tenda_AC6_stack_overflow](https://github.com/FzBacon/CVE-2023-25234_Tenda_AC6_stack_overflow) :  ![starts](https://img.shields.io/github/stars/FzBacon/CVE-2023-25234_Tenda_AC6_stack_overflow.svg) ![forks](https://img.shields.io/github/forks/FzBacon/CVE-2023-25234_Tenda_AC6_stack_overflow.svg)


## CVE-2023-21823
 Windows Graphics Component Remote Code Execution Vulnerability

- [https://github.com/Elizarfish/CVE-2023-21823](https://github.com/Elizarfish/CVE-2023-21823) :  ![starts](https://img.shields.io/github/stars/Elizarfish/CVE-2023-21823.svg) ![forks](https://img.shields.io/github/forks/Elizarfish/CVE-2023-21823.svg)


## CVE-2023-21768
 Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability.

- [https://github.com/zoemurmure/CVE-2023-21768-AFD-for-WinSock-EoP-exploit](https://github.com/zoemurmure/CVE-2023-21768-AFD-for-WinSock-EoP-exploit) :  ![starts](https://img.shields.io/github/stars/zoemurmure/CVE-2023-21768-AFD-for-WinSock-EoP-exploit.svg) ![forks](https://img.shields.io/github/forks/zoemurmure/CVE-2023-21768-AFD-for-WinSock-EoP-exploit.svg)


## CVE-2023-21554
 Microsoft Message Queuing Remote Code Execution Vulnerability

- [https://github.com/g3tS3rvic3s/CVE-2023-21554-RCE-POC](https://github.com/g3tS3rvic3s/CVE-2023-21554-RCE-POC) :  ![starts](https://img.shields.io/github/stars/g3tS3rvic3s/CVE-2023-21554-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/g3tS3rvic3s/CVE-2023-21554-RCE-POC.svg)
- [https://github.com/g1x-r/CVE-2023-21554-PoC](https://github.com/g1x-r/CVE-2023-21554-PoC) :  ![starts](https://img.shields.io/github/stars/g1x-r/CVE-2023-21554-PoC.svg) ![forks](https://img.shields.io/github/forks/g1x-r/CVE-2023-21554-PoC.svg)


## CVE-2023-0286
 There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName. X.400 addresses were parsed as an ASN1_STRING but the public structure definition for GENERAL_NAME incorrectly specified the type of the x400Address field as ASN1_TYPE. This field is subsequently interpreted by the OpenSSL function GENERAL_NAME_cmp as an ASN1_TYPE rather than an ASN1_STRING. When CRL checking is enabled (i.e. the application sets the X509_V_FLAG_CRL_CHECK flag), this vulnerability may allow an attacker to pass arbitrary pointers to a memcmp call, enabling them to read memory contents or enact a denial of service. In most cases, the attack requires the attacker to provide both the certificate chain and CRL, neither of which need to have a valid signature. If the attacker only controls one of these inputs, the other input must already contain an X.400 address as a CRL distribution point, which is uncommon. As such, this vulnerability is most likely to only affect applications which have implemented their own functionality for retrieving CRLs over a network.

- [https://github.com/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2023-0286](https://github.com/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2023-0286) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2023-0286.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.1.1g_G3_CVE-2023-0286.svg)


## CVE-2022-0435
 A stack overflow flaw was found in the Linux kernel's TIPC protocol functionality in the way a user sends a packet with malicious content where the number of domain member nodes is higher than the 64 allowed. This flaw allows a remote user to crash the system or possibly escalate their privileges if they have access to the TIPC network.

- [https://github.com/wlswotmd/CVE-2022-0435](https://github.com/wlswotmd/CVE-2022-0435) :  ![starts](https://img.shields.io/github/stars/wlswotmd/CVE-2022-0435.svg) ![forks](https://img.shields.io/github/forks/wlswotmd/CVE-2022-0435.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/zhzyker/CVE-2021-4034](https://github.com/zhzyker/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/zhzyker/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/zhzyker/CVE-2021-4034.svg)
- [https://github.com/c3l3si4n/pwnkit](https://github.com/c3l3si4n/pwnkit) :  ![starts](https://img.shields.io/github/stars/c3l3si4n/pwnkit.svg) ![forks](https://img.shields.io/github/forks/c3l3si4n/pwnkit.svg)
- [https://github.com/dadvlingd/CVE-2021-4034](https://github.com/dadvlingd/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/dadvlingd/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dadvlingd/CVE-2021-4034.svg)
- [https://github.com/chenaotian/CVE-2021-4034](https://github.com/chenaotian/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2021-4034.svg)
- [https://github.com/Kirill89/CVE-2021-4034](https://github.com/Kirill89/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Kirill89/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Kirill89/CVE-2021-4034.svg)
- [https://github.com/FDlucifer/Pwnkit-go](https://github.com/FDlucifer/Pwnkit-go) :  ![starts](https://img.shields.io/github/stars/FDlucifer/Pwnkit-go.svg) ![forks](https://img.shields.io/github/forks/FDlucifer/Pwnkit-go.svg)
- [https://github.com/x04000/CVE-2021-4034](https://github.com/x04000/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/x04000/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/x04000/CVE-2021-4034.svg)


## CVE-2021-3572
 A flaw was found in python-pip in the way it handled Unicode separators in git references. A remote attacker could possibly use this issue to install a different revision on a repository. The highest threat from this vulnerability is to data integrity. This is fixed in python-pip version 21.1.

- [https://github.com/litios/cve_2021_3572-old-pip](https://github.com/litios/cve_2021_3572-old-pip) :  ![starts](https://img.shields.io/github/stars/litios/cve_2021_3572-old-pip.svg) ![forks](https://img.shields.io/github/forks/litios/cve_2021_3572-old-pip.svg)


## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-1698.

- [https://github.com/r2bet/CVE-2021-1732](https://github.com/r2bet/CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/r2bet/CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/r2bet/CVE-2021-1732.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/simeononsecurity/CVE-2020-1350-Fix](https://github.com/simeononsecurity/CVE-2020-1350-Fix) :  ![starts](https://img.shields.io/github/stars/simeononsecurity/CVE-2020-1350-Fix.svg) ![forks](https://img.shields.io/github/forks/simeononsecurity/CVE-2020-1350-Fix.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/Anonimo501/ssh_enum_users_CVE-2018-15473](https://github.com/Anonimo501/ssh_enum_users_CVE-2018-15473) :  ![starts](https://img.shields.io/github/stars/Anonimo501/ssh_enum_users_CVE-2018-15473.svg) ![forks](https://img.shields.io/github/forks/Anonimo501/ssh_enum_users_CVE-2018-15473.svg)

