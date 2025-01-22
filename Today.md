# Update 2025-01-22
## CVE-2025-22620
 gitoxide is an implementation of git written in Rust. Prior to 0.17.0, gix-worktree-state specifies 0777 permissions when checking out executable files, intending that the umask will restrict them appropriately. But one of the strategies it uses to set permissions is not subject to the umask. This causes files in a repository to be world-writable in some situations. This vulnerability is fixed in 0.17.0.

- [https://github.com/EliahKagan/checkout-index](https://github.com/EliahKagan/checkout-index) :  ![starts](https://img.shields.io/github/stars/EliahKagan/checkout-index.svg) ![forks](https://img.shields.io/github/forks/EliahKagan/checkout-index.svg)


## CVE-2025-21298
 Windows OLE Remote Code Execution Vulnerability

- [https://github.com/ynwarcs/CVE-2025-21298](https://github.com/ynwarcs/CVE-2025-21298) :  ![starts](https://img.shields.io/github/stars/ynwarcs/CVE-2025-21298.svg) ![forks](https://img.shields.io/github/forks/ynwarcs/CVE-2025-21298.svg)


## CVE-2025-0282
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser](https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser) :  ![starts](https://img.shields.io/github/stars/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg) ![forks](https://img.shields.io/github/forks/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg)


## CVE-2024-55511
 A null pointer dereference vulnerability in Macrium Reflect prior to 8.1.8017 allows an attacker to elevate their privileges via executing a specially crafted executable.

- [https://github.com/nikosecurity/CVE-2024-55511](https://github.com/nikosecurity/CVE-2024-55511) :  ![starts](https://img.shields.io/github/stars/nikosecurity/CVE-2024-55511.svg) ![forks](https://img.shields.io/github/forks/nikosecurity/CVE-2024-55511.svg)


## CVE-2024-54880
 SeaCMS V13.1 is vulnerable to Incorrect Access Control. A logic flaw can be exploited by an attacker to allow any user to register accounts in bulk.

- [https://github.com/ailenye/CVE-2024-54880](https://github.com/ailenye/CVE-2024-54880) :  ![starts](https://img.shields.io/github/stars/ailenye/CVE-2024-54880.svg) ![forks](https://img.shields.io/github/forks/ailenye/CVE-2024-54880.svg)


## CVE-2024-54879
 SeaCMS V13.1 is vulnerable to Incorrect Access Control. A logic flaw can be exploited by an attacker to allow any user to recharge members indefinitely.

- [https://github.com/ailenye/CVE-2024-54879](https://github.com/ailenye/CVE-2024-54879) :  ![starts](https://img.shields.io/github/stars/ailenye/CVE-2024-54879.svg) ![forks](https://img.shields.io/github/forks/ailenye/CVE-2024-54879.svg)


## CVE-2024-43998
 Missing Authorization vulnerability in WebsiteinWP Blogpoet allows Accessing Functionality Not Properly Constrained by ACLs.This issue affects Blogpoet: from n/a through 1.0.3.

- [https://github.com/Nxploited/CVE-2024-43998](https://github.com/Nxploited/CVE-2024-43998) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-43998.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-43998.svg)


## CVE-2024-21887
 A command injection vulnerability in web components of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x)  allows an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance.

- [https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser](https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser) :  ![starts](https://img.shields.io/github/stars/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg) ![forks](https://img.shields.io/github/forks/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/AzrDll/CVE-2024-6387](https://github.com/AzrDll/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/AzrDll/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/AzrDll/CVE-2024-6387.svg)


## CVE-2024-0582
 A memory leak flaw was found in the Linux kernel’s io_uring functionality in how a user registers a buffer ring with IORING_REGISTER_PBUF_RING, mmap() it, and then frees it. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/101010zyl/CVE-2024-0582-dataonly](https://github.com/101010zyl/CVE-2024-0582-dataonly) :  ![starts](https://img.shields.io/github/stars/101010zyl/CVE-2024-0582-dataonly.svg) ![forks](https://img.shields.io/github/forks/101010zyl/CVE-2024-0582-dataonly.svg)


## CVE-2023-46805
 An authentication bypass vulnerability in the web component of Ivanti ICS 9.x, 22.x and Ivanti Policy Secure allows a remote attacker to access restricted resources by bypassing control checks.

- [https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser](https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser) :  ![starts](https://img.shields.io/github/stars/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg) ![forks](https://img.shields.io/github/forks/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg)


## CVE-2023-40028
 Ghost is an open source content management system. Versions prior to 5.59.1 are subject to a vulnerability which allows authenticated users to upload files that are symlinks. This can be exploited to perform an arbitrary file read of any file on the host operating system. Site administrators can check for exploitation of this issue by looking for unknown symlinks within Ghost's `content/` folder. Version 5.59.1 contains a fix for this issue. All users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/godylockz/CVE-2023-40028](https://github.com/godylockz/CVE-2023-40028) :  ![starts](https://img.shields.io/github/stars/godylockz/CVE-2023-40028.svg) ![forks](https://img.shields.io/github/forks/godylockz/CVE-2023-40028.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/WuliRuler/SBSCAN](https://github.com/WuliRuler/SBSCAN) :  ![starts](https://img.shields.io/github/stars/WuliRuler/SBSCAN.svg) ![forks](https://img.shields.io/github/forks/WuliRuler/SBSCAN.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/WuliRuler/SBSCAN](https://github.com/WuliRuler/SBSCAN) :  ![starts](https://img.shields.io/github/stars/WuliRuler/SBSCAN.svg) ![forks](https://img.shields.io/github/forks/WuliRuler/SBSCAN.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/WuliRuler/SBSCAN](https://github.com/WuliRuler/SBSCAN) :  ![starts](https://img.shields.io/github/stars/WuliRuler/SBSCAN.svg) ![forks](https://img.shields.io/github/forks/WuliRuler/SBSCAN.svg)


## CVE-2022-21888
 Windows Modern Execution Server Remote Code Execution Vulnerability

- [https://github.com/Sausageinforest/CVE-2022-218882](https://github.com/Sausageinforest/CVE-2022-218882) :  ![starts](https://img.shields.io/github/stars/Sausageinforest/CVE-2022-218882.svg) ![forks](https://img.shields.io/github/forks/Sausageinforest/CVE-2022-218882.svg)


## CVE-2021-21234
 spring-boot-actuator-logview in a library that adds a simple logfile viewer as spring boot actuator endpoint. It is maven package "eu.hinsch:spring-boot-actuator-logview". In spring-boot-actuator-logview before version 0.2.13 there is a directory traversal vulnerability. The nature of this library is to expose a log file directory via admin (spring boot actuator) HTTP endpoints. Both the filename to view and a base folder (relative to the logging folder root) can be specified via request parameters. While the filename parameter was checked to prevent directory traversal exploits (so that `filename=../somefile` would not work), the base folder parameter was not sufficiently checked, so that `filename=somefile&base=../` could access a file outside the logging base directory). The vulnerability has been patched in release 0.2.13. Any users of 0.2.12 should be able to update without any issues as there are no other changes in that release. There is no workaround to fix the vulnerability other than updating or removing the dependency. However, removing read access of the user the application is run with to any directory not required for running the application can limit the impact. Additionally, access to the logview endpoint can be limited by deploying the application behind a reverse proxy.

- [https://github.com/WuliRuler/SBSCAN](https://github.com/WuliRuler/SBSCAN) :  ![starts](https://img.shields.io/github/stars/WuliRuler/SBSCAN.svg) ![forks](https://img.shields.io/github/forks/WuliRuler/SBSCAN.svg)


## CVE-2021-1732
 Windows Win32k Elevation of Privilege Vulnerability

- [https://github.com/Sausageinforest/CVE-2021-1732](https://github.com/Sausageinforest/CVE-2021-1732) :  ![starts](https://img.shields.io/github/stars/Sausageinforest/CVE-2021-1732.svg) ![forks](https://img.shields.io/github/forks/Sausageinforest/CVE-2021-1732.svg)

