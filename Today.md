# Update 2022-03-15
## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/k3rwin/spring-cloud-gateway-rce](https://github.com/k3rwin/spring-cloud-gateway-rce) :  ![starts](https://img.shields.io/github/stars/k3rwin/spring-cloud-gateway-rce.svg) ![forks](https://img.shields.io/github/forks/k3rwin/spring-cloud-gateway-rce.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/realbatuhan/dirtypipetester](https://github.com/realbatuhan/dirtypipetester) :  ![starts](https://img.shields.io/github/stars/realbatuhan/dirtypipetester.svg) ![forks](https://img.shields.io/github/forks/realbatuhan/dirtypipetester.svg)
- [https://github.com/sa-infinity8888/Dirty-Pipe-CVE-2022-0847](https://github.com/sa-infinity8888/Dirty-Pipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/sa-infinity8888/Dirty-Pipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/sa-infinity8888/Dirty-Pipe-CVE-2022-0847.svg)


## CVE-2021-44229
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/awsassets/CVE-2021-44229](https://github.com/awsassets/CVE-2021-44229) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2021-44229.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2021-44229.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab](https://github.com/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab) :  ![starts](https://img.shields.io/github/stars/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab.svg) ![forks](https://img.shields.io/github/forks/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/k3rwin/CVE-2021-43798-Grafana](https://github.com/k3rwin/CVE-2021-43798-Grafana) :  ![starts](https://img.shields.io/github/stars/k3rwin/CVE-2021-43798-Grafana.svg) ![forks](https://img.shields.io/github/forks/k3rwin/CVE-2021-43798-Grafana.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/twseptian/cve-2021-42013-docker-lab](https://github.com/twseptian/cve-2021-42013-docker-lab) :  ![starts](https://img.shields.io/github/stars/twseptian/cve-2021-42013-docker-lab.svg) ![forks](https://img.shields.io/github/forks/twseptian/cve-2021-42013-docker-lab.svg)
- [https://github.com/awsassets/CVE-2021-42013](https://github.com/awsassets/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2021-42013.svg)
- [https://github.com/cryst4lliz3/CVE-2021-42013](https://github.com/cryst4lliz3/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/cryst4lliz3/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/cryst4lliz3/CVE-2021-42013.svg)


## CVE-2021-41777
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/awsassets/CVE-2021-41777](https://github.com/awsassets/CVE-2021-41777) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2021-41777.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2021-41777.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/j4k0m/CVE-2021-41773](https://github.com/j4k0m/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/j4k0m/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/j4k0m/CVE-2021-41773.svg)
- [https://github.com/twseptian/cve-2021-41773](https://github.com/twseptian/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/twseptian/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/twseptian/cve-2021-41773.svg)
- [https://github.com/awsassets/CVE-2021-41777](https://github.com/awsassets/CVE-2021-41777) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2021-41777.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2021-41777.svg)
- [https://github.com/awsassets/CVE-2021-42013](https://github.com/awsassets/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2021-42013.svg)
- [https://github.com/cryst4lliz3/CVE-2021-41773](https://github.com/cryst4lliz3/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/cryst4lliz3/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/cryst4lliz3/CVE-2021-41773.svg)


## CVE-2021-35587
 Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: OpenSSO Agent). Supported versions that are affected are 11.1.2.3.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Access Manager. Successful attacks of this vulnerability can result in takeover of Oracle Access Manager. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/antx-code/CVE-2021-35587](https://github.com/antx-code/CVE-2021-35587) :  ![starts](https://img.shields.io/github/stars/antx-code/CVE-2021-35587.svg) ![forks](https://img.shields.io/github/forks/antx-code/CVE-2021-35587.svg)


## CVE-2021-24499
 The Workreap WordPress theme before 2.2.2 AJAX actions workreap_award_temp_file_uploader and workreap_temp_file_uploader did not perform nonce checks, or validate that the request is from a valid user in any other way. The endpoints allowed for uploading arbitrary files to the uploads/workreap-temp directory. Uploaded files were neither sanitized nor validated, allowing an unauthenticated visitor to upload executable code such as php scripts.

- [https://github.com/j4k0m/CVE-2021-24499](https://github.com/j4k0m/CVE-2021-24499) :  ![starts](https://img.shields.io/github/stars/j4k0m/CVE-2021-24499.svg) ![forks](https://img.shields.io/github/forks/j4k0m/CVE-2021-24499.svg)


## CVE-2021-22210
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.2. When querying the repository branches through API, GitLab was ignoring a query parameter and returning a considerable amount of results.

- [https://github.com/awsassets/CVE-2021-22210](https://github.com/awsassets/CVE-2021-22210) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2021-22210.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2021-22210.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/awsassets/CVE-2021-22210](https://github.com/awsassets/CVE-2021-22210) :  ![starts](https://img.shields.io/github/stars/awsassets/CVE-2021-22210.svg) ![forks](https://img.shields.io/github/forks/awsassets/CVE-2021-22210.svg)
- [https://github.com/cryst4lliz3/CVE-2021-22205](https://github.com/cryst4lliz3/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/cryst4lliz3/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/cryst4lliz3/CVE-2021-22205.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Nel0x/PWNKITVulnerability](https://github.com/Nel0x/PWNKITVulnerability) :  ![starts](https://img.shields.io/github/stars/Nel0x/PWNKITVulnerability.svg) ![forks](https://img.shields.io/github/forks/Nel0x/PWNKITVulnerability.svg)


## CVE-2019-5420
 A remote code execution vulnerability in development mode Rails &lt;5.2.2.1, &lt;6.0.0.beta3 can allow an attacker to guess the automatically generated development mode secret token. This secret token can be used in combination with other Rails internals to escalate to a remote code execution exploit.

- [https://github.com/j4k0m/CVE-2019-5420](https://github.com/j4k0m/CVE-2019-5420) :  ![starts](https://img.shields.io/github/stars/j4k0m/CVE-2019-5420.svg) ![forks](https://img.shields.io/github/forks/j4k0m/CVE-2019-5420.svg)


## CVE-2018-0114
 A vulnerability in the Cisco node-jose open source library before 0.11.0 could allow an unauthenticated, remote attacker to re-sign tokens using a key that is embedded within the token. The vulnerability is due to node-jose following the JSON Web Signature (JWS) standard for JSON Web Tokens (JWTs). This standard specifies that a JSON Web Key (JWK) representing a public key can be embedded within the header of a JWS. This public key is then trusted for verification. An attacker could exploit this by forging valid JWS objects by removing the original signature, adding a new public key to the header, and then signing the object using the (attacker-owned) private key associated with the public key embedded in that JWS header.

- [https://github.com/j4k0m/CVE-2018-0114](https://github.com/j4k0m/CVE-2018-0114) :  ![starts](https://img.shields.io/github/stars/j4k0m/CVE-2018-0114.svg) ![forks](https://img.shields.io/github/forks/j4k0m/CVE-2018-0114.svg)

