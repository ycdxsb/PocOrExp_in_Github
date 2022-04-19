# Update 2022-04-19
## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/sherlocksecurity/Microsoft-CVE-2022-26809-The-Little-Boy](https://github.com/sherlocksecurity/Microsoft-CVE-2022-26809-The-Little-Boy) :  ![starts](https://img.shields.io/github/stars/sherlocksecurity/Microsoft-CVE-2022-26809-The-Little-Boy.svg) ![forks](https://img.shields.io/github/forks/sherlocksecurity/Microsoft-CVE-2022-26809-The-Little-Boy.svg)
- [https://github.com/F1uk369/CVE-2022-26809](https://github.com/F1uk369/CVE-2022-26809) :  ![starts](https://img.shields.io/github/stars/F1uk369/CVE-2022-26809.svg) ![forks](https://img.shields.io/github/forks/F1uk369/CVE-2022-26809.svg)


## CVE-2022-1329
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/mcdulltii/CVE-2022-1329](https://github.com/mcdulltii/CVE-2022-1329) :  ![starts](https://img.shields.io/github/stars/mcdulltii/CVE-2022-1329.svg) ![forks](https://img.shields.io/github/forks/mcdulltii/CVE-2022-1329.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/rexpository/linux-privilege-escalation](https://github.com/rexpository/linux-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/rexpository/linux-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/rexpository/linux-privilege-escalation.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/manishkanyal/log4j-scanner](https://github.com/manishkanyal/log4j-scanner) :  ![starts](https://img.shields.io/github/stars/manishkanyal/log4j-scanner.svg) ![forks](https://img.shields.io/github/forks/manishkanyal/log4j-scanner.svg)


## CVE-2021-31805
 The fix issued for CVE-2020-17530 was incomplete. So from Apache Struts 2.0.0 to 2.5.29, still some of the tag&#8217;s attributes could perform a double evaluation if a developer applied forced OGNL evaluation by using the %{...} syntax. Using forced OGNL evaluation on untrusted user input can lead to a Remote Code Execution and security degradation.

- [https://github.com/3SsFuck/CVE-2021-31805-POC](https://github.com/3SsFuck/CVE-2021-31805-POC) :  ![starts](https://img.shields.io/github/stars/3SsFuck/CVE-2021-31805-POC.svg) ![forks](https://img.shields.io/github/forks/3SsFuck/CVE-2021-31805-POC.svg)


## CVE-2021-28476
 Hyper-V Remote Code Execution Vulnerability

- [https://github.com/dengyang123x/0vercl0k](https://github.com/dengyang123x/0vercl0k) :  ![starts](https://img.shields.io/github/stars/dengyang123x/0vercl0k.svg) ![forks](https://img.shields.io/github/forks/dengyang123x/0vercl0k.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/momika233/cve-2021-22205-GitLab-13.10.2---Remote-Code-Execution-RCE-Unauthenticated-](https://github.com/momika233/cve-2021-22205-GitLab-13.10.2---Remote-Code-Execution-RCE-Unauthenticated-) :  ![starts](https://img.shields.io/github/stars/momika233/cve-2021-22205-GitLab-13.10.2---Remote-Code-Execution-RCE-Unauthenticated-.svg) ![forks](https://img.shields.io/github/forks/momika233/cve-2021-22205-GitLab-13.10.2---Remote-Code-Execution-RCE-Unauthenticated-.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/f0rkr/CVE-2019-15107](https://github.com/f0rkr/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/f0rkr/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/f0rkr/CVE-2019-15107.svg)


## CVE-2018-16845
 nginx before versions 1.15.6, 1.14.1 has a vulnerability in the ngx_http_mp4_module, which might allow an attacker to cause infinite loop in a worker process, cause a worker process crash, or might result in worker process memory disclosure by using a specially crafted mp4 file. The issue only affects nginx if it is built with the ngx_http_mp4_module (the module is not built by default) and the .mp4. directive is used in the configuration file. Further, the attack is only possible if an attacker is able to trigger processing of a specially crafted mp4 file with the ngx_http_mp4_module.

- [https://github.com/T4t4ru/CVE-2018-16845](https://github.com/T4t4ru/CVE-2018-16845) :  ![starts](https://img.shields.io/github/stars/T4t4ru/CVE-2018-16845.svg) ![forks](https://img.shields.io/github/forks/T4t4ru/CVE-2018-16845.svg)

