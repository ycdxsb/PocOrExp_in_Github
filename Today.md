# Update 2023-03-04
## CVE-2022-45988
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/happy0717/CVE-2022-45988](https://github.com/happy0717/CVE-2022-45988) :  ![starts](https://img.shields.io/github/stars/happy0717/CVE-2022-45988.svg) ![forks](https://img.shields.io/github/forks/happy0717/CVE-2022-45988.svg)


## CVE-2022-23093
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Inplex-sys/CVE-2022-23093](https://github.com/Inplex-sys/CVE-2022-23093) :  ![starts](https://img.shields.io/github/stars/Inplex-sys/CVE-2022-23093.svg) ![forks](https://img.shields.io/github/forks/Inplex-sys/CVE-2022-23093.svg)


## CVE-2022-2588
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/PolymorphicOpcode/CVE-2022-2588](https://github.com/PolymorphicOpcode/CVE-2022-2588) :  ![starts](https://img.shields.io/github/stars/PolymorphicOpcode/CVE-2022-2588.svg) ![forks](https://img.shields.io/github/forks/PolymorphicOpcode/CVE-2022-2588.svg)


## CVE-2022-1471
 SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization.

- [https://github.com/1fabunicorn/SnakeYAML-CVE-2022-1471-POC](https://github.com/1fabunicorn/SnakeYAML-CVE-2022-1471-POC) :  ![starts](https://img.shields.io/github/stars/1fabunicorn/SnakeYAML-CVE-2022-1471-POC.svg) ![forks](https://img.shields.io/github/forks/1fabunicorn/SnakeYAML-CVE-2022-1471-POC.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)
- [https://github.com/DoTuan1/Reserch-CVE-2021-41773](https://github.com/DoTuan1/Reserch-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/DoTuan1/Reserch-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/DoTuan1/Reserch-CVE-2021-41773.svg)
- [https://github.com/mightysai1997/CVE-2021-41773-i-](https://github.com/mightysai1997/CVE-2021-41773-i-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-i-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-i-.svg)
- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/nel0x/pwnkit-vulnerability](https://github.com/nel0x/pwnkit-vulnerability) :  ![starts](https://img.shields.io/github/stars/nel0x/pwnkit-vulnerability.svg) ![forks](https://img.shields.io/github/forks/nel0x/pwnkit-vulnerability.svg)


## CVE-2020-28119
 Cross site scripting vulnerability in 53KF &lt; 2.0.0.2 that allows for arbitrary code to be executed via crafted HTML statement inserted into chat window.

- [https://github.com/i900008/CVE-2020-28119](https://github.com/i900008/CVE-2020-28119) :  ![starts](https://img.shields.io/github/stars/i900008/CVE-2020-28119.svg) ![forks](https://img.shields.io/github/forks/i900008/CVE-2020-28119.svg)


## CVE-2020-7247
 smtp_mailaddr in smtp_session.c in OpenSMTPD 6.6, as used in OpenBSD 6.6 and other products, allows remote attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by shell metacharacters in a MAIL FROM field. This affects the &quot;uncommented&quot; default configuration. The issue exists because of an incorrect return value upon failure of input validation.

- [https://github.com/gatariee/CVE-2020-7247](https://github.com/gatariee/CVE-2020-7247) :  ![starts](https://img.shields.io/github/stars/gatariee/CVE-2020-7247.svg) ![forks](https://img.shields.io/github/forks/gatariee/CVE-2020-7247.svg)


## CVE-2020-1066
 An elevation of privilege vulnerability exists in .NET Framework which could allow an attacker to elevate their privilege level.To exploit the vulnerability, an attacker would first have to access the local machine, and then run a malicious program.The update addresses the vulnerability by correcting how .NET Framework activates COM objects., aka '.NET Framework Elevation of Privilege Vulnerability'.

- [https://github.com/xyddnljydd/cve-2020-1066](https://github.com/xyddnljydd/cve-2020-1066) :  ![starts](https://img.shields.io/github/stars/xyddnljydd/cve-2020-1066.svg) ![forks](https://img.shields.io/github/forks/xyddnljydd/cve-2020-1066.svg)


## CVE-2020-0618
 A remote code execution vulnerability exists in Microsoft SQL Server Reporting Services when it incorrectly handles page requests, aka 'Microsoft SQL Server Reporting Services Remote Code Execution Vulnerability'.

- [https://github.com/itstarsec/CVE-2020-0618](https://github.com/itstarsec/CVE-2020-0618) :  ![starts](https://img.shields.io/github/stars/itstarsec/CVE-2020-0618.svg) ![forks](https://img.shields.io/github/forks/itstarsec/CVE-2020-0618.svg)


## CVE-2019-9766
 Stack-based buffer overflow in Free MP3 CD Ripper 2.6, when converting a file, allows user-assisted remote attackers to execute arbitrary code via a crafted .mp3 file.

- [https://github.com/zeronohacker/CVE-2019-9766](https://github.com/zeronohacker/CVE-2019-9766) :  ![starts](https://img.shields.io/github/stars/zeronohacker/CVE-2019-9766.svg) ![forks](https://img.shields.io/github/forks/zeronohacker/CVE-2019-9766.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/k4is3r13/Bash-Script-CVE-2018-16763](https://github.com/k4is3r13/Bash-Script-CVE-2018-16763) :  ![starts](https://img.shields.io/github/stars/k4is3r13/Bash-Script-CVE-2018-16763.svg) ![forks](https://img.shields.io/github/forks/k4is3r13/Bash-Script-CVE-2018-16763.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/colorblindpentester/CVE-2017-5638](https://github.com/colorblindpentester/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/colorblindpentester/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/colorblindpentester/CVE-2017-5638.svg)


## CVE-2016-2468
 The Qualcomm GPU driver in Android before 2016-06-01 on Nexus 5, 5X, 6, 6P, and 7 devices allows attackers to gain privileges via a crafted application, aka internal bug 27475454.

- [https://github.com/gitcollect/CVE-2016-2468](https://github.com/gitcollect/CVE-2016-2468) :  ![starts](https://img.shields.io/github/stars/gitcollect/CVE-2016-2468.svg) ![forks](https://img.shields.io/github/forks/gitcollect/CVE-2016-2468.svg)


## CVE-2016-2338
 An exploitable heap overflow vulnerability exists in the Psych::Emitter start_document function of Ruby. In Psych::Emitter start_document function heap buffer &quot;head&quot; allocation is made based on tags array length. Specially constructed object passed as element of tags array can increase this array size after mentioned allocation and cause heap overflow.

- [https://github.com/SpiralBL0CK/CVE-2016-2338-nday](https://github.com/SpiralBL0CK/CVE-2016-2338-nday) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/CVE-2016-2338-nday.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/CVE-2016-2338-nday.svg)

