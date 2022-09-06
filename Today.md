# Update 2022-09-06
## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/CEOrbey/CVE-2022-36804-POC](https://github.com/CEOrbey/CVE-2022-36804-POC) :  ![starts](https://img.shields.io/github/stars/CEOrbey/CVE-2022-36804-POC.svg) ![forks](https://img.shields.io/github/forks/CEOrbey/CVE-2022-36804-POC.svg)


## CVE-2021-39174
 Cachet is an open source status page system. Prior to version 2.5.1, authenticated users, regardless of their privileges (User or Admin), can leak the value of any configuration entry of the dotenv file, e.g. the application secret (`APP_KEY`) and various passwords (email, database, etc). This issue was addressed in version 2.5.1 by improving `UpdateConfigCommandHandler` and preventing the use of nested variables in the resulting dotenv configuration file. As a workaround, only allow trusted source IP addresses to access to the administration dashboard.

- [https://github.com/n0kovo/CVE-2021-39174-PoC](https://github.com/n0kovo/CVE-2021-39174-PoC) :  ![starts](https://img.shields.io/github/stars/n0kovo/CVE-2021-39174-PoC.svg) ![forks](https://img.shields.io/github/forks/n0kovo/CVE-2021-39174-PoC.svg)

