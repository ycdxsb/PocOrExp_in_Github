# Update 2022-03-28
## CVE-2022-26629
 An Access Control vulnerability exists in SoroushPlus+ Messenger 1.0.30 in the Lock Screen Security Feature function due to insufficient permissions and privileges, which allows a malicious attacker bypass the lock screen function.

- [https://github.com/scopion/CVE-2022-26629](https://github.com/scopion/CVE-2022-26629) :  ![starts](https://img.shields.io/github/stars/scopion/CVE-2022-26629.svg) ![forks](https://img.shields.io/github/forks/scopion/CVE-2022-26629.svg)


## CVE-2022-21668
 pipenv is a Python development workflow tool. Starting with version 2018.10.9 and prior to version 2022.1.8, a flaw in pipenv's parsing of requirements files allows an attacker to insert a specially crafted string inside a comment anywhere within a requirements.txt file, which will cause victims who use pipenv to install the requirements file to download dependencies from a package index server controlled by the attacker. By embedding malicious code in packages served from their malicious index server, the attacker can trigger arbitrary remote code execution (RCE) on the victims' systems. If an attacker is able to hide a malicious `--index-url` option in a requirements file that a victim installs with pipenv, the attacker can embed arbitrary malicious code in packages served from their malicious index server that will be executed on the victim's host during installation (remote code execution/RCE). When pip installs from a source distribution, any code in the setup.py is executed by the install process. This issue is patched in version 2022.1.8. The GitHub Security Advisory contains more information about this vulnerability.

- [https://github.com/sreeram281997/CVE-2022-21668-Pipenv-RCE-vulnerability](https://github.com/sreeram281997/CVE-2022-21668-Pipenv-RCE-vulnerability) :  ![starts](https://img.shields.io/github/stars/sreeram281997/CVE-2022-21668-Pipenv-RCE-vulnerability.svg) ![forks](https://img.shields.io/github/forks/sreeram281997/CVE-2022-21668-Pipenv-RCE-vulnerability.svg)


## CVE-2021-44117
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/warmachine-57/CVE-2021-44117](https://github.com/warmachine-57/CVE-2021-44117) :  ![starts](https://img.shields.io/github/stars/warmachine-57/CVE-2021-44117.svg) ![forks](https://img.shields.io/github/forks/warmachine-57/CVE-2021-44117.svg)


## CVE-2021-43858
 MinIO is a Kubernetes native application for cloud storage. Prior to version `RELEASE.2021-12-27T07-23-18Z`, a malicious client can hand-craft an HTTP API call that allows for updating policy for a user and gaining higher privileges. The patch in version `RELEASE.2021-12-27T07-23-18Z` changes the accepted request body type and removes the ability to apply policy changes through this API. There is a workaround for this vulnerability: Changing passwords can be disabled by adding an explicit `Deny` rule to disable the API for users.

- [https://github.com/0rx1/cve-2021-43858](https://github.com/0rx1/cve-2021-43858) :  ![starts](https://img.shields.io/github/stars/0rx1/cve-2021-43858.svg) ![forks](https://img.shields.io/github/forks/0rx1/cve-2021-43858.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/knqyf263/CVE-2021-3129](https://github.com/knqyf263/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2021-3129.svg)


## CVE-2018-11235
 In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs &quot;git clone --recurse-submodules&quot; because submodule &quot;names&quot; are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with &quot;../&quot; in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.

- [https://github.com/0rx1/CVE-2018-11235](https://github.com/0rx1/CVE-2018-11235) :  ![starts](https://img.shields.io/github/stars/0rx1/CVE-2018-11235.svg) ![forks](https://img.shields.io/github/forks/0rx1/CVE-2018-11235.svg)

