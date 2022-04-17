# Update 2022-04-17
## CVE-2022-29072
 7-Zip through 21.07 on Windows allows privilege escalation and command execution when a file with the .7z extension is dragged to the Help&gt;Contents area. This is caused by misconfiguration of 7z.dll and a heap overflow. The command runs in a child process under the 7zFM.exe process,

- [https://github.com/kagancapar/CVE-2022-29072](https://github.com/kagancapar/CVE-2022-29072) :  ![starts](https://img.shields.io/github/stars/kagancapar/CVE-2022-29072.svg) ![forks](https://img.shields.io/github/forks/kagancapar/CVE-2022-29072.svg)


## CVE-2022-24934
 wpsupdater.exe in Kingsoft WPS Office through 11.2.0.10382 allows remote code execution by modifying HKEY_CURRENT_USER in the registry.

- [https://github.com/ASkyeye/WPS-CVE-2022-24934](https://github.com/ASkyeye/WPS-CVE-2022-24934) :  ![starts](https://img.shields.io/github/stars/ASkyeye/WPS-CVE-2022-24934.svg) ![forks](https://img.shields.io/github/forks/ASkyeye/WPS-CVE-2022-24934.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)
- [https://github.com/MLX15/CVE-2022-22954](https://github.com/MLX15/CVE-2022-22954) :  ![starts](https://img.shields.io/github/stars/MLX15/CVE-2022-22954.svg) ![forks](https://img.shields.io/github/forks/MLX15/CVE-2022-22954.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/twseptian/cve-2022-22947](https://github.com/twseptian/cve-2022-22947) :  ![starts](https://img.shields.io/github/stars/twseptian/cve-2022-22947.svg) ![forks](https://img.shields.io/github/forks/twseptian/cve-2022-22947.svg)


## CVE-2022-21971
 Windows Runtime Remote Code Execution Vulnerability.

- [https://github.com/tufanturhan/CVE-2022-21971-Windows-Runtime-RCE](https://github.com/tufanturhan/CVE-2022-21971-Windows-Runtime-RCE) :  ![starts](https://img.shields.io/github/stars/tufanturhan/CVE-2022-21971-Windows-Runtime-RCE.svg) ![forks](https://img.shields.io/github/forks/tufanturhan/CVE-2022-21971-Windows-Runtime-RCE.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/tufanturhan/CVE-2022-0847-L-nux-PrivEsc](https://github.com/tufanturhan/CVE-2022-0847-L-nux-PrivEsc) :  ![starts](https://img.shields.io/github/stars/tufanturhan/CVE-2022-0847-L-nux-PrivEsc.svg) ![forks](https://img.shields.io/github/forks/tufanturhan/CVE-2022-0847-L-nux-PrivEsc.svg)


## CVE-2022-0185
 A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to legacy handling) could use this flaw to escalate their privileges on the system.

- [https://github.com/E1efuntik/CVE-2022-0185](https://github.com/E1efuntik/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/E1efuntik/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/E1efuntik/CVE-2022-0185.svg)


## CVE-2021-43129
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Skotizo/CVE-2021-43129](https://github.com/Skotizo/CVE-2021-43129) :  ![starts](https://img.shields.io/github/stars/Skotizo/CVE-2021-43129.svg) ![forks](https://img.shields.io/github/forks/Skotizo/CVE-2021-43129.svg)


## CVE-2021-31805
 The fix issued for CVE-2020-17530 was incomplete. So from Apache Struts 2.0.0 to 2.5.29, still some of the tag&#8217;s attributes could perform a double evaluation if a developer applied forced OGNL evaluation by using the %{...} syntax. Using forced OGNL evaluation on untrusted user input can lead to a Remote Code Execution and security degradation.

- [https://github.com/jax7sec/S2-062](https://github.com/jax7sec/S2-062) :  ![starts](https://img.shields.io/github/stars/jax7sec/S2-062.svg) ![forks](https://img.shields.io/github/forks/jax7sec/S2-062.svg)
- [https://github.com/aeyesec/CVE-2021-31805](https://github.com/aeyesec/CVE-2021-31805) :  ![starts](https://img.shields.io/github/stars/aeyesec/CVE-2021-31805.svg) ![forks](https://img.shields.io/github/forks/aeyesec/CVE-2021-31805.svg)
- [https://github.com/Axx8/Struts2_S2-062_CVE-2021-31805](https://github.com/Axx8/Struts2_S2-062_CVE-2021-31805) :  ![starts](https://img.shields.io/github/stars/Axx8/Struts2_S2-062_CVE-2021-31805.svg) ![forks](https://img.shields.io/github/forks/Axx8/Struts2_S2-062_CVE-2021-31805.svg)


## CVE-2021-0331
 In onCreate of NotificationAccessConfirmationActivity.java, there is a possible overlay attack due to an insecure default value. This could lead to local escalation of privilege and notification access with User execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-9 Android-10 Android-11 Android-8.1Android ID: A-170731783

- [https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0331](https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0331) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0331.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2021-0331.svg)


## CVE-2020-25213
 The File Manager (wp-file-manager) plugin before 6.9 for WordPress allows remote attackers to upload and execute arbitrary PHP code because it renames an unsafe example elFinder connector file to have the .php extension. This, for example, allows attackers to run the elFinder upload (or mkfile and put) command to write PHP code into the wp-content/plugins/wp-file-manager/lib/files/ directory. This was exploited in the wild in August and September 2020.

- [https://github.com/Aron-Tn/0day-elFinder-2020](https://github.com/Aron-Tn/0day-elFinder-2020) :  ![starts](https://img.shields.io/github/stars/Aron-Tn/0day-elFinder-2020.svg) ![forks](https://img.shields.io/github/forks/Aron-Tn/0day-elFinder-2020.svg)

