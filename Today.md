# Update 2021-04-21
## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/briskets/CVE-2021-3493](https://github.com/briskets/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/briskets/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/briskets/CVE-2021-3493.svg)


## CVE-2020-14364
 An out-of-bounds read/write access flaw was found in the USB emulator of the QEMU in versions before 5.2.0. This issue occurs while processing USB packets from a guest when USBDevice 'setup_len' exceeds its 'data_buf[4096]' in the do_token_in, do_token_out routines. This flaw allows a guest user to crash the QEMU process, resulting in a denial of service, or the potential execution of arbitrary code with the privileges of the QEMU process on the host.

- [https://github.com/gejian-iscas/CVE-2020-14364](https://github.com/gejian-iscas/CVE-2020-14364) :  ![starts](https://img.shields.io/github/stars/gejian-iscas/CVE-2020-14364.svg) ![forks](https://img.shields.io/github/forks/gejian-iscas/CVE-2020-14364.svg)


## CVE-2018-11235
 In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs &quot;git clone --recurse-submodules&quot; because submodule &quot;names&quot; are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with &quot;../&quot; in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.

- [https://github.com/Yealid/CVE-2018-11235-Git-Submodule-RCE](https://github.com/Yealid/CVE-2018-11235-Git-Submodule-RCE) :  ![starts](https://img.shields.io/github/stars/Yealid/CVE-2018-11235-Git-Submodule-RCE.svg) ![forks](https://img.shields.io/github/forks/Yealid/CVE-2018-11235-Git-Submodule-RCE.svg)


## CVE-2018-9206
 Unauthenticated arbitrary file upload vulnerability in Blueimp jQuery-File-Upload &lt;= v9.22.0

- [https://github.com/mi-hood/CVE-2018-9206](https://github.com/mi-hood/CVE-2018-9206) :  ![starts](https://img.shields.io/github/stars/mi-hood/CVE-2018-9206.svg) ![forks](https://img.shields.io/github/forks/mi-hood/CVE-2018-9206.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/MohamedTarekq/test-CVE-2018-6574-](https://github.com/MohamedTarekq/test-CVE-2018-6574-) :  ![starts](https://img.shields.io/github/stars/MohamedTarekq/test-CVE-2018-6574-.svg) ![forks](https://img.shields.io/github/forks/MohamedTarekq/test-CVE-2018-6574-.svg)

