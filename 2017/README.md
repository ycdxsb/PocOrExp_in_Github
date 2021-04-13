## CVE-2017-1002101
 In Kubernetes versions 1.3.x, 1.4.x, 1.5.x, 1.6.x and prior to versions 1.7.14, 1.8.9 and 1.9.4 containers using subpath volume mounts with any volume type (including non-privileged pods, subject to file permissions) can access files/directories outside of the volume, including the host's filesystem.



- [https://github.com/bgeesaman/subpath-exploit](https://github.com/bgeesaman/subpath-exploit) :  ![starts](https://img.shields.io/github/stars/bgeesaman/subpath-exploit.svg) ![forks](https://img.shields.io/github/forks/bgeesaman/subpath-exploit.svg)

## CVE-2017-1001004
 typed-function before 0.10.6 had an arbitrary code execution in the JavaScript engine. Creating a typed function with JavaScript code in the name could result arbitrary execution.



- [https://github.com/ossf-cve-benchmark/CVE-2017-1001004](https://github.com/ossf-cve-benchmark/CVE-2017-1001004) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1001004.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1001004.svg)

## CVE-2017-1000499
 phpMyAdmin versions 4.7.x (prior to 4.7.6.1/4.7.7) are vulnerable to a CSRF weakness. By deceiving a user to click on a crafted URL, it is possible to perform harmful database operations such as deleting records, dropping/truncating tables etc.



- [https://github.com/Villaquiranm/5MMISSI-CVE-2017-1000499](https://github.com/Villaquiranm/5MMISSI-CVE-2017-1000499) :  ![starts](https://img.shields.io/github/stars/Villaquiranm/5MMISSI-CVE-2017-1000499.svg) ![forks](https://img.shields.io/github/forks/Villaquiranm/5MMISSI-CVE-2017-1000499.svg)

## CVE-2017-1000486
 Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution



- [https://github.com/pimps/CVE-2017-1000486](https://github.com/pimps/CVE-2017-1000486) :  ![starts](https://img.shields.io/github/stars/pimps/CVE-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/pimps/CVE-2017-1000486.svg)

- [https://github.com/mogwailabs/CVE-2017-1000486](https://github.com/mogwailabs/CVE-2017-1000486) :  ![starts](https://img.shields.io/github/stars/mogwailabs/CVE-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/mogwailabs/CVE-2017-1000486.svg)

- [https://github.com/cved-sources/cve-2017-1000486](https://github.com/cved-sources/cve-2017-1000486) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-1000486.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-1000486.svg)

## CVE-2017-1000475
 FreeSSHd 1.3.1 version is vulnerable to an Unquoted Path Service allowing local users to launch processes with elevated privileges.



- [https://github.com/lajarajorge/CVE-2017-1000475](https://github.com/lajarajorge/CVE-2017-1000475) :  ![starts](https://img.shields.io/github/stars/lajarajorge/CVE-2017-1000475.svg) ![forks](https://img.shields.io/github/forks/lajarajorge/CVE-2017-1000475.svg)

## CVE-2017-1000427
 marked version 0.3.6 and earlier is vulnerable to an XSS attack in the data: URI parser.



- [https://github.com/ossf-cve-benchmark/CVE-2017-1000427](https://github.com/ossf-cve-benchmark/CVE-2017-1000427) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1000427.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1000427.svg)

## CVE-2017-1000405
 The Linux Kernel versions 2.6.38 through 4.14 have a problematic use of pmd_mkdirty() in the touch_pmd() function inside the THP implementation. touch_pmd() can be reached by get_user_pages(). In such case, the pmd will become dirty. This scenario breaks the new can_follow_write_pmd()'s logic - pmd can become dirty without going through a COW cycle. This bug is not as severe as the original &quot;Dirty cow&quot; because an ext4 file (or any other regular file) cannot be mapped using THP. Nevertheless, it does allow us to overwrite read-only huge pages. For example, the zero huge page and sealed shmem files can be overwritten (since their mapping can be populated using THP). Note that after the first write page-fault to the zero page, it will be replaced with a new fresh (and zeroed) thp.



- [https://github.com/bindecy/HugeDirtyCowPOC](https://github.com/bindecy/HugeDirtyCowPOC) :  ![starts](https://img.shields.io/github/stars/bindecy/HugeDirtyCowPOC.svg) ![forks](https://img.shields.io/github/forks/bindecy/HugeDirtyCowPOC.svg)

## CVE-2017-1000367
 Todd Miller's sudo version 1.8.20 and earlier is vulnerable to an input validation (embedded spaces) in the get_process_ttyname() function resulting in information disclosure and command execution.



- [https://github.com/c0d3z3r0/sudo-CVE-2017-1000367](https://github.com/c0d3z3r0/sudo-CVE-2017-1000367) :  ![starts](https://img.shields.io/github/stars/c0d3z3r0/sudo-CVE-2017-1000367.svg) ![forks](https://img.shields.io/github/forks/c0d3z3r0/sudo-CVE-2017-1000367.svg)

- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)

- [https://github.com/pucerpocok/sudo_exploit](https://github.com/pucerpocok/sudo_exploit) :  ![starts](https://img.shields.io/github/stars/pucerpocok/sudo_exploit.svg) ![forks](https://img.shields.io/github/forks/pucerpocok/sudo_exploit.svg)

- [https://github.com/homjxi0e/CVE-2017-1000367](https://github.com/homjxi0e/CVE-2017-1000367) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-1000367.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-1000367.svg)

## CVE-2017-1000353
 Jenkins versions 2.56 and earlier as well as 2.46.1 LTS and earlier are vulnerable to an unauthenticated remote code execution. An unauthenticated remote code execution vulnerability allowed attackers to transfer a serialized Java `SignedObject` object to the Jenkins CLI, that would be deserialized using a new `ObjectInputStream`, bypassing the existing blacklist-based protection mechanism. We're fixing this issue by adding `SignedObject` to the blacklist. We're also backporting the new HTTP CLI protocol from Jenkins 2.54 to LTS 2.46.2, and deprecating the remoting-based (i.e. Java serialization) CLI protocol, disabling it by default.



- [https://github.com/vulhub/CVE-2017-1000353](https://github.com/vulhub/CVE-2017-1000353) :  ![starts](https://img.shields.io/github/stars/vulhub/CVE-2017-1000353.svg) ![forks](https://img.shields.io/github/forks/vulhub/CVE-2017-1000353.svg)

## CVE-2017-1000253
 Linux distributions that have not patched their long-term kernels with https://git.kernel.org/linus/a87938b2e246b81b4fb713edb371a9fa3c5c3c86 (committed on April 14, 2015). This kernel vulnerability was fixed in April 2015 by commit a87938b2e246b81b4fb713edb371a9fa3c5c3c86 (backported to Linux 3.10.77 in May 2015), but it was not recognized as a security threat. With CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE enabled, and a normal top-down address allocation strategy, load_elf_binary() will attempt to map a PIE binary into an address range immediately below mm-&gt;mmap_base. Unfortunately, load_elf_ binary() does not take account of the need to allocate sufficient space for the entire binary which means that, while the first PT_LOAD segment is mapped below mm-&gt;mmap_base, the subsequent PT_LOAD segment(s) end up being mapped above mm-&gt;mmap_base into the are that is supposed to be the &quot;gap&quot; between the stack and the binary.



- [https://github.com/RicterZ/PIE-Stack-Clash-CVE-2017-1000253](https://github.com/RicterZ/PIE-Stack-Clash-CVE-2017-1000253) :  ![starts](https://img.shields.io/github/stars/RicterZ/PIE-Stack-Clash-CVE-2017-1000253.svg) ![forks](https://img.shields.io/github/forks/RicterZ/PIE-Stack-Clash-CVE-2017-1000253.svg)

## CVE-2017-1000251
 The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.



- [https://github.com/hayzamjs/Blueborne-CVE-2017-1000251](https://github.com/hayzamjs/Blueborne-CVE-2017-1000251) :  ![starts](https://img.shields.io/github/stars/hayzamjs/Blueborne-CVE-2017-1000251.svg) ![forks](https://img.shields.io/github/forks/hayzamjs/Blueborne-CVE-2017-1000251.svg)

- [https://github.com/marcinguy/blueborne-CVE-2017-1000251](https://github.com/marcinguy/blueborne-CVE-2017-1000251) :  ![starts](https://img.shields.io/github/stars/marcinguy/blueborne-CVE-2017-1000251.svg) ![forks](https://img.shields.io/github/forks/marcinguy/blueborne-CVE-2017-1000251.svg)

- [https://github.com/own2pwn/blueborne-CVE-2017-1000251-POC](https://github.com/own2pwn/blueborne-CVE-2017-1000251-POC) :  ![starts](https://img.shields.io/github/stars/own2pwn/blueborne-CVE-2017-1000251-POC.svg) ![forks](https://img.shields.io/github/forks/own2pwn/blueborne-CVE-2017-1000251-POC.svg)

- [https://github.com/tlatkdgus1/blueborne-CVE-2017-1000251](https://github.com/tlatkdgus1/blueborne-CVE-2017-1000251) :  ![starts](https://img.shields.io/github/stars/tlatkdgus1/blueborne-CVE-2017-1000251.svg) ![forks](https://img.shields.io/github/forks/tlatkdgus1/blueborne-CVE-2017-1000251.svg)

- [https://github.com/CrackSoft900/Blue-Borne](https://github.com/CrackSoft900/Blue-Borne) :  ![starts](https://img.shields.io/github/stars/CrackSoft900/Blue-Borne.svg) ![forks](https://img.shields.io/github/forks/CrackSoft900/Blue-Borne.svg)

## CVE-2017-1000250
 All versions of the SDP server in BlueZ 5.46 and earlier are vulnerable to an information disclosure vulnerability which allows remote attackers to obtain sensitive information from the bluetoothd process memory. This vulnerability lies in the processing of SDP search attribute requests.



- [https://github.com/AxelRoudaut/THC_BlueBorne](https://github.com/AxelRoudaut/THC_BlueBorne) :  ![starts](https://img.shields.io/github/stars/AxelRoudaut/THC_BlueBorne.svg) ![forks](https://img.shields.io/github/forks/AxelRoudaut/THC_BlueBorne.svg)

- [https://github.com/olav-st/CVE-2017-1000250-PoC](https://github.com/olav-st/CVE-2017-1000250-PoC) :  ![starts](https://img.shields.io/github/stars/olav-st/CVE-2017-1000250-PoC.svg) ![forks](https://img.shields.io/github/forks/olav-st/CVE-2017-1000250-PoC.svg)

## CVE-2017-1000219
 npm/KyleRoss windows-cpu all versions vulnerable to command injection resulting in code execution as Node.js user



- [https://github.com/ossf-cve-benchmark/CVE-2017-1000219](https://github.com/ossf-cve-benchmark/CVE-2017-1000219) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1000219.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1000219.svg)

## CVE-2017-1000170
 jqueryFileTree 2.1.5 and older Directory Traversal



- [https://github.com/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal](https://github.com/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal) :  ![starts](https://img.shields.io/github/stars/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal.svg) ![forks](https://img.shields.io/github/forks/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal.svg)

## CVE-2017-1000117
 A malicious third-party can give a crafted &quot;ssh://...&quot; URL to an unsuspecting victim, and an attempt to visit the URL can result in any program that exists on the victim's machine being executed. Such a URL could be placed in the .gitmodules file of a malicious project, and an unsuspecting victim could be tricked into running &quot;git clone --recurse-submodules&quot; to trigger the vulnerability.



- [https://github.com/greymd/CVE-2017-1000117](https://github.com/greymd/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/greymd/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/greymd/CVE-2017-1000117.svg)

- [https://github.com/Manouchehri/CVE-2017-1000117](https://github.com/Manouchehri/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/Manouchehri/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/Manouchehri/CVE-2017-1000117.svg)

- [https://github.com/timwr/CVE-2017-1000117](https://github.com/timwr/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/timwr/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/timwr/CVE-2017-1000117.svg)

- [https://github.com/VulApps/CVE-2017-1000117](https://github.com/VulApps/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/VulApps/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/VulApps/CVE-2017-1000117.svg)

- [https://github.com/ieee0824/CVE-2017-1000117](https://github.com/ieee0824/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/ieee0824/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/ieee0824/CVE-2017-1000117.svg)

- [https://github.com/nkoneko/CVE-2017-1000117](https://github.com/nkoneko/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/nkoneko/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/nkoneko/CVE-2017-1000117.svg)

- [https://github.com/sasairc/CVE-2017-1000117_wasawasa](https://github.com/sasairc/CVE-2017-1000117_wasawasa) :  ![starts](https://img.shields.io/github/stars/sasairc/CVE-2017-1000117_wasawasa.svg) ![forks](https://img.shields.io/github/forks/sasairc/CVE-2017-1000117_wasawasa.svg)

- [https://github.com/AnonymKing/CVE-2017-1000117](https://github.com/AnonymKing/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/AnonymKing/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/AnonymKing/CVE-2017-1000117.svg)

- [https://github.com/rootclay/CVE-2017-1000117](https://github.com/rootclay/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/rootclay/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/rootclay/CVE-2017-1000117.svg)

- [https://github.com/cved-sources/cve-2017-1000117](https://github.com/cved-sources/cve-2017-1000117) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-1000117.svg)

- [https://github.com/chenzhuo0618/test](https://github.com/chenzhuo0618/test) :  ![starts](https://img.shields.io/github/stars/chenzhuo0618/test.svg) ![forks](https://img.shields.io/github/forks/chenzhuo0618/test.svg)

- [https://github.com/ieee0824/CVE-2017-1000117-sl](https://github.com/ieee0824/CVE-2017-1000117-sl) :  ![starts](https://img.shields.io/github/stars/ieee0824/CVE-2017-1000117-sl.svg) ![forks](https://img.shields.io/github/forks/ieee0824/CVE-2017-1000117-sl.svg)

- [https://github.com/alilangtest/CVE-2017-1000117](https://github.com/alilangtest/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/alilangtest/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/alilangtest/CVE-2017-1000117.svg)

- [https://github.com/Shadow5523/CVE-2017-1000117-test](https://github.com/Shadow5523/CVE-2017-1000117-test) :  ![starts](https://img.shields.io/github/stars/Shadow5523/CVE-2017-1000117-test.svg) ![forks](https://img.shields.io/github/forks/Shadow5523/CVE-2017-1000117-test.svg)

- [https://github.com/Q2h1Cg/CVE-2017-1000117](https://github.com/Q2h1Cg/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/Q2h1Cg/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/Q2h1Cg/CVE-2017-1000117.svg)

- [https://github.com/siling2017/CVE-2017-1000117](https://github.com/siling2017/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/siling2017/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/siling2017/CVE-2017-1000117.svg)

- [https://github.com/thelastbyte/CVE-2017-1000117](https://github.com/thelastbyte/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/thelastbyte/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/thelastbyte/CVE-2017-1000117.svg)

- [https://github.com/takehaya/CVE-2017-1000117](https://github.com/takehaya/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/takehaya/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/takehaya/CVE-2017-1000117.svg)

- [https://github.com/leezp/CVE-2017-1000117](https://github.com/leezp/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/leezp/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/leezp/CVE-2017-1000117.svg)

- [https://github.com/ikmski/CVE-2017-1000117](https://github.com/ikmski/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/ikmski/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/ikmski/CVE-2017-1000117.svg)

- [https://github.com/bells17/CVE-2017-1000117](https://github.com/bells17/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/bells17/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/bells17/CVE-2017-1000117.svg)

- [https://github.com/shogo82148/Fix-CVE-2017-1000117](https://github.com/shogo82148/Fix-CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/shogo82148/Fix-CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/shogo82148/Fix-CVE-2017-1000117.svg)

- [https://github.com/GrahamMThomas/test-git-vuln_CVE-2017-1000117](https://github.com/GrahamMThomas/test-git-vuln_CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/GrahamMThomas/test-git-vuln_CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/GrahamMThomas/test-git-vuln_CVE-2017-1000117.svg)

## CVE-2017-1000112
 Linux kernel: Exploitable memory corruption due to UFO to non-UFO path switch. When building a UFO packet with MSG_MORE __ip_append_data() calls ip_ufo_append_data() to append. However in between two send() calls, the append path can be switched from UFO to non-UFO one, which leads to a memory corruption. In case UFO packet lengths exceeds MTU, copy = maxfraglen - skb-&gt;len becomes negative on the non-UFO path and the branch to allocate new skb is taken. This triggers fragmentation and computation of fraggap = skb_prev-&gt;len - maxfraglen. Fraggap can exceed MTU, causing copy = datalen - transhdrlen - fraggap to become negative. Subsequently skb_copy_and_csum_bits() writes out-of-bounds. A similar issue is present in IPv6 code. The bug was introduced in e89e9cf539a2 (&quot;[IPv4/IPv6]: UFO Scatter-gather approach&quot;) on Oct 18 2005.



- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)

- [https://github.com/ol0273st-s/CVE-2017-1000112-Adpated](https://github.com/ol0273st-s/CVE-2017-1000112-Adpated) :  ![starts](https://img.shields.io/github/stars/ol0273st-s/CVE-2017-1000112-Adpated.svg) ![forks](https://img.shields.io/github/forks/ol0273st-s/CVE-2017-1000112-Adpated.svg)

- [https://github.com/IT19083124/SNP-Assignment](https://github.com/IT19083124/SNP-Assignment) :  ![starts](https://img.shields.io/github/stars/IT19083124/SNP-Assignment.svg) ![forks](https://img.shields.io/github/forks/IT19083124/SNP-Assignment.svg)

- [https://github.com/hikame/docker_escape_pwn](https://github.com/hikame/docker_escape_pwn) :  ![starts](https://img.shields.io/github/stars/hikame/docker_escape_pwn.svg) ![forks](https://img.shields.io/github/forks/hikame/docker_escape_pwn.svg)

## CVE-2017-1000083
 backend/comics/comics-document.c (aka the comic book backend) in GNOME Evince before 3.24.1 allows remote attackers to execute arbitrary commands via a .cbt file that is a TAR archive containing a filename beginning with a &quot;--&quot; command-line option substring, as demonstrated by a --checkpoint-action=exec=bash at the beginning of the filename.



- [https://github.com/matlink/evince-cve-2017-1000083](https://github.com/matlink/evince-cve-2017-1000083) :  ![starts](https://img.shields.io/github/stars/matlink/evince-cve-2017-1000083.svg) ![forks](https://img.shields.io/github/forks/matlink/evince-cve-2017-1000083.svg)

- [https://github.com/matlink/cve-2017-1000083-atril-nautilus](https://github.com/matlink/cve-2017-1000083-atril-nautilus) :  ![starts](https://img.shields.io/github/stars/matlink/cve-2017-1000083-atril-nautilus.svg) ![forks](https://img.shields.io/github/forks/matlink/cve-2017-1000083-atril-nautilus.svg)

## CVE-2017-1000006
 Plotly, Inc. plotly.js versions prior to 1.16.0 are vulnerable to an XSS issue.



- [https://github.com/ossf-cve-benchmark/CVE-2017-1000006](https://github.com/ossf-cve-benchmark/CVE-2017-1000006) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-1000006.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-1000006.svg)

## CVE-2017-1000000
 ** RE



- [https://github.com/smythtech/DWF-CVE-2017-1000000](https://github.com/smythtech/DWF-CVE-2017-1000000) :  ![starts](https://img.shields.io/github/stars/smythtech/DWF-CVE-2017-1000000.svg) ![forks](https://img.shields.io/github/forks/smythtech/DWF-CVE-2017-1000000.svg)

## CVE-2017-10952
 This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Foxit Reader 8.2.0.2051. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the saveAs JavaScript function. The issue results from the lack of proper validation of user-supplied data, which can lead to writing arbitrary files into attacker controlled locations. An attacker can leverage this vulnerability to execute code under the context of the current process. Was ZDI-CAN-4518.



- [https://github.com/afbase/CVE-2017-10952](https://github.com/afbase/CVE-2017-10952) :  ![starts](https://img.shields.io/github/stars/afbase/CVE-2017-10952.svg) ![forks](https://img.shields.io/github/forks/afbase/CVE-2017-10952.svg)

## CVE-2017-10910
 MQTT.js 2.x.x prior to 2.15.0 issue in handling PUBLISH tickets may lead to an attacker causing a denial-of-service condition.



- [https://github.com/ossf-cve-benchmark/CVE-2017-10910](https://github.com/ossf-cve-benchmark/CVE-2017-10910) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-10910.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-10910.svg)

## CVE-2017-10797
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/n4xh4ck5/CVE-2017-10797](https://github.com/n4xh4ck5/CVE-2017-10797) :  ![starts](https://img.shields.io/github/stars/n4xh4ck5/CVE-2017-10797.svg) ![forks](https://img.shields.io/github/forks/n4xh4ck5/CVE-2017-10797.svg)

## CVE-2017-10661
 Race condition in fs/timerfd.c in the Linux kernel before 4.10.15 allows local users to gain privileges or cause a denial of service (list corruption or use-after-free) via simultaneous file-descriptor operations that leverage improper might_cancel queueing.



- [https://github.com/GeneBlue/CVE-2017-10661_POC](https://github.com/GeneBlue/CVE-2017-10661_POC) :  ![starts](https://img.shields.io/github/stars/GeneBlue/CVE-2017-10661_POC.svg) ![forks](https://img.shields.io/github/forks/GeneBlue/CVE-2017-10661_POC.svg)

## CVE-2017-10617
 The ifmap service that comes bundled with Contrail has an XML External Entity (XXE) vulnerability that may allow an attacker to retrieve sensitive system files. Affected releases are Juniper Networks Contrail 2.2 prior to 2.21.4; 3.0 prior to 3.0.3.4; 3.1 prior to 3.1.4.0; 3.2 prior to 3.2.5.0. CVE-2017-10616 and CVE-2017-10617 can be chained together and have a combined CVSSv3 score of 5.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N).



- [https://github.com/gteissier/CVE-2017-10617](https://github.com/gteissier/CVE-2017-10617) :  ![starts](https://img.shields.io/github/stars/gteissier/CVE-2017-10617.svg) ![forks](https://img.shields.io/github/forks/gteissier/CVE-2017-10617.svg)

## CVE-2017-10616
 The ifmap service that comes bundled with Juniper Networks Contrail releases uses hard coded credentials. Affected releases are Contrail releases 2.2 prior to 2.21.4; 3.0 prior to 3.0.3.4; 3.1 prior to 3.1.4.0; 3.2 prior to 3.2.5.0. CVE-2017-10616 and CVE-2017-10617 can be chained together and have a combined CVSSv3 score of 5.8 (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N).



- [https://github.com/gteissier/CVE-2017-10617](https://github.com/gteissier/CVE-2017-10617) :  ![starts](https://img.shields.io/github/stars/gteissier/CVE-2017-10617.svg) ![forks](https://img.shields.io/github/forks/gteissier/CVE-2017-10617.svg)

## CVE-2017-10417
 Vulnerability in the Oracle Advanced Outbound Telephony component of Oracle E-Business Suite (subcomponent: Setup and Configuration). Supported versions that are affected are 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Advanced Outbound Telephony. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Advanced Outbound Telephony, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Advanced Outbound Telephony accessible data as well as unauthorized update, insert or delete access to some of Oracle Advanced Outbound Telephony accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10416
 Vulnerability in the Oracle Advanced Outbound Telephony component of Oracle E-Business Suite (subcomponent: Setup and Configuration). Supported versions that are affected are 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Advanced Outbound Telephony. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Advanced Outbound Telephony, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Advanced Outbound Telephony accessible data as well as unauthorized update, insert or delete access to some of Oracle Advanced Outbound Telephony accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10415
 Vulnerability in the Oracle iSupport component of Oracle E-Business Suite (subcomponent: Others). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iSupport. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle iSupport, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle iSupport accessible data as well as unauthorized update, insert or delete access to some of Oracle iSupport accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10414
 Vulnerability in the Oracle iStore component of Oracle E-Business Suite (subcomponent: Checkout and Order Placement). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iStore. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle iStore, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle iStore accessible data as well as unauthorized update, insert or delete access to some of Oracle iStore accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10413
 Vulnerability in the Oracle Mobile Field Service component of Oracle E-Business Suite (subcomponent: Multiplatform Based on HTML5). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Mobile Field Service. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Mobile Field Service, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Mobile Field Service accessible data as well as unauthorized update, insert or delete access to some of Oracle Mobile Field Service accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10412
 Vulnerability in the Oracle Knowledge Management component of Oracle E-Business Suite (subcomponent: User Interface). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Knowledge Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Knowledge Management accessible data as well as unauthorized update, insert or delete access to some of Oracle Knowledge Management accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10411
 Vulnerability in the Oracle Knowledge Management component of Oracle E-Business Suite (subcomponent: User Interface). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Knowledge Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Knowledge Management accessible data as well as unauthorized update, insert or delete access to some of Oracle Knowledge Management accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10410
 Vulnerability in the Oracle Knowledge Management component of Oracle E-Business Suite (subcomponent: Search). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Knowledge Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Knowledge Management accessible data as well as unauthorized update, insert or delete access to some of Oracle Knowledge Management accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10409
 Vulnerability in the Oracle iStore component of Oracle E-Business Suite (subcomponent: Merchant UI). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iStore. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle iStore, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle iStore accessible data as well as unauthorized update, insert or delete access to some of Oracle iStore accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10366
 Vulnerability in the PeopleSoft Enterprise PT PeopleTools component of Oracle PeopleSoft Products (subcomponent: Performance Monitor). Supported versions that are affected are 8.54, 8.55 and 8.56. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PT PeopleTools. Successful attacks of this vulnerability can result in takeover of PeopleSoft Enterprise PT PeopleTools. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

- [https://github.com/blazeinfosec/CVE-2017-10366_peoplesoft](https://github.com/blazeinfosec/CVE-2017-10366_peoplesoft) :  ![starts](https://img.shields.io/github/stars/blazeinfosec/CVE-2017-10366_peoplesoft.svg) ![forks](https://img.shields.io/github/forks/blazeinfosec/CVE-2017-10366_peoplesoft.svg)

## CVE-2017-10352
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS - Web Services). The supported version that is affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0, 12.2.1.2.0 and 12.2.1.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server as well as unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data and unauthorized read access to a subset of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 9.9 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H).



- [https://github.com/bigsizeme/weblogic-XMLDecoder](https://github.com/bigsizeme/weblogic-XMLDecoder) :  ![starts](https://img.shields.io/github/stars/bigsizeme/weblogic-XMLDecoder.svg) ![forks](https://img.shields.io/github/forks/bigsizeme/weblogic-XMLDecoder.svg)

## CVE-2017-10271
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)

- [https://github.com/shack2/javaserializetools](https://github.com/shack2/javaserializetools) :  ![starts](https://img.shields.io/github/stars/shack2/javaserializetools.svg) ![forks](https://img.shields.io/github/forks/shack2/javaserializetools.svg)

- [https://github.com/c0mmand3rOpSec/CVE-2017-10271](https://github.com/c0mmand3rOpSec/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/c0mmand3rOpSec/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/c0mmand3rOpSec/CVE-2017-10271.svg)

- [https://github.com/kkirsche/CVE-2017-10271](https://github.com/kkirsche/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/kkirsche/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/kkirsche/CVE-2017-10271.svg)

- [https://github.com/7kbstorm/WebLogic_CNVD_C2019_48814](https://github.com/7kbstorm/WebLogic_CNVD_C2019_48814) :  ![starts](https://img.shields.io/github/stars/7kbstorm/WebLogic_CNVD_C2019_48814.svg) ![forks](https://img.shields.io/github/forks/7kbstorm/WebLogic_CNVD_C2019_48814.svg)

- [https://github.com/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961](https://github.com/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961) :  ![starts](https://img.shields.io/github/stars/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961.svg) ![forks](https://img.shields.io/github/forks/SkyBlueEternal/CNVD-C-2019-48814-CNNVD-201904-961.svg)

- [https://github.com/1337g/CVE-2017-10271](https://github.com/1337g/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/1337g/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/1337g/CVE-2017-10271.svg)

- [https://github.com/Luffin/CVE-2017-10271](https://github.com/Luffin/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/Luffin/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/Luffin/CVE-2017-10271.svg)

- [https://github.com/s3xy/CVE-2017-10271](https://github.com/s3xy/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/s3xy/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/s3xy/CVE-2017-10271.svg)

- [https://github.com/Cymmetria/weblogic_honeypot](https://github.com/Cymmetria/weblogic_honeypot) :  ![starts](https://img.shields.io/github/stars/Cymmetria/weblogic_honeypot.svg) ![forks](https://img.shields.io/github/forks/Cymmetria/weblogic_honeypot.svg)

- [https://github.com/bigsizeme/weblogic-XMLDecoder](https://github.com/bigsizeme/weblogic-XMLDecoder) :  ![starts](https://img.shields.io/github/stars/bigsizeme/weblogic-XMLDecoder.svg) ![forks](https://img.shields.io/github/forks/bigsizeme/weblogic-XMLDecoder.svg)

- [https://github.com/ETOCheney/JavaDeserialization](https://github.com/ETOCheney/JavaDeserialization) :  ![starts](https://img.shields.io/github/stars/ETOCheney/JavaDeserialization.svg) ![forks](https://img.shields.io/github/forks/ETOCheney/JavaDeserialization.svg)

- [https://github.com/SuperHacker-liuan/cve-2017-10271-poc](https://github.com/SuperHacker-liuan/cve-2017-10271-poc) :  ![starts](https://img.shields.io/github/stars/SuperHacker-liuan/cve-2017-10271-poc.svg) ![forks](https://img.shields.io/github/forks/SuperHacker-liuan/cve-2017-10271-poc.svg)

- [https://github.com/pssss/CVE-2017-10271](https://github.com/pssss/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/pssss/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/pssss/CVE-2017-10271.svg)

- [https://github.com/ZH3FENG/PoCs-Weblogic_2017_10271](https://github.com/ZH3FENG/PoCs-Weblogic_2017_10271) :  ![starts](https://img.shields.io/github/stars/ZH3FENG/PoCs-Weblogic_2017_10271.svg) ![forks](https://img.shields.io/github/forks/ZH3FENG/PoCs-Weblogic_2017_10271.svg)

- [https://github.com/cjjduck/weblogic_wls_wsat_rce](https://github.com/cjjduck/weblogic_wls_wsat_rce) :  ![starts](https://img.shields.io/github/stars/cjjduck/weblogic_wls_wsat_rce.svg) ![forks](https://img.shields.io/github/forks/cjjduck/weblogic_wls_wsat_rce.svg)

- [https://github.com/kbsec/Weblogic_Wsat_RCE](https://github.com/kbsec/Weblogic_Wsat_RCE) :  ![starts](https://img.shields.io/github/stars/kbsec/Weblogic_Wsat_RCE.svg) ![forks](https://img.shields.io/github/forks/kbsec/Weblogic_Wsat_RCE.svg)

- [https://github.com/nhwuxiaojun/CVE-2017-10271](https://github.com/nhwuxiaojun/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/nhwuxiaojun/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/nhwuxiaojun/CVE-2017-10271.svg)

- [https://github.com/ianxtianxt/-CVE-2017-10271-](https://github.com/ianxtianxt/-CVE-2017-10271-) :  ![starts](https://img.shields.io/github/stars/ianxtianxt/-CVE-2017-10271-.svg) ![forks](https://img.shields.io/github/forks/ianxtianxt/-CVE-2017-10271-.svg)

- [https://github.com/s0wr0b1ndef/Oracle-WebLogic-WLS-WSAT](https://github.com/s0wr0b1ndef/Oracle-WebLogic-WLS-WSAT) :  ![starts](https://img.shields.io/github/stars/s0wr0b1ndef/Oracle-WebLogic-WLS-WSAT.svg) ![forks](https://img.shields.io/github/forks/s0wr0b1ndef/Oracle-WebLogic-WLS-WSAT.svg)

- [https://github.com/JackyTsuuuy/weblogic_wls_rce_poc-exp](https://github.com/JackyTsuuuy/weblogic_wls_rce_poc-exp) :  ![starts](https://img.shields.io/github/stars/JackyTsuuuy/weblogic_wls_rce_poc-exp.svg) ![forks](https://img.shields.io/github/forks/JackyTsuuuy/weblogic_wls_rce_poc-exp.svg)

- [https://github.com/XHSecurity/Oracle-WebLogic-CVE-2017-10271](https://github.com/XHSecurity/Oracle-WebLogic-CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/XHSecurity/Oracle-WebLogic-CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/XHSecurity/Oracle-WebLogic-CVE-2017-10271.svg)

- [https://github.com/bmcculley/CVE-2017-10271](https://github.com/bmcculley/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/bmcculley/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/bmcculley/CVE-2017-10271.svg)

- [https://github.com/lonehand/Oracle-WebLogic-CVE-2017-10271-master](https://github.com/lonehand/Oracle-WebLogic-CVE-2017-10271-master) :  ![starts](https://img.shields.io/github/stars/lonehand/Oracle-WebLogic-CVE-2017-10271-master.svg) ![forks](https://img.shields.io/github/forks/lonehand/Oracle-WebLogic-CVE-2017-10271-master.svg)

- [https://github.com/Yuusuke4/WebLogic_CNVD_C_2019_48814](https://github.com/Yuusuke4/WebLogic_CNVD_C_2019_48814) :  ![starts](https://img.shields.io/github/stars/Yuusuke4/WebLogic_CNVD_C_2019_48814.svg) ![forks](https://img.shields.io/github/forks/Yuusuke4/WebLogic_CNVD_C_2019_48814.svg)

- [https://github.com/testwc/CVE-2017-10271](https://github.com/testwc/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/testwc/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/testwc/CVE-2017-10271.svg)

- [https://github.com/cved-sources/cve-2017-10271](https://github.com/cved-sources/cve-2017-10271) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-10271.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-10271.svg)

- [https://github.com/Al1ex/CVE-2017-10271](https://github.com/Al1ex/CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2017-10271.svg)

- [https://github.com/rambleZzz/weblogic_CVE_2017_10271](https://github.com/rambleZzz/weblogic_CVE_2017_10271) :  ![starts](https://img.shields.io/github/stars/rambleZzz/weblogic_CVE_2017_10271.svg) ![forks](https://img.shields.io/github/forks/rambleZzz/weblogic_CVE_2017_10271.svg)

- [https://github.com/peterpeter228/Oracle-WebLogic-CVE-2017-10271](https://github.com/peterpeter228/Oracle-WebLogic-CVE-2017-10271) :  ![starts](https://img.shields.io/github/stars/peterpeter228/Oracle-WebLogic-CVE-2017-10271.svg) ![forks](https://img.shields.io/github/forks/peterpeter228/Oracle-WebLogic-CVE-2017-10271.svg)

## CVE-2017-10235
 Vulnerability in the Oracle VM VirtualBox component of Oracle Virtualization (subcomponent: Core). The supported version that is affected is Prior to 5.1.24. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox as well as unauthorized update, insert or delete access to some of Oracle VM VirtualBox accessible data. CVSS 3.0 Base Score 6.7 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H).



- [https://github.com/fundacion-sadosky/vbox_cve_2017_10235](https://github.com/fundacion-sadosky/vbox_cve_2017_10235) :  ![starts](https://img.shields.io/github/stars/fundacion-sadosky/vbox_cve_2017_10235.svg) ![forks](https://img.shields.io/github/forks/fundacion-sadosky/vbox_cve_2017_10235.svg)

## CVE-2017-10148
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.1 and 12.2.1.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 5.8 (Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N). NOTE: the previous information is from the July 2017 CPU. Oracle has not commented on third-party claims that this issue allows remote attackers to inject special data into log files via a crafted T3 request.



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-10147
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.1 and 12.2.1.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server. CVSS 3.0 Base Score 8.6 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H). NOTE: the previous information is from the July 2017 CPU. Oracle has not commented on third-party claims that this issue exists in the migrate functionality in the WebLogic/cluster/singleton/ServerMigrationCoordinator class and allows remote attackers to shutdown the server via a crafted T3 request.



- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)

## CVE-2017-0931
 html-janitor node module suffers from a Cross-Site Scripting (XSS) vulnerability via clean() accepting user-controlled values.



- [https://github.com/ossf-cve-benchmark/CVE-2017-0931](https://github.com/ossf-cve-benchmark/CVE-2017-0931) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-0931.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-0931.svg)

## CVE-2017-0807
 An elevation of privilege vulnerability in the Android framework (ui framework). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2. Android ID: A-35056974.



- [https://github.com/kpatsakis/PoC_CVE-2017-0807](https://github.com/kpatsakis/PoC_CVE-2017-0807) :  ![starts](https://img.shields.io/github/stars/kpatsakis/PoC_CVE-2017-0807.svg) ![forks](https://img.shields.io/github/forks/kpatsakis/PoC_CVE-2017-0807.svg)

## CVE-2017-0806
 An elevation of privilege vulnerability in the Android framework (gatekeeperresponse). Product: Android. Versions: 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-62998805.



- [https://github.com/michalbednarski/ReparcelBug](https://github.com/michalbednarski/ReparcelBug) :  ![starts](https://img.shields.io/github/stars/michalbednarski/ReparcelBug.svg) ![forks](https://img.shields.io/github/forks/michalbednarski/ReparcelBug.svg)

## CVE-2017-0785
 A information disclosure vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146698.



- [https://github.com/ojasookert/CVE-2017-0785](https://github.com/ojasookert/CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/ojasookert/CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/ojasookert/CVE-2017-0785.svg)

- [https://github.com/pieterbork/blueborne](https://github.com/pieterbork/blueborne) :  ![starts](https://img.shields.io/github/stars/pieterbork/blueborne.svg) ![forks](https://img.shields.io/github/forks/pieterbork/blueborne.svg)

- [https://github.com/Alfa100001/-CVE-2017-0785-BlueBorne-PoC](https://github.com/Alfa100001/-CVE-2017-0785-BlueBorne-PoC) :  ![starts](https://img.shields.io/github/stars/Alfa100001/-CVE-2017-0785-BlueBorne-PoC.svg) ![forks](https://img.shields.io/github/forks/Alfa100001/-CVE-2017-0785-BlueBorne-PoC.svg)

- [https://github.com/henrychoi7/Bluepwn](https://github.com/henrychoi7/Bluepwn) :  ![starts](https://img.shields.io/github/stars/henrychoi7/Bluepwn.svg) ![forks](https://img.shields.io/github/forks/henrychoi7/Bluepwn.svg)

- [https://github.com/RavSS/Bluetooth-Crash-CVE-2017-0785](https://github.com/RavSS/Bluetooth-Crash-CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/RavSS/Bluetooth-Crash-CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/RavSS/Bluetooth-Crash-CVE-2017-0785.svg)

- [https://github.com/aymankhalfatni/CVE-2017-0785](https://github.com/aymankhalfatni/CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/aymankhalfatni/CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/aymankhalfatni/CVE-2017-0785.svg)

- [https://github.com/SigBitsLabs/diff](https://github.com/SigBitsLabs/diff) :  ![starts](https://img.shields.io/github/stars/SigBitsLabs/diff.svg) ![forks](https://img.shields.io/github/forks/SigBitsLabs/diff.svg)

- [https://github.com/sigbitsadmin/diff](https://github.com/sigbitsadmin/diff) :  ![starts](https://img.shields.io/github/stars/sigbitsadmin/diff.svg) ![forks](https://img.shields.io/github/forks/sigbitsadmin/diff.svg)

- [https://github.com/Hackerscript/BlueBorne-CVE-2017-0785](https://github.com/Hackerscript/BlueBorne-CVE-2017-0785) :  ![starts](https://img.shields.io/github/stars/Hackerscript/BlueBorne-CVE-2017-0785.svg) ![forks](https://img.shields.io/github/forks/Hackerscript/BlueBorne-CVE-2017-0785.svg)

- [https://github.com/CrackSoft900/Blue-Borne](https://github.com/CrackSoft900/Blue-Borne) :  ![starts](https://img.shields.io/github/stars/CrackSoft900/Blue-Borne.svg) ![forks](https://img.shields.io/github/forks/CrackSoft900/Blue-Borne.svg)

## CVE-2017-0781
 A remote code execution vulnerability in the Android system (bluetooth). Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2, 8.0. Android ID: A-63146105.



- [https://github.com/ojasookert/CVE-2017-0781](https://github.com/ojasookert/CVE-2017-0781) :  ![starts](https://img.shields.io/github/stars/ojasookert/CVE-2017-0781.svg) ![forks](https://img.shields.io/github/forks/ojasookert/CVE-2017-0781.svg)

- [https://github.com/marcinguy/android712-blueborne](https://github.com/marcinguy/android712-blueborne) :  ![starts](https://img.shields.io/github/stars/marcinguy/android712-blueborne.svg) ![forks](https://img.shields.io/github/forks/marcinguy/android712-blueborne.svg)

- [https://github.com/mjancek/BlueborneDetection](https://github.com/mjancek/BlueborneDetection) :  ![starts](https://img.shields.io/github/stars/mjancek/BlueborneDetection.svg) ![forks](https://img.shields.io/github/forks/mjancek/BlueborneDetection.svg)

- [https://github.com/CrackSoft900/Blue-Borne](https://github.com/CrackSoft900/Blue-Borne) :  ![starts](https://img.shields.io/github/stars/CrackSoft900/Blue-Borne.svg) ![forks](https://img.shields.io/github/forks/CrackSoft900/Blue-Borne.svg)

## CVE-2017-0564
 An elevation of privilege vulnerability in the kernel ION subsystem could enable a local malicious application to execute arbitrary code within the context of the kernel. This issue is rated as Critical due to the possibility of a local permanent device compromise, which may require reflashing the operating system to repair the device. Product: Android. Versions: Kernel-3.10, Kernel-3.18. Android ID: A-34276203.



- [https://github.com/guoygang/CVE-2017-0564-ION-PoC](https://github.com/guoygang/CVE-2017-0564-ION-PoC) :  ![starts](https://img.shields.io/github/stars/guoygang/CVE-2017-0564-ION-PoC.svg) ![forks](https://img.shields.io/github/forks/guoygang/CVE-2017-0564-ION-PoC.svg)

## CVE-2017-0554
 An elevation of privilege vulnerability in the Telephony component could enable a local malicious application to access capabilities outside of its permission levels. This issue is rated as Moderate because it could be used to gain access to elevated capabilities, which are not normally accessible to a third-party application. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-33815946.



- [https://github.com/lanrat/tethr](https://github.com/lanrat/tethr) :  ![starts](https://img.shields.io/github/stars/lanrat/tethr.svg) ![forks](https://img.shields.io/github/forks/lanrat/tethr.svg)

## CVE-2017-0541
 A remote code execution vulnerability in sonivox in Mediaserver could enable an attacker using a specially crafted file to cause memory corruption during media file and data processing. This issue is rated as Critical due to the possibility of remote code execution within the context of the Mediaserver process. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-34031018.



- [https://github.com/JiounDai/CVE-2017-0541](https://github.com/JiounDai/CVE-2017-0541) :  ![starts](https://img.shields.io/github/stars/JiounDai/CVE-2017-0541.svg) ![forks](https://img.shields.io/github/forks/JiounDai/CVE-2017-0541.svg)

- [https://github.com/likescam/CVE-2017-0541](https://github.com/likescam/CVE-2017-0541) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-0541.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-0541.svg)

## CVE-2017-0478
 A remote code execution vulnerability in the Framesequence library could enable an attacker using a specially crafted file to execute arbitrary code in the context of an unprivileged process. This issue is rated as High due to the possibility of remote code execution in an application that uses the Framesequence library. Product: Android. Versions: 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-33718716.



- [https://github.com/JiounDai/CVE-2017-0478](https://github.com/JiounDai/CVE-2017-0478) :  ![starts](https://img.shields.io/github/stars/JiounDai/CVE-2017-0478.svg) ![forks](https://img.shields.io/github/forks/JiounDai/CVE-2017-0478.svg)

- [https://github.com/likescam/CVE-2017-0478](https://github.com/likescam/CVE-2017-0478) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-0478.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-0478.svg)

## CVE-2017-0411
 An elevation of privilege vulnerability in the Framework APIs could enable a local malicious application to execute arbitrary code within the context of a privileged process. This issue is rated as High because it could be used to gain local access to elevated capabilities, which are not normally accessible to a third-party application. Product: Android. Versions: 7.0, 7.1.1. Android ID: A-33042690.



- [https://github.com/lulusudoku/PoC](https://github.com/lulusudoku/PoC) :  ![starts](https://img.shields.io/github/stars/lulusudoku/PoC.svg) ![forks](https://img.shields.io/github/forks/lulusudoku/PoC.svg)

## CVE-2017-0290
 The Microsoft Malware Protection Engine running on Microsoft Forefront and Microsoft Defender on Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 does not properly scan a specially crafted file leading to memory corruption, aka &quot;Microsoft Malware Protection Engine Remote Code Execution Vulnerability.&quot;



- [https://github.com/homjxi0e/CVE-2017-0290-](https://github.com/homjxi0e/CVE-2017-0290-) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-0290-.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-0290-.svg)

## CVE-2017-0263
 The kernel-mode drivers in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allow local users to gain privileges via a crafted application, aka &quot;Win32k Elevation of Privilege Vulnerability.&quot;



- [https://github.com/R06otMD5/cve-2017-0263-poc](https://github.com/R06otMD5/cve-2017-0263-poc) :  ![starts](https://img.shields.io/github/stars/R06otMD5/cve-2017-0263-poc.svg) ![forks](https://img.shields.io/github/forks/R06otMD5/cve-2017-0263-poc.svg)

## CVE-2017-0261
 Microsoft Office 2010 SP2, Office 2013 SP1, and Office 2016 allow a remote code execution vulnerability when the software fails to properly handle objects in memory, aka &quot;Office Remote Code Execution Vulnerability&quot;. This CVE ID is unique from CVE-2017-0262 and CVE-2017-0281.



- [https://github.com/kcufId/eps-CVE-2017-0261](https://github.com/kcufId/eps-CVE-2017-0261) :  ![starts](https://img.shields.io/github/stars/kcufId/eps-CVE-2017-0261.svg) ![forks](https://img.shields.io/github/forks/kcufId/eps-CVE-2017-0261.svg)

- [https://github.com/erfze/CVE-2017-0261](https://github.com/erfze/CVE-2017-0261) :  ![starts](https://img.shields.io/github/stars/erfze/CVE-2017-0261.svg) ![forks](https://img.shields.io/github/forks/erfze/CVE-2017-0261.svg)

## CVE-2017-0248
 Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2 and 4.7 allow an attacker to bypass Enhanced Security Usage taggings when they present a certificate that is invalid for a specific use, aka &quot;.NET Security Feature Bypass Vulnerability.&quot;



- [https://github.com/rubenmamo/CVE-2017-0248-Test](https://github.com/rubenmamo/CVE-2017-0248-Test) :  ![starts](https://img.shields.io/github/stars/rubenmamo/CVE-2017-0248-Test.svg) ![forks](https://img.shields.io/github/forks/rubenmamo/CVE-2017-0248-Test.svg)

## CVE-2017-0213
 Windows COM Aggregate Marshaler in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation privilege vulnerability when an attacker runs a specially crafted application, aka &quot;Windows COM Elevation of Privilege Vulnerability&quot;. This CVE ID is unique from CVE-2017-0214.



- [https://github.com/zcgonvh/CVE-2017-0213](https://github.com/zcgonvh/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/zcgonvh/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/zcgonvh/CVE-2017-0213.svg)

- [https://github.com/eonrickity/CVE-2017-0213](https://github.com/eonrickity/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/eonrickity/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/eonrickity/CVE-2017-0213.svg)

- [https://github.com/jbooz1/CVE-2017-0213](https://github.com/jbooz1/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/jbooz1/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/jbooz1/CVE-2017-0213.svg)

- [https://github.com/Jos675/CVE-2017-0213-Exploit](https://github.com/Jos675/CVE-2017-0213-Exploit) :  ![starts](https://img.shields.io/github/stars/Jos675/CVE-2017-0213-Exploit.svg) ![forks](https://img.shields.io/github/forks/Jos675/CVE-2017-0213-Exploit.svg)

- [https://github.com/shaheemirza/CVE-2017-0213-](https://github.com/shaheemirza/CVE-2017-0213-) :  ![starts](https://img.shields.io/github/stars/shaheemirza/CVE-2017-0213-.svg) ![forks](https://img.shields.io/github/forks/shaheemirza/CVE-2017-0213-.svg)

- [https://github.com/likescam/CVE-2017-0213](https://github.com/likescam/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-0213.svg)

- [https://github.com/billa3283/CVE-2017-0213](https://github.com/billa3283/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/billa3283/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/billa3283/CVE-2017-0213.svg)

## CVE-2017-0204
 Microsoft Outlook 2007 SP3, Microsoft Outlook 2010 SP2, Microsoft Outlook 2013 SP1, and Microsoft Outlook 2016 allow remote attackers to bypass the Office Protected View via a specially crafted document, aka &quot;Microsoft Office Security Feature Bypass Vulnerability.&quot;



- [https://github.com/ryhanson/CVE-2017-0204](https://github.com/ryhanson/CVE-2017-0204) :  ![starts](https://img.shields.io/github/stars/ryhanson/CVE-2017-0204.svg) ![forks](https://img.shields.io/github/forks/ryhanson/CVE-2017-0204.svg)

## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka &quot;Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API.&quot;



- [https://github.com/bhdresh/CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/bhdresh/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/bhdresh/CVE-2017-0199.svg)

- [https://github.com/haibara3839/CVE-2017-0199-master](https://github.com/haibara3839/CVE-2017-0199-master) :  ![starts](https://img.shields.io/github/stars/haibara3839/CVE-2017-0199-master.svg) ![forks](https://img.shields.io/github/forks/haibara3839/CVE-2017-0199-master.svg)

- [https://github.com/NotAwful/CVE-2017-0199-Fix](https://github.com/NotAwful/CVE-2017-0199-Fix) :  ![starts](https://img.shields.io/github/stars/NotAwful/CVE-2017-0199-Fix.svg) ![forks](https://img.shields.io/github/forks/NotAwful/CVE-2017-0199-Fix.svg)

- [https://github.com/SyFi/cve-2017-0199](https://github.com/SyFi/cve-2017-0199) :  ![starts](https://img.shields.io/github/stars/SyFi/cve-2017-0199.svg) ![forks](https://img.shields.io/github/forks/SyFi/cve-2017-0199.svg)

- [https://github.com/Exploit-install/CVE-2017-0199](https://github.com/Exploit-install/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/Exploit-install/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/Exploit-install/CVE-2017-0199.svg)

- [https://github.com/SwordSheath/CVE-2017-8570](https://github.com/SwordSheath/CVE-2017-8570) :  ![starts](https://img.shields.io/github/stars/SwordSheath/CVE-2017-8570.svg) ![forks](https://img.shields.io/github/forks/SwordSheath/CVE-2017-8570.svg)

- [https://github.com/kn0wm4d/htattack](https://github.com/kn0wm4d/htattack) :  ![starts](https://img.shields.io/github/stars/kn0wm4d/htattack.svg) ![forks](https://img.shields.io/github/forks/kn0wm4d/htattack.svg)

- [https://github.com/nicpenning/RTF-Cleaner](https://github.com/nicpenning/RTF-Cleaner) :  ![starts](https://img.shields.io/github/stars/nicpenning/RTF-Cleaner.svg) ![forks](https://img.shields.io/github/forks/nicpenning/RTF-Cleaner.svg)

- [https://github.com/jacobsoo/RTF-Cleaner](https://github.com/jacobsoo/RTF-Cleaner) :  ![starts](https://img.shields.io/github/stars/jacobsoo/RTF-Cleaner.svg) ![forks](https://img.shields.io/github/forks/jacobsoo/RTF-Cleaner.svg)

- [https://github.com/sUbc0ol/Microsoft-Word-CVE-2017-0199-](https://github.com/sUbc0ol/Microsoft-Word-CVE-2017-0199-) :  ![starts](https://img.shields.io/github/stars/sUbc0ol/Microsoft-Word-CVE-2017-0199-.svg) ![forks](https://img.shields.io/github/forks/sUbc0ol/Microsoft-Word-CVE-2017-0199-.svg)

- [https://github.com/n1shant-sinha/CVE-2017-0199](https://github.com/n1shant-sinha/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/n1shant-sinha/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/n1shant-sinha/CVE-2017-0199.svg)

- [https://github.com/zakybstrd21215/PoC-CVE-2017-0199](https://github.com/zakybstrd21215/PoC-CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/zakybstrd21215/PoC-CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/zakybstrd21215/PoC-CVE-2017-0199.svg)

- [https://github.com/bloomer1016/2017-11-17-Maldoc-Using-CVE-2017-0199](https://github.com/bloomer1016/2017-11-17-Maldoc-Using-CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/bloomer1016/2017-11-17-Maldoc-Using-CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/bloomer1016/2017-11-17-Maldoc-Using-CVE-2017-0199.svg)

- [https://github.com/Nacromencer/cve2017-0199-in-python](https://github.com/Nacromencer/cve2017-0199-in-python) :  ![starts](https://img.shields.io/github/stars/Nacromencer/cve2017-0199-in-python.svg) ![forks](https://img.shields.io/github/forks/Nacromencer/cve2017-0199-in-python.svg)

- [https://github.com/joke998/Cve-2017-0199-](https://github.com/joke998/Cve-2017-0199-) :  ![starts](https://img.shields.io/github/stars/joke998/Cve-2017-0199-.svg) ![forks](https://img.shields.io/github/forks/joke998/Cve-2017-0199-.svg)

- [https://github.com/viethdgit/CVE-2017-0199](https://github.com/viethdgit/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/viethdgit/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/viethdgit/CVE-2017-0199.svg)

- [https://github.com/likescam/CVE-2017-0199](https://github.com/likescam/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/likescam/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/likescam/CVE-2017-0199.svg)

- [https://github.com/joke998/Cve-2017-0199](https://github.com/joke998/Cve-2017-0199) :  ![starts](https://img.shields.io/github/stars/joke998/Cve-2017-0199.svg) ![forks](https://img.shields.io/github/forks/joke998/Cve-2017-0199.svg)

- [https://github.com/ryhanson/CVE-2017-0199](https://github.com/ryhanson/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/ryhanson/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/ryhanson/CVE-2017-0199.svg)

- [https://github.com/Winter3un/cve_2017_0199](https://github.com/Winter3un/cve_2017_0199) :  ![starts](https://img.shields.io/github/stars/Winter3un/cve_2017_0199.svg) ![forks](https://img.shields.io/github/forks/Winter3un/cve_2017_0199.svg)

- [https://github.com/stealth-ronin/CVE-2017-0199-PY-KIT](https://github.com/stealth-ronin/CVE-2017-0199-PY-KIT) :  ![starts](https://img.shields.io/github/stars/stealth-ronin/CVE-2017-0199-PY-KIT.svg) ![forks](https://img.shields.io/github/forks/stealth-ronin/CVE-2017-0199-PY-KIT.svg)

## CVE-2017-0145
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0144, CVE-2017-0146, and CVE-2017-0148.



- [https://github.com/peterpt/eternal_scanner](https://github.com/peterpt/eternal_scanner) :  ![starts](https://img.shields.io/github/stars/peterpt/eternal_scanner.svg) ![forks](https://img.shields.io/github/forks/peterpt/eternal_scanner.svg)

- [https://github.com/MelonSmasher/chef_tissues](https://github.com/MelonSmasher/chef_tissues) :  ![starts](https://img.shields.io/github/stars/MelonSmasher/chef_tissues.svg) ![forks](https://img.shields.io/github/forks/MelonSmasher/chef_tissues.svg)

## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.



- [https://github.com/peterpt/eternal_scanner](https://github.com/peterpt/eternal_scanner) :  ![starts](https://img.shields.io/github/stars/peterpt/eternal_scanner.svg) ![forks](https://img.shields.io/github/forks/peterpt/eternal_scanner.svg)

- [https://github.com/kimocoder/eternalblue](https://github.com/kimocoder/eternalblue) :  ![starts](https://img.shields.io/github/stars/kimocoder/eternalblue.svg) ![forks](https://img.shields.io/github/forks/kimocoder/eternalblue.svg)

- [https://github.com/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution](https://github.com/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution) :  ![starts](https://img.shields.io/github/stars/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution.svg) ![forks](https://img.shields.io/github/forks/EEsshq/CVE-2017-0144---EtneralBlue-MS17-010-Remote-Code-Execution.svg)

## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.



- [https://github.com/valarauco/wannafind](https://github.com/valarauco/wannafind) :  ![starts](https://img.shields.io/github/stars/valarauco/wannafind.svg) ![forks](https://img.shields.io/github/forks/valarauco/wannafind.svg)

- [https://github.com/6A0BCD80/Etern-blue-Windows-7-Checker](https://github.com/6A0BCD80/Etern-blue-Windows-7-Checker) :  ![starts](https://img.shields.io/github/stars/6A0BCD80/Etern-blue-Windows-7-Checker.svg) ![forks](https://img.shields.io/github/forks/6A0BCD80/Etern-blue-Windows-7-Checker.svg)

## CVE-2017-0108
 The Windows Graphics Component in Microsoft Office 2007 SP3; 2010 SP2; and Word Viewer; Skype for Business 2016; Lync 2013 SP1; Lync 2010; Live Meeting 2007; Silverlight 5; Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; and Windows 7 SP1 allows remote attackers to execute arbitrary code via a crafted web site, aka &quot;Graphics Component Remote Code Execution Vulnerability.&quot; This vulnerability is different from that described in CVE-2017-0014.



- [https://github.com/homjxi0e/CVE-2017-0108](https://github.com/homjxi0e/CVE-2017-0108) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-0108.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-0108.svg)

## CVE-2017-0106
 Microsoft Excel 2007 SP3, Microsoft Outlook 2010 SP2, Microsoft Outlook 2013 SP1, and Microsoft Outlook 2016 allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted document, aka &quot;Microsoft Office Memory Corruption Vulnerability.&quot;



- [https://github.com/ryhanson/CVE-2017-0106](https://github.com/ryhanson/CVE-2017-0106) :  ![starts](https://img.shields.io/github/stars/ryhanson/CVE-2017-0106.svg) ![forks](https://img.shields.io/github/forks/ryhanson/CVE-2017-0106.svg)

## CVE-2017-0100
 A DCOM object in Helppane.exe in Microsoft Windows 7 SP1; Windows Server 2008 R2; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows local users to gain privileges via a crafted application, aka &quot;Windows HelpPane Elevation of Privilege Vulnerability.&quot;



- [https://github.com/cssxn/CVE-2017-0100](https://github.com/cssxn/CVE-2017-0100) :  ![starts](https://img.shields.io/github/stars/cssxn/CVE-2017-0100.svg) ![forks](https://img.shields.io/github/forks/cssxn/CVE-2017-0100.svg)

## CVE-2017-0075
 Hyper-V in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows guest OS users to execute arbitrary code on the host OS via a crafted application, aka &quot;Hyper-V Remote Code Execution Vulnerability.&quot; This vulnerability is different from that described in CVE-2017-0109.



- [https://github.com/4B5F5F4B/HyperV](https://github.com/4B5F5F4B/HyperV) :  ![starts](https://img.shields.io/github/stars/4B5F5F4B/HyperV.svg) ![forks](https://img.shields.io/github/forks/4B5F5F4B/HyperV.svg)

## CVE-2017-0065
 Microsoft Edge allows remote attackers to obtain sensitive information from process memory via a crafted web site, aka &quot;Microsoft Browser Information Disclosure Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0009, CVE-2017-0011, CVE-2017-0017, and CVE-2017-0068.



- [https://github.com/Dankirk/cve-2017-0065](https://github.com/Dankirk/cve-2017-0065) :  ![starts](https://img.shields.io/github/stars/Dankirk/cve-2017-0065.svg) ![forks](https://img.shields.io/github/forks/Dankirk/cve-2017-0065.svg)

## CVE-2017-0038
 gdi32.dll in Graphics Device Interface (GDI) in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold, 1511, and 1607 allows remote attackers to obtain sensitive information from process heap memory via a crafted EMF file, as demonstrated by an EMR_SETDIBITSTODEVICE record with modified Device Independent Bitmap (DIB) dimensions. NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-3216, CVE-2016-3219, and/or CVE-2016-3220.



- [https://github.com/k0keoyo/CVE-2017-0038-EXP-C-JS](https://github.com/k0keoyo/CVE-2017-0038-EXP-C-JS) :  ![starts](https://img.shields.io/github/stars/k0keoyo/CVE-2017-0038-EXP-C-JS.svg) ![forks](https://img.shields.io/github/forks/k0keoyo/CVE-2017-0038-EXP-C-JS.svg)

## CVE-2017-0005
 The Graphics Device Interface (GDI) in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607 allows local users to gain privileges via a crafted application, aka &quot;Windows GDI Elevation of Privilege Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0001, CVE-2017-0025, and CVE-2017-0047.



- [https://github.com/sheri31/0005poc](https://github.com/sheri31/0005poc) :  ![starts](https://img.shields.io/github/stars/sheri31/0005poc.svg) ![forks](https://img.shields.io/github/forks/sheri31/0005poc.svg)
